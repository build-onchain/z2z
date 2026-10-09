use ziquid_proofs::native_relation::{self, GlobalMarkers, NativeInputFacts, NativeOutputFacts};
use pczt::{
    Pczt,
    roles::verifier::{OrchardError, Verifier},
};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::{
    TxVersion,
    sighash::SignableInput,
    sighash_v6::v6_signature_hash,
    txid::{TxIdDigester, to_txid},
};
use zcash_protocol::{
    constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID},
    value::Zatoshis,
};

use super::{
    CheckedNativeOutput, CustodyError, ExpectedNativeEffects, NativeOutputKind, UnsignedNativeInspection,
};

/// Inspects real native effects, not a fully authorized or proved transaction.
/// Inventory/source occurrence and genesis are independently enrolled caller
/// facts; neither a branch identifier nor this PCZT establishes source history.
pub fn inspect_pczt<'a>(
    bytes: &[u8],
    expected: &ExpectedNativeEffects<'a>,
) -> Result<UnsignedNativeInspection<'a>, CustodyError> {
    validate_expected(expected)?;
    let pczt = Pczt::parse(bytes).map_err(|_| CustodyError::InvalidPczt)?;
    let global = pczt.global();
    if *global.tx_version() != V6_TX_VERSION
        || *global.version_group_id() != V6_VERSION_GROUP_ID
        || *global.consensus_branch_id() != expected.domain.source_branch
        || *global.tx_version() != expected.domain.source_tx_version
    {
        return Err(CustodyError::UnsupportedProfile);
    }
    if *global.expiry_height() != expected.expiry_height {
        return Err(CustodyError::GlobalMetadata);
    }
    let markers = GlobalMarkers::read(global).map_err(relation_error)?;
    // The pinned profile is testnet. Regtest uses this same public SLIP44 marker;
    // explicit source_genesis must therefore remain an independent domain fact.
    if markers.coin_type != Some(1) {
        return Err(CustodyError::NetworkMarkerMismatch);
    }
    if markers.tx_modifiable != Some(0) {
        return Err(CustodyError::ModifiableTransaction);
    }
    if !pczt.transparent().inputs().is_empty()
        || !pczt.transparent().outputs().is_empty()
        || !pczt.sapling().spends().is_empty()
        || !pczt.sapling().outputs().is_empty()
        || *pczt.sapling().value_sum() != 0
        || !pczt.orchard().actions().is_empty()
        || *pczt.orchard().value_sum() != (0, false)
    {
        return Err(CustodyError::UnsupportedPool);
    }
    let mut outputs = Vec::with_capacity(expected.outputs.len());
    let verified = Verifier::new(pczt)
        .with_ironwood(|bundle| {
            verify_bundle(bundle, expected, &mut outputs).map_err(OrchardError::Custom)
        })
        .map_err(|error| match error {
            OrchardError::Custom(error) => error,
            OrchardError::Verify(_) => CustodyError::NativeVerification,
            OrchardError::Parse(_) => CustodyError::NativeParse,
            OrchardError::UnsupportedConsensusBranchId => CustodyError::UnsupportedProfile,
        })?
        .finish();
    let effects = verified
        .into_effects()
        .map_err(|_| CustodyError::EffectExtraction)?;
    if effects.version() != TxVersion::V6
        || effects.lock_time() != expected.lock_time
        || u32::from(effects.expiry_height()) != expected.expiry_height
    {
        return Err(CustodyError::GlobalMetadata);
    }
    let actual_fee = effects
        .fee_paid::<zcash_protocol::value::BalanceError, _>(|_| Ok(None))
        .map_err(|_| CustodyError::AmountOutOfRange)?
        .ok_or(CustodyError::MissingMetadata)?;
    if u64::from(actual_fee) != expected.fee {
        return Err(CustodyError::FeeMismatch);
    }
    let digests = effects.digest(TxIdDigester);
    let txid = to_txid(effects.version(), effects.consensus_branch_id(), &digests).into();
    // Hash.as_array() is the 64-byte backing store, not the configured digest.
    // This exact checked conversion matches PCZT's maintained sighash wrapper.
    let hash = v6_signature_hash(&effects, &SignableInput::Shielded, &digests);
    let shielded_sighash = hash
        .as_ref()
        .try_into()
        .map_err(|_| CustodyError::SighashEncoding)?;
    Ok(UnsignedNativeInspection {
        domain: *expected.domain,
        lock_time: expected.lock_time,
        expiry_height: expected.expiry_height,
        fee: expected.fee,
        exact_pczt_digest: Sha256::digest(bytes).into(),
        txid,
        shielded_sighash,
        inputs: expected.inputs,
        outputs,
        expected_outputs: expected.outputs,
    })
}

fn validate_expected(expected: &ExpectedNativeEffects<'_>) -> Result<(), CustodyError> {
    expected.domain.validate().map_err(CustodyError::Protocol)?;
    if expected.inputs.is_empty() || expected.outputs.is_empty() {
        return Err(CustodyError::InvalidExpectedEffects);
    }
    Zatoshis::from_u64(expected.fee).map_err(|_| CustodyError::AmountOutOfRange)?;
    for (index, input) in expected.inputs.iter().enumerate() {
        if input.value == 0
            || input.inventory_note == [0; 32]
            || input.source_occurrence.network != expected.domain.source_network
            || input.source_occurrence.pool != expected.domain.source_pool
            || input.source_occurrence.txid == [0; 32]
            || input.note_commitment == [0; 32]
            || input.nullifier == [0; 32]
            || expected.inputs[..index].iter().any(|prior| {
                prior.nullifier == input.nullifier
                    || prior.inventory_note == input.inventory_note
                    || prior.source_occurrence == input.source_occurrence
                    || prior.note_commitment == input.note_commitment
            })
        {
            return Err(CustodyError::InvalidExpectedEffects);
        }
        Zatoshis::from_u64(input.value).map_err(|_| CustodyError::AmountOutOfRange)?;
    }
    for output in expected.outputs {
        if output.value == 0 {
            return Err(CustodyError::InvalidExpectedEffects);
        }
        Zatoshis::from_u64(output.value).map_err(|_| CustodyError::AmountOutOfRange)?;
        if output.kind == NativeOutputKind::Change
            && !expected.inputs.iter().any(|input| {
                input
                    .trusted_fvk
                    .scope_for_address(&output.recipient)
                    .is_some()
            })
        {
            return Err(CustodyError::ChangeOwnership);
        }
    }
    Ok(())
}


fn verify_bundle(
    bundle: &orchard::pczt::Bundle,
    expected: &ExpectedNativeEffects<'_>,
    outputs: &mut Vec<CheckedNativeOutput>,
) -> Result<(), CustodyError> {
    let mut checked = Vec::with_capacity(expected.outputs.len());
    native_relation::verify_source_bundle(
        bundle,
        expected.inputs.iter().map(|input| NativeInputFacts {
            nullifier: &input.nullifier, note_commitment: &input.note_commitment,
            value: input.value, trusted_fvk: &input.trusted_fvk,
        }),
        expected.outputs.iter().map(|output| NativeOutputFacts {
            recipient: output.recipient, value: output.value, memo: None,
        }),
        expected.fee, &mut checked,
    ).map_err(relation_error)?;
    outputs.extend(checked.into_iter().map(|output| CheckedNativeOutput {
        recipient: output.recipient, value: output.value, action_index: output.action_index,
        note_commitment: output.note_commitment, nullifier: output.nullifier,
    }));
    Ok(())
}


pub(crate) fn relation_error(error: native_relation::NativeRelationError) -> CustodyError {
    use native_relation::NativeRelationError as E;
    match error {
        E::UnsupportedProfile | E::WrongBundleVersion => CustodyError::UnsupportedProfile,
        E::UnsupportedPool => CustodyError::UnsupportedPool,
        E::GlobalMetadata => CustodyError::GlobalMetadata,
        E::MissingMetadata => CustodyError::MissingMetadata,
        E::NativeVerification => CustodyError::NativeVerification,
        E::InputMismatch => CustodyError::InputMismatch,
        E::OutputMismatch => CustodyError::OutputMismatch,
        E::ChangeOwnership => CustodyError::ChangeOwnership,
        E::CiphertextMismatch => CustodyError::CiphertextMismatch,
        E::ValueBalanceMismatch => CustodyError::ValueBalanceMismatch,
        E::FeeMismatch => CustodyError::FeeMismatch,
        E::AmountOutOfRange => CustodyError::AmountOutOfRange,
        E::EffectExtraction => CustodyError::EffectExtraction,
        E::SighashEncoding => CustodyError::SighashEncoding,
        E::DummySpendKey => CustodyError::DummySpendKey,
        _ => CustodyError::InvalidPczt,
    }
}
