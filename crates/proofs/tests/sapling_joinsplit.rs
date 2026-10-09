//! Original V4 Sprout Groth16 + branch-selected JoinSplit Ed25519 authorization.
//! These isolated fixtures are not connected history or a financial source fact.

use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion, components::sprout::{Bundle, JsDescription}};
use zcash_protocol::{consensus::BranchId, value::{MAX_MONEY, ZatBalance, Zatoshis}};
use zcash_transparent::{address::Script, bundle::TxOut};
use ziquid_proofs::{legacy_joinsplit::{LegacyJoinSplitError, verify_sapling_joinsplit_crypto}, sapling_sighash::SaplingSignatureHash, sprout_groth16::GrothError};

#[path = "fixtures/sprout-groth16-testnet-280003.rs"]
mod primary;
#[path = "fixtures/sapling-mainnet-419202.rs"]
mod sapling_primary;

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        let digit = |c| match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, _ => panic!("fixture hex") };
        digit(pair[0]) * 16 + digit(pair[1])
    }).collect()
}

fn parse(raw: &[u8]) -> Transaction {
    let mut reader = raw;
    let transaction = Transaction::read(&mut reader, BranchId::Sapling).unwrap();
    assert!(reader.is_empty());
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).unwrap();
    assert_eq!(canonical, raw);
    transaction
}

fn verify(transaction: &Transaction) -> Result<(), LegacyJoinSplitError> {
    verify_sapling_joinsplit_crypto(&SaplingSignatureHash::new(transaction).unwrap())
}

fn transaction(sprout: Option<Bundle>, outputs: &[u64], vb: Option<i64>, branch: BranchId) -> Transaction {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    let mut transparent = original.transparent_bundle().unwrap().clone();
    transparent.vout = outputs.iter().map(|value| TxOut::new(Zatoshis::from_u64(*value).unwrap(), Script::default())).collect();
    let sapling = vb.and_then(|vb| {
        let source = parse(&bytes(sapling_primary::TRANSACTION_HEX));
        let source = source.sapling_bundle().unwrap();
        sapling_crypto::Bundle::from_parts(source.shielded_spends().to_vec(), source.shielded_outputs().to_vec(), ZatBalance::from_i64(vb).unwrap(), *source.authorization())
    });
    TransactionData::<Authorized>::from_parts(TxVersion::V4, branch, 0, original.expiry_height(), Some(transparent), sprout, sapling, None).freeze().unwrap()
}

fn description(old: u64, new: u64, nf: u8) -> JsDescription {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    let mut raw = Vec::new();
    original.sprout_bundle().unwrap().joinsplits[0].write(&mut raw).unwrap();
    raw[..8].copy_from_slice(&old.to_le_bytes());
    raw[8..16].copy_from_slice(&new.to_le_bytes());
    raw[48..80].fill(nf);
    raw[80..112].fill(nf + 1);
    JsDescription::read(raw.as_slice(), true).unwrap()
}

fn bundle(descriptions: Vec<JsDescription>) -> Bundle {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    let mut bundle = original.sprout_bundle().unwrap().clone();
    bundle.joinsplits = descriptions;
    bundle
}

#[test]
fn original_mined_v4_checks_groth_proof_and_fixed_all_actual_signature() {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    assert_eq!(verify(&original), Ok(()));
    let mut raw = bytes(primary::TRANSACTION_HEX);
    raw[50] ^= 1; // transparent scriptSig is intentionally not the JoinSplit digest.
    assert_eq!(verify(&parse(&raw)), Ok(()));
    let mut raw = bytes(primary::TRANSACTION_HEX);
    let end = raw.len();
    raw[end - 1] ^= 1;
    assert_eq!(verify(&parse(&raw)), Err(LegacyJoinSplitError::InvalidSignature));
}

#[test]
fn cheap_v4_money_guards_include_sapling_balance_without_net_cancellation() {
    for (descriptions, outputs, vb, error) in [
        (vec![description(1, 1, 1)], vec![], None, LegacyJoinSplitError::InvalidPublicValues),
        (vec![description(MAX_MONEY, 0, 1)], vec![], Some(-1), LegacyJoinSplitError::DebitOutOfRange),
        (vec![description(0, MAX_MONEY, 1)], vec![], Some(1), LegacyJoinSplitError::CreditOutOfRange),
        (vec![description(0, 0, 1)], vec![MAX_MONEY], Some(-1), LegacyJoinSplitError::DebitOutOfRange),
        (vec![description(0, 0, 1), description(0, 0, 1)], vec![], Some(0), LegacyJoinSplitError::DuplicateNullifier),
        (vec![description(MAX_MONEY, 0, 1), description(1, 0, 3), description(0, MAX_MONEY, 5)], vec![], None, LegacyJoinSplitError::DebitOutOfRange),
    ] {
        assert_eq!(verify(&transaction(Some(bundle(descriptions)), &outputs, vb, BranchId::Sapling)), Err(error));
    }
    assert_eq!(verify(&transaction(None, &[MAX_MONEY], Some(-1), BranchId::Sapling)), Err(LegacyJoinSplitError::DebitOutOfRange));
    assert_eq!(verify(&transaction(None, &[], None, BranchId::Sapling)), Ok(()));
}

#[test]
fn v4_signature_wrapper_supports_current_nu63_branch() {
    for branch in [BranchId::Sapling, BranchId::Blossom, BranchId::Heartwood, BranchId::Canopy, BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2, BranchId::Nu6_3] {
        assert_eq!(verify(&transaction(None, &[], None, branch)), Ok(()));
    }
}

#[test]
fn original_ed25519_identity_acceptance_does_not_bypass_actual_groth_equation() {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    let mut sprout = original.sprout_bundle().unwrap().clone();
    sprout.joinsplit_pubkey = [0; 32];
    sprout.joinsplit_pubkey[0] = 1;
    // Independently observed libsodium1.0.15 acceptance: A=identity,R=B,S=1.
    // Different actual JS key changes h_sig, so the real proof MUST reject.
    sprout.joinsplit_sig = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000").try_into().unwrap();
    let changed = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, original.lock_time(), original.expiry_height(), original.transparent_bundle().cloned(), Some(sprout), None, None).freeze().unwrap();
    assert_eq!(verify(&changed), Err(LegacyJoinSplitError::SproutGrothProof { index: 0, error: GrothError::InvalidProof }));
}

#[test]
fn canopy_zip215_accepts_zero_key_identity_signature_then_checks_actual_groth() {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    let mut sprout = original.sprout_bundle().unwrap().clone();
    // A=order-four (raw zero), R=identity, S=0 is valid under the ZIP215
    // cofactored equation for every digest; original libsodium rejects raw A=0.
    sprout.joinsplit_pubkey = [0; 32];
    sprout.joinsplit_sig = [0; 64];
    sprout.joinsplit_sig[0] = 1;
    let changed = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, original.lock_time(), original.expiry_height(), original.transparent_bundle().cloned(), Some(sprout), None, None).freeze().unwrap();
    // Changed key changes h_sig, so the recorded Groth proof is NOT valid.
    assert_eq!(verify(&changed), Err(LegacyJoinSplitError::SproutGrothProof { index: 0, error: GrothError::InvalidProof }));
}

#[test]
fn actual_branch_selects_zip215_without_bypassing_money_nullifiers_or_groth() {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    let mut sprout = original.sprout_bundle().unwrap().clone();
    sprout.joinsplit_pubkey = [0; 32];
    sprout.joinsplit_sig = [0; 64];
    sprout.joinsplit_sig[0] = 1;
    for branch in [BranchId::Sapling, BranchId::Blossom, BranchId::Heartwood] {
        assert_eq!(verify(&transaction(Some(sprout.clone()), &[], None, branch)), Err(LegacyJoinSplitError::InvalidSignature));
    }
    for (descriptions, outputs, vb, error) in [
        (vec![description(1, 1, 1)], vec![], None, LegacyJoinSplitError::InvalidPublicValues),
        (vec![description(MAX_MONEY, 0, 1)], vec![], Some(-1), LegacyJoinSplitError::DebitOutOfRange),
        (vec![description(0, MAX_MONEY, 1)], vec![], Some(1), LegacyJoinSplitError::CreditOutOfRange),
        (vec![description(0, 0, 1), description(0, 0, 1)], vec![], None, LegacyJoinSplitError::DuplicateNullifier),
    ] {
        let mut changed = sprout.clone();
        changed.joinsplits = descriptions;
        assert_eq!(verify(&transaction(Some(changed), &outputs, vb, BranchId::Canopy)), Err(error));
    }
    // ZIP215 accepts this signature, not this transaction: h_sig changed and
    // the genuine recorded proof must still fail its actual Groth equation.
    assert_eq!(verify(&transaction(Some(sprout.clone()), &[], None, BranchId::Canopy)), Err(LegacyJoinSplitError::SproutGrothProof { index: 0, error: GrothError::InvalidProof }));
    sprout.joinsplit_sig[32] = 1;
    assert_eq!(verify(&transaction(Some(sprout), &[], None, BranchId::Canopy)), Err(LegacyJoinSplitError::InvalidSignature));
}

#[test]
fn canopy_rejects_genuine_pre_canopy_signature_without_previous_branch_fallback() {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    let changed = TransactionData::<Authorized>::from_parts(
        TxVersion::V4, BranchId::Canopy, original.lock_time(), original.expiry_height(),
        original.transparent_bundle().cloned(), original.sprout_bundle().cloned(), None, None,
    ).freeze().unwrap();
    // Proof/key/description remain genuine; only the actual digest branch
    // changes. An old-branch retry must not accept the recorded signature.
    assert_eq!(verify(&changed), Err(LegacyJoinSplitError::InvalidSignature));
}

#[test]
fn nu5_through_nu63_zip215_retain_cofactored_acceptance_then_every_actual_groth_equation() {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    let mut sprout = original.sprout_bundle().unwrap().clone();
    sprout.joinsplit_pubkey = [0; 32];
    sprout.joinsplit_sig = [0; 64];
    sprout.joinsplit_sig[0] = 1;
    for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2, BranchId::Nu6_3] {
        let changed = transaction(Some(sprout.clone()), &[], None, branch);
        assert_eq!(verify(&changed), Err(LegacyJoinSplitError::SproutGrothProof { index: 0, error: GrothError::InvalidProof }));
        let mut invalid = sprout.clone();
        invalid.joinsplit_sig[32] = 1;
        assert_eq!(verify(&transaction(Some(invalid), &[], None, branch)), Err(LegacyJoinSplitError::InvalidSignature));
    }
}

#[test]
fn nu61_through_nu63_zip215_check_all_public_values_nullifiers_and_old_signed_v4_digests() {
    let original = parse(&bytes(primary::TRANSACTION_HEX));
    for branch in [BranchId::Nu6_1, BranchId::Nu6_2, BranchId::Nu6_3] {
        let old = TransactionData::<Authorized>::from_parts(TxVersion::V4, branch,
            original.lock_time(), original.expiry_height(), original.transparent_bundle().cloned(), original.sprout_bundle().cloned(), None, None).freeze().unwrap();
        assert_eq!(verify(&old), Err(LegacyJoinSplitError::InvalidSignature));
        for (descriptions, outputs, balance, error) in [
            (vec![description(1, 1, 1)], vec![], None, LegacyJoinSplitError::InvalidPublicValues),
            (vec![description(MAX_MONEY, 0, 1)], vec![1], None, LegacyJoinSplitError::DebitOutOfRange),
            (vec![description(0, MAX_MONEY, 1)], vec![], Some(1), LegacyJoinSplitError::CreditOutOfRange),
            (vec![description(0, 0, 1), description(0, 0, 1)], vec![], None, LegacyJoinSplitError::DuplicateNullifier),
        ] {
            let changed = transaction(Some(bundle(descriptions)), &outputs, balance, branch);
            assert_eq!(verify(&changed), Err(error));
        }
    }
}
