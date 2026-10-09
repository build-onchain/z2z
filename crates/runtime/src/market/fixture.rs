//! Explicit generated LocalFixture inputs, not source history, MPC, signing or payment.
use super::{Error, Result, native::NativeContext};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use ziquid_zcash::custody::{ExpectedNativeOutput, NativeOutputKind, ReservedNativeInput};
use ziquid_protocol::market::{Domain, Id, ObservationEnvironment, SourceOccurrence};
use orchard::{
    Address, Anchor, Note,
    keys::{FullViewingKey, Scope},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::roles::creator::Creator;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::fixed,
};
use zcash_protocol::{local_consensus::LocalNetwork, memo::MemoBytes, value::Zatoshis};

pub const USER_NOTE: Id = [20; 32];
pub const FIRST_SPONSOR_NOTE: Id = [21; 32];
pub const CHANGE_NOTE: Id = [22; 32];
pub const SECOND_SPONSOR_NOTE: Id = [23; 32];

pub struct FixtureNative {
    pub bytes: Vec<u8>,
    pub context: NativeContext,
    pub change_note: Option<Note>,
}
impl FixtureNative {
    pub fn payout(
        domain: Domain,
        fvk: FullViewingKey,
        recipient: Address,
        change: Address,
    ) -> Result<Self> {
        let inputs = [note(change, 34, 0)?, note(change, 10_000, 1)?];
        let outputs = vec![
            ExpectedNativeOutput {
                recipient,
                value: 25,
                kind: NativeOutputKind::Recipient,
            },
            ExpectedNativeOutput {
                recipient: change,
                value: 9,
                kind: NativeOutputKind::Change,
            },
        ];
        build(
            domain,
            fvk,
            inputs,
            [USER_NOTE, FIRST_SPONSOR_NOTE],
            [
                SourceOccurrence {
                    network: domain.source_network,
                    pool: domain.source_pool,
                    txid: [30; 32],
                    action_index: 0,
                },
                SourceOccurrence {
                    network: domain.source_network,
                    pool: domain.source_pool,
                    txid: [31; 32],
                    action_index: 0,
                },
            ],
            outputs,
        )
    }
    pub fn refund(
        domain: Domain,
        fvk: FullViewingKey,
        confirmed_change: Note,
        confirmed_occurrence: SourceOccurrence,
        recipient: Address,
    ) -> Result<Self> {
        if confirmed_change.value().inner() != 9 {
            return Err(Error::Input);
        }
        let inputs = [confirmed_change, note(recipient, 10_000, 2)?];
        let outputs = vec![ExpectedNativeOutput {
            recipient,
            value: 9,
            kind: NativeOutputKind::Recipient,
        }];
        build(
            domain,
            fvk,
            inputs,
            [CHANGE_NOTE, SECOND_SPONSOR_NOTE],
            [
                confirmed_occurrence,
                SourceOccurrence {
                    network: domain.source_network,
                    pool: domain.source_pool,
                    txid: [33; 32],
                    action_index: 0,
                },
            ],
            outputs,
        )
    }
}

fn build(
    domain: Domain,
    fvk: FullViewingKey,
    notes: [Note; 2],
    ids: [Id; 2],
    occurrences: [SourceOccurrence; 2],
    outputs: Vec<ExpectedNativeOutput>,
) -> Result<FixtureNative> {
    domain.validate().map_err(|_| Error::Configuration)?;
    let (anchor, paths) = witnesses(&notes)?;
    let network = LocalNetwork {
        overwinter: Some(1.into()),
        sapling: Some(1.into()),
        blossom: Some(1.into()),
        heartwood: Some(1.into()),
        canopy: Some(1.into()),
        nu5: Some(1.into()),
        nu6: Some(1.into()),
        nu6_1: Some(1.into()),
        nu6_2: Some(1.into()),
        nu6_3: Some(1.into()),
    };
    let mut builder = Builder::new(
        network,
        200.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(220.into());
    let inputs = notes
        .iter()
        .enumerate()
        .map(|(index, note)| ReservedNativeInput {
            inventory_note: ids[index],
            source_occurrence: occurrences[index],
            note_commitment: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
            nullifier: note.nullifier(&fvk).to_bytes(),
            value: note.value().inner(),
            trusted_fvk: fvk.clone(),
        })
        .collect::<Vec<_>>();
    for (note, path) in notes.iter().zip(paths) {
        builder
            .add_ironwood_spend::<core::convert::Infallible>(fvk.clone(), *note, path)
            .map_err(|_| Error::Input)?;
    }
    for output in &outputs {
        builder
            .add_ironwood_output::<core::convert::Infallible>(
                Some(fvk.to_ovk(Scope::External)),
                output.recipient,
                Zatoshis::from_u64(output.value).map_err(|_| Error::Input)?,
                MemoBytes::empty(),
            )
            .map_err(|_| Error::Input)?;
    }
    let mut rng_seed = [0; 32];
    getrandom::fill(&mut rng_seed).map_err(|_| Error::Input)?;
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(
            ChaCha20Rng::from_seed(rng_seed),
            &fixed::FeeRule::non_standard(Zatoshis::const_from_u64(10_000)),
        )
        .map_err(|_| Error::Input)?;
    let pczt = Creator::build_from_parts(pczt_parts).ok_or(Error::Input)?;
    // Two real spends avoid dummy spend keys. A one-output refund can have
    // explicit zero-value output padding; no signing/proving/finalization occurs.
    if pczt.ironwood().actions().len() != 2
        || pczt.ironwood().zkproof().is_some()
        || pczt.ironwood().actions().iter().any(|action| {
            action.spend().dummy_sk().is_some() || action.spend().spend_auth_sig().is_some()
        })
    {
        return Err(Error::Input);
    }
    let change_note = if let Some(change) = outputs
        .iter()
        .find(|output| output.kind == NativeOutputKind::Change)
    {
        let action = pczt
            .ironwood()
            .actions()
            .iter()
            .find(|action| {
                *action.output().value() == Some(change.value)
                    && *action.output().recipient() == Some(change.recipient.to_raw_address_bytes())
            })
            .ok_or(Error::Input)?;
        let rho = Rho::from_bytes(action.spend().nullifier())
            .into_option()
            .ok_or(Error::Input)?;
        let rseed = RandomSeed::from_bytes(action.output().rseed().ok_or(Error::Input)?, &rho)
            .into_option()
            .ok_or(Error::Input)?;
        Some(
            Note::from_parts(
                change.recipient,
                NoteValue::from_raw(change.value),
                rho,
                rseed,
                NoteVersion::V3,
            )
            .into_option()
            .ok_or(Error::Input)?,
        )
    } else {
        None
    };
    let bytes = pczt.serialize().map_err(|_| Error::Input)?;
    Ok(FixtureNative {
        bytes,
        context: NativeContext {
            domain,
            environment: ObservationEnvironment::LocalFixture,
            lock_time: 0,
            expiry_height: 220,
            fee: 10_000,
            inputs,
            outputs,
        },
        change_note,
    })
}

fn note(recipient: Address, value: u64, index: u8) -> Result<Note> {
    let mut rho_bytes = [0; 32];
    rho_bytes[0] = index + 1;
    let rho = Rho::from_bytes(&rho_bytes)
        .into_option()
        .ok_or(Error::Input)?;
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).map_err(|_| Error::Input)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(rseed) = RandomSeed::from_bytes(bytes, &rho).into_option()
            && let Some(note) = Note::from_parts(
                recipient,
                NoteValue::from_raw(value),
                rho,
                rseed,
                NoteVersion::V3,
            )
            .into_option()
        {
            return Ok(note);
        }
    }
}

fn witnesses(notes: &[Note]) -> Result<(Anchor, Vec<MerklePath>)> {
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut witnesses: Vec<IncrementalWitness<MerkleHashOrchard, 32>> = Vec::new();
    for note in notes {
        let leaf = MerkleHashOrchard::from_cmx(&note.commitment().into());
        tree.append(leaf).map_err(|_| Error::Input)?;
        for witness in &mut witnesses {
            witness.append(leaf).map_err(|_| Error::Input)?;
        }
        witnesses.push(IncrementalWitness::from_tree(tree.clone()).ok_or(Error::Input)?);
    }
    let anchor = tree.root().into();
    let paths = witnesses
        .into_iter()
        .map(|witness| witness.path().map(Into::into).ok_or(Error::Input))
        .collect::<Result<Vec<MerklePath>>>()?;
    if notes
        .iter()
        .zip(&paths)
        .any(|(note, path)| path.root(note.commitment().into()) != anchor)
    {
        return Err(Error::Input);
    }
    Ok((anchor, paths))
}
