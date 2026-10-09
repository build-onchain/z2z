use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use ziquid_zcash::custody::{
    ExpectedNativeEffects, ExpectedNativeOutput, NativeOutputKind, ReservedNativeInput,
    inspect_pczt,
};
use ziquid_protocol::market::{Domain, SourceOccurrence};
use orchard::{
    Address, Anchor, Note,
    keys::{FullViewingKey, Scope},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::{
    Pczt,
    roles::{creator::Creator, redactor::Redactor, signer::Signer},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::fixed,
    sighash::SignableInput,
    sighash_v6::v6_signature_hash,
    txid::{TxIdDigester, to_txid},
};
use zcash_protocol::{
    consensus::BranchId, local_consensus::LocalNetwork, memo::MemoBytes, value::Zatoshis,
};

const EXPIRY: u32 = 220;
const FEE: u64 = 10_000;

// Public viewing components only: ak || nk || rivk from the first two Orchard
// key-components vectors in orchard 0.15.5 src/test_vectors/keys.rs, attributed to
// https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/orchard/key_components.py.
// No spending key or spend-authorizing key is copied, derived, or used here.
const PUBLIC_FVKS: [[u8; 96]; 2] = [
    [
        0x74, 0x0b, 0xbe, 0x5d, 0x05, 0x80, 0xb2, 0xca, 0xd4, 0x30, 0x18, 0x0d, 0x02, 0xcc, 0x12,
        0x8b, 0x9a, 0x14, 0x0d, 0x5e, 0x07, 0xc1, 0x51, 0x72, 0x1d, 0xc1, 0x6d, 0x25, 0xd4, 0xe2,
        0x0f, 0x15, 0x9f, 0x2f, 0x82, 0x67, 0x38, 0x94, 0x5a, 0xd0, 0x1f, 0x47, 0xf7, 0x0d, 0xb0,
        0xc3, 0x67, 0xc2, 0x46, 0xc2, 0x0c, 0x61, 0xff, 0x55, 0x83, 0x94, 0x8c, 0x39, 0xde, 0xa9,
        0x68, 0xfe, 0xfd, 0x1b, 0x02, 0x1c, 0xcf, 0x89, 0x60, 0x4f, 0x5f, 0x7c, 0xc6, 0xe0, 0x34,
        0xb3, 0x2d, 0x33, 0x89, 0x08, 0xb8, 0x19, 0xfb, 0xe3, 0x25, 0xfe, 0xe6, 0x45, 0x8b, 0x56,
        0xb4, 0xca, 0x71, 0xa7, 0xe4, 0x3d,
    ],
    [
        0x6d, 0xe1, 0x34, 0x98, 0x30, 0xd6, 0x6d, 0x7b, 0x97, 0xfe, 0x23, 0x1f, 0xc7, 0xb0, 0x2a,
        0xd6, 0x43, 0x23, 0x62, 0x9c, 0xfe, 0xd1, 0xe3, 0xaa, 0x24, 0xef, 0x05, 0x2f, 0x56, 0xe4,
        0x00, 0x2a, 0xa8, 0xb7, 0x3d, 0x97, 0x9b, 0x6e, 0xaa, 0xda, 0x89, 0x24, 0xbc, 0xbd, 0xc6,
        0x3a, 0x9e, 0xf4, 0xe8, 0x73, 0x46, 0xf2, 0x30, 0xab, 0xa6, 0xbb, 0xe1, 0xe2, 0xb4, 0x3c,
        0x5b, 0xea, 0x6b, 0x22, 0xda, 0xcb, 0x2f, 0x2a, 0x9c, 0xed, 0x36, 0x31, 0x71, 0x82, 0x1a,
        0xaf, 0x5d, 0x8c, 0xd9, 0x02, 0xbc, 0x5e, 0x3a, 0x5a, 0x41, 0xfb, 0x51, 0xae, 0x61, 0xa9,
        0xf0, 0x2d, 0xc8, 0x9d, 0x1d, 0x12,
    ],
];

fn domain() -> Domain {
    Domain {
        schema_version: 1,
        deployment: [1; 32],
        solana_genesis: [2; 32],
        solana_program: [3; 32],
        mint: [4; 32],
        token_program: [
            6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180,
            133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
        ],
        source_network: 2,
        source_pool: 4,
        source_branch: 0x37a5_165b,
        source_tx_version: 6,
        // Synthetic local fixture genesis: not Ironwood network history evidence.
        source_genesis: [5; 32],
        receiver_policy: [6; 32],
        pair: [7; 32],
        epoch: 8,
        rules_hash: [9; 32],
        roster_version: 10,
        signature_scheme: 1,
    }
}

fn local_network() -> LocalNetwork {
    LocalNetwork {
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
    }
}

fn synthetic_note(recipient: Address, value: u64, index: u8) -> Note {
    let mut rho_bytes = [0; 32];
    rho_bytes[0] = index + 1;
    let rho = Rho::from_bytes(&rho_bytes).unwrap();
    let mut rng = ChaCha20Rng::from_seed([index + 40; 32]);
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
            return note;
        }
    }
}

// Genuine upstream tree and witnesses; local construction does not establish that
// any note was received, canonically mined, or is spendable on a real network.
fn witnesses(notes: &[Note]) -> (Anchor, Vec<MerklePath>) {
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut witnesses: Vec<IncrementalWitness<MerkleHashOrchard, 32>> = Vec::new();
    for note in notes {
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        tree.append(leaf).unwrap();
        for witness in &mut witnesses {
            witness.append(leaf).unwrap();
        }
        witnesses.push(IncrementalWitness::from_tree(tree.clone()).unwrap());
    }
    let anchor = tree.root().into();
    let paths: Vec<MerklePath> = witnesses
        .into_iter()
        .map(|witness| witness.path().unwrap().into())
        .collect();
    for (note, path) in notes.iter().zip(&paths) {
        assert!(path.root(note.commitment().into()) == anchor);
    }
    (anchor, paths)
}

struct Fixture {
    pczt: Pczt,
    domain: Domain,
    inputs: Vec<ReservedNativeInput>,
    outputs: Vec<ExpectedNativeOutput>,
    spend_actions: Vec<usize>,
    output_actions: Vec<usize>,
}

impl Fixture {
    fn new(extra_output: bool) -> Self {
        Self::build(extra_output, false, false)
    }

    fn build(extra_output: bool, distinct_owners: bool, equal_output_roles: bool) -> Self {
        let fvk = FullViewingKey::from_bytes(&PUBLIC_FVKS[0]).unwrap();
        let recipient_fvk = FullViewingKey::from_bytes(&PUBLIC_FVKS[1]).unwrap();
        let second_fvk = if distinct_owners {
            recipient_fvk.clone()
        } else {
            fvk.clone()
        };
        let change = second_fvk.address_at(0u32, Scope::Internal);
        let recipient = if equal_output_roles {
            change
        } else {
            recipient_fvk.address_at(0u32, Scope::External)
        };
        let input_keys = [&fvk, &second_fvk, &fvk];
        let input_values: &[u64] = if extra_output {
            &[650_000, 340_000, 10_000]
        } else {
            &[650_000, 350_000]
        };
        let notes: Vec<_> = input_values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                synthetic_note(
                    input_keys[index].address_at(0u32, Scope::External),
                    *value,
                    index as u8,
                )
            })
            .collect();
        let (anchor, paths) = witnesses(&notes);
        let mut builder = Builder::new(
            local_network(),
            200.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        )
        .with_expiry_height(EXPIRY.into());
        let mut inputs = Vec::new();
        for (index, (note, path)) in notes.iter().zip(paths).enumerate() {
            inputs.push(ReservedNativeInput {
                inventory_note: [index as u8 + 20; 32],
                source_occurrence: SourceOccurrence {
                    network: domain().source_network,
                    pool: domain().source_pool,
                    txid: [index as u8 + 30; 32],
                    action_index: 0,
                },
                note_commitment: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                nullifier: note.nullifier(input_keys[index]).to_bytes(),
                value: note.value().inner(),
                trusted_fvk: input_keys[index].clone(),
            });
            builder
                .add_ironwood_spend::<core::convert::Infallible>(
                    input_keys[index].clone(),
                    *note,
                    path,
                )
                .unwrap();
        }
        let outputs = vec![
            ExpectedNativeOutput {
                recipient,
                value: if equal_output_roles { 495_000 } else { 400_000 },
                kind: NativeOutputKind::Recipient,
            },
            ExpectedNativeOutput {
                recipient: change,
                value: if equal_output_roles {
                    495_000
                } else if extra_output {
                    589_999
                } else {
                    590_000
                },
                kind: NativeOutputKind::Change,
            },
        ];
        for output in &outputs {
            builder
                .add_ironwood_output::<core::convert::Infallible>(
                    Some(fvk.to_ovk(Scope::External)),
                    output.recipient,
                    Zatoshis::from_u64(output.value).unwrap(),
                    MemoBytes::empty(),
                )
                .unwrap();
        }
        if extra_output {
            builder
                .add_ironwood_output::<core::convert::Infallible>(
                    None,
                    recipient_fvk.address_at(1u32, Scope::External),
                    Zatoshis::const_from_u64(1),
                    MemoBytes::empty(),
                )
                .unwrap();
        }
        let PcztResult {
            pczt_parts,
            ironwood_meta,
            ..
        } = builder
            .build_for_pczt(
                ChaCha20Rng::from_seed([11; 32]),
                &fixed::FeeRule::non_standard(Zatoshis::const_from_u64(FEE)),
            )
            .unwrap();
        let count = input_values.len();
        let spend_actions = (0..count)
            .map(|index| ironwood_meta.spend_action_index(index).unwrap())
            .collect();
        let output_actions = (0..count)
            .map(|index| ironwood_meta.output_action_index(index).unwrap())
            .collect();
        // Two real spends/two real outputs (or three/three for the extra-output
        // attack) avoid dummy spend keys entirely. Stop before IO finalization.
        let pczt = Creator::build_from_parts(pczt_parts).unwrap();
        assert_eq!(pczt.ironwood().actions().len(), count);
        assert!(pczt.ironwood().zkproof().is_none());
        for action in pczt.ironwood().actions() {
            assert!(action.spend().dummy_sk().is_none());
            assert!(action.spend().spend_auth_sig().is_none());
        }
        Self {
            pczt,
            domain: domain(),
            inputs,
            outputs,
            spend_actions,
            output_actions,
        }
    }

    fn expected(&self) -> ExpectedNativeEffects<'_> {
        ExpectedNativeEffects {
            domain: &self.domain,
            lock_time: 0,
            expiry_height: EXPIRY,
            fee: FEE,
            inputs: &self.inputs,
            outputs: &self.outputs,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.pczt.clone().serialize().unwrap()
    }

    // Test-only mutation of upstream public Serialize/Deserialize types. This is
    // not a second native wire parser or a product source of transaction effects.
    fn mutated(&self, mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
        let encoded = pczt::v2::Pczt::try_from(self.pczt.clone()).unwrap();
        let mut fields = serde_json::to_value(encoded).unwrap();
        mutate(&mut fields);
        let encoded: pczt::v2::Pczt = serde_json::from_value(fields).unwrap();
        encoded.serialize()
    }
}

#[test]
fn accepts_real_unsigned_effects_and_matches_independent_upstream_sighash() {
    let fixture = Fixture::new(false);
    let bytes = fixture.bytes();
    // This reference computes a digest only, before inspection borrows policy.
    let signer_sighash = Signer::new(fixture.pczt.clone())
        .unwrap()
        .shielded_sighash();
    let inspected =
        inspect_pczt(&bytes, &fixture.expected()).expect("exact native effects accepted");
    assert_eq!(inspected.fee(), 10_000);
    let effects = fixture.pczt.clone().into_effects().unwrap();
    let digests = effects.digest(TxIdDigester);
    let txid = to_txid(effects.version(), effects.consensus_branch_id(), &digests);
    let sighash = v6_signature_hash(&effects, &SignableInput::Shielded, &digests);
    assert_eq!(inspected.txid(), &<[u8; 32]>::from(txid));
    let sighash: [u8; 32] = sighash.as_ref().try_into().unwrap();
    assert_eq!(inspected.shielded_sighash(), &sighash);
    assert_eq!(
        inspected.exact_pczt_digest(),
        &<[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert_eq!(inspected.shielded_sighash(), &signer_sighash);
}

#[test]
fn checked_change_nullifier_uses_owning_viewing_key_not_first_input_key() {
    let fixture = Fixture::build(false, true, false);
    let bytes = fixture.bytes();
    let checked = inspect_pczt(&bytes, &fixture.expected()).unwrap();
    let action_index = fixture.output_actions[1];
    let action = &fixture.pczt.ironwood().actions()[action_index];
    let output = action.output();
    let rho = Rho::from_bytes(action.spend().nullifier())
        .into_option()
        .unwrap();
    let rseed = RandomSeed::from_bytes(output.rseed().unwrap(), &rho)
        .into_option()
        .unwrap();
    let note = Note::from_parts(
        fixture.outputs[1].recipient,
        NoteValue::from_raw(fixture.outputs[1].value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .into_option()
    .unwrap();
    let owning_fvk = FullViewingKey::from_bytes(&PUBLIC_FVKS[1]).unwrap();
    let first_fvk = FullViewingKey::from_bytes(&PUBLIC_FVKS[0]).unwrap();
    let change = checked
        .outputs()
        .iter()
        .find(|output| output.action_index() == action_index as u32)
        .unwrap();
    assert!(
        change.note_commitment() == &ExtractedNoteCommitment::from(note.commitment()).to_bytes()
    );
    assert!(change.nullifier() == Some(&note.nullifier(&owning_fvk).to_bytes()));
    assert!(change.nullifier() != Some(&note.nullifier(&first_fvk).to_bytes()));
    let mut reversed = fixture.inputs.clone();
    reversed.reverse();
    let reordered = inspect_pczt(
        &bytes,
        &ExpectedNativeEffects {
            inputs: &reversed,
            ..fixture.expected()
        },
    )
    .unwrap();
    assert!(
        reordered
            .outputs()
            .iter()
            .find(|output| output.action_index() == action_index as u32)
            .unwrap()
            .nullifier()
            == change.nullifier()
    );
}

#[test]
fn duplicate_receiver_value_outputs_keep_distinct_actual_identity_without_role_order() {
    let fixture = Fixture::build(false, false, true);
    let bytes = fixture.bytes();
    let checked = inspect_pczt(&bytes, &fixture.expected()).unwrap();
    assert_eq!(checked.outputs().len(), 2);
    let first = &checked.outputs()[0];
    let second = &checked.outputs()[1];
    assert!(first.recipient() == second.recipient());
    assert_eq!(first.value(), 495_000);
    assert_eq!(second.value(), 495_000);
    assert_ne!(first.action_index(), second.action_index());
    assert!(first.note_commitment() != second.note_commitment());
    assert!(first.nullifier().is_some());
    assert!(second.nullifier().is_some());
    assert!(first.nullifier() != second.nullifier());
    let mut reversed = fixture.outputs.clone();
    reversed.reverse();
    let reordered = inspect_pczt(
        &bytes,
        &ExpectedNativeEffects {
            outputs: &reversed,
            ..fixture.expected()
        },
    )
    .unwrap();
    for (original, reordered) in checked.outputs().iter().zip(reordered.outputs()) {
        assert_eq!(reordered.action_index(), original.action_index());
        assert!(reordered.note_commitment() == original.note_commitment());
        assert!(reordered.nullifier() == original.nullifier());
    }
}

#[test]
fn deferred_anchor_and_compact_metadata_do_not_reuse_exact_byte_identity() {
    let fixture = Fixture::new(false);
    let expected = fixture.expected();
    let original = inspect_pczt(&fixture.bytes(), &expected).unwrap();
    let deferred = Redactor::new(fixture.pczt.clone())
        .redact_ironwood_with(|mut bundle| {
            bundle.clear_anchor();
            bundle.redact_actions(|mut action| action.clear_spend_witness());
        })
        .finish();
    let checked = inspect_pczt(&deferred.serialize().unwrap(), &expected).unwrap();
    assert_eq!(checked.txid(), original.txid());
    assert_eq!(checked.shielded_sighash(), original.shielded_sighash());
    assert_ne!(checked.exact_pczt_digest(), original.exact_pczt_digest());
    let compacted = Redactor::new(fixture.pczt.clone())
        .redact_ironwood_with(|mut bundle| bundle.compact_resolvable_fields())
        .finish();
    let compact = inspect_pczt(&compacted.serialize().unwrap(), &expected).unwrap();
    assert_eq!(compact.shielded_sighash(), original.shielded_sighash());
    assert_ne!(compact.exact_pczt_digest(), original.exact_pczt_digest());
}

#[test]
fn policy_rejects_wrong_inventory_receiver_change_value_fee_and_expiry() {
    let fixture = Fixture::new(false);
    let bytes = fixture.bytes();
    assert!(inspect_pczt(&bytes, &fixture.expected()).is_ok());
    let occurrence_mutations: [fn(&mut SourceOccurrence); 3] = [
        |occurrence| occurrence.txid = [0; 32],
        |occurrence| occurrence.network = 1,
        |occurrence| occurrence.pool = 3,
    ];
    for mutate in occurrence_mutations {
        let mut inputs = fixture.inputs.clone();
        mutate(&mut inputs[0].source_occurrence);
        assert!(
            inspect_pczt(
                &bytes,
                &ExpectedNativeEffects {
                    inputs: &inputs,
                    ..fixture.expected()
                }
            )
            .is_err()
        );
    }
    let mut wrong_inputs = fixture.inputs.clone();
    wrong_inputs[0].note_commitment[0] ^= 1;
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                inputs: &wrong_inputs,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    wrong_inputs = fixture.inputs.clone();
    wrong_inputs[0].nullifier[0] ^= 1;
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                inputs: &wrong_inputs,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    wrong_inputs = fixture.inputs.clone();
    wrong_inputs[0].value -= 1;
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                inputs: &wrong_inputs,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    wrong_inputs = fixture.inputs.clone();
    wrong_inputs[0].trusted_fvk = FullViewingKey::from_bytes(&PUBLIC_FVKS[1]).unwrap();
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                inputs: &wrong_inputs,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    let mut wrong_outputs = fixture.outputs.clone();
    wrong_outputs[0].recipient = fixture.outputs[1].recipient;
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                outputs: &wrong_outputs,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    wrong_outputs = fixture.outputs.clone();
    wrong_outputs[1].recipient = fixture.outputs[0].recipient;
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                outputs: &wrong_outputs,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    wrong_outputs = fixture.outputs.clone();
    wrong_outputs[0].value += 1;
    wrong_outputs[1].value -= 1;
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                outputs: &wrong_outputs,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                fee: 9_999,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                expiry_height: 221,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                lock_time: 1,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    let mut wrong_domain = fixture.domain;
    wrong_domain.source_pool = 3;
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                domain: &wrong_domain,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    wrong_domain = fixture.domain;
    wrong_domain.source_network = 1;
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                domain: &wrong_domain,
                ..fixture.expected()
            }
        )
        .is_err()
    );
}

#[test]
fn exact_multisets_reject_duplicate_or_omitted_inputs_and_outputs() {
    let fixture = Fixture::new(false);
    let bytes = fixture.bytes();
    assert!(inspect_pczt(&bytes, &fixture.expected()).is_ok());
    let duplicated = vec![fixture.inputs[0].clone(), fixture.inputs[0].clone()];
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                inputs: &duplicated,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                inputs: &fixture.inputs[..1],
                ..fixture.expected()
            }
        )
        .is_err()
    );
    let duplicated = vec![fixture.outputs[0].clone(), fixture.outputs[0].clone()];
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                outputs: &duplicated,
                ..fixture.expected()
            }
        )
        .is_err()
    );
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                outputs: &fixture.outputs[..1],
                ..fixture.expected()
            }
        )
        .is_err()
    );
}

#[test]
fn genuine_extra_native_output_is_not_ignored() {
    let fixture = Fixture::new(true);
    let bytes = fixture.bytes();
    let recipient_fvk = FullViewingKey::from_bytes(&PUBLIC_FVKS[1]).unwrap();
    let mut all_outputs = fixture.outputs.clone();
    all_outputs.push(ExpectedNativeOutput {
        recipient: recipient_fvk.address_at(1u32, Scope::External),
        value: 1,
        kind: NativeOutputKind::Recipient,
    });
    assert!(
        inspect_pczt(
            &bytes,
            &ExpectedNativeEffects {
                outputs: &all_outputs,
                ..fixture.expected()
            }
        )
        .is_ok()
    );
    assert!(inspect_pczt(&bytes, &fixture.expected()).is_err());
}

#[test]
fn redacted_policy_required_fields_are_not_invented_from_zero_padding() {
    let fixture = Fixture::new(false);
    assert!(inspect_pczt(&fixture.bytes(), &fixture.expected()).is_ok());
    for field in 0..9 {
        let pczt = Redactor::new(fixture.pczt.clone())
            .redact_ironwood_with(|mut bundle| {
                bundle.redact_action(fixture.spend_actions[0], |mut action| match field {
                    0 => action.clear_spend_recipient(),
                    1 => action.clear_spend_value(),
                    2 => action.clear_spend_rho(),
                    3 => action.clear_spend_rseed(),
                    4 => action.clear_spend_alpha(),
                    5 => action.clear_output_recipient(),
                    6 => action.clear_output_value(),
                    7 => action.clear_output_rseed(),
                    8 => action.clear_rcv(),
                    _ => unreachable!(),
                });
            })
            .finish();
        assert!(
            inspect_pczt(&pczt.serialize().unwrap(), &fixture.expected()).is_err(),
            "required field {field} was accepted"
        );
    }
}

#[test]
fn inconsistent_native_metadata_and_ciphertext_reject_even_when_parse_succeeds() {
    let fixture = Fixture::new(false);
    assert!(inspect_pczt(&fixture.bytes(), &fixture.expected()).is_ok());
    let spend = fixture.spend_actions[0];
    let output = fixture.output_actions[0];
    let alternate_fvk = PUBLIC_FVKS[1].to_vec();
    let mutations: Vec<(&str, Value)> =
        vec![("value", json!(649_999)), ("fvk", json!(alternate_fvk))];
    for (field, value) in mutations {
        let bytes =
            fixture.mutated(|fields| fields["ironwood"]["actions"][spend]["spend"][field] = value);
        assert!(Pczt::parse(&bytes).is_ok());
        assert!(
            inspect_pczt(&bytes, &fixture.expected()).is_err(),
            "unverified {field} accepted"
        );
    }
    let bad_ciphertext = fixture.mutated(|fields| {
        let bytes = fields["ironwood"]["actions"][output]["output"]["enc_ciphertext"]["Encrypted"]
            .as_array_mut()
            .unwrap();
        bytes[70] = json!(bytes[70].as_u64().unwrap() ^ 1);
    });
    assert!(Pczt::parse(&bad_ciphertext).is_ok());
    assert!(inspect_pczt(&bad_ciphertext, &fixture.expected()).is_err());
    let bad_output_value = fixture.mutated(|fields| {
        fields["ironwood"]["actions"][output]["output"]["value"] = json!(399_999)
    });
    assert!(Pczt::parse(&bad_output_value).is_ok());
    assert!(inspect_pczt(&bad_output_value, &fixture.expected()).is_err());
    let bad_balance =
        fixture.mutated(|fields| fields["ironwood"]["value_sum"] = json!([9_999, false]));
    assert!(Pczt::parse(&bad_balance).is_ok());
    assert!(inspect_pczt(&bad_balance, &fixture.expected()).is_err());
}

#[test]
fn wrong_native_profile_network_marker_modifiable_state_and_other_pool_reject() {
    let fixture = Fixture::new(false);
    assert!(inspect_pczt(&fixture.bytes(), &fixture.expected()).is_ok());
    for (field, value) in [
        ("tx_version", json!(5)),
        ("version_group_id", json!(0)),
        ("consensus_branch_id", json!(u32::from(BranchId::Nu6_2))),
        ("coin_type", json!(133)),
        ("tx_modifiable", json!(128)),
    ] {
        let bytes = fixture.mutated(|fields| fields["global"][field] = value);
        assert!(Pczt::parse(&bytes).is_ok());
        assert!(
            inspect_pczt(&bytes, &fixture.expected()).is_err(),
            "wrong {field} accepted"
        );
    }
    let other_pool = fixture.mutated(|fields| {
        let mut bundle = fields["ironwood"].clone();
        bundle["flags"] = json!(3);
        fields["orchard"] = bundle;
    });
    assert!(Pczt::parse(&other_pool).is_ok());
    assert!(inspect_pczt(&other_pool, &fixture.expected()).is_err());
}

#[test]
fn disabled_native_spends_reject_nonzero_reserved_inputs() {
    let fixture = Fixture::new(false);
    assert!(inspect_pczt(&fixture.bytes(), &fixture.expected()).is_ok());
    let bytes = fixture.mutated(|fields| fields["ironwood"]["flags"] = json!(6));
    assert!(Pczt::parse(&bytes).is_ok());
    assert!(
        inspect_pczt(&bytes, &fixture.expected()).is_err(),
        "disabled spends accepted nonzero reserved notes"
    );
}

#[test]
fn disabled_native_outputs_reject_nonzero_payout_and_change() {
    let fixture = Fixture::new(false);
    assert!(inspect_pczt(&fixture.bytes(), &fixture.expected()).is_ok());
    let bytes = fixture.mutated(|fields| fields["ironwood"]["flags"] = json!(5));
    assert!(Pczt::parse(&bytes).is_ok());
    assert!(
        inspect_pczt(&bytes, &fixture.expected()).is_err(),
        "disabled outputs accepted nonzero payout and change"
    );
}
