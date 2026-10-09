//! Original transaction bytes from Zebra e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291,
//! block-test-1-842-467.txt, transaction index 1; not accepted-history evidence.
/*
Copyright (c) 2019-2025 Zcash Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use std::sync::LazyLock;

use zcash_primitives::transaction::Transaction;
use zcash_protocol::{consensus::BranchId, value::MAX_BALANCE};
use ziquid_proofs::{
    orchard_original::{FixedOrchardVerifier, OriginalOrchardVerifier},
    raw_v5::RawV5Error,
};

const ORIGINAL: &[u8; 9165] = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
const ACTIONS: usize = 25;
const ACTION_WIDTH: usize = 820;
const FLAGS: usize = ACTIONS + 2 * ACTION_WIDTH;
const PROOF_LENGTH: usize = FLAGS + 41;
const PROOF: usize = PROOF_LENGTH + 3;
const SPEND_SIGS: usize = PROOF + 7264;
const BINDING_SIG: usize = SPEND_SIGS + 2 * 64;
static VERIFIER: LazyLock<OriginalOrchardVerifier> = LazyLock::new(OriginalOrchardVerifier::new);
static FIXED_VERIFIER: LazyLock<FixedOrchardVerifier> = LazyLock::new(FixedOrchardVerifier::new);

use ziquid_proofs::raw_v5::RawV5;
#[test]
fn original_orchard_epk_remains_opaque_in_raw_nu5_parsing(){
 let original=include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
 let parsed=RawV5::parse_exact(original).unwrap();
 assert_eq!(parsed.orchard().unwrap().action_count(),2);
 let mut identity=original.to_vec();
 // V5 header20, four empty transparent/Sapling count bytes, action count byte.
 // Original action cv/nf/rk/cmx128 then exact transmitted32-byte EPK.
 identity[25+128..25+160].fill(0);
 let changed=RawV5::parse_exact(&identity).unwrap();
 assert_ne!(changed.effect_id(),parsed.effect_id());
 assert_eq!(changed.auth_digest(),parsed.auth_digest());
}

#[test]
fn genuine_original_proof_both_spend_signatures_and_binding_verify() {
    let raw = RawV5::parse_exact(ORIGINAL).unwrap();
    assert_eq!(raw.original_bytes(), ORIGINAL);
    assert_eq!(raw.consumed_bytes(), 9165);
    assert_eq!(raw.version(), zcash_primitives::transaction::TxVersion::V5);
    assert_eq!(raw.consensus_branch_id(), BranchId::Nu5);
    assert!(raw.transparent_bundle().is_none());
    assert!(raw.sapling_bundle().is_none());
    let orchard = *raw.orchard().unwrap();
    assert_eq!(orchard.action_count(), 2);
    assert_eq!(orchard.actions(), &ORIGINAL[ACTIONS..FLAGS]);
    assert_eq!(orchard.proof(), &ORIGINAL[PROOF..SPEND_SIGS]);
    assert_eq!(orchard.spend_auth_signatures(), &ORIGINAL[SPEND_SIGS..BINDING_SIG]);
    assert_eq!(orchard.binding_signature().as_slice(), &ORIGINAL[BINDING_SIG..]);
    assert_eq!(i64::from(orchard.value_balance()), 1000);
    assert!(orchard.flags().spends_enabled() && orchard.flags().outputs_enabled());

    // Independent maintained parser succeeds on this genuine EPK encoding.
    let mut upstream_reader = ORIGINAL.as_slice();
    let upstream = Transaction::read(&mut upstream_reader, BranchId::Nu5).unwrap();
    assert!(upstream_reader.is_empty());
    assert_eq!(raw.effect_id(), <[u8; 32]>::from(upstream.txid()));
    assert_eq!(raw.auth_digest().as_slice(), upstream.auth_commitment().as_bytes());
    let expected_effect = raw.effect_id();
    let expected_auth = raw.auth_digest();
    let context = raw.into_signature_context(vec![]).unwrap();
    assert_eq!(context.effect_id(), expected_effect);
    assert_eq!(context.auth_digest(), expected_auth);
    assert_eq!(context.shielded(), <[u8; 32]>::from(upstream.txid()));
    orchard.verify_orchard(&VERIFIER, &context.shielded()).unwrap();
}

#[test]
fn sequential_parsing_borrows_and_consumes_exactly_one_transaction() {
    let mut joined = ORIGINAL.to_vec();
    joined.extend_from_slice(ORIGINAL);
    let mut reader = joined.as_slice();
    let first = RawV5::parse(&mut reader).unwrap();
    assert_eq!(first.original_bytes().as_ptr(), joined.as_ptr());
    assert_eq!(reader, ORIGINAL);
    let second = RawV5::parse(&mut reader).unwrap();
    assert_eq!(second.effect_id(), first.effect_id());
    assert!(reader.is_empty());
    assert_eq!(RawV5::parse_exact(&joined).unwrap_err(), RawV5Error::TrailingBytes);

    let truncated = &ORIGINAL[..ORIGINAL.len() - 1];
    let mut failed = truncated;
    assert_eq!(RawV5::parse(&mut failed).unwrap_err(), RawV5Error::Truncated);
    assert_eq!(failed.as_ptr(), truncated.as_ptr());
    assert_eq!(failed.len(), truncated.len(), "failed parsing does not consume input");
}

#[test]
fn every_field_boundary_and_authorization_truncation_rejects() {
    for length in [
        0, 3, 7, 11, 15, 19, 20, 21, 22, 23, 24, 25,
        ACTIONS + 31, ACTIONS + 63, ACTIONS + 95, ACTIONS + 127,
        ACTIONS + 159, ACTIONS + 739, FLAGS - 1, FLAGS,
        FLAGS + 1, FLAGS + 8, PROOF_LENGTH - 1, PROOF_LENGTH,
        PROOF_LENGTH + 1, PROOF_LENGTH + 2, PROOF,
        SPEND_SIGS - 1, SPEND_SIGS, SPEND_SIGS + 63,
        SPEND_SIGS + 64, BINDING_SIG - 1, BINDING_SIG,
        BINDING_SIG + 63,
    ] {
        assert_eq!(RawV5::parse_exact(&ORIGINAL[..length]).unwrap_err(), RawV5Error::Truncated, "length {length}");
    }
}

#[test]
fn framing_counts_and_wire_resource_limits_precede_allocations() {
    for (position, encoded) in [
        (20, vec![0xfd, 0, 0]),
        (21, vec![0xfd, 0, 0]),
        (22, vec![0xfd, 0, 0]),
        (23, vec![0xfd, 0, 0]),
        (24, vec![0xfd, 2, 0]),
        (24, vec![0xfe, 2, 0, 0, 0]),
        (24, vec![0xff, 2, 0, 0, 0, 0, 0, 0, 0]),
    ] {
        let mut bad = ORIGINAL.to_vec();
        bad.splice(position..position + 1, encoded);
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), RawV5Error::InvalidCompactSize, "position {position}");
    }
    for (position, expected) in [
        (22, RawV5Error::TooManySaplingSpends),
        (23, RawV5Error::TooManySaplingOutputs),
        (24, RawV5Error::TooManyOrchardActions),
    ] {
        let mut bad = ORIGINAL.to_vec();
        bad.splice(position..position + 1, [0xfe, 0, 0, 1, 0]);
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), expected);
    }
    for position in [20, 21, 24] {
        let mut bad = ORIGINAL.to_vec();
        bad.splice(position..position + 1, [0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), RawV5Error::InvalidCompactSize);
    }
    let mut huge_count = ORIGINAL[..20].to_vec();
    huge_count.extend_from_slice(&[0xfe, 0, 0, 0, 2]);
    assert_eq!(RawV5::parse_exact(&huge_count).unwrap_err(), RawV5Error::Truncated);

    // Exactly 2,000,000 original wire bytes are permitted, even for an invalid
    // proof; the next byte exceeds the local transaction bound before decoding.
    let mut maximum = ORIGINAL[..PROOF_LENGTH].to_vec();
    let length = 2_000_000 - maximum.len() - 5 - 128 - 64;
    maximum.push(0xfe);
    maximum.extend_from_slice(&(length as u32).to_le_bytes());
    maximum.resize(maximum.len() + length, 0);
    maximum.extend_from_slice(&ORIGINAL[SPEND_SIGS..]);
    assert_eq!(maximum.len(), 2_000_000);
    assert_eq!(RawV5::parse_exact(&maximum).unwrap().consumed_bytes(), 2_000_000);
    let mut too_large = maximum;
    let length = length + 1;
    too_large[PROOF_LENGTH + 1..PROOF_LENGTH + 5].copy_from_slice(&(length as u32).to_le_bytes());
    too_large.insert(too_large.len() - 192, 0);
    assert_eq!(RawV5::parse_exact(&too_large).unwrap_err(), RawV5Error::TransactionTooLarge);
}

#[test]
fn original_header_flags_money_and_canonical_fields_are_not_normalized() {
    for (offset, expected) in [
        (0, RawV5Error::UnsupportedVersion),
        (4, RawV5Error::UnsupportedVersionGroup),
        (8, RawV5Error::UnsupportedBranch),
    ] {
        let mut bad = ORIGINAL.to_vec();
        bad[offset] ^= 1;
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), expected);
    }
    for flags in [0, 4, 7, 0x80, 0xff] {
        let mut bad = ORIGINAL.to_vec();
        bad[FLAGS] = flags;
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), RawV5Error::InvalidOrchardFlags);
    }
    for balance in [i64::MIN, -MAX_BALANCE - 1, MAX_BALANCE + 1, i64::MAX] {
        let mut bad = ORIGINAL.to_vec();
        bad[FLAGS + 1..FLAGS + 9].copy_from_slice(&balance.to_le_bytes());
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), RawV5Error::InvalidOrchardValueBalance);
    }
    for balance in [-MAX_BALANCE, 0, MAX_BALANCE] {
        let mut changed = ORIGINAL.to_vec();
        changed[FLAGS + 1..FLAGS + 9].copy_from_slice(&balance.to_le_bytes());
        assert_eq!(i64::from(RawV5::parse_exact(&changed).unwrap().orchard().unwrap().value_balance()), balance);
    }
    for (offset, expected) in [
        (ACTIONS, RawV5Error::InvalidOrchardValueCommitment { index: 0 }),
        (ACTIONS + 32, RawV5Error::InvalidOrchardNullifier { index: 0 }),
        (ACTIONS + 64, RawV5Error::InvalidOrchardRandomizedKey { index: 0 }),
        (ACTIONS + 96, RawV5Error::InvalidOrchardNoteCommitment { index: 0 }),
        (FLAGS + 9, RawV5Error::InvalidOrchardAnchor),
    ] {
        let mut bad = ORIGINAL.to_vec();
        bad[offset..offset + 32].fill(0xff);
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), expected);
    }
    let mut empty = ORIGINAL[..24].to_vec();
    empty.push(0);
    let absent = RawV5::parse_exact(&empty).unwrap();
    assert!(absent.orchard().is_none());
    absent.verify_orchard(&VERIFIER, &[0; 32]).unwrap();
    empty.extend_from_slice(&ORIGINAL[FLAGS..]);
    assert_eq!(RawV5::parse_exact(&empty).unwrap_err(), RawV5Error::TrailingBytes);
}

#[test]
fn every_original_effect_region_and_action_order_changes_effect_not_auth() {
    let original = RawV5::parse_exact(ORIGINAL).unwrap();
    for offset in [
        12, 16, ACTIONS + 31, ACTIONS + 32, ACTIONS + 95,
        ACTIONS + 96, ACTIONS + 128, ACTIONS + 160,
        ACTIONS + 212, ACTIONS + 723, ACTIONS + 724,
        ACTIONS + 739, ACTIONS + 740, ACTIONS + 819,
        FLAGS + 1, FLAGS + 9,
    ] {
        let mut changed = ORIGINAL.to_vec();
        changed[offset] ^= if offset == ACTIONS + 31 || offset == ACTIONS + 95 { 0x80 } else { 1 };
        let parsed = RawV5::parse_exact(&changed).unwrap();
        assert_ne!(parsed.effect_id(), original.effect_id(), "effect offset {offset}");
        assert_eq!(parsed.auth_digest(), original.auth_digest(), "auth offset {offset}");
    }
    let mut swapped = ORIGINAL.to_vec();
    let (first, second) = swapped[ACTIONS..FLAGS].split_at_mut(ACTION_WIDTH);
    first.swap_with_slice(second);
    let swapped = RawV5::parse_exact(&swapped).unwrap();
    assert_ne!(swapped.effect_id(), original.effect_id());
    assert_eq!(swapped.auth_digest(), original.auth_digest());
}

#[test]
fn every_authorization_region_changes_auth_not_effect_and_rejects_crypto() {
    let original = RawV5::parse_exact(ORIGINAL).unwrap();
    let effect = original.effect_id();
    let auth = original.auth_digest();
    for (offset, expected) in [
        (PROOF, RawV5Error::InvalidOrchardProof),
        (SPEND_SIGS - 1, RawV5Error::InvalidOrchardProof),
        (SPEND_SIGS, RawV5Error::InvalidOrchardSpendAuth { index: 0 }),
        (SPEND_SIGS + 63, RawV5Error::InvalidOrchardSpendAuth { index: 0 }),
        (SPEND_SIGS + 64, RawV5Error::InvalidOrchardSpendAuth { index: 1 }),
        (BINDING_SIG - 1, RawV5Error::InvalidOrchardSpendAuth { index: 1 }),
        (BINDING_SIG, RawV5Error::InvalidOrchardBindingSignature),
        (ORIGINAL.len() - 1, RawV5Error::InvalidOrchardBindingSignature),
    ] {
        let mut changed = ORIGINAL.to_vec();
        changed[offset] ^= 1;
        let parsed = RawV5::parse_exact(&changed).unwrap();
        assert_eq!(parsed.effect_id(), effect);
        assert_ne!(parsed.auth_digest(), auth);
        assert_eq!(parsed.verify_orchard(&VERIFIER, &effect), Err(expected), "offset {offset}");
    }
}

#[test]
fn changed_effects_opaque_epks_and_wrong_context_never_authorize_original_signatures() {
    let original = RawV5::parse_exact(ORIGINAL).unwrap();
    let mut wrong_message = original.effect_id();
    wrong_message[0] ^= 1;
    assert_eq!(original.verify_orchard(&VERIFIER, &wrong_message), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
    for offset in [12, 16, ACTIONS + 32, ACTIONS + 96, ACTIONS + 160, ACTIONS + 212, ACTIONS + 724, ACTIONS + 740, FLAGS + 1, FLAGS + 9] {
        let mut changed = ORIGINAL.to_vec();
        changed[offset] ^= 1;
        let parsed = RawV5::parse_exact(&changed).unwrap();
        let orchard = *parsed.orchard().unwrap();
        let context = parsed.into_signature_context(vec![]).unwrap();
        assert_eq!(orchard.verify_orchard(&VERIFIER, &context.shielded()), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }), "offset {offset}");
    }
    for epk in [[0; 32], [0xff; 32]] {
        let mut changed = ORIGINAL.to_vec();
        changed[ACTIONS + 128..ACTIONS + 160].copy_from_slice(&epk);
        let parsed = RawV5::parse_exact(&changed).unwrap();
        assert_eq!(&parsed.orchard().unwrap().actions()[128..160], &epk);
        let orchard = *parsed.orchard().unwrap();
        let context = parsed.into_signature_context(vec![]).unwrap();
        assert_ne!(context.shielded(), original.effect_id());
        assert_eq!(orchard.verify_orchard(&VERIFIER, &context.shielded()), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
    }
}

#[test]
fn identity_rk_is_parseable_but_typed_unsupported_original_crash_domain() {
    let mut identity = ORIGINAL.to_vec();
    identity[ACTIONS + ACTION_WIDTH + 64..ACTIONS + ACTION_WIDTH + 96].fill(0);
    let parsed = RawV5::parse_exact(&identity).unwrap();
    assert_eq!(parsed.verify_orchard(&VERIFIER, &parsed.effect_id()), Err(RawV5Error::UnsupportedHistoricalIdentityRk { index: 1 }));
}

#[test]
fn full_proof_suffix_is_authenticated_by_auth_digest_not_effect_signatures() {
    let original = RawV5::parse_exact(ORIGINAL).unwrap();
    let mut padded = ORIGINAL.to_vec();
    padded[PROOF_LENGTH + 1..PROOF].copy_from_slice(&(7265u16).to_le_bytes());
    padded.insert(SPEND_SIGS, 0x42);
    let parsed = RawV5::parse_exact(&padded).unwrap();
    assert_eq!(parsed.effect_id(), original.effect_id());
    assert_ne!(parsed.auth_digest(), original.auth_digest());
    assert_eq!(parsed.orchard().unwrap().proof().last(), Some(&0x42));
    let orchard = *parsed.orchard().unwrap();
    let context = parsed.into_signature_context(vec![]).unwrap();
    assert_eq!(context.shielded(), original.effect_id());
    // Original Halo2 permits this suffix. ZIP244 signatures commit effects,
    // while the enclosing block auth commitment distinguishes padded bytes.
    orchard.verify_orchard(&VERIFIER, &context.shielded()).unwrap();
    padded[SPEND_SIGS + 1] ^= 1;
    let changed = RawV5::parse_exact(&padded).unwrap();
    assert_eq!(changed.verify_orchard(&VERIFIER, &changed.effect_id()), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
}

#[test]
fn disabled_flags_never_skip_any_spend_or_binding_authorization() {
    let message = RawV5::parse_exact(ORIGINAL).unwrap().effect_id();
    for flags in [1, 2] {
        for (offset, expected) in [
            (SPEND_SIGS, RawV5Error::InvalidOrchardSpendAuth { index: 0 }),
            (SPEND_SIGS + 64, RawV5Error::InvalidOrchardSpendAuth { index: 1 }),
            (BINDING_SIG, RawV5Error::InvalidOrchardBindingSignature),
        ] {
            let mut changed = ORIGINAL.to_vec();
            changed[FLAGS] = flags;
            changed[offset] ^= 1;
            let parsed = RawV5::parse_exact(&changed).unwrap();
            // Isolate the authorization stage using the original message;
            // no claim that the mutated flag/proof statement is valid.
            assert_eq!(parsed.verify_orchard(&VERIFIER, &message), Err(expected));
        }
        let mut changed = ORIGINAL.to_vec();
        changed[FLAGS] = flags;
        assert_eq!(RawV5::parse_exact(&changed).unwrap().verify_orchard(&VERIFIER, &message), Err(RawV5Error::InvalidOrchardProof));
    }
}

#[test]
fn action_order_reaches_real_halo2_and_signed_balance_reaches_real_binding() {
    let message = RawV5::parse_exact(ORIGINAL).unwrap().effect_id();
    let mut swapped = ORIGINAL.to_vec();
    let (first, second) = swapped[ACTIONS..FLAGS].split_at_mut(ACTION_WIDTH);
    first.swap_with_slice(second);
    let (first_sig, second_sig) = swapped[SPEND_SIGS..BINDING_SIG].split_at_mut(64);
    first_sig.swap_with_slice(second_sig);
    // Each original signature still matches its moved rk; cv sum is unchanged.
    // Only the original proof's ordered public statement must reject this.
    assert_eq!(RawV5::parse_exact(&swapped).unwrap().verify_orchard(&VERIFIER, &message), Err(RawV5Error::InvalidOrchardProof));
    for balance in [-MAX_BALANCE, -1000, 0, MAX_BALANCE] {
        let mut changed = ORIGINAL.to_vec();
        changed[FLAGS + 1..FLAGS + 9].copy_from_slice(&balance.to_le_bytes());
        assert_eq!(RawV5::parse_exact(&changed).unwrap().verify_orchard(&VERIFIER, &message), Err(RawV5Error::InvalidOrchardBindingSignature), "signed balance {balance}");
    }
    // Synthetic statement only: identity cv is canonically representable and
    // identity Binding verification must not gain a nonidentity guard. The
    // original Halo2 proof does not authorize the changed commitments.
    let mut identity_binding = ORIGINAL.to_vec();
    identity_binding[ACTIONS..ACTIONS + 32].fill(0);
    identity_binding[ACTIONS + ACTION_WIDTH..ACTIONS + ACTION_WIDTH + 32].fill(0);
    identity_binding[FLAGS + 1..FLAGS + 9].fill(0);
    identity_binding[BINDING_SIG..].fill(0);
    assert_eq!(RawV5::parse_exact(&identity_binding).unwrap().verify_orchard(&VERIFIER, &message), Err(RawV5Error::InvalidOrchardProof));
}

#[test]
fn variable_scripts_and_proof_lengths_are_preflighted_canonically() {
    let mut input = ORIGINAL[..20].to_vec();
    input.push(1);
    input.extend_from_slice(&[1; 36]);
    input.extend_from_slice(&[0xfd, 0, 0]);
    input.extend_from_slice(&[0; 8]);
    assert_eq!(RawV5::parse_exact(&input).unwrap_err(), RawV5Error::InvalidCompactSize);
    let mut output = ORIGINAL[..20].to_vec();
    output.extend_from_slice(&[0, 1]);
    output.extend_from_slice(&0i64.to_le_bytes());
    output.extend_from_slice(&[0xfd, 0, 0]);
    output.extend_from_slice(&[0; 4]);
    assert_eq!(RawV5::parse_exact(&output).unwrap_err(), RawV5Error::InvalidCompactSize);
    let mut truncated = ORIGINAL[..20].to_vec();
    truncated.push(1);
    truncated.extend_from_slice(&[1; 36]);
    truncated.extend_from_slice(&[0xfe, 0, 0, 1, 0]);
    assert_eq!(RawV5::parse_exact(&truncated).unwrap_err(), RawV5Error::Truncated);

    let mut empty_proof = ORIGINAL[..PROOF_LENGTH].to_vec();
    empty_proof.push(0);
    empty_proof.extend_from_slice(&ORIGINAL[SPEND_SIGS..]);
    let parsed = RawV5::parse_exact(&empty_proof).unwrap();
    assert!(parsed.orchard().unwrap().proof().is_empty());
    assert_eq!(parsed.effect_id(), RawV5::parse_exact(ORIGINAL).unwrap().effect_id());
    assert_eq!(parsed.verify_orchard(&VERIFIER, &parsed.effect_id()), Err(RawV5Error::InvalidOrchardProof));
    let mut noncanonical_proof = empty_proof;
    noncanonical_proof.splice(PROOF_LENGTH..PROOF_LENGTH + 1, [0xfd, 0, 0]);
    assert_eq!(RawV5::parse_exact(&noncanonical_proof).unwrap_err(), RawV5Error::InvalidCompactSize);
}

#[test]
fn genuine_mixed_sapling_projection_and_original_orchard_both_verify() {
    let original = include_bytes!("fixtures/nu5-mixed-testnet-1842421.bin");
    let parsed = RawV5::parse_exact(original).unwrap();
    assert!(parsed.sapling_bundle().is_some());
    let mut reader = original.as_slice();
    let upstream = Transaction::read(&mut reader, BranchId::Nu5).unwrap();
    assert!(reader.is_empty());
    assert_eq!(parsed.effect_id(), <[u8; 32]>::from(upstream.txid()));
    assert_eq!(parsed.auth_digest().as_slice(), upstream.auth_commitment().as_bytes());
    let orchard = *parsed.orchard().unwrap();
    let context = parsed.into_signature_context(vec![]).unwrap();
    ziquid_proofs::zip244::verify_sapling_post_nu5_crypto(&context).unwrap();
    orchard.verify_orchard(&VERIFIER, &context.shielded()).unwrap();
}

#[test]
fn synthetic_nu6_reuses_original_proof_bytes_but_rejects_original_nu5_signatures() {
    let nu5 = RawV5::parse_exact(ORIGINAL).unwrap();
    let mut bytes = ORIGINAL.to_vec();
    bytes[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
    let nu6 = RawV5::parse_exact(&bytes).unwrap();
    assert_eq!(nu6.consensus_branch_id(), BranchId::Nu6);
    assert_eq!(&bytes[..8], &ORIGINAL[..8]);
    assert_eq!(&bytes[12..], &ORIGINAL[12..]);
    let orchard = *nu6.orchard().unwrap();
    assert_eq!(orchard.proof(), nu5.orchard().unwrap().proof());
    assert_eq!(orchard.spend_auth_signatures(), nu5.orchard().unwrap().spend_auth_signatures());
    assert_eq!(orchard.binding_signature(), nu5.orchard().unwrap().binding_signature());
    let context = nu6.into_signature_context(vec![]).unwrap();
    assert_ne!(context.shielded(), nu5.effect_id());
    assert_eq!(orchard.verify_orchard(&VERIFIER, &context.shielded()),
        Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
    // Isolate the unchanged original crypto, NOT a valid NU6 authorization.
    orchard.verify_orchard(&VERIFIER, &nu5.effect_id()).unwrap();
}

#[test]
fn nu6_effect_auth_regions_opaque_epks_suffix_and_preflight_keep_original_wire() {
    let mut bytes = ORIGINAL.to_vec();
    bytes[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
    let baseline = RawV5::parse_exact(&bytes).unwrap();
    for offset in [12, 16, ACTIONS + 32, ACTIONS + 96, ACTIONS + 128,
        ACTIONS + 160, ACTIONS + 212, ACTIONS + 724, ACTIONS + 740, FLAGS + 1, FLAGS + 9] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let parsed = RawV5::parse_exact(&changed).unwrap();
        assert_ne!(parsed.effect_id(), baseline.effect_id(), "effect {offset}");
        assert_eq!(parsed.auth_digest(), baseline.auth_digest(), "auth {offset}");
        assert_eq!(parsed.original_bytes(), changed);
    }
    for offset in [PROOF, SPEND_SIGS - 1, SPEND_SIGS, SPEND_SIGS + 64, BINDING_SIG, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let parsed = RawV5::parse_exact(&changed).unwrap();
        assert_eq!(parsed.effect_id(), baseline.effect_id());
        assert_ne!(parsed.auth_digest(), baseline.auth_digest());
    }
    for epk in [[0; 32], [0xff; 32]] {
        let mut changed = bytes.clone();
        changed[ACTIONS + 128..ACTIONS + 160].copy_from_slice(&epk);
        let parsed = RawV5::parse_exact(&changed).unwrap();
        assert_eq!(&parsed.orchard().unwrap().actions()[128..160], &epk);
        assert_ne!(parsed.effect_id(), baseline.effect_id());
        assert_eq!(parsed.auth_digest(), baseline.auth_digest());
    }
    let mut padded = bytes.clone();
    padded[PROOF_LENGTH + 1..PROOF].copy_from_slice(&7265_u16.to_le_bytes());
    padded.insert(SPEND_SIGS, 0x42);
    let parsed = RawV5::parse_exact(&padded).unwrap();
    assert_eq!(parsed.effect_id(), baseline.effect_id());
    assert_ne!(parsed.auth_digest(), baseline.auth_digest());
    assert_eq!(parsed.orchard().unwrap().proof().last(), Some(&0x42));
    for (offset, expected) in [(22, RawV5Error::TooManySaplingSpends),
        (23, RawV5Error::TooManySaplingOutputs), (24, RawV5Error::TooManyOrchardActions)] {
        let mut bad = bytes.clone();
        bad.splice(offset..offset + 1, [0xfe, 0, 0, 1, 0]);
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), expected);
    }
    for offset in [20, 21, 22, 23, 24] {
        let mut bad = bytes.clone();
        let count = bad[offset];
        bad.splice(offset..offset + 1, [0xfd, count, 0]);
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), RawV5Error::InvalidCompactSize);
    }
    for removed in [1, 64, 192, 7456] {
        let truncated = &bytes[..bytes.len() - removed];
        let mut reader = truncated;
        assert_eq!(RawV5::parse(&mut reader).unwrap_err(), RawV5Error::Truncated);
        assert_eq!(reader, truncated);
    }
    let mut joined = bytes.clone();
    joined.extend_from_slice(ORIGINAL);
    let mut reader = joined.as_slice();
    assert_eq!(RawV5::parse(&mut reader).unwrap().consensus_branch_id(), BranchId::Nu6);
    assert_eq!(reader, ORIGINAL);
    assert_eq!(RawV5::parse(&mut reader).unwrap().consensus_branch_id(), BranchId::Nu5);
    assert!(reader.is_empty());
}

#[test]
fn synthetic_nu6_mixed_projection_keeps_sapling_bytes_but_rejects_old_authorizations() {
    let original = include_bytes!("fixtures/nu5-mixed-testnet-1842421.bin");
    let mut raw = original.to_vec();
    raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
    let parsed = RawV5::parse_exact(&raw).unwrap();
    assert!(parsed.sapling_bundle().is_some());
    let mut maintained_reader = raw.as_slice();
    let maintained = Transaction::read(&mut maintained_reader, BranchId::Nu5).unwrap();
    assert!(maintained_reader.is_empty());
    assert_eq!(maintained.consensus_branch_id(), BranchId::Nu6);
    assert_eq!(parsed.effect_id(), <[u8; 32]>::from(maintained.txid()));
    assert_eq!(parsed.auth_digest().as_slice(), maintained.auth_commitment().as_bytes());
    let mut original_sapling = Vec::new();
    let nu5 = RawV5::parse_exact(original).unwrap();
    Transaction::temporary_zcashd_write_v5_sapling(nu5.sapling_bundle(), &mut original_sapling).unwrap();
    let mut retained_sapling = Vec::new();
    Transaction::temporary_zcashd_write_v5_sapling(parsed.sapling_bundle(), &mut retained_sapling).unwrap();
    assert_eq!(retained_sapling, original_sapling);
    let orchard = *parsed.orchard().unwrap();
    let context = parsed.into_signature_context(vec![]).unwrap();
    assert!(matches!(ziquid_proofs::zip244::verify_sapling_post_nu5_crypto(&context),
        Err(ziquid_proofs::sapling_crypto::SaplingCryptoError::InvalidSpendAuthSignature { .. })
        | Err(ziquid_proofs::sapling_crypto::SaplingCryptoError::InvalidBindingSignature)));
    assert_eq!(orchard.verify_orchard(&VERIFIER, &context.shielded()),
        Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
}

// These exact framing/digest mutations contain the OLD proof and signatures.
// They qualify parser/mode boundaries only, not a valid fixed-era transaction.
fn nu62_wire() -> Vec<u8> {
    let mut raw = ORIGINAL.to_vec();
    raw[8..12].copy_from_slice(&0x5437_f330_u32.to_le_bytes());
    raw
}

#[test]
fn fixed_proof_length_is_checked_before_action_decode_and_reader_commit() {
    let raw = nu62_wire();
    assert_eq!(RawV5::parse_exact(&raw).unwrap().orchard().unwrap().proof().len(), 7264);
    for length in [0_u16, 4992, 7263, 7265] {
        let mut bad = raw[..PROOF_LENGTH].to_vec();
        zcash_encoding::CompactSize::write(&mut bad, usize::from(length)).unwrap();
        // No proof bytes at all: the fixed declared-size gate precedes copying
        // or Action point decoding, even for an invalid first randomized key.
        bad[ACTIONS + 64..ACTIONS + 96].fill(0xff);
        let mut reader = bad.as_slice();
        assert_eq!(RawV5::parse(&mut reader).unwrap_err(), RawV5Error::InvalidOrchardProofLength);
        assert_eq!(reader, bad);
    }
    for length in [7263_u16, 7265] {
        let mut bad = raw.clone();
        bad[PROOF_LENGTH + 1..PROOF].copy_from_slice(&length.to_le_bytes());
        if length == 7263 { bad.remove(SPEND_SIGS - 1); }
        else { bad.insert(SPEND_SIGS, 0x42); }
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), RawV5Error::InvalidOrchardProofLength);
        for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1] {
            bad[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
            assert_eq!(RawV5::parse_exact(&bad).unwrap().orchard().unwrap().proof().len(), usize::from(length));
        }
    }
    let mut noncanonical = raw.clone();
    noncanonical.splice(PROOF_LENGTH..PROOF, [0xfe, 0x60, 0x1c, 0, 0]);
    assert_eq!(RawV5::parse_exact(&noncanonical).unwrap_err(), RawV5Error::InvalidCompactSize);
    for removed in [1, 64, 192, 7456] {
        let truncated = &raw[..raw.len() - removed];
        let mut reader = truncated;
        assert_eq!(RawV5::parse(&mut reader).unwrap_err(), RawV5Error::Truncated);
        assert_eq!(reader, truncated);
    }
    // A structurally bounded one-Action descriptor has the literal 4992-byte
    // size, not the two-Action size. Its proof/signatures are not claimed valid.
    let mut one = raw[..ACTIONS].to_vec();
    one[24] = 1;
    one.extend_from_slice(&raw[ACTIONS..ACTIONS + ACTION_WIDTH]);
    one.extend_from_slice(&raw[FLAGS..PROOF_LENGTH]);
    zcash_encoding::CompactSize::write(&mut one, 4992).unwrap();
    one.extend_from_slice(&raw[PROOF..PROOF + 4992]);
    one.extend_from_slice(&raw[SPEND_SIGS..SPEND_SIGS + 64]);
    one.extend_from_slice(&raw[BINDING_SIG..]);
    let parsed = RawV5::parse_exact(&one).unwrap();
    assert_eq!(parsed.orchard().unwrap().action_count(), 1);
    assert_eq!(parsed.orchard().unwrap().proof().len(), 4992);
}

#[test]
fn fixed_raw_resources_and_absent_orchard_remain_bounded_without_normalization() {
    let raw = nu62_wire();
    for (offset, expected) in [(22, RawV5Error::TooManySaplingSpends),
        (23, RawV5Error::TooManySaplingOutputs), (24, RawV5Error::TooManyOrchardActions)] {
        let mut bad = raw.clone();
        bad.splice(offset..offset + 1, [0xfe, 0, 0, 1, 0]);
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), expected);
    }
    for offset in [20, 21, 22, 23, 24] {
        let mut bad = raw.clone();
        let count = bad[offset];
        bad.splice(offset..offset + 1, [0xfd, count, 0]);
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), RawV5Error::InvalidCompactSize);
    }
    let mut huge_script = raw[..20].to_vec();
    huge_script.push(1);
    huge_script.extend_from_slice(&[0x41; 36]);
    zcash_encoding::CompactSize::write(&mut huge_script, 1_999_950).unwrap();
    huge_script.resize(2_000_005, 0);
    assert_eq!(RawV5::parse_exact(&huge_script).unwrap_err(), RawV5Error::TransactionTooLarge);
    let mut absent = raw[..24].to_vec();
    absent.push(0);
    let parsed = RawV5::parse_exact(&absent).unwrap();
    assert!(parsed.orchard().is_none());
    assert_eq!(parsed.consensus_branch_id(), BranchId::Nu6_2);
    absent.extend_from_slice(&raw[FLAGS..]);
    assert_eq!(RawV5::parse_exact(&absent).unwrap_err(), RawV5Error::TrailingBytes);
}

#[test]
fn fixed_every_action_requires_canonical_nonidentity_epk_and_randomized_key() {
    let raw = nu62_wire();
    let identity = [0; 32];
    let mut off_curve = [0; 32];
    off_curve[0] = 2; // x=2: x^3+5 is a nonsquare in the Pallas base field.
    let noncanonical = [
        1, 0, 0, 0, 0xed, 0x30, 0x2d, 0x99, 0x1b, 0xf9, 0x4c, 9, 0xfc, 0x98, 0x46, 0x22,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40,
    ]; // x equals the Pallas base-field modulus.
    for flags in [1, 2, 3] {
        for index in 0..2 {
            for encoding in [identity, off_curve, noncanonical, [0xff; 32]] {
                for (field, expected) in [
                    (64, RawV5Error::InvalidOrchardRandomizedKey { index }),
                    (128, RawV5Error::InvalidOrchardEphemeralKey { index }),
                ] {
                    let mut bad = raw.clone();
                    bad[FLAGS] = flags;
                    let offset = ACTIONS + index * ACTION_WIDTH + field;
                    bad[offset..offset + 32].copy_from_slice(&encoding);
                    assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), expected, "flags {flags}, action {index}, field {field}");
                    if field == 128 || encoding == identity {
                        for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1] {
                            bad[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
                            RawV5::parse_exact(&bad).unwrap();
                        }
                    }
                }
            }
            // Identity cv is allowed in both modes; no invented point ban.
            let mut identity_cv = raw.clone();
            identity_cv[FLAGS] = flags;
            let offset = ACTIONS + index * ACTION_WIDTH;
            identity_cv[offset..offset + 32].fill(0);
            RawV5::parse_exact(&identity_cv).unwrap();
        }
    }
    for flags in [0, 4, 5, 7, 8, 0x80, 0xff] {
        let mut bad = raw.clone();
        bad[FLAGS] = flags;
        assert_eq!(RawV5::parse_exact(&bad).unwrap_err(), RawV5Error::InvalidOrchardFlags);
    }
    for flags in [1, 2, 3] {
        let mut valid_shape = raw.clone();
        valid_shape[FLAGS] = flags;
        let parsed = RawV5::parse_exact(&valid_shape).unwrap();
        assert!(parsed.orchard().unwrap().flags().cross_address_enabled());
    }
}

#[test]
fn actual_encoded_mode_prevents_wrong_verifier_before_authorization() {
    let raw = nu62_wire();
    let fixed = RawV5::parse_exact(&raw).unwrap();
    assert_eq!(fixed.verify_orchard(&VERIFIER, &[0; 32]), Err(RawV5Error::OrchardVerifierModeMismatch));
    for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1] {
        let mut old = ORIGINAL.to_vec();
        old[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
        // Historic identity crash classification must not mask wrong-method
        // rejection, and remains unchanged under its correct historical API.
        old[ACTIONS + ACTION_WIDTH + 64..ACTIONS + ACTION_WIDTH + 96].fill(0);
        let parsed = RawV5::parse_exact(&old).unwrap();
        let orchard = parsed.orchard().unwrap();
        assert_eq!(orchard.verify_orchard_fixed(&FIXED_VERIFIER, &[0; 32]), Err(RawV5Error::OrchardVerifierModeMismatch));
        assert_eq!(orchard.verify_orchard(&VERIFIER, &[0; 32]), Err(RawV5Error::UnsupportedHistoricalIdentityRk { index: 1 }));
    }
    let orchard = fixed.orchard().unwrap();
    // Old authorization never certifies the new message, even though framing
    // and every strict point are eligible. This is NOT a fixed proof positive.
    assert_eq!(orchard.verify_orchard_fixed(&FIXED_VERIFIER, &fixed.effect_id()), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
    // With the original message, both real old SpendAuth and binding equations
    // pass, reaching the actual fixed key which must reject the old circuit.
    let original = RawV5::parse_exact(ORIGINAL).unwrap();
    assert_eq!(orchard.verify_orchard_fixed(&FIXED_VERIFIER, &original.effect_id()), Err(RawV5Error::InvalidOrchardProof));
}

#[test]
fn fixed_shared_authorization_checks_disabled_actions_and_allows_identity_binding() {
    let message = RawV5::parse_exact(ORIGINAL).unwrap().effect_id();
    for flags in [1, 2, 3] {
        for (offset, expected) in [
            (SPEND_SIGS + 63, RawV5Error::InvalidOrchardSpendAuth { index: 0 }),
            (SPEND_SIGS + 127, RawV5Error::InvalidOrchardSpendAuth { index: 1 }),
            (BINDING_SIG + 63, RawV5Error::InvalidOrchardBindingSignature),
        ] {
            let mut changed = nu62_wire();
            changed[FLAGS] = flags;
            changed[offset] ^= 1;
            let parsed = RawV5::parse_exact(&changed).unwrap();
            // Isolate real signatures using their original message. Neither
            // changed flags nor the OLD proof are qualified fixed positives.
            assert_eq!(parsed.orchard().unwrap().verify_orchard_fixed(&FIXED_VERIFIER, &message), Err(expected));
        }
    }
    // The synthetic identity cv/binding equation is legal; the actual fixed
    // proof must still fail its changed statement, after signature verification.
    let mut identity_binding = nu62_wire();
    identity_binding[ACTIONS..ACTIONS + 32].fill(0);
    identity_binding[ACTIONS + ACTION_WIDTH..ACTIONS + ACTION_WIDTH + 32].fill(0);
    identity_binding[FLAGS + 1..FLAGS + 9].fill(0);
    identity_binding[BINDING_SIG..].fill(0);
    let parsed = RawV5::parse_exact(&identity_binding).unwrap();
    assert_eq!(parsed.orchard().unwrap().verify_orchard_fixed(&FIXED_VERIFIER, &message), Err(RawV5Error::InvalidOrchardProof));
}

#[test]
fn fixed_wire_borrows_every_ciphertext_and_auth_byte_without_reencoding() {
    let raw = nu62_wire();
    let parsed = RawV5::parse_exact(&raw).unwrap();
    let orchard = parsed.orchard().unwrap();
    assert_eq!(orchard.actions().as_ptr(), raw[ACTIONS..].as_ptr());
    assert_eq!(orchard.proof().as_ptr(), raw[PROOF..].as_ptr());
    assert_eq!(orchard.spend_auth_signatures().as_ptr(), raw[SPEND_SIGS..].as_ptr());
    assert_eq!(orchard.binding_signature().as_ptr(), raw[BINDING_SIG..].as_ptr());
    for offset in [ACTIONS + 160, ACTIONS + 212, ACTIONS + 724, ACTIONS + 740,
        ACTIONS + ACTION_WIDTH + 160, ACTIONS + ACTION_WIDTH + 212,
        ACTIONS + ACTION_WIDTH + 724, ACTIONS + ACTION_WIDTH + 740] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        let actual = RawV5::parse_exact(&changed).unwrap();
        assert_ne!(actual.effect_id(), parsed.effect_id());
        assert_eq!(actual.auth_digest(), parsed.auth_digest());
        assert_eq!(actual.original_bytes(), changed);
    }
    // Canonical field replacements use the other Action's actual encoding;
    // strict key parsing cannot hide a missing effect-region commitment.
    for field in [0, 32, 64, 96, 128] {
        let mut changed = raw.clone();
        changed[ACTIONS + field..ACTIONS + field + 32]
            .copy_from_slice(&raw[ACTIONS + ACTION_WIDTH + field..ACTIONS + ACTION_WIDTH + field + 32]);
        let actual = RawV5::parse_exact(&changed).unwrap();
        assert_ne!(actual.effect_id(), parsed.effect_id());
        assert_eq!(actual.auth_digest(), parsed.auth_digest());
    }
    for offset in [12, 16, FLAGS + 1, FLAGS + 9] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        let actual = RawV5::parse_exact(&changed).unwrap();
        assert_ne!(actual.effect_id(), parsed.effect_id());
        assert_eq!(actual.auth_digest(), parsed.auth_digest());
    }
    for offset in [PROOF, SPEND_SIGS - 1, SPEND_SIGS, SPEND_SIGS + 64, BINDING_SIG, raw.len() - 1] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        let actual = RawV5::parse_exact(&changed).unwrap();
        assert_eq!(actual.effect_id(), parsed.effect_id());
        assert_ne!(actual.auth_digest(), parsed.auth_digest());
        assert_eq!(actual.original_bytes(), changed);
    }
    let mut joined = raw.clone();
    joined.extend_from_slice(ORIGINAL);
    let mut reader = joined.as_slice();
    assert_eq!(RawV5::parse(&mut reader).unwrap().consensus_branch_id(), BranchId::Nu6_2);
    assert_eq!(reader, ORIGINAL);
    assert_eq!(RawV5::parse(&mut reader).unwrap().consensus_branch_id(), BranchId::Nu5);
    assert!(reader.is_empty());
}

#[test]
fn nu62_mixed_projection_keeps_real_sapling_and_complete_orchard_original_bytes() {
    let original = include_bytes!("fixtures/nu5-mixed-testnet-1842421.bin");
    let mut raw = original.to_vec();
    raw[8..12].copy_from_slice(&0x5437_f330_u32.to_le_bytes());
    let parsed = RawV5::parse_exact(&raw).unwrap();
    let mut reader = raw.as_slice();
    let maintained = Transaction::read(&mut reader, BranchId::Nu5).unwrap();
    assert!(reader.is_empty());
    assert_eq!(maintained.consensus_branch_id(), BranchId::Nu6_2);
    assert_eq!(parsed.effect_id(), <[u8; 32]>::from(maintained.txid()));
    assert_eq!(parsed.auth_digest().as_slice(), maintained.auth_commitment().as_bytes());
    let nu5 = RawV5::parse_exact(original).unwrap();
    let mut before = Vec::new();
    let mut retained = Vec::new();
    Transaction::temporary_zcashd_write_v5_sapling(nu5.sapling_bundle(), &mut before).unwrap();
    Transaction::temporary_zcashd_write_v5_sapling(parsed.sapling_bundle(), &mut retained).unwrap();
    assert_eq!(retained, before);
    let orchard = *parsed.orchard().unwrap();
    assert_eq!(orchard.actions(), nu5.orchard().unwrap().actions());
    assert_eq!(orchard.proof(), nu5.orchard().unwrap().proof());
    assert_eq!(orchard.spend_auth_signatures(), nu5.orchard().unwrap().spend_auth_signatures());
    assert_eq!(orchard.binding_signature(), nu5.orchard().unwrap().binding_signature());
    let hashes = parsed.into_signature_context(vec![]).unwrap();
    let expected = ziquid_proofs::zip244::PostNu5SignatureHash::new(maintained, vec![]).unwrap();
    assert_eq!(hashes.shielded(), expected.shielded());
    assert!(matches!(ziquid_proofs::zip244::verify_sapling_post_nu5_crypto(&hashes),
        Err(ziquid_proofs::sapling_crypto::SaplingCryptoError::InvalidSpendAuthSignature { .. })
        | Err(ziquid_proofs::sapling_crypto::SaplingCryptoError::InvalidBindingSignature)));
    assert_eq!(orchard.verify_orchard_fixed(&FIXED_VERIFIER, &hashes.shielded()), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
}
