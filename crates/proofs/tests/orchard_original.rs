//! Frozen original Orchard Halo2 proof, not a transaction/history certificate.
/*
The MIT License (MIT)
Copyright (c) 2020-2025 The Electric Coin Company
Copyright (c) 2026 Zcash Open Development Lab
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
use ziquid_proofs::orchard_original::{OriginalActionInstance,OriginalOrchardVerifier};
#[test]
fn frozen_original_orchard_proof_verifies_actual_instance(){
 let raw=include_bytes!("fixtures/orchard-original-proof.bin");
 let field=|offset|raw[offset..offset+32].try_into().unwrap();
 let instance=OriginalActionInstance{anchor:field(0),cv_net:field(32),nullifier:field(64),rk:field(96),cmx:field(128),flags:raw[160]|(raw[161]<<1)};
 let verifier=OriginalOrchardVerifier::new();verifier.verify(&[instance],&raw[162..]).unwrap();
}

use std::sync::LazyLock;

use orchard::{
    Proof,
    bundle::{BundleVersion, Flags},
    circuit::{Instance, OrchardCircuitVersion, VerifyingKey},
    note::{ExtractedNoteCommitment, Nullifier},
    primitives::redpallas::{SpendAuth, VerificationKey},
    tree::Anchor,
    value::ValueCommitment,
};
use ziquid_proofs::orchard_original::OriginalOrchardError;

static VERIFIER: LazyLock<OriginalOrchardVerifier> = LazyLock::new(OriginalOrchardVerifier::new);

fn fixture() -> (OriginalActionInstance, &'static [u8]) {
    // Upstream test-case encoding, deliberately not a transaction/bundle parser.
    let raw = include_bytes!("fixtures/orchard-original-proof.bin");
    let field = |offset| raw[offset..offset + 32].try_into().unwrap();
    (
        OriginalActionInstance {
            anchor: field(0),
            cv_net: field(32),
            nullifier: field(64),
            rk: field(96),
            cmx: field(128),
            flags: raw[160] | (raw[161] << 1),
        },
        &raw[162..],
    )
}

#[test]
fn every_original_public_input_is_bound_to_the_frozen_proof() {
    let (original, proof) = fixture();
    let mut mutations = [original; 7];
    mutations[0].anchor[0] ^= 1;
    // Opposite signs are distinct canonical encodings of these nonidentity points.
    mutations[1].cv_net[31] ^= 0x80;
    mutations[2].nullifier[0] ^= 1;
    mutations[3].rk[31] ^= 0x80;
    mutations[4].cmx[0] ^= 1;
    mutations[5].flags = 1;
    mutations[6].flags = 2;
    for (field, instance) in mutations.into_iter().enumerate() {
        assert_eq!(
            VERIFIER.verify(&[instance], proof),
            Err(OriginalOrchardError::InvalidProof),
            "canonical public-input mutation {field} must change the statement",
        );
    }
    assert_eq!(
        VERIFIER.verify(&[original, original], proof),
        Err(OriginalOrchardError::InvalidProof),
        "a one-action proof does not authorize two actions",
    );
}

#[test]
fn noncanonical_fields_fail_with_redacted_indexed_errors() {
    let (original, proof) = fixture();
    let mut cases = [
        (original, OriginalOrchardError::InvalidAnchor { index: 1 }),
        (original, OriginalOrchardError::InvalidValueCommitment { index: 1 }),
        (original, OriginalOrchardError::InvalidNullifier { index: 1 }),
        (original, OriginalOrchardError::InvalidRandomizedKey { index: 1 }),
        (original, OriginalOrchardError::InvalidNoteCommitment { index: 1 }),
    ];
    cases[0].0.anchor = [0xff; 32];
    cases[1].0.cv_net = [0xff; 32];
    cases[2].0.nullifier = [0xff; 32];
    cases[3].0.rk = [0xff; 32];
    cases[4].0.cmx = [0xff; 32];
    for (instance, expected) in cases {
        let error = VERIFIER.verify(&[original, instance], proof).unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("255"));
        assert!(!format!("{error:?}").contains("255"));
    }
}

#[test]
fn empty_and_reserved_flags_are_rejected_before_proof_verification() {
    let (mut instance, proof) = fixture();
    for flags in 0..=u8::MAX {
        if matches!(flags, 1..=3) {
            continue;
        }
        instance.flags = flags;
        assert_eq!(
            VERIFIER.verify(&[instance], proof),
            Err(OriginalOrchardError::InvalidFlags { index: 0 }),
        );
    }
}

#[test]
fn identity_randomized_key_is_an_unsupported_old_crash_domain() {
    let (original, proof) = fixture();
    let mut identity = original;
    identity.rk = [0; 32];
    // Identity is canonically decodable, not an invalid encoding or a substituted point.
    assert!(VerificationKey::<SpendAuth>::try_from(identity.rk).is_ok());
    assert_eq!(
        VERIFIER.verify(&[original, identity], proof),
        Err(OriginalOrchardError::UnsupportedIdentityKey { index: 1 }),
    );
}

#[test]
fn synthetic_identity_commitment_does_not_authorize_the_frozen_statement() {
    let (mut instance, proof) = fixture();
    // Identity cv is an allowed point encoding; this is only a synthetic negative.
    instance.cv_net = [0; 32];
    assert_eq!(
        VERIFIER.verify(&[instance], proof),
        Err(OriginalOrchardError::InvalidProof),
    );
}

#[test]
fn mutated_and_truncated_transcripts_fail_real_halo2_verification() {
    let (instance, proof) = fixture();
    for offset in [0, proof.len() / 2, proof.len() - 1] {
        let mut mutated = proof.to_vec();
        mutated[offset] ^= 1;
        assert_eq!(
            VERIFIER.verify(&[instance], &mutated),
            Err(OriginalOrchardError::InvalidProof),
        );
    }
    for length in [0, 1, proof.len() - 1] {
        assert_eq!(
            VERIFIER.verify(&[instance], &proof[..length]),
            Err(OriginalOrchardError::InvalidProof),
        );
    }
}

#[test]
fn resource_limits_are_checked_before_instance_decoding() {
    let (mut instance, _) = fixture();
    instance.flags = 0;
    assert_eq!(VERIFIER.verify(&[], &[]), Err(OriginalOrchardError::EmptyInstances));
    let mut instances = vec![instance; 65_535];
    assert_eq!(
        VERIFIER.verify(&instances, &[]),
        Err(OriginalOrchardError::InvalidFlags { index: 0 }),
        "the inclusive action limit must reach decoding",
    );
    instances.push(instance);
    assert_eq!(
        VERIFIER.verify(&instances, &[]),
        Err(OriginalOrchardError::TooManyInstances),
    );
    let mut proof = vec![0; 2 * 1024 * 1024];
    assert_eq!(
        VERIFIER.verify(&[instance], &proof),
        Err(OriginalOrchardError::InvalidFlags { index: 0 }),
        "the inclusive proof limit must reach decoding",
    );
    proof.push(0);
    assert_eq!(
        VERIFIER.verify(&[instance], &proof),
        Err(OriginalOrchardError::ProofTooLarge),
    );
}

#[test]
fn trailing_proof_bytes_follow_the_actual_original_halo2_relation() {
    let (instance, proof) = fixture();
    let typed = Instance::from_parts(
        Option::<Anchor>::from(Anchor::from_bytes(instance.anchor)).unwrap(),
        Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&instance.cv_net)).unwrap(),
        Option::<Nullifier>::from(Nullifier::from_bytes(&instance.nullifier)).unwrap(),
        VerificationKey::<SpendAuth>::try_from(instance.rk).unwrap(),
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&instance.cmx)).unwrap(),
        Flags::from_byte(instance.flags, BundleVersion::orchard_insecure_v1()).unwrap(),
    ).unwrap();
    let vk = VerifyingKey::build(OrchardCircuitVersion::InsecurePreNu6_2);
    let mut padded = proof.to_vec();
    padded.extend_from_slice(&[0x5a, 0xa5]);
    let actual = Proof::new(padded.clone()).verify(&vk, &[typed]).is_ok();
    eprintln!("actual InsecurePreNu6_2 Halo2 trailing-byte acceptance: {actual}");
    assert_eq!(VERIFIER.verify(&[instance], &padded).is_ok(), actual);
}

#[test]
fn frozen_fixed_orchard_proof_requires_fixed_key_and_exact_length() {
    // Original Orchard0.14.0 fixture, same Git blob in pinned0.15.5:
    // 724ac01f68125c061ebad7987b250a630ac335a3,5154B,
    // SHA256628b03e73f5533e3a21103d8c041414191f56b2b3a3affe468adfe92e99ae468.
    // Synthetic proof-only fixture, not a signed transaction or mined body.
    let raw = include_bytes!("fixtures/orchard-fixed-proof.bin");
    let field = |offset| raw[offset..offset + 32].try_into().unwrap();
    let instance = OriginalActionInstance { anchor: field(0), cv_net: field(32),
        nullifier: field(64), rk: field(96), cmx: field(128), flags: raw[160] | (raw[161] << 1) };
    let verifier = ziquid_proofs::orchard_original::FixedOrchardVerifier::new();
    verifier.verify(&[instance], &raw[162..]).unwrap();
    assert_eq!(VERIFIER.verify(&[instance], &raw[162..]), Err(OriginalOrchardError::InvalidProof));
    let mut padded = raw[162..].to_vec();
    padded.push(0);
    assert!(verifier.verify(&[instance], &padded).is_err());
    assert!(verifier.verify(&[instance], &raw[162..raw.len() - 1]).is_err());
}

use ziquid_proofs::orchard_original::{FixedOrchardError, FixedOrchardVerifier};

static FIXED_VERIFIER: LazyLock<FixedOrchardVerifier> = LazyLock::new(FixedOrchardVerifier::new);

fn fixed_fixture() -> (OriginalActionInstance, &'static [u8]) {
    let raw = include_bytes!("fixtures/orchard-fixed-proof.bin");
    let field = |offset| raw[offset..offset + 32].try_into().unwrap();
    (
        OriginalActionInstance {
            anchor: field(0),
            cv_net: field(32),
            nullifier: field(64),
            rk: field(96),
            cmx: field(128),
            flags: raw[160] | (raw[161] << 1),
        },
        &raw[162..],
    )
}

#[test]
fn every_fixed_public_input_is_bound_to_the_frozen_proof() {
    let (original, proof) = fixed_fixture();
    let mut mutations = [original; 7];
    mutations[0].anchor[0] ^= 1;
    mutations[1].cv_net[31] ^= 0x80;
    mutations[2].nullifier[0] ^= 1;
    mutations[3].rk[31] ^= 0x80;
    mutations[4].cmx[0] ^= 1;
    mutations[5].flags = 1;
    mutations[6].flags = 2;
    for (field, instance) in mutations.into_iter().enumerate() {
        assert_eq!(
            FIXED_VERIFIER.verify(&[instance], proof),
            Err(FixedOrchardError::InvalidProof),
            "canonical fixed public-input mutation {field} must change the statement",
        );
    }
}

#[test]
fn fixed_noncanonical_fields_and_identity_key_are_invalid_at_the_action_index() {
    let (original, proof) = fixed_fixture();
    let mut cases = [
        (original, FixedOrchardError::InvalidAnchor { index: 1 }),
        (original, FixedOrchardError::InvalidValueCommitment { index: 1 }),
        (original, FixedOrchardError::InvalidNullifier { index: 1 }),
        (original, FixedOrchardError::InvalidRandomizedKey { index: 1 }),
        (original, FixedOrchardError::InvalidNoteCommitment { index: 1 }),
        (original, FixedOrchardError::InvalidRandomizedKey { index: 1 }),
    ];
    cases[0].0.anchor = [0xff; 32];
    cases[1].0.cv_net = [0xff; 32];
    cases[2].0.nullifier = [0xff; 32];
    cases[3].0.rk = [0xff; 32];
    cases[4].0.cmx = [0xff; 32];
    cases[5].0.rk = [0; 32];
    // Correct two-action framing reaches decoding; this padded one-action
    // transcript is not a valid two-action proof and is never claimed to be.
    let mut framed = proof.to_vec();
    framed.resize(7264, 0);
    for (instance, expected) in cases {
        let error = FIXED_VERIFIER.verify(&[original, instance], &framed).unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("255"));
        assert!(!format!("{error:?}").contains("255"));
    }
}

#[test]
fn fixed_empty_and_reserved_flags_are_invalid() {
    let (mut instance, proof) = fixed_fixture();
    for flags in 0..=u8::MAX {
        if matches!(flags, 1..=3) {
            continue;
        }
        instance.flags = flags;
        assert_eq!(
            FIXED_VERIFIER.verify(&[instance], proof),
            Err(FixedOrchardError::InvalidFlags { index: 0 }),
        );
    }
}

#[test]
fn fixed_identity_value_commitment_is_decodable_but_changes_the_statement() {
    let (mut instance, proof) = fixed_fixture();
    instance.cv_net = [0; 32];
    assert_eq!(
        FIXED_VERIFIER.verify(&[instance], proof),
        Err(FixedOrchardError::InvalidProof),
    );
}

#[test]
fn fixed_proof_mutations_require_actual_halo2_verification() {
    let (instance, proof) = fixed_fixture();
    for offset in [0, proof.len() / 2, proof.len() - 1] {
        let mut mutated = proof.to_vec();
        mutated[offset] ^= 1;
        assert_eq!(
            FIXED_VERIFIER.verify(&[instance], &mutated),
            Err(FixedOrchardError::InvalidProof),
        );
    }
    let (old_instance, old_proof) = fixture();
    assert_eq!(
        FIXED_VERIFIER.verify(&[old_instance], old_proof),
        Err(FixedOrchardError::InvalidProof),
        "the fixed verifier must not fall back to the insecure key",
    );
}

#[test]
fn fixed_action_count_and_proof_length_are_bound_before_decoding() {
    let (instance, proof) = fixed_fixture();
    assert_eq!(
        FIXED_VERIFIER.verify(&[instance, instance], proof),
        Err(FixedOrchardError::InvalidProofLength),
    );
    let mut framed = proof.to_vec();
    framed.resize(7264, 0);
    assert_eq!(
        FIXED_VERIFIER.verify(&[instance, instance], &framed),
        Err(FixedOrchardError::InvalidProof),
        "matching two-action framing cannot authorize a repeated one-action statement",
    );
    let mut malformed = instance;
    malformed.flags = 0;
    for length in [0, 1, 4991, 4993, 7264] {
        let bytes = vec![0; length];
        assert_eq!(
            FIXED_VERIFIER.verify(&[malformed], &bytes),
            Err(FixedOrchardError::InvalidProofLength),
            "framing must be rejected before malformed fields at length {length}",
        );
    }
}

#[test]
fn fixed_resource_bounds_precede_length_and_instance_decoding() {
    let (mut instance, _) = fixed_fixture();
    instance.flags = 0;
    assert_eq!(FIXED_VERIFIER.verify(&[], &[]), Err(FixedOrchardError::EmptyInstances));
    let mut instances = vec![instance; 65_535];
    assert_eq!(
        FIXED_VERIFIER.verify(&instances, &[]),
        Err(FixedOrchardError::InvalidProofLength),
    );
    instances.push(instance);
    assert_eq!(
        FIXED_VERIFIER.verify(&instances, &[]),
        Err(FixedOrchardError::TooManyInstances),
    );
    let mut proof = vec![0; 2 * 1024 * 1024];
    assert_eq!(
        FIXED_VERIFIER.verify(&[instance], &proof),
        Err(FixedOrchardError::InvalidProofLength),
    );
    proof.push(0);
    assert_eq!(
        FIXED_VERIFIER.verify(&[instance], &proof),
        Err(FixedOrchardError::ProofTooLarge),
    );
    // 921 is the last action count whose exact proof fits the local 2 MiB cap.
    let instances = vec![instance; 922];
    assert_eq!(
        FIXED_VERIFIER.verify(&instances[..921], &vec![0; 2_095_232]),
        Err(FixedOrchardError::InvalidFlags { index: 0 }),
    );
    assert_eq!(
        FIXED_VERIFIER.verify(&instances, &vec![0; 2_097_504]),
        Err(FixedOrchardError::ProofTooLarge),
    );
}
