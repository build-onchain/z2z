//! Upstream frozen proof-only fixtures; not signed transactions or mined history.
/*
The MIT License (MIT)
Copyright (c) 2020-2025 The Electric Coin Company
Copyright (c) 2026 Zcash Open Development Lab
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
use std::sync::LazyLock;

use ziquid_proofs::orchard_original::{
    FixedOrchardError, FixedOrchardVerifier, OriginalActionInstance, OriginalOrchardError,
    OriginalOrchardVerifier, PostNu63ActionInstance, PostNu63OrchardError,
    PostNu63OrchardVerifier,
};

static VERIFIER: LazyLock<PostNu63OrchardVerifier> = LazyLock::new(PostNu63OrchardVerifier::new);

fn fixtures() -> [(PostNu63ActionInstance, &'static [u8]); 2] {
    // Frozen orchard 0.15.5 primary proof fixtures: five 32-byte fields,
    // enableSpend, enableOutput, DISABLE cross-address, then 4992 proof bytes.
    // Unrestricted SHA256: 3be9c159e5f238566a814b5446716b31bade2c1fd82c45ee8582ddf500df165a
    // Restricted SHA256: 994492e214928e03456767c7c1ee7359d161f00a54d4ecb4ad55883968600c72
    [
        include_bytes!("fixtures/orchard-post-nu63.bin").as_slice(),
        include_bytes!("fixtures/orchard-post-nu63_restricted.bin").as_slice(),
    ]
    .map(|raw| {
        assert_eq!(raw.len(), 5155);
        assert_eq!(&raw[160..162], &[1, 1]);
        assert!(raw[162] <= 1);
        let field = |offset| raw[offset..offset + 32].try_into().unwrap();
        (
            PostNu63ActionInstance {
                anchor: field(0),
                cv_net: field(32),
                nullifier: field(64),
                rk: field(96),
                cmx: field(128),
                flags: raw[160] | (raw[161] << 1),
                disable_cross_address: raw[162] != 0,
            },
            &raw[163..],
        )
    })
}

#[test]
fn both_primary_post_nu63_proofs_bind_actual_cross_address_restriction() {
    let [unrestricted, restricted] = fixtures();
    assert!(!unrestricted.0.disable_cross_address);
    assert!(restricted.0.disable_cross_address);
    for (instance, proof) in [unrestricted, restricted] {
        VERIFIER.verify(&[instance], proof).unwrap();
        let changed = PostNu63ActionInstance {
            disable_cross_address: !instance.disable_cross_address,
            ..instance
        };
        assert_eq!(
            VERIFIER.verify(&[changed], proof),
            Err(PostNu63OrchardError::InvalidProof),
        );
    }
}

#[test]
fn post_nu63_proofs_cannot_use_original_or_fixed_keys() {
    let original_verifier = OriginalOrchardVerifier::new();
    let fixed_verifier = FixedOrchardVerifier::new();
    for (instance, proof) in fixtures() {
        let old = OriginalActionInstance {
            anchor: instance.anchor,
            cv_net: instance.cv_net,
            nullifier: instance.nullifier,
            rk: instance.rk,
            cmx: instance.cmx,
            flags: instance.flags,
        };
        assert_eq!(
            original_verifier.verify(&[old], proof),
            Err(OriginalOrchardError::InvalidProof),
        );
        assert_eq!(
            fixed_verifier.verify(&[old], proof),
            Err(FixedOrchardError::InvalidProof),
        );
    }
    // Conversely, the new verifier must not fall back to either older key.
    for raw in [
        include_bytes!("fixtures/orchard-original-proof.bin").as_slice(),
        include_bytes!("fixtures/orchard-fixed-proof.bin").as_slice(),
    ] {
        let field = |offset| raw[offset..offset + 32].try_into().unwrap();
        let instance = PostNu63ActionInstance {
            anchor: field(0),
            cv_net: field(32),
            nullifier: field(64),
            rk: field(96),
            cmx: field(128),
            flags: raw[160] | (raw[161] << 1),
            disable_cross_address: false,
        };
        assert_eq!(
            VERIFIER.verify(&[instance], &raw[162..]),
            Err(PostNu63OrchardError::InvalidProof),
        );
    }
}

#[test]
fn every_post_nu63_public_input_is_bound_to_the_frozen_proofs() {
    for (original, proof) in fixtures() {
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
                VERIFIER.verify(&[instance], proof),
                Err(PostNu63OrchardError::InvalidProof),
                "canonical public-input mutation {field} must change the statement",
            );
        }
    }
}

#[test]
fn post_nu63_noncanonical_fields_and_identity_key_have_indexed_errors() {
    let (original, proof) = fixtures()[1];
    let mut cases = [
        (original, PostNu63OrchardError::InvalidAnchor { index: 1 }),
        (original, PostNu63OrchardError::InvalidValueCommitment { index: 1 }),
        (original, PostNu63OrchardError::InvalidNullifier { index: 1 }),
        (original, PostNu63OrchardError::InvalidRandomizedKey { index: 1 }),
        (original, PostNu63OrchardError::InvalidNoteCommitment { index: 1 }),
        (original, PostNu63OrchardError::InvalidRandomizedKey { index: 1 }),
    ];
    cases[0].0.anchor = [0xff; 32];
    cases[1].0.cv_net = [0xff; 32];
    cases[2].0.nullifier = [0xff; 32];
    cases[3].0.rk = [0xff; 32];
    cases[4].0.cmx = [0xff; 32];
    cases[5].0.rk = [0; 32];
    // Correct two-action framing reaches decoding, not a claimed positive proof.
    let mut framed = proof.to_vec();
    framed.resize(7264, 0);
    for (instance, expected) in cases {
        let error = VERIFIER.verify(&[original, instance], &framed).unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("255"));
        assert!(!format!("{error:?}").contains("255"));
    }
}

#[test]
fn post_nu63_empty_and_reserved_flags_cannot_override_the_separate_disable_bit() {
    for (mut instance, proof) in fixtures() {
        for flags in 0..=u8::MAX {
            if matches!(flags, 1..=3) {
                continue;
            }
            instance.flags = flags;
            assert_eq!(
                VERIFIER.verify(&[instance], proof),
                Err(PostNu63OrchardError::InvalidFlags { index: 0 }),
            );
        }
    }
}

#[test]
fn post_nu63_identity_value_commitment_is_decodable_but_changes_the_statement() {
    for (mut instance, proof) in fixtures() {
        instance.cv_net = [0; 32];
        assert_eq!(
            VERIFIER.verify(&[instance], proof),
            Err(PostNu63OrchardError::InvalidProof),
        );
    }
}

#[test]
fn post_nu63_proof_mutations_require_actual_halo2_verification() {
    for (instance, proof) in fixtures() {
        for offset in [0, proof.len() / 2, proof.len() - 1] {
            let mut mutated = proof.to_vec();
            mutated[offset] ^= 1;
            assert_eq!(
                VERIFIER.verify(&[instance], &mutated),
                Err(PostNu63OrchardError::InvalidProof),
            );
        }
    }
}

#[test]
fn post_nu63_padding_truncation_and_action_count_fail_before_decoding() {
    let (instance, proof) = fixtures()[1];
    assert_eq!(
        VERIFIER.verify(&[instance, instance], proof),
        Err(PostNu63OrchardError::InvalidProofLength),
    );
    let mut framed = proof.to_vec();
    framed.resize(7264, 0);
    assert_eq!(
        VERIFIER.verify(&[instance, instance], &framed),
        Err(PostNu63OrchardError::InvalidProof),
    );
    let malformed = PostNu63ActionInstance { flags: 0, ..instance };
    for length in [0, 1, 4991, 4993, 7264] {
        assert_eq!(
            VERIFIER.verify(&[malformed], &vec![0; length]),
            Err(PostNu63OrchardError::InvalidProofLength),
        );
    }
}

#[test]
fn post_nu63_resource_guards_precede_length_and_instance_decoding() {
    let (instance, _) = fixtures()[1];
    let malformed = PostNu63ActionInstance { flags: 0, ..instance };
    assert_eq!(VERIFIER.verify(&[], &[]), Err(PostNu63OrchardError::EmptyInstances));
    let mut instances = vec![malformed; 65_535];
    assert_eq!(
        VERIFIER.verify(&instances, &[]),
        Err(PostNu63OrchardError::InvalidProofLength),
    );
    instances.push(malformed);
    assert_eq!(
        VERIFIER.verify(&instances, &[]),
        Err(PostNu63OrchardError::TooManyInstances),
    );
    let mut proof = vec![0; 2 * 1024 * 1024];
    assert_eq!(
        VERIFIER.verify(&[malformed], &proof),
        Err(PostNu63OrchardError::InvalidProofLength),
    );
    proof.push(0);
    assert_eq!(
        VERIFIER.verify(&[malformed], &proof),
        Err(PostNu63OrchardError::ProofTooLarge),
    );
    // 921 is the last exact-size action proof that fits the local 2 MiB cap.
    assert_eq!(
        VERIFIER.verify(&instances[..921], &vec![0; 2_095_232]),
        Err(PostNu63OrchardError::InvalidFlags { index: 0 }),
    );
    assert_eq!(
        VERIFIER.verify(&instances[..922], &vec![0; 2_097_504]),
        Err(PostNu63OrchardError::ProofTooLarge),
    );
}
