use ziquid_protocol::market::Transition;
use ziquid_solana_interface::{effect_digest, Envelope, PrepareFillEffects, ReleaseEffects};
use sha2::{Digest, Sha256};

#[test]
fn independent_release_preimage_binds_amount_result_fence_and_recipient_accounts() {
    let release = ReleaseEffects {
        amount: 25,
        result: [0x61; 32],
        fence: [0x63; 32],
    };
    let mut expected = [0; 72];
    expected[..8].copy_from_slice(&25u64.to_le_bytes());
    expected[8..40].fill(0x61);
    expected[40..].fill(0x63);
    assert_eq!(release.encode(), expected);
    assert_eq!(ReleaseEffects::decode(&expected).unwrap(), release);
    let accounts = [[0x11; 32], [0x22; 32], [0x33; 32]];
    let mut preimage = b"KERBSFX1\x0b".to_vec();
    preimage.extend_from_slice(&expected);
    for key in &accounts {
        preimage.extend_from_slice(key);
    }
    let expected_digest: [u8; 32] = Sha256::digest(&preimage).into();
    assert_eq!(
        effect_digest(Transition::ReleaseSpl, &expected, &accounts),
        expected_digest
    );
    for index in [0, 8, 40] {
        let mut changed = expected;
        changed[index] ^= 1;
        assert_ne!(
            effect_digest(Transition::ReleaseSpl, &changed, &accounts),
            expected_digest
        );
    }
    let substituted = [[0x11; 32], [0x22; 32], [0x44; 32]];
    assert_ne!(
        effect_digest(Transition::ReleaseSpl, &expected, &substituted),
        expected_digest
    );
    assert!(ReleaseEffects::decode(&expected[..71]).is_err());
    let mut trailing = expected.to_vec();
    trailing.push(0);
    assert!(ReleaseEffects::decode(&trailing).is_err());
    let zero = ReleaseEffects {
        amount: 0,
        ..release
    }
    .encode();
    assert!(ReleaseEffects::decode(&zero).is_err());
}

#[test]
fn first_leg_and_envelope_encode_exact_values_not_opaque_client_digest() {
    let prepare = PrepareFillEffects {
        amount: 25,
        journal: [0x62; 32],
        fence: [0x63; 32],
    };
    let mut expected = [0; 72];
    expected[..8].copy_from_slice(&25u64.to_le_bytes());
    expected[8..40].fill(0x62);
    expected[40..].fill(0x63);
    assert_eq!(prepare.encode(), expected);
    assert_eq!(PrepareFillEffects::decode(&expected).unwrap(), prepare);
    let envelope = Envelope {
        intent: [7; 32],
        generation: 9,
        prior: 4,
        predecessor: [8; 32],
    };
    let mut bytes = [0; 64];
    bytes[..32].fill(7);
    bytes[32..].fill(8);
    assert_eq!(envelope.compact().encode(), bytes);
    let compact = ziquid_solana_interface::CompactEnvelope::decode(&bytes).unwrap();
    assert_eq!(compact.bind(9, 4).unwrap(), envelope);
    assert_ne!(compact.bind(10, 4).unwrap(), envelope);
    assert_ne!(compact.bind(9, 5).unwrap(), envelope);
    assert!(ziquid_solana_interface::CompactEnvelope::decode(&bytes[..63]).is_err());
}
