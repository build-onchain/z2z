use ziquid_protocol::market::*;
use sha2::{Digest, Sha256};

fn domain() -> Domain {
    Domain {
        schema_version: 1,
        deployment: [1; 32],
        solana_genesis: [2; 32],
        solana_program: [3; 32],
        mint: [4; 32],
        token_program: LEGACY_TOKEN_PROGRAM,
        source_network: 2,
        source_pool: 4,
        source_branch: 0x37a5165b,
        source_tx_version: 6,
        source_genesis: [5; 32],
        receiver_policy: [6; 32],
        pair: [7; 32],
        epoch: 0x0102030405060708,
        rules_hash: [8; 32],
        roster_version: 3,
        signature_scheme: 1,
    }
}
fn operation() -> Operation {
    Operation {
        domain: domain(),
        entity: [9; 32],
        portion: [10; 32],
        intent: [11; 32],
        generation: 1,
        prior_version: 0,
        transition: Transition::PrepareNative,
        effects: [12; 32],
    }
}
fn independent_domain() -> Vec<u8> {
    let mut bytes = b"KERBDM01".to_vec();
    bytes.extend([1, 0]);
    for byte in [1, 2, 3, 4] {
        bytes.extend([byte; 32]);
    }
    bytes.extend([
        6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133,
        237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
    ]);
    bytes.extend([2, 4, 0x5b, 0x16, 0xa5, 0x37, 6, 0, 0, 0]);
    for byte in [5, 6, 7] {
        bytes.extend([byte; 32]);
    }
    bytes.extend([8, 7, 6, 5, 4, 3, 2, 1]);
    bytes.extend([8; 32]);
    bytes.extend([3, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes
}
fn independent_operation() -> Vec<u8> {
    let mut bytes = b"KERBOP01".to_vec();
    bytes.extend(independent_domain());
    for byte in [9, 10, 11] {
        bytes.extend([byte; 32]);
    }
    bytes.extend([1, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend([0; 8]);
    bytes.push(16);
    bytes.extend([12; 32]);
    bytes
}
fn hash(bytes: &[u8]) -> Id {
    Sha256::digest(bytes).into()
}

#[test]
fn canonical_domain_matches_independent_vector_and_rejects_foreign_profiles() {
    let expected = independent_domain();
    let mut buffer = [0xff; 325];
    assert_eq!(domain().encode_into(&mut buffer), Ok(325));
    assert_eq!(buffer.as_slice(), expected);
    assert_eq!(Domain::decode(&expected), Ok(domain()));
    assert_eq!(
        Domain::decode(&expected[..324]),
        Err(ProtocolError::InvalidLength)
    );
    let mut trailing = expected.clone();
    trailing.push(0);
    assert_eq!(Domain::decode(&trailing), Err(ProtocolError::InvalidLength));
    for (offset, byte, error) in [
        (8, 2, ProtocolError::UnsupportedVersion),
        (170, 1, ProtocolError::UnsupportedSourceNetwork),
        (171, 3, ProtocolError::UnsupportedSourcePool),
        (172, 0, ProtocolError::UnsupportedSourceBranch),
        (176, 5, ProtocolError::UnsupportedTransactionVersion),
        (324, 2, ProtocolError::UnsupportedSignatureScheme),
        (138, 0, ProtocolError::TokenProgramMismatch),
    ] {
        let mut wrong = expected.clone();
        wrong[offset] = byte;
        assert_eq!(Domain::decode(&wrong), Err(error));
    }
    assert_eq!(
        domain().encode_into(&mut [0; 324]),
        Err(ProtocolError::InvalidLength)
    );
}

#[test]
fn stable_identity_excludes_effects_but_authorization_binds_complete_record_and_role() {
    let op = operation();
    let raw = independent_operation();
    let mut buffer = [0; 478];
    assert_eq!(op.encode_into(&mut buffer), Ok(478));
    assert_eq!(buffer.as_slice(), raw);
    let mut id_preimage = b"KERBID01".to_vec();
    id_preimage.extend(&raw[8..446]);
    assert_eq!(op.id(), Ok(hash(&id_preimage)));
    assert_eq!(op.digest(), Ok(hash(&raw)));
    assert_eq!(Operation::decode(&raw), Ok(op));
    let mut signing = b"KERB_ED25519_APPLICATION_V1\0\0\0\0\0".to_vec();
    signing.extend(hash(&raw));
    assert_eq!(
        op.signing_bytes(SignatureRole::Application)
            .unwrap()
            .as_slice(),
        signing
    );
    assert_ne!(
        op.signing_bytes(SignatureRole::Application),
        op.signing_bytes(SignatureRole::NativeIntent)
    );
    let mut mutations = [op; 8];
    mutations[0].entity[0] ^= 1;
    mutations[1].portion[0] ^= 1;
    mutations[2].intent[0] ^= 1;
    mutations[3].generation = 2;
    mutations[4].prior_version = 1;
    mutations[5].transition = Transition::ReturnUnused;
    mutations[6].domain.pair[0] ^= 1;
    mutations[7].domain.receiver_policy[0] ^= 1;
    for changed in mutations {
        assert_ne!(changed.id(), op.id());
        assert_ne!(
            changed.signing_bytes(SignatureRole::Application),
            op.signing_bytes(SignatureRole::Application)
        );
    }
    let mut changed = op;
    changed.effects[0] ^= 1;
    assert_eq!(changed.id(), op.id());
    assert_ne!(changed.digest(), op.digest());
    let mut bad_tag = raw.clone();
    bad_tag[445] = 255;
    assert_eq!(
        Operation::decode(&bad_tag),
        Err(ProtocolError::InvalidTransition)
    );
    let mut trailing = raw;
    trailing.push(0);
    assert_eq!(
        Operation::decode(&trailing),
        Err(ProtocolError::InvalidLength)
    );
}

#[test]
fn entity_version_checks_exact_scope_prior_version_and_monotonic_generation() {
    let op = operation();
    let state = EntityVersion {
        domain: op.domain,
        entity: op.entity,
        portion: op.portion,
        generation: 1,
        version: 0,
    };
    assert_eq!(state.check_next(&op), Ok(1));
    let mut changed = op;
    changed.entity = [77; 32];
    assert_eq!(
        state.check_next(&changed),
        Err(ProtocolError::EvidenceMismatch)
    );
    changed = op;
    changed.prior_version = 1;
    assert_eq!(
        state.check_next(&changed),
        Err(ProtocolError::InvalidGeneration)
    );
    changed = op;
    changed.generation = 0;
    assert_eq!(
        state.check_next(&changed),
        Err(ProtocolError::InvalidGeneration)
    );
    let full = EntityVersion {
        version: u64::MAX,
        ..state
    };
    changed = op;
    changed.prior_version = u64::MAX;
    assert_eq!(full.check_next(&changed), Err(ProtocolError::Overflow));
}

#[test]
fn checked_notional_rejects_zero_units_and_both_product_and_transfer_overflow() {
    let units = Units {
        base_atoms_per_lot: 5,
        quote_atoms_per_lot_tick: 7,
    };
    assert_eq!(notional(2, 3, units), Ok(42));
    assert_eq!(base_atoms(2, units), Ok(10));
    assert_eq!(notional(0, 3, units), Ok(0));
    assert_eq!(
        notional(
            1,
            1,
            Units {
                base_atoms_per_lot: 0,
                ..units
            }
        ),
        Err(ProtocolError::ZeroUnits)
    );
    assert_eq!(
        notional(
            1,
            1,
            Units {
                quote_atoms_per_lot_tick: 0,
                ..units
            }
        ),
        Err(ProtocolError::ZeroUnits)
    );
    assert_eq!(
        notional(
            u64::MAX,
            1,
            Units {
                base_atoms_per_lot: 1,
                quote_atoms_per_lot_tick: 1
            }
        ),
        Ok(u64::MAX)
    );
    assert_eq!(notional(u64::MAX, 2, units), Err(ProtocolError::Overflow));
    assert_eq!(
        notional(
            u64::MAX,
            u64::MAX,
            Units {
                base_atoms_per_lot: 1,
                quote_atoms_per_lot_tick: u64::MAX
            }
        ),
        Err(ProtocolError::Overflow)
    );
    assert_eq!(base_atoms(u64::MAX, units), Err(ProtocolError::Overflow));
}

#[test]
fn allocation_requires_exact_34_equals_25_plus_9_without_overlap_or_duplicate_portions() {
    let portions = [
        AllocationPortion {
            portion: [1; 32],
            offset: 0,
            amount: 25,
            kind: AllocationKind::SellerLiability,
        },
        AllocationPortion {
            portion: [2; 32],
            offset: 25,
            amount: 9,
            kind: AllocationKind::BuyerUnused,
        },
    ];
    assert_eq!(
        AllocationPartition {
            portions: &portions
        }
        .validate(34),
        Ok(())
    );
    let mut bad = portions;
    bad[1].offset = 24;
    assert_eq!(
        AllocationPartition { portions: &bad }.validate(34),
        Err(ProtocolError::OverlappingPortion)
    );
    bad = portions;
    bad[1].portion = [1; 32];
    assert_eq!(
        AllocationPartition { portions: &bad }.validate(34),
        Err(ProtocolError::DuplicatePortion)
    );
    bad = portions;
    bad[1].amount = 10;
    assert_eq!(
        AllocationPartition { portions: &bad }.validate(34),
        Err(ProtocolError::PartitionMismatch)
    );
    bad = portions;
    bad[1].amount = 8;
    assert_eq!(
        AllocationPartition { portions: &bad }.validate(34),
        Err(ProtocolError::PartitionMismatch)
    );
    bad = portions;
    bad[1].offset = u64::MAX;
    assert_eq!(
        AllocationPartition { portions: &bad }.validate(34),
        Err(ProtocolError::PartitionMismatch)
    );
}

fn activation() -> AllocationActivation {
    AllocationActivation {
        domain: domain(),
        allocation: [20; 32],
        expected_chunks: 2,
        authenticated_chunks: 2,
        finalized_allocation: [20; 32],
        activated_allocation: [20; 32],
        acknowledgement_head: [21; 32],
    }
}
fn native(kind: NativeIntentKind, amount: u64) -> NativeIntent {
    let mut intent = NativeIntent {
        operation: operation(),
        kind,
        recipient: [22; 43],
        amount,
        inventory_scope: domain().pair,
    };
    intent.operation.effects = intent.effects_digest().unwrap();
    intent
}
fn liability(disposition: Disposition, amount: u64) -> NativeLiability {
    NativeLiability {
        domain: domain(),
        entity: operation().entity,
        portion: operation().portion,
        disposition,
        recipient: [22; 43],
        amount,
        inventory_scope: domain().pair,
        live_intent: None,
    }
}
fn release_evidence() -> SplReleaseEvidence {
    let release_operation = Operation {
        transition: Transition::ReleaseSpl,
        intent: [23; 32],
        ..operation()
    };
    SplReleaseEvidence {
        domain: domain(),
        entity: operation().entity,
        portion: operation().portion,
        recipient: [24; 32],
        base_atoms: 5,
        expected_recipient: [24; 32],
        expected_base_atoms: 5,
        release: ChainObservation {
            environment: ObservationEnvironment::LocalFixture,
            operation: release_operation.id().unwrap(),
            transaction: [25; 32],
            slot: 5,
            commitment: ChainCommitment::Finalized,
            effects: release_operation.effects,
        },
        release_operation,
        environment: ObservationEnvironment::LocalFixture,
        activation: activation(),
    }
}

#[test]
fn unused_refund_needs_complete_activation_but_no_spl_and_cannot_share_live_intent() {
    let intent = native(NativeIntentKind::BuyerRefund, 9);
    let activation = activation();
    let refund = RefundEvidence::FinalUnused(&activation);
    let evidence = NativeIntentEvidence::BuyerRefund {
        liability: &liability(Disposition::BuyerUnused, 9),
        refund: &refund,
    };
    assert_eq!(intent.validate(&domain(), &evidence), Ok(()));
    let mut partial = activation;
    partial.authenticated_chunks = 1;
    assert_eq!(
        intent.validate(
            &domain(),
            &NativeIntentEvidence::BuyerRefund {
                liability: &liability(Disposition::BuyerUnused, 9),
                refund: &RefundEvidence::FinalUnused(&partial)
            }
        ),
        Err(ProtocolError::EvidenceMismatch)
    );
    let mut live = liability(Disposition::BuyerUnused, 9);
    live.live_intent = Some([99; 32]);
    assert_eq!(
        intent.validate(
            &domain(),
            &NativeIntentEvidence::BuyerRefund {
                liability: &live,
                refund: &refund
            }
        ),
        Err(ProtocolError::CompetingIntent)
    );
    assert_eq!(
        intent.validate(
            &domain(),
            &NativeIntentEvidence::BuyerRefund {
                liability: &liability(Disposition::Prepared, 9),
                refund: &refund
            }
        ),
        Err(ProtocolError::IntentNotPermitted)
    );
    let mut wrong = domain();
    wrong.pair = [77; 32];
    assert_eq!(
        intent.validate(&wrong, &evidence),
        Err(ProtocolError::DomainMismatch)
    );
}

#[test]
fn seller_payout_requires_exact_final_spl_while_sponsor_inventory_is_isolated() {
    let payout = native(NativeIntentKind::SellerPayout, 25);
    let spl = release_evidence();
    let evidence = NativeIntentEvidence::SellerPayout {
        liability: &liability(Disposition::SellerLiability, 25),
        spl: &spl,
    };
    assert_eq!(payout.validate(&domain(), &evidence), Ok(()));
    let mut wrong = spl;
    wrong.recipient = [99; 32];
    assert_eq!(
        payout.validate(
            &domain(),
            &NativeIntentEvidence::SellerPayout {
                liability: &liability(Disposition::SellerLiability, 25),
                spl: &wrong
            }
        ),
        Err(ProtocolError::EvidenceMismatch)
    );
    wrong = spl;
    wrong.release.commitment = ChainCommitment::Confirmed;
    assert_eq!(
        payout.validate(
            &domain(),
            &NativeIntentEvidence::SellerPayout {
                liability: &liability(Disposition::SellerLiability, 25),
                spl: &wrong
            }
        ),
        Err(ProtocolError::EvidenceMismatch)
    );
    assert_eq!(
        payout.validate(
            &domain(),
            &NativeIntentEvidence::BuyerRefund {
                liability: &liability(Disposition::BuyerUnused, 25),
                refund: &RefundEvidence::FinalUnused(&activation())
            }
        ),
        Err(ProtocolError::IntentNotPermitted)
    );
    let sponsor = native(NativeIntentKind::SponsorFee, 2);
    let sponsor_evidence = NativeIntentEvidence::SponsorFee {
        liability: &liability(Disposition::SponsorAvailable, 2),
        operator: [31; 32],
        authorized_operator: [31; 32],
        sponsor_scope: domain().pair,
    };
    assert_eq!(
        sponsor.validate(&domain(), &sponsor_evidence),
        Err(ProtocolError::EvidenceMismatch)
    );
}

#[test]
fn native_effects_commitment_binds_exact_kind_recipient_amount_and_scope() {
    let intent = native(NativeIntentKind::BuyerRefund, 9);
    let op_raw = independent_operation();
    let mut id_preimage = b"KERBID01".to_vec();
    id_preimage.extend(&op_raw[8..446]);
    let mut preimage = b"KERBNE01".to_vec();
    preimage.extend(hash(&id_preimage));
    preimage.push(2);
    preimage.extend([22; 43]);
    preimage.extend([9, 0, 0, 0, 0, 0, 0, 0]);
    preimage.extend([7; 32]);
    assert_eq!(intent.effects_digest(), Ok(hash(&preimage)));
    let activation = activation();
    let refund = RefundEvidence::FinalUnused(&activation);
    let evidence = NativeIntentEvidence::BuyerRefund {
        liability: &liability(Disposition::BuyerUnused, 9),
        refund: &refund,
    };
    let mut altered = intent;
    altered.operation.effects = [99; 32];
    assert_eq!(
        altered.validate(&domain(), &evidence),
        Err(ProtocolError::EvidenceMismatch)
    );
    let message = intent.signing_bytes().unwrap();
    for changed in [
        NativeIntent {
            kind: NativeIntentKind::SellerPayout,
            ..intent
        },
        NativeIntent {
            recipient: [99; 43],
            ..intent
        },
        NativeIntent {
            amount: 10,
            ..intent
        },
        NativeIntent {
            inventory_scope: [99; 32],
            ..intent
        },
    ] {
        assert_ne!(changed.effects_digest(), intent.effects_digest());
        assert_eq!(
            changed.signing_bytes(),
            Err(ProtocolError::EvidenceMismatch)
        );
    }
    assert_ne!(
        message,
        intent
            .operation
            .signing_bytes(SignatureRole::NativeIntent)
            .unwrap()
    );
}

#[test]
fn stable_identity_constructs_native_effects_without_an_arbitrary_nonzero_placeholder() {
    let complete = native(NativeIntentKind::BuyerRefund, 9);
    let zero = NativeIntent {
        operation: Operation {
            effects: [0; 32],
            ..complete.operation
        },
        ..complete
    };
    assert_eq!(zero.operation.id(), complete.operation.id());
    assert_eq!(zero.effects_digest(), complete.effects_digest());
    assert_eq!(
        zero.operation.digest(),
        Err(ProtocolError::EvidenceMismatch)
    );
    assert_eq!(zero.signing_bytes(), Err(ProtocolError::EvidenceMismatch));
}

#[test]
fn safe_cancel_refund_rejects_unrelated_finalized_release_and_missing_custody_head() {
    let intent = native(NativeIntentKind::BuyerRefund, 9);
    let cancel = Operation {
        transition: Transition::CancelFill,
        intent: [33; 32],
        ..operation()
    };
    let observation = ChainObservation {
        environment: ObservationEnvironment::LocalFixture,
        operation: cancel.id().unwrap(),
        transaction: [34; 32],
        slot: 6,
        commitment: ChainCommitment::Finalized,
        effects: cancel.effects,
    };
    let validate = |op: &Operation, fact: &ChainObservation, head| {
        intent.validate(
            &domain(),
            &NativeIntentEvidence::BuyerRefund {
                liability: &liability(Disposition::SafelyCancelled, 9),
                refund: &RefundEvidence::SafelyCancelled {
                    domain: &domain(),
                    portion: operation().portion,
                    cancellation: fact,
                    cancellation_operation: op,
                    environment: ObservationEnvironment::LocalFixture,
                    custody_head: head,
                },
            },
        )
    };
    assert_eq!(validate(&cancel, &observation, [35; 32]), Ok(()));
    let release = Operation {
        transition: Transition::ReleaseSpl,
        ..cancel
    };
    let release_fact = ChainObservation {
        operation: release.id().unwrap(),
        ..observation
    };
    assert_eq!(
        validate(&release, &release_fact, [35; 32]),
        Err(ProtocolError::EvidenceMismatch)
    );
    assert_eq!(
        validate(&cancel, &release_fact, [35; 32]),
        Err(ProtocolError::EvidenceMismatch)
    );
    assert_eq!(
        validate(&cancel, &observation, [0; 32]),
        Err(ProtocolError::EvidenceMismatch)
    );
}

#[test]
fn observation_policy_does_not_promote_local_fixture_or_nonfinal_chain_facts() {
    let op = operation();
    let fact = ChainObservation {
        environment: ObservationEnvironment::LocalFixture,
        operation: op.id().unwrap(),
        transaction: [1; 32],
        slot: 5,
        commitment: ChainCommitment::Finalized,
        effects: op.effects,
    };
    assert_eq!(
        fact.matches(
            &op,
            ObservationEnvironment::LocalFixture,
            ChainCommitment::Finalized
        ),
        Ok(())
    );
    assert_eq!(
        fact.matches(
            &op,
            ObservationEnvironment::Network,
            ChainCommitment::Finalized
        ),
        Err(ProtocolError::EvidenceMismatch)
    );
    let pending = ChainObservation {
        commitment: ChainCommitment::Submitted,
        ..fact
    };
    assert_eq!(
        pending.matches(
            &op,
            ObservationEnvironment::LocalFixture,
            ChainCommitment::Finalized
        ),
        Err(ProtocolError::EvidenceMismatch)
    );
}

fn hex<const N: usize>(encoded: &str) -> [u8; N] {
    assert_eq!(encoded.len(), 2 * N);
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[2 * index..2 * index + 2], 16).unwrap();
    }
    bytes
}

#[test]
fn portable_authority_checks_reject_weak_noncanonical_mixed_torsion_and_scalar_reduction() {
    // RFC8032 test1 public key and signature; no protocol signer made this vector.
    let key = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    assert_eq!(validate_authorization_key(&key), Ok(()));
    assert_eq!(validate_signature_encoding(&signature), Ok(()));
    // C2SP CCTV ed25519 vectors reused as bytes, not as receipt authority.
    for encoded in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
    ] {
        let rejected = hex(encoded);
        assert_eq!(
            validate_authorization_key(&rejected),
            Err(ProtocolError::InvalidAuthorizationKey)
        );
        let mut altered = signature;
        altered[..32].copy_from_slice(&rejected);
        assert_eq!(
            validate_signature_encoding(&altered),
            Err(ProtocolError::InvalidSignature)
        );
    }
    let mut altered = signature;
    altered[32..].copy_from_slice(&hex::<32>(
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    ));
    assert_eq!(
        validate_signature_encoding(&altered),
        Err(ProtocolError::InvalidSignature)
    );
    altered[32] -= 1;
    assert_eq!(validate_signature_encoding(&altered), Ok(()));
}

#[cfg(feature = "market-host")]
mod host {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn independent_canonical_decision_signatures_require_all_three_exact_distinct_keys() {
        let op_raw = independent_operation();
        let mut head_raw = b"KERBHD01".to_vec();
        head_raw.extend([30; 32]);
        head_raw.extend(hash(&op_raw));
        let next_head = hash(&head_raw);
        let mut decision_raw = b"KERBDC01".to_vec();
        decision_raw.extend(op_raw);
        decision_raw.extend([30; 32]);
        decision_raw.extend(next_head);
        let mut signing = b"KERB_ED25519_DECISION_V1\0\0\0\0\0\0\0\0".to_vec();
        signing.extend(hash(&decision_raw));
        let decision = Decision::new(operation(), [30; 32]).unwrap();
        assert_eq!(decision.next_head, next_head);
        let mut buffer = [0; 550];
        decision.encode_into(&mut buffer).unwrap();
        assert_eq!(buffer.as_slice(), decision_raw);
        assert_eq!(decision.signing_bytes().unwrap().as_slice(), signing);
        let keys = [
            SigningKey::from_bytes(&[41; 32]),
            SigningKey::from_bytes(&[42; 32]),
            SigningKey::from_bytes(&[43; 32]),
        ];
        let roster = keys.each_ref().map(|key| key.verifying_key().to_bytes());
        let acks = keys.each_ref().map(|key| Acknowledgement {
            signer: key.verifying_key().to_bytes(),
            signature: key.sign(&signing).to_bytes(),
            decision,
        });
        assert_eq!(verify_unanimous(&decision, &acks, &roster), Ok(()));
        assert_eq!(
            verify_unanimous(&decision, &acks[..2], &roster),
            Err(ProtocolError::MissingUnanimity)
        );
        let mut duplicate = acks;
        duplicate[2] = duplicate[1];
        assert_eq!(
            verify_unanimous(&decision, &duplicate, &roster),
            Err(ProtocolError::DuplicateSigner)
        );
        let mut changed = acks;
        changed[0].decision.operation.effects = [99; 32];
        assert_eq!(
            verify_unanimous(&decision, &changed, &roster),
            Err(ProtocolError::WrongAcknowledgement)
        );
        let other = Decision::new(operation(), [31; 32]).unwrap();
        assert_eq!(
            verify_unanimous(&other, &acks, &roster),
            Err(ProtocolError::WrongAcknowledgement)
        );
        changed = acks;
        changed[0].signature[63] |= 0xf0;
        assert_eq!(
            verify_unanimous(&decision, &changed, &roster),
            Err(ProtocolError::InvalidSignature)
        );
        let mut forged = decision;
        forged.next_head = [0; 32];
        assert_eq!(forged.validate(), Err(ProtocolError::InvalidDecisionHead));
    }

    #[test]
    fn unanimous_consumer_rejects_weak_enrolled_key_and_wrong_role_signature() {
        let decision = Decision::new(operation(), [30; 32]).unwrap();
        let keys = [
            SigningKey::from_bytes(&[41; 32]),
            SigningKey::from_bytes(&[42; 32]),
            SigningKey::from_bytes(&[43; 32]),
        ];
        let mut roster = keys.each_ref().map(|key| key.verifying_key().to_bytes());
        let mut acks = keys.each_ref().map(|key| Acknowledgement {
            signer: key.verifying_key().to_bytes(),
            signature: key.sign(&decision.signing_bytes().unwrap()).to_bytes(),
            decision,
        });
        roster[0] = hex("0100000000000000000000000000000000000000000000000000000000000000");
        acks[0].signer = roster[0];
        assert_eq!(
            verify_unanimous(&decision, &acks, &roster),
            Err(ProtocolError::InvalidAuthorizationKey)
        );
        roster = keys.each_ref().map(|key| key.verifying_key().to_bytes());
        acks[0].signer = roster[0];
        acks[0].signature = keys[0]
            .sign(
                &operation()
                    .signing_bytes(SignatureRole::Application)
                    .unwrap(),
            )
            .to_bytes();
        assert_eq!(
            verify_unanimous(&decision, &acks, &roster),
            Err(ProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn claimant_signature_binds_receiver_occurrence_policy_and_inventory_but_not_signature_itself()
    {
        let key = SigningKey::from_bytes(&[51; 32]);
        let mut claim = FundingClaim {
            domain: domain(),
            occurrence: SourceOccurrence {
                network: 2,
                pool: 4,
                txid: [52; 32],
                action_index: 3,
            },
            claimant: key.verifying_key().to_bytes(),
            receiver: [53; 43],
            value: 34,
            block_policy: [54; 32],
            inventory_note: [55; 32],
            evidence_digest: [56; 32],
            credit_intent: [57; 32],
            authorization: [0; 64],
        };
        let message = claim.signing_bytes().unwrap();
        claim.authorization = key.sign(&message).to_bytes();
        assert_eq!(verify_funding_claim(&claim), Ok(()));
        let mut bad = claim;
        bad.receiver[0] ^= 1;
        assert_eq!(
            verify_funding_claim(&bad),
            Err(ProtocolError::InvalidSignature)
        );
        bad = claim;
        bad.occurrence.action_index += 1;
        assert_eq!(
            verify_funding_claim(&bad),
            Err(ProtocolError::InvalidSignature)
        );
        bad = claim;
        bad.block_policy[0] ^= 1;
        assert_eq!(
            verify_funding_claim(&bad),
            Err(ProtocolError::InvalidSignature)
        );
        bad = claim;
        bad.inventory_note[0] ^= 1;
        assert_eq!(
            verify_funding_claim(&bad),
            Err(ProtocolError::InvalidSignature)
        );
        bad = claim;
        bad.occurrence.network = 1;
        assert_eq!(
            verify_funding_claim(&bad),
            Err(ProtocolError::DomainMismatch)
        );
        bad = claim;
        bad.value = 0;
        assert_eq!(verify_funding_claim(&bad), Err(ProtocolError::ZeroAmount));
    }
}
