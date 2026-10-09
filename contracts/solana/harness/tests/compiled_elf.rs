use ziquid_solana_harness::wire::*;
use ziquid_solana_harness::{domain_bytes, Fixture, PROGRAM};
use ziquid_solana_interface::Envelope;
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::error::InstructionError;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;

#[test]
fn initializes_named_pair_from_real_spl_and_cannot_reset_it() {
    let mut fixture = Fixture::new();
    let instruction = fixture.initialize_instruction();
    fixture
        .send(std::slice::from_ref(&instruction), false)
        .expect("compiled InitializePair must succeed");
    let pair = fixture
        .svm
        .get_account(&fixture.pair)
        .expect("created Pair PDA");
    assert_eq!(pair.owner, PROGRAM);
    assert_eq!(&pair.data[9..334], domain_bytes(fixture.mint, 0));
    assert_eq!(&pair.data[334..366], fixture.admin.pubkey().as_ref());
    assert_eq!(fixture.amount(fixture.seller_token), 100);
    assert_eq!(fixture.amount(fixture.buyer_token), 0);
    assert!(
        fixture.send(&[instruction], false).is_err(),
        "permanent pair cannot reset head or consumption"
    );
    assert_eq!(fixture.svm.get_account(&fixture.pair).unwrap(), pair);
}

#[test]
fn rejects_missing_initializer_signature_wrong_pda_and_token_substitution() {
    let mut fixture = Fixture::new();
    let mut wrong_pda = fixture.initialize_instruction();
    wrong_pda.accounts[1].pubkey = fixture.buyer.pubkey();
    assert!(fixture.send(&[wrong_pda], false).is_err());
    assert!(fixture.svm.get_account(&fixture.pair).is_none());
    let mut wrong_token = fixture.initialize_instruction();
    wrong_token.accounts[3].pubkey = PROGRAM;
    assert!(fixture.send(&[wrong_token], false).is_err());
    assert!(fixture.svm.get_account(&fixture.pair).is_none());
    let mut wrong_signer = fixture.initialize_instruction();
    wrong_signer.accounts[0].pubkey = fixture.buyer.pubkey();
    wrong_signer.accounts[0].is_signer = false;
    assert!(fixture.send(&[wrong_signer], false).is_err());
    assert!(fixture.svm.get_account(&fixture.pair).is_none());
}

#[test]
fn prefunded_pda_is_initialized_without_donation_blocking_namespace() {
    let mut fixture = Fixture::new();
    fixture
        .svm
        .set_account(
            fixture.pair,
            Account {
                lamports: 1_000_000,
                ..Account::default()
            },
        )
        .unwrap();
    fixture.initialized();
    fixture.open();
    fixture.lock();
    assert_eq!(fixture.amount(fixture.seller_token), 66);
    assert_eq!(fixture.amount(fixture.escrow_key()), 34);
}

// Omitting native verification, accepting noncanonical offsets, wrong context or signer duplicates breaks this.
#[test]
fn authorizers_require_real_distinct_canonical_precompiles_before_target() {
    let mut fixture = Fixture::new();
    fixture.initialized();
    let initial_pair = fixture.svm.get_account(&fixture.pair).unwrap();
    for mutation in 0..8 {
        let mut instructions = fixture.open_instruction();
        match mutation {
            0 => {
                instructions.remove(0);
            }
            1 => {
                instructions[1] = instructions[0].clone();
            }
            2 => {
                let target = instructions.pop().unwrap();
                instructions.insert(0, target);
            }
            3 => {
                instructions[0].data[1] = 1;
            }
            4 => {
                instructions[0].data.push(0);
            }
            5 => {
                let mut message = instructions[0].data[112..].to_vec();
                message[0] ^= 1;
                for (index, key) in fixture.authorizers.iter().enumerate() {
                    instructions[index] = precompile(key, &message);
                }
            }
            6 => {
                let mut target = instructions[3].clone();
                target.data[1] ^= 1;
                instructions[3] = target;
            }
            7 => {
                instructions[0].data[48] ^= 1;
            }
            _ => unreachable!(),
        }
        assert!(
            fixture.send(&instructions, false).is_err(),
            "authority mutation {mutation} must reject"
        );
        assert_eq!(
            fixture.svm.get_account(&fixture.pair).unwrap(),
            initial_pair
        );
        assert!(fixture.svm.get_account(&fixture.epoch_key()).is_none());
    }
    let instructions = fixture.open_instruction();
    fixture
        .send(&instructions, false)
        .expect("exact canonical 3-key authorization succeeds");
    assert_eq!(fixture.pair_generation(), 1);
    let epoch = fixture.svm.get_account(&fixture.epoch_key()).unwrap();
    assert!(
        fixture.send(&instructions, false).is_err(),
        "fresh blockhash replay cannot reopen epoch or reset head"
    );
    assert_eq!(
        fixture.svm.get_account(&fixture.epoch_key()).unwrap(),
        epoch
    );
}

#[test]
fn prepare_commit_partial_allocation_and_timeout_keep_exact_escrow() {
    let mut fixture = Fixture::new();
    fixture.initialized();
    fixture.open();
    fixture.lock();
    fixture.prepare();
    fixture.commit();
    let mut clock: Clock = fixture.svm.get_sysvar();
    clock.unix_timestamp += 1_000_000;
    clock.slot += 1_000_000;
    fixture.svm.set_sysvar(&clock);
    assert!(
        fixture.send(&fixture.return_instruction(0), false).is_err(),
        "accepted hold cannot time out"
    );
    assert!(
        fixture.send(&fixture.abort_instruction(), false).is_err(),
        "committed epoch cannot abort"
    );
    fixture.record(true);
    assert!(
        fixture
            .send(&fixture.activate_instruction(), false)
            .is_err(),
        "partial authenticated allocation cannot activate"
    );
    assert!(
        fixture
            .send(&fixture.prepare_fill_instruction(), false)
            .is_err(),
        "first leg cannot prepare before complete activation"
    );
    assert!(
        fixture.send(&fixture.release_instruction(), false).is_err(),
        "partial allocation cannot release"
    );
    assert_eq!(fixture.amount(fixture.escrow_key()), 34);
    assert_eq!(fixture.amount(fixture.buyer_token), 0);
    fixture.record(false);
    fixture.activate();
    fixture
        .send(&fixture.return_instruction(1), false)
        .expect("disjoint final-unused9 returns");
    assert_eq!(fixture.amount(fixture.escrow_key()), 25);
    assert_eq!(fixture.amount(fixture.seller_token), 75);
    fixture.prepare_fill();
    fixture
        .send(&fixture.release_instruction(), false)
        .expect("activated first-leg25 actually transfers");
    assert_eq!(fixture.amount(fixture.escrow_key()), 0);
    assert_eq!(fixture.amount(fixture.buyer_token), 25);
    assert!(fixture.send(&fixture.return_instruction(1), false).is_err());
    assert!(fixture.send(&fixture.release_instruction(), false).is_err());
}

// A swallowed CPI error, native no-op transfer or writes committed around CPI failure breaks full-byte equality.
#[test]
fn frozen_recipient_cpi_failure_rolls_back_every_kerb_and_token_byte() {
    let mut fixture = Fixture::new();
    fixture.active_fill();
    fixture.frozen(true);
    let keys = [
        fixture.pair,
        fixture.epoch_key(),
        fixture.hold_key(),
        fixture.filled_key(),
        fixture.unused_key(),
        fixture.escrow_key(),
        fixture.seller_token,
        fixture.buyer_token,
        fixture.mint,
    ];
    let before: Vec<_> = keys
        .iter()
        .map(|key| fixture.svm.get_account(key).unwrap())
        .collect();
    let release = fixture.release_instruction();
    let failure = fixture
        .send(&release, false)
        .expect_err("real legacy SPL frozen transfer must fail");
    assert!(
        failure
            .logs
            .iter()
            .any(|line| line.contains("frozen") || line.contains("Frozen")),
        "must reach actual frozen SPL CPI, got {:?}",
        failure.logs
    );
    for (key, account) in keys.iter().zip(before.iter()) {
        assert_eq!(&fixture.svm.get_account(key).unwrap(), account);
    }
    fixture.frozen(false);
    fixture
        .send(&release, false)
        .expect("same business decision remains valid after actual CPI rollback");
    assert_eq!(fixture.amount(fixture.buyer_token), 25);
    assert_eq!(fixture.amount(fixture.escrow_key()), 9);
}

#[test]
fn cancellation_and_release_consume_same_permanent_disposition() {
    let mut cancelled = Fixture::new();
    cancelled.active_fill();
    let delayed_release = cancelled.release_instruction();
    cancelled
        .send(&cancelled.cancel_instruction(), false)
        .expect("approved cancellation before release");
    assert!(cancelled.send(&delayed_release, false).is_err());
    assert!(cancelled
        .send(&cancelled.release_instruction(), false)
        .is_err());
    cancelled
        .send(&cancelled.return_instruction(2), false)
        .expect("unanimous exact cancellation+custody journal testimony");
    assert_eq!(cancelled.amount(cancelled.buyer_token), 0);
    assert_eq!(cancelled.amount(cancelled.seller_token), 91);
    assert_eq!(cancelled.amount(cancelled.escrow_key()), 9);
    assert!(cancelled
        .send(&cancelled.return_instruction(2), false)
        .is_err());
    let mut released = Fixture::new();
    released.active_fill();
    let delayed_cancel = released.cancel_instruction();
    released
        .send(&released.release_instruction(), false)
        .expect("release25");
    assert!(released.send(&delayed_cancel, false).is_err());
    assert!(released
        .send(&released.cancel_instruction(), false)
        .is_err());
    assert!(released
        .send(&released.return_instruction(2), false)
        .is_err());
    assert_eq!(released.amount(released.buyer_token), 25);
}

#[test]
fn abort_and_frozen_commit_exclusion_allow_return_but_no_timeout_path() {
    let mut aborted = Fixture::new();
    aborted.initialized();
    aborted.open();
    aborted.lock();
    aborted.prepare();
    assert!(aborted.send(&aborted.return_instruction(0), false).is_err());
    aborted
        .send(&aborted.abort_instruction(), false)
        .expect("terminal abort of open epoch");
    aborted
        .send(&aborted.return_instruction(0), false)
        .expect("fenced abort returns full34");
    assert_eq!(aborted.amount(aborted.seller_token), 100);
    assert_eq!(aborted.amount(aborted.escrow_key()), 0);
    assert!(aborted.send(&aborted.return_instruction(0), false).is_err());
    assert!(aborted.send(&[aborted.lock_instruction()], true).is_err());
    let mut excluded = Fixture::new();
    excluded.initialized();
    excluded.open();
    excluded.lock();
    excluded.commit();
    assert!(
        excluded
            .send(&excluded.prepare_instruction(), false)
            .is_err(),
        "frozen membership cannot accept excluded seller later"
    );
    excluded
        .send(&excluded.return_instruction(0), false)
        .expect("never-prepared seller excluded by immutable commit");
    assert_eq!(excluded.amount(excluded.seller_token), 100);
}

#[test]
fn recipient_alias_owner_pda_sysvar_and_writable_substitution_never_moves_tokens() {
    let mut fixture = Fixture::new();
    fixture.active_fill();
    let keys = [
        fixture.pair,
        fixture.hold_key(),
        fixture.filled_key(),
        fixture.escrow_key(),
        fixture.buyer_token,
        fixture.seller_token,
    ];
    let before: Vec<_> = keys
        .iter()
        .map(|key| fixture.svm.get_account(key).unwrap())
        .collect();
    for mutation in 0..5 {
        let mut instructions = fixture.release_instruction();
        let target = instructions.last_mut().unwrap();
        match mutation {
            0 => target.accounts[6].pubkey = fixture.seller_token,
            1 => target.accounts[6].pubkey = fixture.escrow_key(),
            2 => target.accounts[3].pubkey = fixture.unused_key(),
            3 => target.accounts[8].pubkey = fixture.buyer.pubkey(),
            4 => target.accounts[6].is_writable = false,
            _ => unreachable!(),
        }
        assert!(fixture.send(&instructions, false).is_err());
        for (key, account) in keys.iter().zip(&before) {
            assert_eq!(&fixture.svm.get_account(key).unwrap(), account);
        }
    }
    let hold_before = fixture.svm.get_account(&fixture.hold_key()).unwrap();
    let mut tampered = hold_before.clone();
    tampered.owner = fixture.buyer.pubkey();
    fixture
        .svm
        .set_account(fixture.hold_key(), tampered)
        .unwrap();
    assert!(fixture.send(&fixture.release_instruction(), false).is_err());
    assert_eq!(fixture.amount(fixture.escrow_key()), 34);
    fixture
        .svm
        .set_account(fixture.hold_key(), hold_before)
        .unwrap();
    fixture
        .send(&fixture.release_instruction(), false)
        .expect("valid exact accounts still release");
}

#[test]
fn even_unanimous_release_cannot_change_immutable_amount_result_or_first_leg_fence() {
    let mut fixture = Fixture::new();
    fixture.active_fill();
    let keys = [
        fixture.pair,
        fixture.hold_key(),
        fixture.filled_key(),
        fixture.escrow_key(),
        fixture.buyer_token,
    ];
    let before: Vec<_> = keys
        .iter()
        .map(|key| fixture.svm.get_account(key).unwrap())
        .collect();
    for mutation in 0..3 {
        let target = fixture.release_instruction().pop().unwrap();
        let mut payload = target.data[65..].to_vec();
        match mutation {
            0 => payload[..8].copy_from_slice(&26u64.to_le_bytes()),
            1 => payload[8] ^= 1,
            2 => payload[40] ^= 1,
            _ => unreachable!(),
        }
        let instructions = fixture
            .decision(
                11,
                1,
                (fixture.filled_key(), Some(fixture.filled_key())),
                (fixture.version(fixture.filled_key(), 153), FIRST_LEG_INTENT),
                payload,
                target.accounts,
            )
            .0;
        assert!(
            fixture.send(&instructions, false).is_err(),
            "unanimous signature cannot alter immutable release effects"
        );
        for (key, account) in keys.iter().zip(&before) {
            assert_eq!(&fixture.svm.get_account(key).unwrap(), account);
        }
    }
    fixture
        .send(&fixture.release_instruction(), false)
        .expect("exact immutable amount25/root/fence release");
    assert_eq!(fixture.amount(fixture.buyer_token), 25);
}

fn public_hex<const N: usize>(text: &str) -> [u8; N] {
    let mut bytes = [0; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let value = std::str::from_utf8(pair).unwrap();
        bytes[index] = u8::from_str_radix(value, 16).unwrap();
    }
    bytes
}

#[test]
fn compiled_enrollment_rejects_identity_noncanonical_negative_zero_and_mixed_torsion() {
    let mut fixture = Fixture::new();
    // Public C2SP CCTV Ed25519 rejection vectors, also exercised independently by protocol.
    for encoded in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
    ] {
        let mut instruction = fixture.initialize_instruction();
        instruction.data[358..390].copy_from_slice(&public_hex::<32>(encoded));
        assert!(fixture.send(&[instruction], false).is_err());
        assert!(fixture.svm.get_account(&fixture.pair).is_none());
    }
    let mut duplicate = fixture.initialize_instruction();
    let first = duplicate.data[358..390].to_vec();
    duplicate.data[390..422].copy_from_slice(&first);
    assert!(fixture.send(&[duplicate], false).is_err());
    assert!(fixture.svm.get_account(&fixture.pair).is_none());
    fixture.initialized();
    fixture.open();
    assert_eq!(fixture.pair_generation(), 1);
}

#[test]
fn native_verification_rejects_noncanonical_signature_r_and_scalar_before_target() {
    let mut fixture = Fixture::new();
    fixture.initialized();
    let pair = fixture.svm.get_account(&fixture.pair).unwrap();
    for scalar in [false, true] {
        let mut instructions = fixture.open_instruction();
        if scalar {
            instructions[0].data[80..112].copy_from_slice(&public_hex::<32>(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            ));
        } else {
            instructions[0].data[48..80].copy_from_slice(&public_hex::<32>(
                "0100000000000000000000000000000000000000000000000000000000000080",
            ));
        }
        assert!(fixture.send(&instructions, false).is_err());
        assert_eq!(fixture.svm.get_account(&fixture.pair).unwrap(), pair);
        assert!(fixture.svm.get_account(&fixture.epoch_key()).is_none());
    }
    fixture.open();
}

#[test]
fn compact_transport_still_rejects_signed_wrong_prior_generation_or_predecessor() {
    let mut fixture = Fixture::new();
    fixture.active_fill();
    let pair = fixture.svm.get_account(&fixture.pair).unwrap();
    let portion_state = fixture.svm.get_account(&fixture.filled_key()).unwrap();
    for mutation in 0..3 {
        let target = fixture.release_instruction().pop().unwrap();
        let generation = fixture.pair_generation() + if mutation == 1 { 2 } else { 1 };
        let prior = fixture.version(fixture.filled_key(), 153) + u64::from(mutation == 0);
        let mut predecessor = fixture.pair_head();
        if mutation == 2 {
            predecessor[0] ^= 1;
        }
        let (message, _) = canonical_decision(
            &domain_bytes(fixture.mint, 1),
            (fixture.filled_key(), Some(fixture.filled_key())),
            Envelope {
                intent: FIRST_LEG_INTENT,
                generation,
                prior,
                predecessor,
            },
            11,
            &target.data[65..],
            &target.accounts,
        );
        let mut instructions: Vec<_> = fixture
            .authorizers
            .iter()
            .map(|key| precompile(key, &message))
            .collect();
        instructions.push(target);
        assert!(
            fixture.send(&instructions, false).is_err(),
            "omitted wire context remains in exact signed canonical record"
        );
        assert_eq!(fixture.svm.get_account(&fixture.pair).unwrap(), pair);
        assert_eq!(
            fixture.svm.get_account(&fixture.filled_key()).unwrap(),
            portion_state
        );
        assert_eq!(fixture.amount(fixture.buyer_token), 0);
    }
    fixture
        .send(&fixture.release_instruction(), false)
        .expect("current exact signed context releases25");
    assert_eq!(fixture.amount(fixture.buyer_token), 25);
}

#[test]
fn unanimous_signatures_cannot_redirect_immutable_recipient_or_substitute_token_cpi() {
    let mut fixture = Fixture::new();
    fixture.active_fill();
    let keys = [
        fixture.pair,
        fixture.hold_key(),
        fixture.filled_key(),
        fixture.escrow_key(),
        fixture.buyer_token,
        fixture.seller_token,
    ];
    let before: Vec<_> = keys
        .iter()
        .map(|key| fixture.svm.get_account(key).unwrap())
        .collect();
    for mutation in 0..4 {
        let mut target = fixture.release_instruction().pop().unwrap();
        match mutation {
            0 => target.accounts[6].pubkey = fixture.seller_token,
            1 => target.accounts[6].pubkey = fixture.escrow_key(),
            2 => target.accounts[5].pubkey = fixture.buyer_token,
            3 => target.accounts[7].pubkey = PROGRAM,
            _ => unreachable!(),
        }
        let instructions = fixture
            .decision(
                11,
                1,
                (fixture.filled_key(), Some(fixture.filled_key())),
                (fixture.version(fixture.filled_key(), 153), FIRST_LEG_INTENT),
                target.data[65..].to_vec(),
                target.accounts,
            )
            .0;
        assert!(
            fixture.send(&instructions, false).is_err(),
            "even native-valid unanimous authority cannot alter stored recipient/token path"
        );
        for (key, account) in keys.iter().zip(&before) {
            assert_eq!(&fixture.svm.get_account(key).unwrap(), account);
        }
    }
    fixture
        .send(&fixture.release_instruction(), false)
        .expect("original exact immutable recipient receives25");
    assert_eq!(fixture.amount(fixture.buyer_token), 25);
}

#[test]
fn authority_allocation_is_sequential_nonoverlapping_and_exactly_conserves_amount() {
    let mut fixture = Fixture::new();
    fixture.initialized();
    fixture.open();
    fixture.lock();
    fixture.prepare();
    fixture.commit();
    let before_hold = fixture.svm.get_account(&fixture.hold_key()).unwrap();
    let before_epoch = fixture.svm.get_account(&fixture.epoch_key()).unwrap();
    for mutation in 0..4 {
        let target = fixture.allocation_instruction(true).pop().unwrap();
        let mut payload = target.data[65..].to_vec();
        match mutation {
            0 => payload[32..40].copy_from_slice(&1u64.to_le_bytes()),
            1 => payload[40..48].copy_from_slice(&u64::MAX.to_le_bytes()),
            2 => payload[40..48].copy_from_slice(&34u64.to_le_bytes()),
            3 => payload[49] ^= 1,
            _ => unreachable!(),
        }
        let instructions = fixture
            .decision(
                8,
                1,
                (fixture.hold_key(), Some(fixture.filled_key())),
                (fixture.version(fixture.hold_key(), 181), FILLED_ID),
                payload,
                target.accounts,
            )
            .0;
        assert!(fixture.send(&instructions, false).is_err());
        assert_eq!(
            fixture.svm.get_account(&fixture.hold_key()).unwrap(),
            before_hold
        );
        assert_eq!(
            fixture.svm.get_account(&fixture.epoch_key()).unwrap(),
            before_epoch
        );
        assert!(fixture.svm.get_account(&fixture.filled_key()).is_none());
        assert_eq!(fixture.amount(fixture.escrow_key()), 34);
    }
    fixture.record(true);
    let target = fixture.allocation_instruction(false).pop().unwrap();
    let mut payload = target.data[65..].to_vec();
    payload[32..40].copy_from_slice(&24u64.to_le_bytes());
    let overlap = fixture
        .decision(
            8,
            1,
            (fixture.hold_key(), Some(fixture.unused_key())),
            (fixture.version(fixture.hold_key(), 181), UNUSED_ID),
            payload,
            target.accounts,
        )
        .0;
    assert!(fixture.send(&overlap, false).is_err());
    assert!(fixture.svm.get_account(&fixture.unused_key()).is_none());
    fixture.record(false);
    fixture.activate();
    fixture
        .send(&fixture.return_instruction(1), false)
        .expect("complete disjoint unused9");
    assert_eq!(fixture.amount(fixture.escrow_key()), 25);
}

#[test]
fn alternate_native_valid_key_signature_offsets_are_not_canonical_authorization() {
    let mut fixture = Fixture::new();
    fixture.initialized();
    let pair = fixture.svm.get_account(&fixture.pair).unwrap();
    let mut instructions = fixture.open_instruction();
    // Real precompile permits reordered bytes, but this program accepts only key16/sig48.
    let original = instructions[0].data.clone();
    instructions[0].data[2..4].copy_from_slice(&16u16.to_le_bytes());
    instructions[0].data[6..8].copy_from_slice(&80u16.to_le_bytes());
    instructions[0].data[16..80].copy_from_slice(&original[48..112]);
    instructions[0].data[80..112].copy_from_slice(&original[16..48]);
    let failure = fixture
        .send(&instructions, false)
        .expect_err("noncanonical layout must reject despite true native signature");
    assert_eq!(
        failure.err,
        TransactionError::InstructionError(4, InstructionError::Custom(11)),
        "must reject at target after real native verification"
    );
    assert_eq!(fixture.svm.get_account(&fixture.pair).unwrap(), pair);
    assert!(fixture.svm.get_account(&fixture.epoch_key()).is_none());
    fixture.open();
}
