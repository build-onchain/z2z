//! Private isolated consensus requirements. None of these constructed states or
//! public script vectors are a mined/connected history or a settlement fact.

use super::*;
use super::tests::{changed, output, script_input, state};
use zcash_primitives::transaction::{TransactionData, TxVersion, components::sprout::{Bundle, JsDescription}};
use zcash_transparent::bundle::{OutPoint, TxIn};

#[path = "../tests/fixtures/sprout-ledger-primary.rs"]
mod primary;
#[path = "../tests/fixtures/legacy-signed.rs"]
mod signed;
use crate::overwinter_fixture as overwinter_primary;
#[path = "../tests/fixtures/overwinter-offsets.rs"]
mod overwinter_offsets;

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        let digit = |c| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid primary hex"),
        };
        digit(pair[0]) * 16 + digit(pair[1])
    }).collect()
}

fn parse(hex: &str) -> Transaction {
    let raw = bytes(hex);
    let mut reader = raw.as_slice();
    let tx = Transaction::read(&mut reader, BranchId::Sprout).unwrap();
    assert!(reader.is_empty());
    let mut canonical = Vec::new();
    tx.write(&mut canonical).unwrap();
    assert_eq!(canonical, raw);
    tx
}

fn fund(state: &mut SproutTestnetLedger, key: ([u8; 32], u32), value: u64, script: &[u8], height: u32, coinbase: bool) {
    // Test-private state only; production has no arbitrary state constructor.
    state.utxos.insert(key, TransparentCoin { output: output(value, script), created_height: height, is_coinbase: coinbase });
    state.utxo_balance += value;
    state.transparent_balance += value;
    state.issued_supply += value;
}

type SpendInput<'a> = (([u8; 32], u32), &'a [u8], u32);

fn spend(inputs: &[SpendInput<'_>], outputs: Vec<TxOut>, lock: u32) -> Transaction {
    changed(TxVersion::Sprout(1), lock, |bundle| {
        bundle.vin = inputs.iter().map(|(key, script, sequence)| {
            let mut sig = Script::default();
            sig.0.0 = script.to_vec();
            TxIn::from_parts(OutPoint::new(key.0, key.1), sig, *sequence)
        }).collect();
        bundle.vout = outputs;
    })
}

fn coinbase(claimed: u64) -> Transaction {
    changed(TxVersion::Sprout(1), 0, |bundle| {
        bundle.vout = vec![output(claimed - 12_500, &[0x51]), output(12_500, &bytes("a914ef775f1f997f122a062fff1a2d7443abd1f9c64287"))];
    })
}

#[test]
fn primary_cltv_rows_execute_actual_locktime_redeem_code_and_selected_sequence() {
    for &(raw, previous, accepted) in primary::CLTV {
        let tx = parse(raw);
        let mut all_valid = true;
        for &(index, script) in previous {
            all_valid &= verify_transparent_input(&tx, None, index, &output(0, &bytes(script))).is_ok();
        }
        assert_eq!(all_valid, accepted, "primary CLTV row {raw}");
    }
}

#[test]
fn published_signed_noncoinbase_moves_actual_prevout_value_and_destroys_unclaimed_fees() {
    let tx = parse(signed::V1_SIGNED);
    let input = &tx.transparent_bundle().unwrap().vin[0];
    let key = (*input.prevout().hash(), input.prevout().n());
    let mut parent = state();
    fund(&mut parent, key, 100_001, &bytes(signed::V1_SCRIPT), 0, false);
    let delta = parent.stage_block(coinbase(12_500), vec![tx], 1, 1_477_674_473).unwrap();
    assert_eq!(delta.fees, 100_001);
    assert_eq!(delta.issued, 12_500); // C-F negative: fee destruction, not new issuance.
    assert_eq!(parent.utxo_balance(), 100_001); // Nothing changed while staging.
    parent.commit(delta);
    assert!(parent.utxo(&key.0, key.1).is_none());
    assert_eq!((parent.transparent_balance(), parent.issued_supply(), parent.utxo_balance()), (12_500, 12_500, 12_500));

    let mut corrupted = bytes(signed::V1_SIGNED);
    corrupted[52] ^= 1; // Signature scalar bytes, no alternate key or fake digest.
    let tx = Transaction::read(corrupted.as_slice(), BranchId::Sprout).unwrap();
    let mut parent = state();
    fund(&mut parent, key, 100_001, &bytes(signed::V1_SCRIPT), 0, false);
    assert!(matches!(parent.stage_block(coinbase(12_500), vec![tx], 1, 1_477_674_473), Err(SproutLedgerError::InvalidTransparentScript)));
    assert_eq!(parent.utxo_balance(), 100_001);
    assert!(parent.utxo(&key.0, key.1).is_some());
}

#[test]
fn published_two_input_signatures_use_original_input_indices_and_allow_claiming_actual_fees() {
    let tx = parse(signed::V1_ALL_ACP_SIGNED);
    let mut parent = state();
    for (index, input) in tx.transparent_bundle().unwrap().vin.iter().enumerate() {
        fund(&mut parent, (*input.prevout().hash(), input.prevout().n()), if index == 0 { 9 } else { 8 }, &bytes(signed::V1_ALL_ACP_SCRIPT), 0, false);
    }
    let delta = parent.stage_block(coinbase(62_516), vec![tx], 1, 1_477_674_473).unwrap();
    assert_eq!(delta.fees, 16);
    parent.commit(delta);
    assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance()), (62_517, 62_517, 62_517));
    // The reward includes fees, but the individual founder output remains R/5.
    let empty = state();
    assert!(matches!(empty.stage_block(coinbase(62_517), vec![], 1, 1_477_674_473), Err(SproutLedgerError::CoinbaseRewardExceeded)));
}

#[test]
fn raw_script_der_empty_signature_disabled_inactive_and_resource_limits_are_consensus() {
    let key = ([0x31; 32], 0);
    let public_key = bytes("21038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508ac91");
    // Original BIP66 examples: invalid DER aborts even CHECKSIG NOT; empty
    // signature is false and may be consumed. Not a NULLFAIL policy rule.
    for (sig, accepted) in [(vec![0x51], false), (vec![0], true), (bytes("09300602010002010101"), true)] {
        let tx = spend(&[(key, &sig, u32::MAX)], vec![output(0, &[0x51])], 0);
        assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, &public_key)).is_ok(), accepted);
    }
    for (opcode, accepted) in [(0xff, true), (0x65, false), (0x66, false), (0x7e, false), (0xab, false)] {
        let tx = spend(&[(key, &[0], u32::MAX)], vec![output(0, &[0x51])], 0);
        assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, &[0x63, opcode, 0x67, 0x51, 0x68])).is_ok(), accepted);
    }
    for (depth, pubkey, accepted) in [(1_000, &[][..], true), (1_001, &[0x75][..], false)] {
        let sig = vec![0x51; depth];
        let tx = spend(&[(key, &sig, u32::MAX)], vec![output(0, &[0x51])], 0);
        assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, pubkey)).is_ok(), accepted);
    }
    for (size, accepted) in [(520_u16, true), (521, false)] {
        let mut script = vec![0, 0x63, 0x4d];
        script.extend_from_slice(&size.to_le_bytes());
        script.resize(5 + usize::from(size), 0);
        script.extend_from_slice(&[0x68, 0x51]);
        let tx = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
        assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, &script)).is_ok(), accepted);
    }
    for (operations, accepted) in [(201, true), (202, false)] {
        let mut script = vec![0x61; operations];
        script.push(0x51);
        let tx = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
        assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, &script)).is_ok(), accepted);
    }
    for (size, accepted) in [(10_000, true), (10_001, false)] {
        // An inactive OP0 sequence reaches the byte bound without hiding an
        // opcode-count or stack-depth failure.
        let mut script = Vec::with_capacity(size);
        script.extend_from_slice(&[0, 0x63]);
        script.extend(std::iter::repeat_n(0, size - 4));
        script.extend_from_slice(&[0x68, 0x51]);
        let tx = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
        assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, &script)).is_ok(), accepted);
    }
    // No MinimalData, CleanStack, CSV or NullDummy is silently enabled.
    for script in [bytes("4d0100085887"), bytes("4e01000000095987"), vec![0x51, 0x51], vec![0xb2, 0x51], vec![0x51, 0x00, 0x00, 0xae]] {
        let tx = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
        assert!(verify_transparent_input(&tx, None, 0, &output(0, &script)).is_ok());
    }
}

#[test]
fn original_p2sh_accurate_sigops_and_entire_block_budget_include_created_scripts() {
    // Original sigopcount_tests.cpp, blob3fd68f28dab7c270b802a74355ad134f6b4fea1d:
    // OP1,push20,push20,OP2,CHECKMULTISIG,IF,CHECKSIG,ENDIF =>21 legacy/3 accurate.
    let mut redeem = vec![0x51, 20];
    redeem.extend_from_slice(&[0; 20]);
    redeem.push(20);
    redeem.extend_from_slice(&[0; 20]);
    redeem.extend_from_slice(&[0x52, 0xae, 0x63, 0xac, 0x68]);
    assert_eq!(legacy_sigops(&redeem), 21);
    assert_eq!(sigops(&redeem, true), 3);
    let mut sig = vec![0, redeem.len() as u8];
    sig.extend_from_slice(&redeem);
    assert_eq!(p2sh_sigops(&sig, &bytes("a914000000000000000000000000000000000000000087")), 3);
    assert_eq!(p2sh_sigops(&[0x61], &bytes("a914000000000000000000000000000000000000000087")), 0);
    assert_eq!(sigops(&[0x53, 0xff, 0xae], true), 20); // Last opcode must not skip unknowns.

    let key = ([0x32; 32], 0);
    for (count, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let burn = vec![0xac; count]; // Creation is legal; length pruning is not script execution.
        let tx = spend(&[(key, &[], u32::MAX)], vec![output(0, &burn)], 0);
        let reward = changed(TxVersion::Sprout(1), 0, |bundle| bundle.vout[0] = output(50_000, &[0xac]));
        let result = parent.stage_block(reward, vec![tx], 1, 1_477_674_473);
        if accepted {
            assert_eq!(result.unwrap().sigops, 20_000); // Coinbase contributes one.
        } else {
            assert!(matches!(result, Err(SproutLedgerError::TooManySigops)));
        }
    }
}

#[test]
fn ordered_delta_allows_prior_outputs_but_not_future_or_second_spends() {
    let key = ([0x41; 32], 0);
    let mut parent = state();
    fund(&mut parent, key, 100, &[0x51], 0, false);
    let first = spend(&[(key, &[], u32::MAX)], vec![output(80, &[0x51])], 0);
    let first_id: [u8; 32] = first.txid().into();
    let next = || spend(&[((first_id, 0), &[], u32::MAX)], vec![output(50, &[0x51])], 0);
    assert!(matches!(parent.stage_block(coinbase(62_500), vec![next(), first], 1, 1_477_674_473), Err(SproutLedgerError::MissingTransparentInput)));
    let first = spend(&[(key, &[], u32::MAX)], vec![output(80, &[0x51])], 0);
    assert!(matches!(parent.stage_block(coinbase(62_500), vec![first, next(), next()], 1, 1_477_674_473), Err(SproutLedgerError::MissingTransparentInput)));
    assert_eq!(parent.utxo_balance(), 100);
    let first = spend(&[(key, &[], u32::MAX)], vec![output(80, &[0x51])], 0);
    let delta = parent.stage_block(coinbase(62_550), vec![first, next()], 1, 1_477_674_473).unwrap();
    assert_eq!(delta.fees, 50);
    parent.commit(delta);
    assert!(parent.utxo(&key.0, key.1).is_none());
    assert!(parent.utxo(&first_id, 0).is_none());
    assert_eq!(parent.utxo_count(), 3);
    assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance()), (62_600, 62_600, 62_600));
}

#[test]
fn bip30_checks_all_parent_transaction_identities_before_any_candidate_spend() {
    let original = ([0x42; 32], 0);
    let later = spend(&[(original, &[], u32::MAX)], vec![output(10, &[0x51])], 0);
    let later_id = later.txid().into();
    let old = (later_id, 7);
    let earlier = spend(&[(old, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let mut parent = state();
    fund(&mut parent, original, 10, &[0x51], 0, false);
    fund(&mut parent, old, 1, &[0x51], 0, false);
    assert!(matches!(parent.stage_block(coinbase(62_500), vec![earlier, later], 1, 1_477_674_473), Err(SproutLedgerError::UnspentTransactionOverwrite)));
    assert!(parent.utxo(&old.0, old.1).is_some());
    assert_eq!(parent.utxo_balance(), 11);
    // Already fully-spent identities can reappear; no permanent seen-txid ban.
    parent.utxos.remove(&old);
    parent.utxo_balance -= 1;
    parent.transparent_balance -= 1;
    parent.issued_supply -= 1;
    let later = spend(&[(original, &[], u32::MAX)], vec![output(10, &[0x51])], 0);
    let delta = parent.stage_block(coinbase(62_500), vec![later], 1, 1_477_674_473).unwrap();
    parent.commit(delta);
    assert!(parent.utxo(&later_id, 0).is_some());
}

#[test]
fn claimed_burns_stay_in_the_protocol_pool_and_fee_underclaims_destroy_only_actual_value() {
    for (claim, pool, retained) in [(62_500, 152_500, 92_500), (12_500, 102_500, 42_500)] {
        let key = ([0x43; 32], 0);
        let mut parent = state();
        fund(&mut parent, key, 100_000, &[0x51], 0, false);
        let tx = spend(&[(key, &[], u32::MAX)], vec![output(60_000, &[0x6a]), output(30_000, &[0x51]), output(0, &[])], 0);
        let id = tx.txid().into();
        let delta = parent.stage_block(coinbase(claim), vec![tx], 1, 1_477_674_473).unwrap();
        parent.commit(delta);
        assert_eq!((parent.transparent_balance(), parent.issued_supply(), parent.utxo_balance()), (pool, pool, retained));
        assert!(parent.utxo(&id, 0).is_none());
        assert_eq!(u64::from(parent.utxo(&id, 1).unwrap().output().value()), 30_000);
        assert_eq!(u64::from(parent.utxo(&id, 2).unwrap().output().value()), 0);
    }
}

#[test]
fn transaction_finality_shape_duplicate_null_and_actual_input_money_bounds_are_not_ignored() {
    let key = ([0x44; 32], 0);
    for (lock, seq, time, accepted) in [(1, 0, 600_000_001, false), (1, u32::MAX, 600_000_001, true), (600_000_000, 0, 600_000_001, true), (600_000_000, 0, 600_000_000, false)] {
        let tx = spend(&[(key, &[], seq)], vec![output(0, &[0x51])], lock);
        assert_eq!(check_transaction(&tx, 1, time).is_ok(), accepted);
    }
    let duplicate = spend(&[(key, &[], u32::MAX), (key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    assert!(matches!(check_transaction(&duplicate, 1, 1_477_674_473), Err(SproutLedgerError::DuplicateTransparentInput)));
    let null = spend(&[(([0; 32], u32::MAX), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    assert!(matches!(check_transaction(&null, 1, 1_477_674_473), Err(SproutLedgerError::InvalidTransaction)));
    let empty = spend(&[(key, &[], u32::MAX)], vec![], 0);
    assert!(matches!(check_transaction(&empty, 1, 1_477_674_473), Err(SproutLedgerError::InvalidTransaction)));
    let second = ([0x45; 32], 0);
    let mut parent = state();
    fund(&mut parent, key, MAX_MONEY, &[0x51], 0, false);
    fund(&mut parent, second, 1, &[0x51], 0, false);
    let overflow = spend(&[(key, &[], u32::MAX), (second, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    assert!(matches!(parent.stage_block(coinbase(12_500), vec![overflow], 1, 1_477_674_473), Err(SproutLedgerError::ValueOutOfRange)));
}

#[test]
fn actual_published_high_s_and_hybrid_signatures_pass_without_policy_flags() {
    for (sig, pubkey) in primary::HIGH_S_HYBRID {
        let script = bytes(pubkey);
        // Exact original BuildCreditingTransaction/BuildSpendingTransaction,
        // with public txid derivation and authentic published signatures.
        let credit = changed(TxVersion::Sprout(1), 0, |bundle| {
            script_input(bundle, &[0, 0], u32::MAX);
            bundle.vout = vec![output(0, &script)];
        });
        let credit_id: [u8; 32] = credit.txid().into();
        let spending = spend(&[((credit_id, 0), &bytes(sig), u32::MAX)], vec![output(0, &[])], 0);
        let mut parent = state();
        // This is the original script-vector funding recipe, NOT a coinbase
        // accepted into a real source history or a maturity exception.
        fund(&mut parent, (credit_id, 0), 0, &script, 0, false);
        let id: [u8; 32] = spending.txid().into();
        let delta = parent.stage_block(coinbase(62_500), vec![spending], 1, 1_477_674_473).unwrap();
        parent.commit(delta);
        assert!(parent.utxo(&credit_id, 0).is_none());
        assert_eq!(u64::from(parent.utxo(&id, 0).unwrap().output().value()), 0);
    }
}

fn joinsplit(anchor: [u8; 32], nullifier: u8, commitments: [[u8; 32]; 2], old: u64, new: u64) -> JsDescription {
    // Exact native typed description with deliberately invalid proof/signature:
    // usable for CHEAP contextual requirements only, never accepted crypto.
    let mut raw = [0; 1802];
    raw[..8].copy_from_slice(&old.to_le_bytes());
    raw[8..16].copy_from_slice(&new.to_le_bytes());
    raw[16..48].copy_from_slice(&anchor);
    raw[48..80].fill(nullifier);
    raw[80..112].fill(nullifier + 1);
    raw[112..144].copy_from_slice(&commitments[0]);
    raw[144..176].copy_from_slice(&commitments[1]);
    JsDescription::read(raw.as_slice(), false).unwrap()
}

fn with_joinsplits(transaction: Transaction, descriptions: Vec<JsDescription>) -> Transaction {
    TransactionData::<Authorized>::from_parts(
        TxVersion::Sprout(2), BranchId::Sprout, transaction.lock_time(), 0.into(),
        transaction.transparent_bundle().cloned(),
        Some(Bundle { joinsplits: descriptions, joinsplit_pubkey: [0; 32], joinsplit_sig: [0; 64] }),
        None, None,
    ).freeze().unwrap()
}

fn commitments(index: usize) -> [[u8; 32]; 2] {
    [bytes(primary::COMMITMENTS[index]).try_into().unwrap(), bytes(primary::COMMITMENTS[index + 1]).try_into().unwrap()]
}

#[test]
fn maturity_and_testnet_protection_check_every_coinbase_input_including_mixed_funding() {
    let first = ([0x51; 32], 0);
    let second = ([0x52; 32], 0);
    let ordinary = ([0x53; 32], 0);
    let mut parent = state();
    fund(&mut parent, first, 2, &[0x51], 1, true);
    fund(&mut parent, second, 2, &[0x51], 2, true);
    fund(&mut parent, ordinary, 1, &[0x51], 0, false);
    let anchor = parent.shielded_roots[0];
    for (height, key, expected) in [
        (100, first, SproutLedgerError::ImmatureCoinbase),
        (101, first, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (101, second, SproutLedgerError::ImmatureCoinbase),
        (102, second, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
    ] {
        let tx = with_joinsplits(spend(&[(ordinary, &[], u32::MAX), (key, &[], u32::MAX)], vec![], 0), vec![joinsplit(anchor, 1, commitments(0), 3, 0)]);
        let mut delta = BlockDelta::new(&parent);
        assert_eq!(parent.stage_transaction(tx, height, 1_477_674_473, &mut delta), Err(expected));
    }
    // Any transparent output violates protection: zero or pruned is not an
    // exception. Mixed inputs and a second immature coin cannot hide behind one.
    for script in [vec![], vec![0x6a], vec![0x51]] {
        let tx = with_joinsplits(spend(&[(ordinary, &[], u32::MAX), (first, &[], u32::MAX)], vec![output(0, &script)], 0), vec![joinsplit(anchor, 1, commitments(0), 3, 0)]);
        let mut delta = BlockDelta::new(&parent);
        assert_eq!(parent.stage_transaction(tx, 101, 1_477_674_473, &mut delta), Err(SproutLedgerError::UnshieldedCoinbaseSpend));
    }
    let tx = with_joinsplits(spend(&[(first, &[], u32::MAX), (second, &[], u32::MAX)], vec![], 0), vec![joinsplit(anchor, 1, commitments(0), 4, 0)]);
    assert_eq!(parent.stage_transaction(tx, 101, 1_477_674_473, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::ImmatureCoinbase));
    assert_eq!(parent.utxo_balance(), 5);
    assert_eq!(parent.nullifier_count(ShieldedPool::Sprout), 0);
}

#[test]
fn depth29_primary_commitment_roots_and_isolated_testnet2259_crypto_are_exact() {
    let mut tree = Frontier::<SproutNode, 29>::empty();
    for index in (0..16).step_by(2) {
        let leaves = commitments(index);
        assert!(tree.append(SproutNode(leaves[0])));
        assert_eq!(tree.root().0.as_slice(), bytes(primary::ROOTS[index]));
        assert!(tree.append(SproutNode(leaves[1])));
        assert_eq!(tree.root().0.as_slice(), bytes(primary::ROOTS[index + 1]));
    }
    let raw = bytes(primary::TESTNET_2259_HEX);
    let body = ParsedBlockBody::parse(&raw, &TEST_NETWORK).unwrap();
    assert_eq!(u32::from(body.block().claimed_height()), 2259);
    let tx = &body.block().vtx().tail[0];
    verify_legacy_joinsplit_crypto(tx).unwrap(); // Authentic Ed25519 AND PHGR.
    let parent = state();
    let mut delta = BlockDelta::new(&parent);
    parent.stage_sprout(tx, &mut delta).unwrap();
    assert_eq!(delta.tree.tree_size(), 2);
    assert_eq!(delta.tree.root().0.as_slice(), bytes("3377f041ad6b7a04c920e4cd3f0a27b06736c38972fd994262b53f8b1c238529"));
    assert_eq!(delta.nullifiers.len(), 2);
    // These roots/proofs are isolated data: the actual connected genesis ledger
    // cannot append this body without all authentic intervening full bodies.
    let mut connected = state();
    assert_eq!(connected.apply_block(&raw), Err(SproutLedgerError::WrongHeight));
    assert_eq!(connected.sprout_tree_size(), 0);
}

#[test]
fn anchors_branch_within_one_transaction_but_never_from_another_transactions_partial_tree() {
    // Original coins_tests.cpp::chained_joinsplits (blob79609cc025c609a5cd32bea469412c3fe30151da)
    // requires js2/js3 to branch from the SAME prior intermediate js1 root.
    let parent = state();
    let empty = parent.shielded_roots[0];
    let after_first: [u8; 32] = bytes(primary::ROOTS[1]).try_into().unwrap();
    let first = || joinsplit(empty, 1, commitments(0), 0, 0);
    let second = || joinsplit(after_first, 3, commitments(2), 0, 0);
    let third = || joinsplit(after_first, 5, commitments(4), 0, 0);
    let transaction = |descriptions| with_joinsplits(spend(&[], vec![], 0), descriptions);
    let mut delta = BlockDelta::new(&parent);
    parent.stage_sprout(&transaction(vec![first(), second(), third()]), &mut delta).unwrap();
    assert_eq!(delta.tree.tree_size(), 6);
    assert_eq!(delta.tree.root().0.as_slice(), bytes(primary::ROOTS[5]));
    assert_eq!(delta.nullifiers.len(), 6);
    assert!(matches!(verify_legacy_joinsplit_crypto(&transaction(vec![first(), second(), third()])), Err(LegacyJoinSplitError::InvalidSignature)));
    assert!(matches!(parent.stage_sprout(&transaction(vec![second(), first()]), &mut BlockDelta::new(&parent)), Err(SproutLedgerError::UnknownSproutAnchor)));
    let mut other_transaction = BlockDelta::new(&parent);
    parent.stage_sprout(&transaction(vec![first()]), &mut other_transaction).unwrap();
    assert!(matches!(parent.stage_sprout(&transaction(vec![second()]), &mut other_transaction), Err(SproutLedgerError::UnknownSproutAnchor)));
    assert_eq!(parent.sprout_tree_size(), 0);
    assert_eq!(parent.sprout_anchors.len(), 1);
}

#[test]
fn historical_block_anchors_use_current_nullifiers_and_publish_only_the_final_frontier() {
    let mut parent = state();
    let empty = parent.shielded_roots[0];
    let mut delta = parent.stage_block(coinbase(62_500), vec![], 1, 1_477_674_473).unwrap();
    append_commitments(&mut delta.tree, &commitments(0)).unwrap();
    append_commitments(&mut delta.tree, &commitments(2)).unwrap();
    let final_root: [u8; 32] = bytes(primary::ROOTS[3]).try_into().unwrap();
    parent.commit(delta); // Private tree/storage invariant test; no valid-JS history claim.
    assert_eq!(parent.shielded_roots[0], final_root);
    assert_eq!(parent.sprout_anchors.len(), 2);
    let intermediate: [u8; 32] = bytes(primary::ROOTS[1]).try_into().unwrap();
    assert!(!parent.sprout_anchors.contains_key(&intermediate));
    let tx = with_joinsplits(spend(&[], vec![], 0), vec![joinsplit(empty, 7, commitments(4), 0, 0)]);
    let mut next = BlockDelta::new(&parent);
    parent.stage_sprout(&tx, &mut next).unwrap();
    // Anchor appends from the historical empty tree, but block appends from
    // its current four-leaf state: all commitments, in original block order.
    assert_eq!(next.tree.root().0.as_slice(), bytes(primary::ROOTS[5]));
    parent.nullifiers[0].insert([7; 32]);
    assert_eq!(parent.stage_sprout(&tx, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::SpentSproutNullifier));
    let duplicate = with_joinsplits(spend(&[], vec![], 0), vec![joinsplit(empty, 9, commitments(4), 0, 0), joinsplit(empty, 9, commitments(6), 0, 0)]);
    assert_eq!(parent.stage_sprout(&duplicate, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::SpentSproutNullifier));
    let future = with_joinsplits(spend(&[], vec![], 0), vec![joinsplit(parent.shielded_roots[1], 11, commitments(4), 0, 0)]);
    assert_eq!(parent.stage_sprout(&future, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::UnknownSproutAnchor));
}

#[test]
fn zero_commitments_preserve_original_first_intermediate_and_push_anchor_frontiers() {
    let mut parent = state();
    let empty = parent.shielded_roots[0];
    // Appending zero leaves can leave the root unchanged. The earlier SAME-TX
    // root takes precedence over the historical root and keeps first insertion.
    let full = Frontier::from_parts(((1_u64 << 29) - 1).into(), SproutNode([0; 32]), (0_u8..29).map(|level| <SproutNode as incrementalmerkletree::Hashable>::empty_root(level.into())).collect()).unwrap();
    assert_eq!(full.root().0, empty);
    let almost_full = Frontier::from_parts(((1_u64 << 29) - 5).into(), SproutNode([0; 32]), (0_u8..29).filter(|level| *level != 2).map(|level| <SproutNode as incrementalmerkletree::Hashable>::empty_root(level.into())).collect()).unwrap();
    assert_eq!(almost_full.root().0, empty);
    parent.sprout_anchors.insert(empty, almost_full);
    let js = || with_joinsplits(spend(&[], vec![], 0), vec![joinsplit(empty, 1, [[0; 32]; 2], 0, 0), joinsplit(empty, 3, [[0; 32]; 2], 0, 0), joinsplit(empty, 5, [[0; 32]; 2], 0, 0)]);
    // First intermediate has capacity-2 leaves. The second has capacity leaves
    // with that SAME root, but cannot replace the first. Reset only the test's
    // independent block frontier so it does not mask intermediate precedence.
    let mut delta = BlockDelta::new(&parent);
    delta.tree = Frontier::empty();
    parent.stage_sprout(&js(), &mut delta).unwrap();
    assert_eq!(delta.tree.tree_size(), 6);
    // Exact PushAnchor: when best root does not change, stored size remains
    // parent's size, not the silently advanced local zero-leaf frontier.
    let mut parent = state();
    let mut delta = parent.stage_block(coinbase(62_500), vec![], 1, 1_477_674_473).unwrap();
    append_commitments(&mut delta.tree, &[[0; 32]; 2]).unwrap();
    parent.commit(delta);
    assert_eq!(parent.sprout_tree_size(), 0);
    let different = commitments(0);
    let mut delta = BlockDelta::new(&parent);
    append_commitments(&mut delta.tree, &different).unwrap();
    let root = delta.tree.root().0;
    parent.sprout_anchors.insert(root, full);
    parent.commit(delta);
    assert_eq!(parent.sprout_tree_size(), 2); // Existing nonbest root was overwritten.
    assert_eq!(parent.sprout_anchors[&root].tree_size(), 2);
}

#[test]
fn capacity_overflow_and_late_script_or_crypto_failure_leave_every_parent_state_unchanged() {
    let mut parent = state();
    let key = ([0x61; 32], 0);
    fund(&mut parent, key, 20, &[0x51], 0, false);
    let good = || spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0);
    let id: [u8; 32] = good().txid().into();
    let bad = spend(&[((id, 0), &[], u32::MAX)], vec![output(18, &[0x51])], 0);
    let invalid_script = changed(TxVersion::Sprout(1), 0, |bundle| {
        let previous = bad.transparent_bundle().unwrap();
        *bundle = previous.clone();
        let mut sig = Script::default();
        sig.0.0 = vec![0x6a];
        bundle.vin[0] = TxIn::from_parts(OutPoint::new(id, 0), sig, u32::MAX);
    });
    assert!(matches!(parent.stage_block(coinbase(62_500), vec![good(), invalid_script], 1, 1_477_674_473), Err(SproutLedgerError::InvalidTransparentScript)));
    let anchor = parent.shielded_roots[0];
    let crypto = with_joinsplits(spend(&[], vec![output(0, &[0x51])], 0), vec![joinsplit(anchor, 1, commitments(0), 0, 0)]);
    assert!(matches!(parent.stage_block(coinbase(62_500), vec![good(), crypto], 1, 1_477_674_473), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature))));
    assert!(parent.utxo(&key.0, key.1).is_some());
    assert!(parent.utxo(&id, 0).is_none());
    assert_eq!((parent.utxo_balance(), parent.transparent_balance(), parent.issued_supply()), (20, 20, 20));
    assert_eq!(parent.sprout_tree_size(), 0);
    assert_eq!(parent.nullifier_count(ShieldedPool::Sprout), 0);
    assert_eq!(parent.sprout_anchors.len(), 1);
    assert_eq!(parent.tip().height(), 0);
    let last = Frontier::from_parts(((1_u64 << 29) - 2).into(), SproutNode([1; 32]), vec![SproutNode([2; 32]); 28]).unwrap();
    let last_root = last.root().0;
    parent.sprout_anchors.insert(last_root, last);
    let tx = with_joinsplits(spend(&[], vec![], 0), vec![joinsplit(last_root, 3, commitments(0), 0, 0)]);
    assert_eq!(parent.stage_sprout(&tx, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::SproutTreeFull));
    assert_eq!(parent.sprout_anchors[&last_root].tree_size(), (1_u64 << 29) - 1);
}

#[test]
fn money_checks_separate_debits_credits_and_inputs_before_any_crypto_equations() {
    let key = ([0x71; 32], 0);
    let mut parent = state();
    fund(&mut parent, key, 1, &[0x51], 0, false);
    let anchor = parent.shielded_roots[0];
    for (old, new, output_value) in [(MAX_MONEY, 0, 1), (0, MAX_MONEY, 0), (1, 1, 0)] {
        let tx = with_joinsplits(spend(&[(key, &[], u32::MAX)], vec![output(output_value, &[0x51])], 0), vec![joinsplit(anchor, 1, commitments(0), old, new)]);
        assert_eq!(parent.stage_transaction(tx, 1, 1_477_674_473, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::ValueOutOfRange));
    }
    let negative_fee = spend(&[(key, &[], u32::MAX)], vec![output(2, &[0x51])], 0);
    assert_eq!(parent.stage_transaction(negative_fee, 1, 1_477_674_473, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::NegativeFee));
    let absent_io = with_joinsplits(spend(&[], vec![], 0), vec![joinsplit(anchor, 1, commitments(0), 0, 0)]);
    assert!(check_transaction(&absent_io, 1, 1_477_674_473).is_ok());
    assert_eq!(parent.stage_transaction(absent_io, 1, 1_477_674_473, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)));
}

fn authentic_shielding_body() -> (Transaction, Vec<Transaction>) {
    let raw = bytes(primary::TESTNET_2259_HEX);
    let body = ParsedBlockBody::parse(&raw, &TEST_NETWORK).unwrap();
    let (_, transactions) = body.into_block().into_parts();
    (transactions.head, transactions.tail)
}

fn isolated_shielding_state() -> SproutTestnetLedger {
    let funding = parse(primary::TESTNET_2259_FUNDING_HEX);
    let (_, transactions) = authentic_shielding_body();
    let input = &transactions[0].transparent_bundle().unwrap().vin[0];
    assert_eq!(<[u8; 32]>::from(funding.txid()), *input.prevout().hash());
    assert_eq!(input.prevout().n(), 0);
    let bundle = funding.transparent_bundle().unwrap();
    assert!(bundle.is_coinbase());
    assert_eq!(u64::from(bundle.vout[0].value()), 91_800_000);
    assert_eq!(bundle.vout[0].script_pubkey().0.0, bytes("2102ad7de9e0ecec3d84157d0ebee617553f7f440ffcfec24bf2d8d9d11245db8a25ac"));
    let mut parent = state();
    // PRIVATE requirements state: 1836 is the claimed explorer-height exercise,
    // not authenticated block inclusion/unspentness/maturity/connected history.
    for (index, output) in (0_u32..).zip(take_outputs(funding)) {
        let value = u64::from(output.value());
        parent.utxo_balance += value;
        parent.transparent_balance += value;
        parent.issued_supply += value;
        parent.utxos.insert((*input.prevout().hash(), index), TransparentCoin { output, created_height: 1_836, is_coinbase: true });
    }
    parent
}

#[test]
fn authentic_isolated_funding_and_shielding_verify_actual_scripts_proofs_and_full_money_delta() {
    let mut parent = isolated_shielding_state();
    let before = (parent.utxo_balance(), parent.transparent_balance(), parent.issued_supply());
    assert_eq!(before, (114_750_000, 114_750_000, 114_750_000));
    let (reward, transactions) = authentic_shielding_body();
    let funding = *transactions[0].transparent_bundle().unwrap().vin[0].prevout().hash();
    let id: [u8; 32] = transactions[0].txid().into();
    let nullifiers = *transactions[0].sprout_bundle().unwrap().joinsplits[0].nullifiers();
    let delta = parent.stage_block(reward, transactions, 2_259, 1_476_920_000).unwrap();
    assert_eq!(delta.fees, 10_000);
    assert_eq!(delta.issued, 255_937_500);
    assert_eq!(parent.sprout_tree_size(), 0);
    parent.commit(delta);
    assert!(parent.utxo(&funding, 0).is_none());
    assert_eq!(u64::from(parent.utxo(&funding, 1).unwrap().output().value()), 22_950_000);
    assert!(parent.utxo(&id, 0).is_none()); // Protected shielding has NO transparent outputs.
    assert_eq!((parent.utxo_balance(), parent.transparent_balance(), parent.issued_supply()), (164_147_500, 164_147_500, 255_937_500));
    assert_eq!(parent.shielded_balance(ShieldedPool::Sprout), 91_790_000);
    assert_eq!(parent.sprout_tree_size(), 2);
    assert_eq!(parent.shielded_root(ShieldedPool::Sprout).as_slice(), bytes("3377f041ad6b7a04c920e4cd3f0a27b06736c38972fd994262b53f8b1c238529"));
    assert_eq!(parent.nullifier_count(ShieldedPool::Sprout), 2);
    for nullifier in nullifiers { assert!(parent.contains_nullifier(ShieldedPool::Sprout, &nullifier)); }
    assert_eq!(parent.tip().height(), 0); // No fake header connection in this isolated requirement.
}

#[test]
fn authentic_shielding_authorization_failures_do_not_commit_inputs_nullifiers_or_anchors() {
    let parent = isolated_shielding_state();
    let (_, original) = authentic_shielding_body();
    let template = &original[0];
    for ciphertext_corruption in [false, true] {
        let mut shielded = template.sprout_bundle().unwrap().clone();
        if ciphertext_corruption {
            let mut encoded = Vec::new();
            shielded.joinsplits[0].write(&mut encoded).unwrap();
            encoded[1_000] ^= 1; // Ciphertext is bound by original Ed25519, not skipped.
            shielded.joinsplits[0] = JsDescription::read(encoded.as_slice(), false).unwrap();
        } else {
            shielded.joinsplit_sig[0] ^= 1;
        }
        let changed = TransactionData::<Authorized>::from_parts(
            template.version(), BranchId::Sprout, 0, 0.into(), template.transparent_bundle().cloned(), Some(shielded), None, None,
        ).freeze().unwrap();
        let (reward, _) = authentic_shielding_body();
        // Description bytes enter the transparent hash, but joinSplitSig's
        // original zero-masked slot does not. Each actual authorization matters.
        let expected = if ciphertext_corruption {
            SproutLedgerError::InvalidTransparentScript
        } else {
            SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)
        };
        assert!(matches!(parent.stage_block(reward, vec![changed], 2_259, 1_476_920_000), Err(error) if error == expected));
    }
    assert_eq!(parent.utxo_balance(), 114_750_000);
    assert_eq!(parent.nullifier_count(ShieldedPool::Sprout), 0);
    assert_eq!(parent.sprout_anchors.len(), 1);
    assert_eq!(parent.shielded_balance(ShieldedPool::Sprout), 0);
}

#[test]
fn primary_last_sprout_and_first_overwinter_coinbases_use_exact_era_and_actual_fee_claims() {
    let parent = state();
    for (hex, height, claimed) in [(primary::SPROUT_LAST_HEX, 207_499, 1_250_000_000), (primary::OVERWINTER_FIRST_HEX, 207_500, 1_250_000_615)] {
        let raw = bytes(hex);
        let body = ParsedBlockBody::parse(&raw, &TEST_NETWORK).unwrap();
        assert_eq!(u32::from(body.block().claimed_height()), height);
        let time = body.block().header().time;
        assert_eq!(check_coinbase(body.block().vtx().first(), height, time).unwrap().claimed, claimed);
        if height == 207_500 {
            let reward = Transaction::read(&raw[1488..], BranchId::Overwinter).unwrap();
            assert!(matches!(parent.stage_block(reward, vec![], height, time), Err(SproutLedgerError::CoinbaseRewardExceeded)));
        }
        let (_, transactions) = body.into_block().into_parts();
        let result = parent.stage_block(transactions.head, transactions.tail, height, time);
        if height == 207_499 {
            let delta = result.unwrap();
            assert_eq!((delta.issued, delta.transparent, delta.sprout, delta.fees), (1_250_000_000, 1_250_000_000, 0, 0));
        } else {
            // The original block includes real spends and615zat claimed fees.
            // An empty synthetic parent must not invent their unspent funding.
            assert!(matches!(result, Err(SproutLedgerError::MissingTransparentInput)));
        }
    }
    assert_eq!(parent.tip().height(), 0);
    assert_eq!(parent.issued_supply(), 0);
}

#[test]
fn missing_single_output_hash_error_is_false_and_can_be_consumed_by_the_actual_script() {
    let key = ([0x81; 32], 0);
    let pubkey = bytes("2102d5c25adb51b61339d2b05315791e21bbe80ea470a49db0135720983c905aace0");
    // Canonical DER scalars are public invalid-ECDSA data, not a new signature.
    // SIGHASH_SINGLE with NO output forces the actual existing hash's error.
    let tx = spend(&[(key, &bytes("09300602010102010103"), u32::MAX)], vec![], 0);
    let mut script = pubkey;
    script.extend_from_slice(&[0xac, 0x91]);
    assert!(matches!(legacy_signature_hash(&tx, 0, &script, 3), Err(crate::legacy_sighash::LegacySighashError::MissingSingleOutput)));
    assert!(verify_transparent_input(&tx, None, 0, &output(0, &script)).is_ok());
    // Missing output remains a transaction-shape error without JoinSplits;
    // this is ONLY the CHECKSIG continuation rule, never a accepted transaction.
    assert!(matches!(check_transaction(&tx, 1, 1_477_674_473), Err(SproutLedgerError::InvalidTransaction)));
}

#[test]
fn p2sh_exact_direct_push_requires_push_only_and_preserves_the_redeem_stack() {
    let key = ([0x82; 32], 0);
    // Primary CLTV redeem row's actual HASH160(51b1), not a locally invented hash.
    let hash = bytes("c5b93064159b3b2d6ab506a41b1f50463771b988");
    let mut exact = vec![0xa9, 0x14];
    exact.extend_from_slice(&hash);
    exact.push(0x87);
    let tx = spend(&[(key, &bytes("0251b1"), 0)], vec![output(0, &[0x51])], 0);
    // At locktime0 the redeem's OP1 CLTV must fail, even though HASH160 matches.
    assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, &exact)), Err(SproutLedgerError::InvalidTransparentScript));
    let mut semantic_not_p2sh = vec![0xa9, 0x4c, 0x14];
    semantic_not_p2sh.extend_from_slice(&hash);
    semantic_not_p2sh.push(0x87);
    assert!(verify_transparent_input(&tx, None, 0, &output(0, &semantic_not_p2sh)).is_ok());
    assert_eq!(p2sh_sigops(&bytes("0251b1"), &semantic_not_p2sh), 0);
    let tx = spend(&[(key, &bytes("610251b1"), 0)], vec![output(0, &[0x51])], 1);
    assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, &exact)), Err(SproutLedgerError::InvalidTransparentScript));
    let tx = spend(&[(key, &bytes("510251b1"), 0)], vec![output(0, &[0x51])], 1);
    assert!(verify_transparent_input(&tx, None, 0, &output(0, &exact)).is_ok()); // Extra stack permitted.
    // HASH160(5187) derived independently as RIPEMD160(SHA256(raw bytes));
    // redeem OP1 EQUAL consumes the saved scriptSig argument after its code
    // is popped. Not merely a self-contained redeem or a cleanstack assertion.
    let consumes_saved_stack = bytes("a91401b084353e301dad11492341307598f6822fd0c387");
    for (sig, accepted) in [("51025187", true), ("52025187", false)] {
        let tx = spend(&[(key, &bytes(sig), u32::MAX)], vec![output(0, &[0x51])], 0);
        assert_eq!(verify_transparent_input(&tx, None, 0, &output(0, &consumes_saved_stack)).is_ok(), accepted);
    }
}

#[test]
fn final_pool_amount_checks_are_signed_block_results_not_bounded_prefix_deltas() {
    for (parent, delta, expected) in [
        (1, -1, Ok(0)),
        (1, -2, Err(SproutLedgerError::ValueOutOfRange)),
        (MAX_MONEY, 1, Err(SproutLedgerError::ValueOutOfRange)),
        (0, -1, Err(SproutLedgerError::ValueOutOfRange)),
        (MAX_MONEY, -i128::from(MAX_MONEY), Ok(0)),
        (1, i128::MAX, Err(SproutLedgerError::ValueOutOfRange)),
        (1, i128::MIN, Err(SproutLedgerError::ValueOutOfRange)),
    ] {
        assert_eq!(final_money(parent, delta), expected);
    }
}

fn v3(template: &Transaction, branch: BranchId, expiry: u32) -> Transaction {
    TransactionData::<Authorized>::from_parts(
        TxVersion::V3, branch, template.lock_time(), expiry.into(),
        template.transparent_bundle().cloned(), template.sprout_bundle().cloned(), None, None,
    ).freeze().unwrap()
}

fn era_coinbase(height: u32, expiry: u32) -> Transaction {
    // Literal source testnet index11 (207500) and index15 (279999) outputs.
    let founder = if height < 265_635 {
        bytes("a91447498d569e268944c3b6993376009d369140e39a87")
    } else {
        bytes("a9142a71f51b268f74eb3ee5631090589bbf6239bc0c87")
    };
    let (prefix, length) = coinbase_height_prefix(height);
    let reward = changed(TxVersion::Sprout(1), 0, |bundle| {
        script_input(bundle, &prefix[..length], u32::MAX);
        bundle.vout = vec![output(1_000_000_000, &[0x51]), output(250_000_000, &founder)];
    });
    v3(&reward, BranchId::Overwinter, expiry)
}

#[test]
fn exact_era_branch_and_expiry_boundaries_include_coinbase_exemption_not_height_equality() {
    let sprout = spend(&[(([0x91; 32], 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    assert!(check_transaction(&sprout, 207_499, 1_500_000_000).is_ok());
    assert!(matches!(check_transaction(&sprout, 207_500, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    let tx = v3(&sprout, BranchId::Overwinter, 0);
    assert!(matches!(check_transaction(&tx, 207_499, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    for (height, expiry, expected) in [
        (207_500, 0, Ok(())), (207_500, 207_500, Ok(())),
        (207_501, 207_500, Err(SproutLedgerError::ExpiredTransaction)),
        (279_999, 499_999_999, Ok(())),
        (207_500, 500_000_000, Err(SproutLedgerError::InvalidTransaction)),
        (280_000, 0, Err(SproutLedgerError::UnsupportedTransaction)),
    ] {
        let tx = v3(&sprout, BranchId::Overwinter, expiry);
        assert_eq!(check_transaction(&tx, height, 1_500_000_000).map(|_| ()), expected);
    }
    for branch in [BranchId::Sprout, BranchId::Sapling] {
        let tx = v3(&sprout, branch, 0);
        assert!(matches!(check_transaction(&tx, 207_500, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    }
    for expiry in [0, 1, 207_499, 207_500, 207_501, 499_999_999] {
        assert_eq!(check_coinbase(&era_coinbase(207_500, expiry), 207_500, 1_500_000_000).unwrap().claimed, 1_250_000_000);
    }
    for expiry in [500_000_000, u32::MAX] {
        assert_eq!(check_coinbase(&era_coinbase(207_500, expiry), 207_500, 1_500_000_000), Err(SproutLedgerError::InvalidTransaction));
    }
    let parent = state();
    let delta = parent.stage_block(era_coinbase(279_999, 1), vec![], 279_999, 1_500_000_000).unwrap();
    assert_eq!((delta.issued, delta.transparent, delta.retained), (1_250_000_000, 1_250_000_000, 1_250_000_000));
    assert!(matches!(parent.stage_block(era_coinbase(280_000, 0), vec![], 280_000, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    let mut wrong_founder = era_coinbase(279_999, 0).transparent_bundle().unwrap().clone();
    wrong_founder.vout[1] = output(250_000_001, &bytes("a9142a71f51b268f74eb3ee5631090589bbf6239bc0c87"));
    let tx = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 0.into(), Some(wrong_founder), None, None, None).freeze().unwrap();
    assert_eq!(check_coinbase(&tx, 279_999, 1_500_000_000), Err(SproutLedgerError::MissingFoundersReward));
}

fn independently_signed_transparent(version: TxVersion, p2sh: bool, raw_type: u8) -> (Transaction, TxOut) {
    independently_signed_transparent_for_branch(version, if version == TxVersion::V3 { BranchId::Overwinter } else { BranchId::Sapling }, p2sh, raw_type)
}

fn independently_signed_transparent_for_branch(version: TxVersion, branch: BranchId, p2sh: bool, raw_type: u8) -> (Transaction, TxOut) {
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use zcash_primitives::transaction::{sighash::SignableInput, sighash_v4::v4_signature_hash};
    use zcash_transparent::sighash::{SignableInput as TransparentInput, SighashType};
    // Publicly known scalar1 is synthetic test data, never a wallet credential.
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = SecretKey::from_slice(&scalar).unwrap();
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, &key).serialize();
    let mut redeem = vec![33];
    redeem.extend_from_slice(&pubkey);
    redeem.push(0xac);
    let mut code = Script::default();
    code.0.0 = redeem.clone();
    let previous_script = if p2sh {
        let mut previous = vec![0xa9, 20];
        previous.extend_from_slice(&zcash_transparent::util::hash160::hash(&redeem));
        previous.push(0x87);
        previous
    } else {
        redeem.clone()
    };
    let prevout = output(100_002, &previous_script);
    let convert = |template: &Transaction| match version {
        TxVersion::V3 => v3(template, branch, 207_521),
        TxVersion::V4 => v4(template, branch, match branch { BranchId::Blossom => 903_799, BranchId::Heartwood => 1_028_499, BranchId::Canopy => 1_842_419, BranchId::Nu5 => 2_975_999, BranchId::Nu6 => 3_536_499, BranchId::Nu6_1 => 4_051_999, BranchId::Nu6_2 => 4_133_999, BranchId::Nu6_3 => 4_465_025, _ => 280_021 }),
        _ => panic!("independent ZIP143/243 signer fixture version"),
    };
    let unsigned = convert(&spend(&[(([0xa1; 32], 3), &[], 123)], vec![output(100_000, &[0x51])], 0));
    let input = TransparentInput::from_parts(unsigned.transparent_bundle().unwrap(), SighashType::from_raw(raw_type), 0, &code, prevout.script_pubkey(), prevout.value()).unwrap();
    // Independent maintained implementation signs; local hashing only verifies.
    let digest = v4_signature_hash(&unsigned, &SignableInput::Transparent(input));
    let message = Message::from_digest_slice(digest.as_bytes()).unwrap();
    let mut signature = secp.sign_ecdsa(&message, &key);
    if raw_type == 0x41 {
        // Consensus does not apply LOW_S policy. Original full-order n-S is
        // another valid ECDSA signature over the independently signed digest.
        let order = bytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut compact = signature.serialize_compact();
        let mut borrow = 0_u16;
        for index in (0..32).rev() {
            let value = 256 + u16::from(order[index]) - u16::from(compact[32 + index]) - borrow;
            compact[32 + index] = value as u8;
            borrow = u16::from(value < 256);
        }
        assert_eq!(borrow, 0);
        signature = secp256k1::ecdsa::Signature::from_compact(&compact).unwrap();
    }
    let mut signature = signature.serialize_der().to_vec();
    signature.push(raw_type);
    let mut sig = vec![signature.len() as u8];
    sig.extend_from_slice(&signature);
    if p2sh {
        sig.push(redeem.len() as u8);
        sig.extend_from_slice(&redeem);
    }
    let signed = convert(&spend(&[(([0xa1; 32], 3), &sig, 123)], vec![output(100_000, &[0x51])], 0));
    (signed, prevout)
}

#[test]
fn maintained_independently_signed_v3_checks_actual_prevout_amount_and_p2sh_redeem_code() {
    for p2sh in [false, true] {
        for raw_type in [0, 1, 2, 3, 0x81, 0x82, 0x83, 0x41] {
            let (signed, prevout) = independently_signed_transparent(TxVersion::V3, p2sh, raw_type);
            let hashes = TransactionSignatureHash::Overwinter(OverwinterSignatureHash::new(&signed).unwrap());
            assert_eq!(verify_transparent_input(&signed, Some(&hashes), 0, &prevout), Ok(()));
            for amount in [100_001, 100_003] {
                let wrong = output(amount, &prevout.script_pubkey().0.0);
                assert_eq!(verify_transparent_input(&signed, Some(&hashes), 0, &wrong), Err(SproutLedgerError::InvalidTransparentScript));
            }
            let mut wrong_script = prevout.script_pubkey().0.0.clone();
            if p2sh { wrong_script[2] ^= 1; } else { wrong_script.insert(0, 0x61); }
            assert_eq!(verify_transparent_input(&signed, Some(&hashes), 0, &output(100_002, &wrong_script)), Err(SproutLedgerError::InvalidTransparentScript));
            let changed = v3(&signed, BranchId::Overwinter, 207_522);
            let hashes = TransactionSignatureHash::Overwinter(OverwinterSignatureHash::new(&changed).unwrap());
            assert_eq!(verify_transparent_input(&changed, Some(&hashes), 0, &prevout), Err(SproutLedgerError::InvalidTransparentScript));
            let wrong_branch = v3(&signed, BranchId::Sapling, 207_521);
            assert!(matches!(check_transaction(&wrong_branch, 207_500, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
            let mut corrupted = signed.transparent_bundle().unwrap().clone();
            let mut sig = corrupted.vin[0].script_sig().clone();
            sig.0.0[10] ^= 1;
            corrupted.vin[0] = TxIn::from_parts(corrupted.vin[0].prevout().clone(), sig, 123);
            let corrupted = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 207_521_u32.into(), Some(corrupted), None, None, None).freeze().unwrap();
            let hashes = TransactionSignatureHash::Overwinter(OverwinterSignatureHash::new(&corrupted).unwrap());
            assert_eq!(verify_transparent_input(&corrupted, Some(&hashes), 0, &prevout), Err(SproutLedgerError::InvalidTransparentScript));
            let mut parent = state();
            fund(&mut parent, ([0xa1; 32], 3), 100_002, &prevout.script_pubkey().0.0, 0, false);
            let delta = parent.stage_block(era_coinbase(207_500, 0), vec![signed], 207_500, 1_500_000_000).unwrap();
            assert_eq!((delta.fees, delta.issued), (2, 1_250_100_000));
            parent.commit(delta);
            assert!(parent.utxo(&[0xa1; 32], 3).is_none());
            assert_eq!((parent.transparent_balance(), parent.utxo_balance(), parent.issued_supply()), (1_250_100_000, 1_250_100_000, 1_250_100_000));
            assert_eq!(parent.tip().height(), 0); // Isolated stage, not a connected block.
        }
    }
}

type CoinSnapshot = (([u8; 32], u32), TxOut, u32, bool);
type FrontierSnapshot = (u64, [u8; 32], Vec<[u8; 32]>);
type AnchorSnapshot = ([u8; 32], Option<FrontierSnapshot>);

#[derive(Debug, PartialEq)]
struct OwnedState {
    headers: HeaderChain,
    coins: Vec<CoinSnapshot>,
    nullifiers: [BTreeSet<[u8; 32]>; 4],
    anchors: Vec<AnchorSnapshot>,
    sapling_tree: Frontier<SaplingNode, 32>,
    sapling_anchors: BTreeSet<[u8; 32]>,
    orchard_tree: Frontier<MerkleHashOrchard, 32>,
    orchard_anchors: BTreeSet<[u8; 32]>,
    ironwood_tree: Frontier<MerkleHashOrchard, 32>,
    ironwood_anchors: BTreeSet<[u8; 32]>,
    roots: [[u8; 32]; 4],
    transparent: u64,
    retained: u64,
    shielded: [u64; 4],
    deferred: u64,
    issued: u64,
    history: Option<[u8; 32]>,
    chain_history: Option<String>,
    chain_history_v2: Option<String>,
    chain_history_v3: Option<String>,
}

fn owned_state(parent: &SproutTestnetLedger) -> OwnedState {
    OwnedState {
        headers: parent.headers.clone(),
        coins: parent.utxos.iter().map(|(key, coin)| (*key, coin.output.clone(), coin.created_height, coin.is_coinbase)).collect(),
        nullifiers: parent.nullifiers.clone(),
        anchors: parent.sprout_anchors.iter().map(|(root, frontier)| {
            (*root, frontier.value().map(|value| (u64::from(value.position()), value.leaf().0, value.ommers().iter().map(|node| node.0).collect())))
        }).collect(),
        sapling_tree: parent.sapling_tree.clone(), sapling_anchors: parent.sapling_anchors.clone(),
        orchard_tree: parent.orchard_tree.clone(), orchard_anchors: parent.orchard_anchors.clone(),
        ironwood_tree: parent.ironwood_tree.clone(), ironwood_anchors: parent.ironwood_anchors.clone(),
        roots: parent.shielded_roots, transparent: parent.transparent_balance,
        retained: parent.utxo_balance, shielded: parent.shielded_balances,
        deferred: parent.deferred_balance, issued: parent.issued_supply, history: parent.history_root,
        chain_history: parent.chain_history.as_ref().map(|history| format!("{history:?}")),
        chain_history_v2: parent.chain_history_v2.as_ref().map(|history| format!("{history:?}")),
        chain_history_v3: parent.chain_history_v3.as_ref().map(|history| format!("{history:?}")),
    }
}

fn original_v3() -> Transaction {
    let raw = bytes(overwinter_primary::MINED_V3_TX_HEX);
    let mut remaining = raw.as_slice();
    let tx = Transaction::read(&mut remaining, BranchId::Overwinter).unwrap();
    assert!(remaining.is_empty());
    tx
}

fn isolated_v3_sprout_parent() -> SproutTestnetLedger {
    let mut parent = state();
    let tx = original_v3();
    let anchor = *tx.sprout_bundle().unwrap().joinsplits[0].anchor();
    // TEST ONLY: inject anchor availability and pool value to exercise ordered
    // staging/atomicity. This artificial frontier is not the mined predecessor
    // frontier; no valid207500 checkpoint or connected history is claimed.
    parent.sprout_anchors.insert(anchor, Frontier::empty());
    parent.shielded_balances[0] = 10_000;
    parent.issued_supply = 10_000;
    fund(&mut parent, ([0xb1; 32], 0), 20, &[0x51], 0, false);
    parent
}

#[test]
fn recorded_v3_checks_crypto_and_money_in_isolated_stage_without_authenticating_injected_state() {
    let mut parent = isolated_v3_sprout_parent();
    let before = owned_state(&parent);
    let tx = original_v3();
    let nullifiers = *tx.sprout_bundle().unwrap().joinsplits[0].nullifiers();
    let delta = parent.stage_block(era_coinbase(207_501, 0), vec![tx], 207_501, 1_500_000_000).unwrap();
    assert_eq!((delta.fees, delta.issued, delta.sprout), (10_000, 1_250_000_020, 0));
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.transparent_balance(), parent.utxo_balance(), parent.issued_supply()), (1_250_000_020, 1_250_000_020, 1_250_000_020));
    assert_eq!(parent.shielded_balance(ShieldedPool::Sprout), 0);
    assert_eq!(parent.sprout_tree_size(), 2);
    assert_eq!(parent.nullifier_count(ShieldedPool::Sprout), 2);
    for nullifier in nullifiers { assert!(parent.contains_nullifier(ShieldedPool::Sprout, &nullifier)); }
    assert_eq!(parent.tip().height(), 0);
}

#[test]
fn late_v3_format_expiry_script_value_anchor_and_crypto_failures_preserve_every_owned_field() {
    let parent = isolated_v3_sprout_parent();
    let before = owned_state(&parent);
    let good = || v3(&spend(&[(([0xb1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Overwinter, 0);
    for (offset, expected) in [
        (overwinter_offsets::MINED_V3_SIGNATURE_OFFSET, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (overwinter_offsets::MINED_V3_CIPHERTEXT_OFFSET, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (overwinter_offsets::MINED_V3_PROOF_OFFSET + 1, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (overwinter_offsets::MINED_V3_NULLIFIER_OFFSET, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (overwinter_offsets::MINED_V3_ANCHOR_OFFSET, SproutLedgerError::UnknownSproutAnchor),
        (overwinter_offsets::MINED_V3_LOCK_TIME_OFFSET, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (overwinter_offsets::MINED_V3_EXPIRY_HEIGHT_OFFSET, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (overwinter_offsets::MINED_V3_PUBKEY_OFFSET, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
    ] {
        let mut raw = bytes(overwinter_primary::MINED_V3_TX_HEX);
        raw[offset] ^= 1;
        let tx = Transaction::read(raw.as_slice(), BranchId::Overwinter).unwrap();
        assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![good(), tx], 207_501, 1_500_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
    let earlier_id: [u8; 32] = good().txid().into();
    for (expiry, value, script, expected) in [
        (0, 18, &[0x6a][..], SproutLedgerError::InvalidTransparentScript),
        (207_500, 18, &[][..], SproutLedgerError::ExpiredTransaction),
        (500_000_000, 18, &[][..], SproutLedgerError::InvalidTransaction),
        (0, 20, &[][..], SproutLedgerError::NegativeFee),
    ] {
        let tx = v3(&spend(&[((earlier_id, 0), script, u32::MAX)], vec![output(value, &[0x51])], 0), BranchId::Overwinter, expiry);
        assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![good(), tx], 207_501, 1_500_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
    let wrong_era = spend(&[((earlier_id, 0), &[], u32::MAX)], vec![output(18, &[0x51])], 0);
    assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![good(), wrong_era], 207_501, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
    let wrong_branch = v3(&spend(&[((earlier_id, 0), &[], u32::MAX)], vec![output(18, &[0x51])], 0), BranchId::Sapling, 0);
    assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![good(), wrong_branch], 207_501, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
    let tx = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), good().transparent_bundle().cloned(), None, None, None).freeze().unwrap();
    assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![good(), tx], 207_501, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
    assert!(matches!(parent.stage_block(era_coinbase(280_000, 0), vec![], 280_000, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn bad_v3_actual_prevamount_rejects_late_without_spending_earlier_outputs() {
    for p2sh in [false, true] {
        let (tx, prevout) = independently_signed_transparent(TxVersion::V3, p2sh, 1);
        for amount in [100_001, 100_003] {
            let mut parent = isolated_v3_sprout_parent();
            fund(&mut parent, ([0xa1; 32], 3), amount, &prevout.script_pubkey().0.0, 0, false);
            let before = owned_state(&parent);
            let good = v3(&spend(&[(([0xb1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Overwinter, 0);
            let tx = v3(&tx, BranchId::Overwinter, 207_521);
            assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![good, tx], 207_501, 1_500_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn overwinter_preserves_p2sh_cltv_der_and_disabled_opcode_rules() {
    let key = ([0xc1; 32], 0);
    for (lock, sequence, accepted) in [(0, 0, false), (1, 0, true), (1, u32::MAX, false)] {
        let tx = v3(&spend(&[(key, &bytes("0251b1"), sequence)], vec![output(0, &[0x51])], lock), BranchId::Overwinter, 0);
        let hashes = TransactionSignatureHash::Overwinter(OverwinterSignatureHash::new(&tx).unwrap());
        assert_eq!(verify_transparent_input(&tx, Some(&hashes), 0, &output(0, &bytes("a914c5b93064159b3b2d6ab506a41b1f50463771b98887"))).is_ok(), accepted);
    }
    let pubkey_not = bytes("21038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508ac91");
    for (sig, accepted) in [(vec![0x51], false), (vec![0], true)] {
        let tx = v3(&spend(&[(key, &sig, u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Overwinter, 0);
        let hashes = TransactionSignatureHash::Overwinter(OverwinterSignatureHash::new(&tx).unwrap());
        assert_eq!(verify_transparent_input(&tx, Some(&hashes), 0, &output(0, &pubkey_not)).is_ok(), accepted);
    }
    let tx = v3(&spend(&[(key, &[0], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Overwinter, 0);
    let hashes = TransactionSignatureHash::Overwinter(OverwinterSignatureHash::new(&tx).unwrap());
    assert_eq!(verify_transparent_input(&tx, Some(&hashes), 0, &output(0, &[0x63, 0xab, 0x67, 0x51, 0x68])), Err(SproutLedgerError::InvalidTransparentScript));
}

#[test]
fn overwinter_preserves_all_coinbase_input_maturity_and_shielding_protection_checks() {
    let first = ([0xc2; 32], 0);
    let second = ([0xc3; 32], 0);
    let ordinary = ([0xc4; 32], 0);
    let mut parent = state();
    fund(&mut parent, first, 2, &[0x51], 207_401, true);
    fund(&mut parent, second, 2, &[0x51], 207_402, true);
    fund(&mut parent, ordinary, 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let anchor = parent.shielded_roots[0];
    for (height, key, expected) in [
        (207_500, first, SproutLedgerError::ImmatureCoinbase),
        (207_501, first, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (207_501, second, SproutLedgerError::ImmatureCoinbase),
        (207_502, second, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
    ] {
        let unsigned = with_joinsplits(spend(&[(ordinary, &[], u32::MAX), (key, &[], u32::MAX)], vec![], 0), vec![joinsplit(anchor, 1, commitments(0), 3, 0)]);
        let tx = v3(&unsigned, BranchId::Overwinter, 0);
        assert_eq!(parent.stage_transaction(tx, height, 1_500_000_000, &mut BlockDelta::new(&parent)), Err(expected));
        assert_eq!(owned_state(&parent), before);
    }
    for script in [&[][..], &[0x6a][..], &[0x51][..]] {
        let unsigned = with_joinsplits(spend(&[(ordinary, &[], u32::MAX), (first, &[], u32::MAX)], vec![output(0, script)], 0), vec![joinsplit(anchor, 1, commitments(0), 3, 0)]);
        let tx = v3(&unsigned, BranchId::Overwinter, 0);
        assert_eq!(parent.stage_transaction(tx, 207_501, 1_500_000_000, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::UnshieldedCoinbaseSpend));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn overwinter_preserves_pruned_claims_underclaims_fees_and_exact_founder_output() {
    for (burn, issued, retained) in [(1, 1_250_000_000, 1_249_999_999), (0, 1_249_999_999, 1_249_999_999)] {
        let template = era_coinbase(207_500, 0);
        let mut bundle = template.transparent_bundle().unwrap().clone();
        bundle.vout[0] = output(999_999_999, &[0x51]);
        bundle.vout.push(output(burn, &[0x6a]));
        let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
        let mut parent = state();
        let delta = parent.stage_block(coinbase, vec![], 207_500, 1_500_000_000).unwrap();
        parent.commit(delta);
        assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance()), (issued, issued, retained));
        assert_eq!(parent.utxo_count(), 2);
    }
    for founder in [250_000_000, 250_000_001] {
        let mut bundle = era_coinbase(207_500, 0).transparent_bundle().unwrap().clone();
        bundle.vout[0] = output(1_000_000_001, &[0x51]);
        bundle.vout[1] = output(founder, &bytes("a91447498d569e268944c3b6993376009d369140e39a87"));
        let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
        let parent = state();
        let before = owned_state(&parent);
        let expected = if founder == 250_000_000 { SproutLedgerError::CoinbaseRewardExceeded } else { SproutLedgerError::MissingFoundersReward };
        assert!(matches!(parent.stage_block(coinbase, vec![], 207_500, 1_500_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn overwinter_transaction_size_and_block_sigop_limits_are_unchanged() {
    let key = ([0xc5; 32], 0);
    // Header8 + vin count1/input41 + vout count1/value8/length5 + lock4 +
    // expiry4 + JoinSplit count1 =73 bytes outside this output script payload.
    for (script_bytes, expected) in [(99_927, Ok(())), (99_928, Err(SproutLedgerError::TransactionTooLarge))] {
        let tx = v3(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0x51; script_bytes])], 0), BranchId::Overwinter, 0);
        assert_eq!(check_transaction(&tx, 207_500, 1_500_000_000).map(|_| ()), expected);
    }
    for (sigops, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let before = owned_state(&parent);
        let tx = v3(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; sigops])], 0), BranchId::Overwinter, 0);
        let mut coinbase = era_coinbase(207_500, 0).transparent_bundle().unwrap().clone();
        coinbase.vout[0] = output(1_000_000_000, &[0xac]);
        let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 0.into(), Some(coinbase), None, None, None).freeze().unwrap();
        let result = parent.stage_block(coinbase, vec![tx], 207_500, 1_500_000_000);
        if accepted {
            assert_eq!(result.unwrap().sigops, 20_000);
        } else {
            assert!(matches!(result, Err(SproutLedgerError::TooManySigops)));
        }
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn defined_overwinter_single_without_output_can_verify_a_real_signature() {
    use secp256k1::{Message, Secp256k1, SecretKey};
    use zcash_primitives::transaction::{sighash::SignableInput, sighash_v4::v4_signature_hash};
    use zcash_transparent::sighash::{SignableInput as TransparentInput, SighashType};
    let (_, prevout) = independently_signed_transparent(TxVersion::V3, false, 1);
    let unsigned = v3(&spend(&[(([0xd1; 32], 1), &[], u32::MAX)], vec![], 0), BranchId::Overwinter, 0);
    for raw_type in [3_u8, 0x83] {
        let code = prevout.script_pubkey();
        let input = TransparentInput::from_parts(unsigned.transparent_bundle().unwrap(), SighashType::from_raw(raw_type), 0, code, code, prevout.value()).unwrap();
        let expected = v4_signature_hash(&unsigned, &SignableInput::Transparent(input));
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let key = SecretKey::from_slice(&scalar).unwrap();
        let message = Message::from_digest_slice(expected.as_bytes()).unwrap();
        let mut signature = Secp256k1::new().sign_ecdsa(&message, &key).serialize_der().to_vec();
        signature.push(raw_type);
        let mut sig = vec![signature.len() as u8];
        sig.extend_from_slice(&signature);
        let tx = v3(&spend(&[(([0xd1; 32], 1), &sig, u32::MAX)], vec![], 0), BranchId::Overwinter, 0);
        let hashes = TransactionSignatureHash::Overwinter(OverwinterSignatureHash::new(&tx).unwrap());
        assert_eq!(verify_transparent_input(&tx, Some(&hashes), 0, &prevout), Ok(()));
        // A crypto-valid hash/script is not an exception to the transaction's
        // required nonempty outputs absent JoinSplits. No accepted ledger fact.
        assert!(matches!(check_transaction(&tx, 207_500, 1_500_000_000), Err(SproutLedgerError::InvalidTransaction)));
    }
}

#[test]
fn overwinter_keeps_ordered_spends_duplicate_outpoints_and_parent_wide_bip30() {
    let mut parent = state();
    let key = ([0xd2; 32], 0);
    fund(&mut parent, key, 100, &[0x51], 0, false);
    let before = owned_state(&parent);
    let first = || v3(&spend(&[(key, &[], u32::MAX)], vec![output(80, &[0x51])], 0), BranchId::Overwinter, 0);
    let first_id: [u8; 32] = first().txid().into();
    let second = || v3(&spend(&[((first_id, 0), &[], u32::MAX)], vec![output(70, &[0x51])], 0), BranchId::Overwinter, 0);
    assert!(matches!(parent.stage_block(era_coinbase(207_500, 0), vec![second(), first()], 207_500, 1_500_000_000), Err(SproutLedgerError::MissingTransparentInput)));
    assert!(matches!(parent.stage_block(era_coinbase(207_500, 0), vec![first(), second(), second()], 207_500, 1_500_000_000), Err(SproutLedgerError::MissingTransparentInput)));
    let duplicate = v3(&spend(&[(key, &[], u32::MAX), (key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Overwinter, 0);
    assert!(matches!(check_transaction(&duplicate, 207_500, 1_500_000_000), Err(SproutLedgerError::DuplicateTransparentInput)));
    assert_eq!(owned_state(&parent), before);
    let second_id: [u8; 32] = second().txid().into();
    let delta = parent.stage_block(era_coinbase(207_500, 0), vec![first(), second()], 207_500, 1_500_000_000).unwrap();
    assert_eq!(delta.fees, 30);
    parent.commit(delta);
    assert!(parent.utxo(&key.0, key.1).is_none());
    assert!(parent.utxo(&first_id, 0).is_none());
    assert_eq!(u64::from(parent.utxo(&second_id, 0).unwrap().output().value()), 70);
    assert_eq!((parent.transparent_balance(), parent.issued_supply(), parent.utxo_balance()), (1_250_000_070, 1_250_000_070, 1_250_000_070));
    let mut parent = state();
    fund(&mut parent, key, 100, &[0x51], 0, false);
    fund(&mut parent, (first_id, 7), 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let consume_high = v3(&spend(&[((first_id, 7), &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Overwinter, 0);
    assert!(matches!(parent.stage_block(era_coinbase(207_500, 0), vec![consume_high, first()], 207_500, 1_500_000_000), Err(SproutLedgerError::UnspentTransactionOverwrite)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn overwinter_enforces_transaction_finality_at_owned_successor_height_and_candidate_time() {
    let key = ([0xd3; 32], 0);
    for (lock, sequence, time, expected) in [
        (207_499, 0, 1_500_000_000, Ok(())),
        (207_500, 0, 1_500_000_000, Err(SproutLedgerError::NonfinalTransaction)),
        (207_500, u32::MAX, 1_500_000_000, Ok(())),
        (1_500_000_000, 0, 1_500_000_001, Ok(())),
        (1_500_000_000, 0, 1_500_000_000, Err(SproutLedgerError::NonfinalTransaction)),
    ] {
        let tx = v3(&spend(&[(key, &[], sequence)], vec![output(0, &[0x51])], lock), BranchId::Overwinter, 0);
        assert_eq!(check_transaction(&tx, 207_500, time).map(|_| ()), expected);
    }
}

#[test]
fn late_phgr_equation_failure_after_historically_valid_v3_signature_cannot_commit_state() {
    let parent = isolated_v3_sprout_parent();
    let before = owned_state(&parent);
    let source = original_v3();
    let mut bundle = source.sprout_bundle().unwrap().clone();
    bundle.joinsplit_pubkey = [0; 32];
    bundle.joinsplit_pubkey[0] = 1;
    // Original libsodium identity-A tuple passes the historical signature
    // stage, but altered key changes PHGR h_sig. No signature check is skipped.
    bundle.joinsplit_sig = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000").try_into().unwrap();
    let tx = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 207_521_u32.into(), None, Some(bundle), None, None).freeze().unwrap();
    let good = v3(&spend(&[(([0xb1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Overwinter, 0);
    assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![good, tx], 207_501, 1_500_000_000), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutProof { index: 0, error: crate::sprout::LegacyError::InvalidProof }))));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn overwinter_checks_live_nullifiers_against_historical_anchors_and_every_description() {
    let mut parent = isolated_v3_sprout_parent();
    let original = original_v3();
    let bundle = original.sprout_bundle().unwrap();
    parent.nullifiers[0].insert(bundle.joinsplits[0].nullifiers()[0]);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![original_v3()], 207_501, 1_500_000_000), Err(SproutLedgerError::SpentSproutNullifier)));
    assert_eq!(owned_state(&parent), before);
    let parent = isolated_v3_sprout_parent();
    let before = owned_state(&parent);
    let mut duplicated = bundle.clone();
    duplicated.joinsplits.push(duplicated.joinsplits[0].clone());
    let tx = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 207_521_u32.into(), None, Some(duplicated), None, None).freeze().unwrap();
    assert!(matches!(parent.stage_block(era_coinbase(207_501, 0), vec![tx], 207_501, 1_500_000_000), Err(SproutLedgerError::SpentSproutNullifier)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn overwinter_founder_index_changes_at_the_original_17709_block_boundary() {
    for (height, correct, wrong) in [
        (265_634, "a914a71e4588c50c86f4669e0da43db37cbd7428a9f287", "a9142a71f51b268f74eb3ee5631090589bbf6239bc0c87"),
        (265_635, "a9142a71f51b268f74eb3ee5631090589bbf6239bc0c87", "a914a71e4588c50c86f4669e0da43db37cbd7428a9f287"),
    ] {
        for (founder, accepted) in [(correct, true), (wrong, false)] {
            let mut coinbase = era_coinbase(height, 0).transparent_bundle().unwrap().clone();
            coinbase.vout[1] = output(250_000_000, &bytes(founder));
            let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 0.into(), Some(coinbase), None, None, None).freeze().unwrap();
            let result = check_coinbase(&coinbase, height, 1_500_000_000);
            if accepted {
                assert_eq!(result.unwrap().claimed, 1_250_000_000);
            } else {
                assert_eq!(result, Err(SproutLedgerError::MissingFoundersReward));
            }
        }
    }
}

#[test]
fn independent_v3_signatures_use_each_original_input_index_sequence_and_amount() {
    independently_signed_multiinput(TxVersion::V3);
}

#[test]
fn independent_v4_signatures_use_each_original_input_index_sequence_and_amount() {
    independently_signed_multiinput(TxVersion::V4);
}

fn independently_signed_multiinput(version: TxVersion) {
    use secp256k1::{Message, Secp256k1, SecretKey};
    use zcash_primitives::transaction::{sighash::SignableInput, sighash_v4::v4_signature_hash};
    use zcash_transparent::sighash::{SignableInput as TransparentInput, SighashType};
    let (branch, expiry, height) = if version == TxVersion::V3 { (BranchId::Overwinter, 207_521_u32, 207_500) } else { (BranchId::Sapling, 280_021, 280_000) };
    let (_, source_prevout) = independently_signed_transparent(TxVersion::V3, false, 1);
    let prevouts = [output(100_002, &source_prevout.script_pubkey().0.0), output(200_004, &source_prevout.script_pubkey().0.0)];
    let keys = [([0xd4; 32], 3), ([0xd5; 32], 7)];
    let template = spend(&[(keys[0], &[], 123), (keys[1], &[], 456)], vec![output(300_000, &[0x51])], 0);
    let unsigned = TransactionData::<Authorized>::from_parts(version, branch, 0, expiry.into(), template.transparent_bundle().cloned(), None, None, None).freeze().unwrap();
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = SecretKey::from_slice(&scalar).unwrap();
    let secp = Secp256k1::new();
    let mut bundle = unsigned.transparent_bundle().unwrap().clone();
    for (index, raw_type) in [(0, 1_u8), (1, 0x81_u8)] {
        let previous = &prevouts[index];
        let input = TransparentInput::from_parts(unsigned.transparent_bundle().unwrap(), SighashType::from_raw(raw_type), index, previous.script_pubkey(), previous.script_pubkey(), previous.value()).unwrap();
        let expected = v4_signature_hash(&unsigned, &SignableInput::Transparent(input));
        let mut signature = secp.sign_ecdsa(&Message::from_digest_slice(expected.as_bytes()).unwrap(), &key).serialize_der().to_vec();
        signature.push(raw_type);
        let mut sig = Script::default();
        sig.0.0.push(signature.len() as u8);
        sig.0.0.extend_from_slice(&signature);
        bundle.vin[index] = TxIn::from_parts(bundle.vin[index].prevout().clone(), sig, bundle.vin[index].sequence());
    }
    let tx = TransactionData::<Authorized>::from_parts(version, branch, 0, expiry.into(), Some(bundle), None, None, None).freeze().unwrap();
    let hashes = if version == TxVersion::V3 { TransactionSignatureHash::Overwinter(OverwinterSignatureHash::new(&tx).unwrap()) } else { TransactionSignatureHash::Sapling(SaplingSignatureHash::new(&tx).unwrap()) };
    for index in 0..2 {
        assert_eq!(verify_transparent_input(&tx, Some(&hashes), index, &prevouts[index]), Ok(()));
        assert_eq!(verify_transparent_input(&tx, Some(&hashes), index, &prevouts[1 - index]), Err(SproutLedgerError::InvalidTransparentScript));
    }
    let mut parent = state();
    for index in 0..2 { fund(&mut parent, keys[index], u64::from(prevouts[index].value()), &prevouts[index].script_pubkey().0.0, 0, false); }
    let coinbase = if version == TxVersion::V3 { era_coinbase(height, 0) } else { sapling_coinbase(height, 0) };
    let delta = parent.stage_block(coinbase, vec![tx], height, 1_500_000_000).unwrap();
    assert_eq!((delta.fees, delta.issued), (6, 1_250_300_000));
    parent.commit(delta);
    for key in keys { assert!(parent.utxo(&key.0, key.1).is_none()); }
    assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance()), (1_250_300_000, 1_250_300_000, 1_250_300_000));
}

#[test]
fn finite_testnet_extensions_stop_at_published_nu7_boundary() {
    assert_eq!(supported_branch(279_999), Ok(BranchId::Overwinter));
    assert_eq!(supported_branch(280_000), Ok(BranchId::Sapling));
    assert_eq!(supported_branch(583_999), Ok(BranchId::Sapling));
    assert_eq!(supported_branch(584_000), Ok(BranchId::Blossom));
    assert_eq!(supported_branch(903_799), Ok(BranchId::Blossom));
    assert_eq!(supported_branch(903_800), Ok(BranchId::Heartwood));
    assert_eq!(supported_branch(1_028_499), Ok(BranchId::Heartwood));
    assert_eq!(supported_branch(1_028_500), Ok(BranchId::Canopy));
    assert_eq!(supported_branch(1_842_419), Ok(BranchId::Canopy));
    assert_eq!(supported_branch(1_842_420), Ok(BranchId::Nu5));
    assert_eq!(supported_branch(2_975_999), Ok(BranchId::Nu5));
    assert_eq!(supported_branch(2_976_000), Ok(BranchId::Nu6));
    assert_eq!(supported_branch(3_536_499), Ok(BranchId::Nu6));
    assert_eq!(supported_branch(3_536_500), Ok(BranchId::Nu6_1));
    assert_eq!(supported_branch(4_048_499), Ok(BranchId::Nu6_1));
    assert_eq!(supported_branch(4_048_500), Ok(BranchId::Nu6_1));
    assert_eq!(supported_branch(4_051_999), Ok(BranchId::Nu6_1));
    assert_eq!(supported_branch(4_052_000), Ok(BranchId::Nu6_2));
    assert_eq!(supported_branch(4_133_999), Ok(BranchId::Nu6_2));
    assert_eq!(supported_branch(4_134_000), Ok(BranchId::Nu6_3));
    assert_eq!(supported_branch(4_465_025), Ok(BranchId::Nu6_3));
    assert_eq!(supported_branch(4_465_026), Err(SproutLedgerError::UnsupportedEra));
    assert_eq!(supported_branch(u32::MAX), Err(SproutLedgerError::UnsupportedEra));
}

#[path = "../tests/fixtures/sapling-mainnet-419202.rs"]
mod sapling_primary;
use crate::sprout_groth_fixture;

fn v4(template: &Transaction, branch: BranchId, expiry: u32) -> Transaction {
    TransactionData::<Authorized>::from_parts(
        TxVersion::V4, branch, template.lock_time(), expiry.into(),
        template.transparent_bundle().cloned(), template.sprout_bundle().cloned(),
        template.sapling_bundle().cloned(), None,
    ).freeze().unwrap()
}

fn sapling_coinbase(height: u32, expiry: u32) -> Transaction {
    let (prefix, length) = coinbase_height_prefix(height);
    let reward = changed(TxVersion::Sprout(1), 0, |bundle| {
        script_input(bundle, &prefix[..length], u32::MAX);
        bundle.vout = vec![output(1_000_000_000, &[0x51]), output(250_000_000, &founders_script(height))];
    });
    v4(&reward, BranchId::Sapling, expiry)
}

fn recorded_sapling() -> Transaction {
    let raw = bytes(sapling_primary::TRANSACTION_HEX);
    let mut reader = raw.as_slice();
    let transaction = Transaction::read(&mut reader, BranchId::Sapling).unwrap();
    assert!(reader.is_empty());
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).unwrap();
    assert_eq!(canonical, raw);
    transaction
}

fn isolated_sapling_parent() -> SproutTestnetLedger {
    let mut parent = state();
    let transaction = recorded_sapling();
    let bundle = transaction.sapling_bundle().unwrap();
    // TEST ONLY: primary proof material plus injected historical anchor/value.
    // This is not the actual mined predecessor frontier or connected history.
    parent.sapling_anchors.insert(bundle.shielded_spends()[0].anchor().to_bytes());
    parent.shielded_balances[1] = i64::from(*bundle.value_balance()) as u64;
    parent.issued_supply = parent.shielded_balances[1];
    fund(&mut parent, ([0xe1; 32], 0), 20, &[0x51], 0, false);
    parent
}

#[test]
fn primary_activation_coinbases_check_actual_empty_header_root_without_predecessor_authority() {
    let parent = state();
    let before = owned_state(&parent);
    for (raw, height) in [
        (include_bytes!("../tests/fixtures/testnet-sapling-block-279999.bin").as_slice(), 279_999),
        (include_bytes!("../tests/fixtures/testnet-sapling-block-280000.bin").as_slice(), 280_000),
        (include_bytes!("../tests/fixtures/testnet-sapling-block-280001.bin").as_slice(), 280_001),
    ] {
        let parsed = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap();
        let root = parsed.block().header().final_sapling_root;
        let time = parsed.block().header().time;
        let (_, transactions) = parsed.into_block().into_parts();
        assert!(transactions.tail.is_empty());
        let delta = parent.stage_block(transactions.head, transactions.tail, height, time).unwrap();
        assert_eq!((delta.fees, delta.issued, delta.sapling), (0, 1_250_000_000, 0));
        assert_eq!(delta.sapling_tree.tree_size(), 0);
        assert_eq!(delta.sapling_tree.root().to_bytes(), root);
        assert_eq!(delta.check_sapling_root(height, &root), Ok(()));
        let mut wrong = root;
        wrong[0] ^= 1;
        assert_eq!(delta.check_sapling_root(height, &wrong), if height < 280_000 { Ok(()) } else { Err(SproutLedgerError::WrongSaplingRoot) });
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn v4_context_requires_actual_height_branch_and_original_expiry_rules() {
    let template = spend(&[(([0xe2; 32], 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    for (height, branch, expiry, expected) in [
        (279_999, BranchId::Sapling, 0, Err(SproutLedgerError::UnsupportedTransaction)),
        (280_000, BranchId::Sapling, 0, Ok(())),
        (280_000, BranchId::Sapling, 280_000, Ok(())),
        (280_001, BranchId::Sapling, 280_000, Err(SproutLedgerError::ExpiredTransaction)),
        (583_999, BranchId::Sapling, 499_999_999, Ok(())),
        (280_000, BranchId::Blossom, 0, Err(SproutLedgerError::UnsupportedTransaction)),
        (280_000, BranchId::Sapling, 500_000_000, Err(SproutLedgerError::InvalidTransaction)),
        (584_000, BranchId::Blossom, 0, Ok(())),
        (584_000, BranchId::Sapling, 0, Err(SproutLedgerError::UnsupportedTransaction)),
        (583_999, BranchId::Blossom, 0, Err(SproutLedgerError::UnsupportedTransaction)),
        (584_000, BranchId::Blossom, 584_000, Ok(())),
        (584_001, BranchId::Blossom, 584_000, Err(SproutLedgerError::ExpiredTransaction)),
        (903_799, BranchId::Blossom, 499_999_999, Ok(())),
        (584_000, BranchId::Blossom, 500_000_000, Err(SproutLedgerError::InvalidTransaction)),
        (903_800, BranchId::Heartwood, 0, Ok(())),
        (1_028_499, BranchId::Heartwood, 0, Ok(())),
        (1_028_500, BranchId::Canopy, 0, Ok(())),
        (1_842_419, BranchId::Canopy, 0, Ok(())),
        (1_842_420, BranchId::Nu5, 0, Ok(())),
        (2_976_000, BranchId::Nu6, 0, Ok(())),
        (3_536_499, BranchId::Nu6, 0, Ok(())),
        (3_536_500, BranchId::Nu6_1, 0, Ok(())),
        (4_051_999, BranchId::Nu6_1, 0, Ok(())),
        (4_052_000, BranchId::Nu6_2, 0, Ok(())),
        (4_133_999, BranchId::Nu6_2, 0, Ok(())),
        (4_134_000, BranchId::Nu6_3, 0, Ok(())),
        (4_465_025, BranchId::Nu6_3, 0, Ok(())),
        (4_465_026, BranchId::Nu6_3, 0, Err(SproutLedgerError::UnsupportedEra)),
    ] {
        assert_eq!(check_transaction(&v4(&template, branch, expiry), height, 1_500_000_000).map(|_| ()), expected);
    }
    for expiry in [0, 1, 279_999, 280_000, 499_999_999] {
        assert_eq!(check_coinbase(&sapling_coinbase(280_000, expiry), 280_000, 1_500_000_000).unwrap().claimed, 1_250_000_000);
    }
    assert_eq!(check_coinbase(&sapling_coinbase(280_000, 500_000_000), 280_000, 1_500_000_000), Err(SproutLedgerError::InvalidTransaction));
}

#[test]
fn recorded_sapling_crypto_moves_only_its_pool_and_destroys_unclaimed_fee_in_isolated_state() {
    let mut parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let transaction = recorded_sapling();
    let bundle = transaction.sapling_bundle().unwrap();
    assert_eq!(i64::from(*bundle.value_balance()), 10_000);
    let nullifier = bundle.shielded_spends()[0].nullifier().0;
    let mut expected = Frontier::<SaplingNode, 32>::empty();
    for output in bundle.shielded_outputs() { assert!(expected.append(SaplingNode::from_cmu(output.cmu()))); }
    let delta = parent.stage_block(sapling_coinbase(280_000, 0), vec![transaction], 280_000, 1_500_000_000).unwrap();
    assert_eq!((delta.fees, delta.sapling, delta.sprout, delta.issued), (10_000, 0, 0, 1_250_000_020));
    assert_eq!(delta.sapling_tree, expected);
    assert_eq!(delta.check_sapling_root(280_000, &expected.root().to_bytes()), Ok(()));
    assert_eq!(delta.check_sapling_root(280_000, &parent.shielded_roots[1]), Err(SproutLedgerError::WrongSaplingRoot));
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.transparent_balance(), parent.utxo_balance(), parent.issued_supply()), (1_250_000_020, 1_250_000_020, 1_250_000_020));
    assert_eq!(parent.shielded_balance(ShieldedPool::Sapling), 0);
    assert_eq!(parent.sapling_tree_size(), 2);
    assert_eq!(parent.shielded_root(ShieldedPool::Sapling), expected.root().to_bytes());
    assert_eq!(parent.sapling_anchors.len(), 3); // empty, artificial predecessor, accepted end.
    assert!(parent.contains_nullifier(ShieldedPool::Sapling, &nullifier));
    assert_eq!(parent.nullifier_count(ShieldedPool::Sprout), 0);
    assert_eq!(parent.tip().height(), 0); // No accepted connected header/history claim.

    let empty = state();
    assert!(matches!(empty.stage_block(sapling_coinbase(280_000, 0), vec![recorded_sapling()], 280_000, 1_500_000_000), Err(SproutLedgerError::UnknownSaplingAnchor)));
}

#[test]
fn late_sapling_proof_auth_binding_ciphertext_balance_anchor_failures_preserve_entire_parent() {
    let parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Sapling, 0);
    // Authentic no-transparent V4 wire layout: balance18, Spend27, proof155,
    // auth347, outputs412/1360, binding2309. Every mutation parses canonically.
    for (offset, mask, expected) in [
        (18, 1, SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 })),
        (59, 1, SproutLedgerError::UnknownSaplingAnchor),
        (91, 1, SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index: 0 })),
        (155, 0x20, SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index: 0 })),
        (379, 1, SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 })),
        (508, 1, SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 })),
        (2372, 1, SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature)),
    ] {
        let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
        raw[offset] ^= mask;
        let transaction = Transaction::read(raw.as_slice(), BranchId::Sapling).unwrap();
        assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), transaction], 280_000, 1_500_000_000), Err(error) if error == expected), "field{offset}");
        assert_eq!(owned_state(&parent), before);
    }
    let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
    raw[18..26].copy_from_slice(&(-1_i64).to_le_bytes());
    let transaction = Transaction::read(raw.as_slice(), BranchId::Sapling).unwrap();
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), transaction], 280_000, 1_500_000_000), Err(SproutLedgerError::NegativeFee)));
    assert_eq!(owned_state(&parent), before);
    let wrong_branch = v4(&recorded_sapling(), BranchId::Blossom, 0);
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), wrong_branch], 280_000, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
}

fn modified_sapling(spends: Vec<sapling_crypto::bundle::SpendDescription<sapling_crypto::bundle::Authorized>>, outputs: Vec<sapling_crypto::bundle::OutputDescription<[u8; 192]>>, balance: i64, transparent: Option<zcash_transparent::bundle::Bundle<zcash_transparent::bundle::Authorized>>) -> Transaction {
    let original = recorded_sapling();
    let sapling = sapling_crypto::Bundle::from_parts(spends, outputs, zcash_protocol::value::ZatBalance::from_i64(balance).unwrap(), *original.sapling_bundle().unwrap().authorization());
    TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), transparent, None, sapling, None).freeze().unwrap()
}

fn sapling_spend(anchor: [u8; 32], nullifier: [u8; 32]) -> sapling_crypto::bundle::SpendDescription<sapling_crypto::bundle::Authorized> {
    let original = recorded_sapling();
    let spend = &original.sapling_bundle().unwrap().shielded_spends()[0];
    // Context-only modified statement; its copied proof/signature is NOT valid.
    sapling_crypto::bundle::SpendDescription::from_parts(spend.cv().clone(), bls12_381::Scalar::from_bytes(&anchor).unwrap(), sapling_crypto::Nullifier(nullifier), *spend.rk(), *spend.zkproof(), *spend.spend_auth_sig())
}

#[test]
fn sapling_historical_roots_use_current_global_nullifiers_and_no_interstitial_exceptions() {
    let parent = isolated_sapling_parent();
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    let anchor = bundle.shielded_spends()[0].anchor().to_bytes();
    let nf = bundle.shielded_spends()[0].nullifier().0;
    let mut delta = BlockDelta::new(&parent);
    parent.stage_sapling(&original, &mut delta).unwrap();
    assert_eq!(parent.stage_sapling(&original, &mut delta), Err(SproutLedgerError::SpentSaplingNullifier));
    let interstitial = delta.sapling_tree.root().to_bytes();
    let later = modified_sapling(vec![sapling_spend(interstitial, [0xe3; 32])], vec![], 0, None);
    assert_eq!(parent.stage_sapling(&later, &mut delta), Err(SproutLedgerError::UnknownSaplingAnchor));
    let same_transaction = modified_sapling(vec![sapling_spend(anchor, [0xe4; 32]), sapling_spend(interstitial, [0xe5; 32])], bundle.shielded_outputs().to_vec(), 0, None);
    assert_eq!(parent.stage_sapling(&same_transaction, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::UnknownSaplingAnchor));
    let duplicate = modified_sapling(vec![sapling_spend(anchor, nf), sapling_spend(anchor, nf)], bundle.shielded_outputs().to_vec(), 0, None);
    assert_eq!(parent.stage_sapling(&duplicate, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::SpentSaplingNullifier));
    let empty_anchor = modified_sapling(vec![sapling_spend(parent.shielded_roots[1], [0xe6; 32])], vec![], 0, None);
    assert_eq!(parent.stage_sapling(&empty_anchor, &mut BlockDelta::new(&parent)), Ok(()));
    let hashes = SaplingSignatureHash::new(&empty_anchor).unwrap();
    assert!(verify_sapling_v4_crypto(&hashes).is_err()); // recognized empty root is not fake proof validity.
    let mut parent = parent;
    parent.nullifiers[1].insert(nf);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![recorded_sapling()], 280_000, 1_500_000_000), Err(SproutLedgerError::SpentSaplingNullifier)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn independent_v4_ecdsa_checks_actual_prevout_amount_script_raw_bits_and_branch() {
    for p2sh in [false, true] {
        for raw_type in [0, 1, 2, 3, 0x81, 0x82, 0x83, 0x41, 0xff] {
            let (transaction, prevout) = independently_signed_transparent(TxVersion::V4, p2sh, raw_type);
            let hashes = TransactionSignatureHash::Sapling(SaplingSignatureHash::new(&transaction).unwrap());
            assert_eq!(verify_transparent_input(&transaction, Some(&hashes), 0, &prevout), Ok(()));
            for amount in [100_001, 100_003] {
                assert_eq!(verify_transparent_input(&transaction, Some(&hashes), 0, &output(amount, &prevout.script_pubkey().0.0)), Err(SproutLedgerError::InvalidTransparentScript));
                let mut parent = isolated_sapling_parent();
                fund(&mut parent, ([0xa1; 32], 3), amount, &prevout.script_pubkey().0.0, 0, false);
                let before = owned_state(&parent);
                let good = v4(&spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Sapling, 0);
                let bad = v4(&transaction, BranchId::Sapling, 280_021);
                assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good, bad], 280_000, 1_500_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
                assert_eq!(owned_state(&parent), before);
            }
            let mut wrong_script = prevout.script_pubkey().0.0.clone();
            if p2sh { wrong_script[2] ^= 1; } else { wrong_script.insert(0, 0x61); }
            assert_eq!(verify_transparent_input(&transaction, Some(&hashes), 0, &output(100_002, &wrong_script)), Err(SproutLedgerError::InvalidTransparentScript));
            let wrong_branch = v4(&transaction, BranchId::Blossom, 280_021);
            let hashes = TransactionSignatureHash::Sapling(SaplingSignatureHash::new(&wrong_branch).unwrap());
            assert_eq!(verify_transparent_input(&wrong_branch, Some(&hashes), 0, &prevout), Err(SproutLedgerError::InvalidTransparentScript));
            let mut parent = state();
            fund(&mut parent, ([0xa1; 32], 3), 100_002, &prevout.script_pubkey().0.0, 0, false);
            let delta = parent.stage_block(sapling_coinbase(280_000, 0), vec![transaction], 280_000, 1_500_000_000).unwrap();
            assert_eq!(delta.fees, 2);
            parent.commit(delta);
            assert!(parent.utxo(&[0xa1; 32], 3).is_none());
            assert_eq!((parent.transparent_balance(), parent.utxo_balance(), parent.issued_supply()), (1_250_100_000, 1_250_100_000, 1_250_100_000));
        }
    }
}

#[test]
fn sapling_cardinality_requires_spends_for_inputs_and_outputs_for_outputs_separately() {
    let transaction = recorded_sapling();
    let bundle = transaction.sapling_bundle().unwrap();
    let source = spend(&[(([0xe7; 32], 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    for (spends, outputs, has_vin, has_vout, accepted) in [
        (false, false, true, true, true),
        (false, true, false, false, false),
        (true, false, false, false, false),
        (true, true, false, false, true),
        (false, true, true, false, true),
        (true, false, false, true, true),
        (true, false, true, false, false),
        (false, true, false, true, false),
    ] {
        let mut transparent = source.transparent_bundle().unwrap().clone();
        if !has_vin { transparent.vin.clear(); }
        if !has_vout { transparent.vout.clear(); }
        let transaction = modified_sapling(if spends { bundle.shielded_spends().to_vec() } else { vec![] }, if outputs { bundle.shielded_outputs().to_vec() } else { vec![] }, 0, Some(transparent));
        assert_eq!(check_transaction(&transaction, 280_000, 1_500_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::InvalidTransaction) });
        // Context-only modified shape, not a valid copied crypto statement.
        let blossom = v4(&transaction, BranchId::Blossom, 0);
        assert_eq!(check_transaction(&blossom, 584_000, 1_500_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::InvalidTransaction) });
    }
    for (spends, outputs) in [(true, false), (false, true), (true, true)] {
        let transaction = modified_sapling(if spends { bundle.shielded_spends().to_vec() } else { vec![] }, if outputs { bundle.shielded_outputs().to_vec() } else { vec![] }, 0, sapling_coinbase(280_000, 0).transparent_bundle().cloned());
        assert_eq!(check_coinbase(&transaction, 280_000, 1_500_000_000), Err(SproutLedgerError::InvalidCoinbase));
    }
    let groth = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Sapling).unwrap();
    let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), sapling_coinbase(280_000, 0).transparent_bundle().cloned(), groth.sprout_bundle().cloned(), None, None).freeze().unwrap();
    assert_eq!(check_coinbase(&transaction, 280_000, 1_500_000_000), Err(SproutLedgerError::InvalidCoinbase));
}

#[test]
fn sapling_value_balance_and_joinsplits_bound_debit_credit_sides_not_their_net() {
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    let source = spend(&[(([0xe8; 32], 0), &[], u32::MAX)], vec![output(MAX_MONEY, &[0x51])], 0);
    let transaction = modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), -1, source.transparent_bundle().cloned());
    assert!(matches!(check_transaction(&transaction, 280_000, 1_500_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    for balance in [MAX_MONEY as i64, -(MAX_MONEY as i64), 0] {
        let transaction = modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), balance, None);
        assert_eq!(check_transaction(&transaction, 280_000, 1_500_000_000).unwrap().sapling_balance, balance);
    }
    for balance in [i64::MIN, i64::MAX, MAX_MONEY as i64 + 1, -(MAX_MONEY as i64) - 1] {
        let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
        raw[18..26].copy_from_slice(&balance.to_le_bytes());
        assert!(Transaction::read(raw.as_slice(), BranchId::Sapling).is_err());
    }
    // Amount checks consume actual prevouts before cryptography; copied proof
    // is intentionally invalid for each modified statement, never an oracle.
    let mut parent = isolated_sapling_parent();
    fund(&mut parent, ([0xe8; 32], 0), 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let source = spend(&[(([0xe8; 32], 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let transaction = modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), MAX_MONEY as i64, source.transparent_bundle().cloned());
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![transaction], 280_000, 1_500_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    assert_eq!(owned_state(&parent), before);
    let groth = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Sapling).unwrap();
    for (old, new, balance) in [(MAX_MONEY, 0, -1), (0, MAX_MONEY, 1), (1, 1, 0)] {
        let mut sprout = groth.sprout_bundle().unwrap().clone();
        let mut raw = Vec::new();
        sprout.joinsplits[0].write(&mut raw).unwrap();
        raw[..8].copy_from_slice(&old.to_le_bytes());
        raw[8..16].copy_from_slice(&new.to_le_bytes());
        sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap();
        let sapling = sapling_crypto::Bundle::from_parts(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), zcash_protocol::value::ZatBalance::from_i64(balance).unwrap(), *bundle.authorization());
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), None, Some(sprout), sapling, None).freeze().unwrap();
        assert!(matches!(check_transaction(&transaction, 280_000, 1_500_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    }
}

#[test]
fn sapling_frontier_appends_every_output_in_order_and_publishes_only_block_end_roots() {
    let mut parent = state();
    let original = recorded_sapling();
    let outputs = original.sapling_bundle().unwrap().shielded_outputs();
    let output_only = || modified_sapling(vec![], outputs.to_vec(), 0, None);
    let empty = parent.shielded_roots[1];
    let mut delta = parent.stage_block(sapling_coinbase(280_000, 0), vec![], 280_000, 1_500_000_000).unwrap();
    let mut reference = sapling_crypto::CommitmentTree::empty();
    for output in outputs { reference.append(SaplingNode::from_cmu(output.cmu())).unwrap(); }
    parent.stage_sapling(&output_only(), &mut delta).unwrap();
    assert_eq!(delta.sapling_tree.root(), reference.root());
    let intermediate = delta.sapling_tree.root().to_bytes();
    for output in outputs { reference.append(SaplingNode::from_cmu(output.cmu())).unwrap(); }
    parent.stage_sapling(&output_only(), &mut delta).unwrap();
    assert_eq!(delta.sapling_tree.tree_size(), 4);
    assert_eq!(delta.sapling_tree.root(), reference.root());
    let final_root = delta.sapling_tree.root().to_bytes();
    delta.sapling_root = final_root; // Context-only mutation follows production block finalization.
    assert_ne!(final_root, intermediate);
    assert_eq!(delta.check_sapling_root(280_000, &empty), Err(SproutLedgerError::WrongSaplingRoot));
    assert_eq!(delta.check_sapling_root(280_000, &final_root), Ok(()));
    parent.commit(delta); // Private storage/context invariant, NOT proof-valid output-only history.
    assert_eq!(parent.sapling_tree_size(), 4);
    assert_eq!(parent.shielded_roots[1], final_root);
    assert!(parent.sapling_anchors.contains(&empty));
    assert!(parent.sapling_anchors.contains(&final_root));
    assert!(!parent.sapling_anchors.contains(&intermediate));
    let spend = modified_sapling(vec![sapling_spend(final_root, [0xe9; 32])], vec![], 0, None);
    assert_eq!(parent.stage_sapling(&spend, &mut BlockDelta::new(&parent)), Ok(()));
    parent.nullifiers[1].insert([0xe9; 32]);
    assert_eq!(parent.stage_sapling(&spend, &mut BlockDelta::new(&parent)), Err(SproutLedgerError::SpentSaplingNullifier));
}

#[test]
fn sapling_depth32_capacity_failure_and_nonzero_final_pool_failure_keep_owned_state() {
    let mut parent = isolated_sapling_parent();
    parent.sapling_tree = Frontier::from_parts(((1_u64 << 32) - 2).into(), SaplingNode::from_scalar(bls12_381::Scalar::from(2)), vec![SaplingNode::from_scalar(bls12_381::Scalar::from(3)); 31]).unwrap();
    parent.shielded_roots[1] = parent.sapling_tree.root().to_bytes();
    parent.sapling_anchors.insert(parent.shielded_roots[1]);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![recorded_sapling()], 280_000, 1_500_000_000), Err(SproutLedgerError::SaplingTreeFull)));
    assert_eq!(owned_state(&parent), before);
    assert_eq!(parent.sapling_tree_size(), (1_u64 << 32) - 1);

    let mut parent = isolated_sapling_parent();
    parent.shielded_balances[1] -= 1;
    parent.issued_supply -= 1;
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![recorded_sapling()], 280_000, 1_500_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn sapling_two_megabyte_transaction_boundary_keeps_sigops_and_pruned_claim_issuance() {
    let key = ([0xea; 32], 0);
    // V4 overhead83 includes its signed balance and two Sapling counts.
    for (length, accepted) in [(99_918, true), (1_999_917, true), (1_999_918, false)] {
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0; length])], 0), BranchId::Sapling, 0);
        let mut encoded = Vec::new();
        transaction.write(&mut encoded).unwrap();
        assert_eq!(encoded.len(), length + 83);
        assert_eq!(check_transaction(&transaction, 280_000, 1_500_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::TransactionTooLarge) });
    }
    for (sigops, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; sigops])], 0), BranchId::Sapling, 0);
        let mut bundle = sapling_coinbase(280_000, 0).transparent_bundle().unwrap().clone();
        bundle.vout[0] = output(1_000_000_000, &[0xac]);
        let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
        let result = parent.stage_block(coinbase, vec![transaction], 280_000, 1_500_000_000);
        if accepted { assert_eq!(result.unwrap().sigops, 20_000); } else { assert!(matches!(result, Err(SproutLedgerError::TooManySigops))); }
    }
    for (burn, issued, retained) in [(1, 1_250_000_000, 1_249_999_999), (0, 1_249_999_999, 1_249_999_999)] {
        let mut bundle = sapling_coinbase(280_000, 0).transparent_bundle().unwrap().clone();
        bundle.vout[0] = output(999_999_999, &[0x51]);
        bundle.vout.push(output(burn, &[0x6a]));
        let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
        let mut parent = state();
        let delta = parent.stage_block(coinbase, vec![], 280_000, 1_500_000_000).unwrap();
        parent.commit(delta);
        assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance()), (issued, issued, retained));
    }
    // Maintained V4 reader normalizes this hostile absent-bundle balance, but
    // complete byte admission MUST reject its noncanonical round-trip.
    let mut raw = include_bytes!("../tests/fixtures/testnet-sapling-block-280000.bin").to_vec();
    let end = raw.len();
    raw[end - 11] = 1;
    assert!(matches!(ParsedBlockBody::parse(&raw, &TEST_NETWORK), Err(BodyError::NoncanonicalEncoding)));
}

#[test]
fn late_v4_sprout_signature_and_real_groth_failure_roll_back_all_sapling_fields() {
    let original = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Sapling).unwrap();
    let mut parent = isolated_sapling_parent();
    parent.sprout_anchors.insert(*original.sprout_bundle().unwrap().joinsplits[0].anchor(), Frontier::empty());
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Sapling, 0);
    let before_id: [u8; 32] = good().txid().into();
    let source = spend(&[((before_id, 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let mut sprout = original.sprout_bundle().unwrap().clone();
    let mut raw = Vec::new();
    sprout.joinsplits[0].write(&mut raw).unwrap();
    raw[..8].fill(0); // Cheap amount rules pass; original proof remains real but now invalid.
    sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap();
    for (identity_signature, expected) in [
        (false, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (true, SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof })),
    ] {
        let mut sprout = sprout.clone();
        if identity_signature {
            sprout.joinsplit_pubkey = [0; 32];
            sprout.joinsplit_pubkey[0] = 1;
            sprout.joinsplit_sig = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000").try_into().unwrap();
        }
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), source.transparent_bundle().cloned(), Some(sprout), None, None).freeze().unwrap();
        assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), recorded_sapling(), transaction], 280_000, 1_500_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn sapling_fee_claim_limit_issuance_maturity_bip30_and_ordered_utxos_remain_original() {
    let key = ([0xeb; 32], 0);
    for claimed_fee in [9_999, 10_000, 10_001] {
        let mut parent = isolated_sapling_parent();
        let before = owned_state(&parent);
        let mut transparent = sapling_coinbase(280_000, 0).transparent_bundle().unwrap().clone();
        transparent.vout[0] = output(1_000_000_000 + claimed_fee, &[0x51]);
        let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), Some(transparent), None, None, None).freeze().unwrap();
        let result = parent.stage_block(coinbase, vec![recorded_sapling()], 280_000, 1_500_000_000);
        if claimed_fee > 10_000 {
            assert!(matches!(result, Err(SproutLedgerError::CoinbaseRewardExceeded)));
            assert_eq!(owned_state(&parent), before);
        } else {
            let delta = result.unwrap();
            assert_eq!(delta.issued, 1_250_000_020 + claimed_fee);
            parent.commit(delta);
            assert_eq!(parent.issued_supply(), 1_250_000_020 + claimed_fee);
        }
    }
    for created_height in [279_900, 279_901] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], created_height, true);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Sapling, 0);
        let expected = if created_height == 279_900 { SproutLedgerError::UnshieldedCoinbaseSpend } else { SproutLedgerError::ImmatureCoinbase };
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![transaction], 280_000, 1_500_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = state();
    fund(&mut parent, key, 100, &[0x51], 0, false);
    let first = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(80, &[0x51])], 0), BranchId::Sapling, 0);
    let first_id: [u8; 32] = first().txid().into();
    let second = || v4(&spend(&[((first_id, 0), &[], u32::MAX)], vec![output(70, &[0x51])], 0), BranchId::Sapling, 0);
    let before = owned_state(&parent);
    for transactions in [vec![second(), first()], vec![first(), second(), second()]] {
        assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), transactions, 280_000, 1_500_000_000), Err(SproutLedgerError::MissingTransparentInput)));
        assert_eq!(owned_state(&parent), before);
    }
    let duplicate = v4(&spend(&[(key, &[], u32::MAX), (key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Sapling, 0);
    assert!(matches!(check_transaction(&duplicate, 280_000, 1_500_000_000), Err(SproutLedgerError::DuplicateTransparentInput)));
    let delta = parent.stage_block(sapling_coinbase(280_000, 0), vec![first(), second()], 280_000, 1_500_000_000).unwrap();
    assert_eq!(delta.fees, 30);
    parent.commit(delta);
    assert!(parent.utxo(&key.0, key.1).is_none());
    assert!(parent.utxo(&first_id, 0).is_none());
    let mut parent = state();
    fund(&mut parent, key, 100, &[0x51], 0, false);
    fund(&mut parent, (first_id, 7), 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let consume_high = v4(&spend(&[((first_id, 7), &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Sapling, 0);
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![consume_high, first()], 280_000, 1_500_000_000), Err(SproutLedgerError::UnspentTransactionOverwrite)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn late_wrong_sapling_root_and_invalid_script_do_not_publish_any_staged_field() {
    let parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Sapling, 0);
    let id: [u8; 32] = good().txid().into();
    let bad = v4(&spend(&[((id, 0), &[0x6a], u32::MAX)], vec![output(18, &[0x51])], 0), BranchId::Sapling, 0);
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), recorded_sapling(), bad], 280_000, 1_500_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
    assert_eq!(owned_state(&parent), before);
    let delta = parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), recorded_sapling()], 280_000, 1_500_000_000).unwrap();
    assert_eq!(delta.fees, 10_001);
    assert_eq!(delta.sapling_tree.tree_size(), 2);
    assert_eq!(delta.sapling_nullifiers.len(), 1);
    assert!(delta.utxos.get(&([0xe1; 32], 0)).unwrap().is_none());
    assert_eq!(delta.check_sapling_root(280_000, &parent.shielded_roots[1]), Err(SproutLedgerError::WrongSaplingRoot));
    assert_eq!(owned_state(&parent), before);
    let root = delta.sapling_tree.root().to_bytes();
    assert_eq!(delta.check_sapling_root(280_000, &root), Ok(()));
    assert_eq!(owned_state(&parent), before);
    drop(delta);
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn sapling_finality_and_founders_rotation_keep_original_non_policy_semantics() {
    for (lock, sequence, time, expected) in [
        (279_999, 0, 1_500_000_000, Ok(())),
        (280_000, 0, 1_500_000_000, Err(SproutLedgerError::NonfinalTransaction)),
        (280_000, u32::MAX, 1_500_000_000, Ok(())),
        (500_000_000, 0, 500_000_001, Ok(())),
        (500_000_000, 0, 500_000_000, Err(SproutLedgerError::NonfinalTransaction)),
    ] {
        let transaction = v4(&spend(&[(([0xec; 32], 0), &[], sequence)], vec![output(0, &[0x51])], lock), BranchId::Sapling, 0);
        assert_eq!(check_transaction(&transaction, 280_000, time).map(|_| ()), expected);
    }
    // Literal original testnet indices15/16 and31/32; never use a latest
    // funding-stream/subsidy implementation before its own era transition.
    for (height, correct, wrong) in [
        (283_343, "a9142a71f51b268f74eb3ee5631090589bbf6239bc0c87", "a914fd79e0c84acac223142cf503dc6afde24acac50e87"),
        (283_344, "a914fd79e0c84acac223142cf503dc6afde24acac50e87", "a9142a71f51b268f74eb3ee5631090589bbf6239bc0c87"),
        (566_687, "a914ada06a32434d37abb8ff7dff590544d3245cd1a187", "a91453dafe420ac703a7ec9cc3f593778054b459a83187"),
        (566_688, "a91453dafe420ac703a7ec9cc3f593778054b459a83187", "a914ada06a32434d37abb8ff7dff590544d3245cd1a187"),
        (583_999, "a91453dafe420ac703a7ec9cc3f593778054b459a83187", "a914ada06a32434d37abb8ff7dff590544d3245cd1a187"),
    ] {
        assert_eq!(subsidy(height), Ok(1_250_000_000));
        for (founder, accepted) in [(correct, true), (wrong, false)] {
            let mut transparent = sapling_coinbase(height, 0).transparent_bundle().unwrap().clone();
            transparent.vout[1] = output(250_000_000, &bytes(founder));
            let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 0, 0.into(), Some(transparent), None, None, None).freeze().unwrap();
            assert_eq!(check_coinbase(&coinbase, height, 1_500_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::MissingFoundersReward) });
        }
    }
}

#[test]
fn sapling_storage_preserves_unchanged_best_frontier_and_separate_pool_identity() {
    let mut parent = state();
    let root = parent.shielded_roots[1];
    let mut delta = parent.stage_block(sapling_coinbase(280_000, 0), vec![], 280_000, 1_500_000_000).unwrap();
    // Context/tree-only: uncommitted leaf1 is not a proof-valid note output.
    // It gives the original unchanged-root PushAnchor regression without mocks.
    assert!(delta.sapling_tree.append(SaplingNode::from_scalar(bls12_381::Scalar::one())));
    assert_eq!(delta.sapling_tree.root().to_bytes(), root);
    delta.sapling_root = root;
    parent.commit(delta);
    assert_eq!(parent.sapling_tree_size(), 0);
    assert_eq!(parent.sapling_anchors.len(), 1);
    assert_eq!(parent.nullifier_count(ShieldedPool::Sprout), 0);
    assert_eq!(parent.nullifier_count(ShieldedPool::Sapling), 0);
    let mut parent = isolated_sapling_parent();
    let original = recorded_sapling();
    let nf = original.sapling_bundle().unwrap().shielded_spends()[0].nullifier().0;
    parent.nullifiers[0].insert(nf); // Same bytes in another pool do not spend Sapling.
    assert_eq!(parent.stage_sapling(&original, &mut BlockDelta::new(&parent)), Ok(()));
}

#[test]
fn late_each_output_proof_and_binding_equation_reject_without_signature_masking_or_state_commit() {
    let parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Sapling, 0);
    let id: [u8; 32] = good().txid().into();
    let source = spend(&[((id, 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let original = recorded_sapling();
    let original_outputs = original.sapling_bundle().unwrap().shielded_outputs();
    // Output-only candidate has no SpendAuth signature to mask an output's
    // equation. Actual recorded output proofs remain real and fixed-key checked;
    // the copied binding signature is deliberately invalid for this new context.
    for index in 0..original_outputs.len() {
        let mut outputs = original_outputs.to_vec();
        let output = &outputs[index];
        let mut proof = *output.zkproof();
        proof[0] ^= 0x20; // Valid compressed subgroup point, opposite sign, wrong equation.
        outputs[index] = sapling_crypto::bundle::OutputDescription::from_parts(output.cv().clone(), *output.cmu(), output.ephemeral_key().clone(), *output.enc_ciphertext(), *output.out_ciphertext(), proof);
        let transaction = modified_sapling(vec![], outputs, 0, source.transparent_bundle().cloned());
        assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), recorded_sapling(), transaction], 280_000, 1_500_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index: actual })) if actual == index));
        assert_eq!(owned_state(&parent), before);
    }
    let transaction = modified_sapling(vec![], original_outputs.to_vec(), 0, source.transparent_bundle().cloned());
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), recorded_sapling(), transaction], 280_000, 1_500_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature))));
    assert_eq!(owned_state(&parent), before);
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![recorded_sapling(), recorded_sapling()], 280_000, 1_500_000_000), Err(SproutLedgerError::SpentSaplingNullifier)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn late_sapling_small_order_keys_cmu_and_commitments_fail_closed_with_full_snapshot() {
    let parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Sapling, 0);
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
    raw[123..155].copy_from_slice(&identity);
    let transaction = Transaction::read(raw.as_slice(), BranchId::Sapling).unwrap();
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), transaction], 280_000, 1_500_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendKey { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    let description = &bundle.shielded_spends()[0];
    let zero_cv = sapling_crypto::value::ValueCommitment::derive(sapling_crypto::value::NoteValue::from_raw(0), sapling_crypto::value::ValueCommitTrapdoor::from_bytes([0; 32]).unwrap());
    let changed = sapling_crypto::bundle::SpendDescription::from_parts(zero_cv, *description.anchor(), *description.nullifier(), *description.rk(), *description.zkproof(), *description.spend_auth_sig());
    let transaction = modified_sapling(vec![changed], bundle.shielded_outputs().to_vec(), 10_000, None);
    assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![good(), transaction], 280_000, 1_500_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendValueCommitment { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let source = spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    for index in 0..bundle.shielded_outputs().len() {
        for (bad_epk, expected) in [(true, SaplingCryptoError::InvalidEphemeralKey { index }), (false, SaplingCryptoError::InvalidOutputProof { index })] {
            let mut outputs = bundle.shielded_outputs().to_vec();
            let output = &outputs[index];
            let epk = if bad_epk { zcash_note_encryption::EphemeralKeyBytes(identity) } else { output.ephemeral_key().clone() };
            let cmu = if bad_epk { *output.cmu() } else { sapling_crypto::note::ExtractedNoteCommitment::from_bytes(&[0; 32]).unwrap() };
            outputs[index] = sapling_crypto::bundle::OutputDescription::from_parts(output.cv().clone(), cmu, epk, *output.enc_ciphertext(), *output.out_ciphertext(), *output.zkproof());
            let transaction = modified_sapling(vec![], outputs, 0, source.transparent_bundle().cloned());
            assert!(matches!(parent.stage_block(sapling_coinbase(280_000, 0), vec![transaction], 280_000, 1_500_000_000), Err(SproutLedgerError::Sapling(actual)) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn blossom_spacing_cutover_and_canopy_halving_remain_distinct_before_nu5() {
    assert_eq!(supported_branch(583_999), Ok(BranchId::Sapling));
    assert_eq!(supported_branch(584_000), Ok(BranchId::Blossom));
    assert_eq!(supported_branch(903_799), Ok(BranchId::Blossom));
    assert_eq!(supported_branch(903_800), Ok(BranchId::Heartwood));
    assert_eq!(supported_branch(1_028_500), Ok(BranchId::Canopy));
    assert_eq!(supported_branch(2_976_000), Ok(BranchId::Nu6));
    assert_eq!(subsidy(583_999), Ok(1_250_000_000));
    assert_eq!(subsidy(584_000), Ok(625_000_000));
    assert_eq!(subsidy(903_800), Ok(625_000_000));
    assert_eq!(subsidy(1_028_499), Ok(625_000_000));
    assert_eq!(subsidy(1_028_500), Ok(625_000_000));
    assert_eq!(subsidy(1_115_999), Ok(625_000_000));
    assert_eq!(subsidy(1_116_000), Ok(312_500_000));
    assert_eq!(subsidy(1_842_419), Ok(312_500_000));
    assert_eq!(subsidy(2_976_000), Ok(156_250_000));
}

fn blossom_coinbase(height: u32, expiry: u32) -> Transaction {
    let (prefix, length) = coinbase_height_prefix(height);
    let reward = changed(TxVersion::Sprout(1), 0, |bundle| {
        script_input(bundle, &prefix[..length], u32::MAX);
        bundle.vout = vec![output(500_000_000, &[0x51]), output(125_000_000, &founders_script(height))];
    });
    v4(&reward, BranchId::Blossom, expiry)
}

// Unchanged decoded vectors from Zebra e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291:
// zebra-test/src/vectors/block-test-0-{583-999,584-000,584-001,903-799}.txt.
// MIT selected; exact source LICENSE-MIT notice retained for these fixtures.
/*
Copyright (c) 2019-2025 Zcash Foundation

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#[test]
fn primary_blossom_coinbases_use_halved_reward_and_adjusted_founder_without_history_claim() {
    for (raw, height, reward, founder, index) in [
        (include_bytes!("../tests/fixtures/testnet-blossom-block-583999.bin").as_slice(), 583_999, 1_250_000_000, 250_000_000, 32),
        (include_bytes!("../tests/fixtures/testnet-blossom-block-584000.bin").as_slice(), 584_000, 625_000_000, 125_000_000, 32),
        (include_bytes!("../tests/fixtures/testnet-blossom-block-584001.bin").as_slice(), 584_001, 625_000_000, 125_000_000, 32),
        (include_bytes!("../tests/fixtures/testnet-blossom-block-903799.bin").as_slice(), 903_799, 625_000_000, 125_000_000, 42),
    ] {
        let parsed = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap();
        assert_eq!(u32::from(parsed.block().claimed_height()), height);
        let time = parsed.block().header().time;
        let root = parsed.block().header().final_sapling_root;
        let (_, transactions) = parsed.into_block().into_parts();
        assert!(transactions.tail.is_empty());
        assert_eq!(check_coinbase(&transactions.head, height, time).unwrap().claimed, reward);
        let bundle = transactions.head.transparent_bundle().unwrap().clone();
        let expected = [vec![0xa9, 0x14], FOUNDERS_HASHES[index].to_vec(), vec![0x87]].concat();
        assert!(bundle.vout.iter().any(|out| u64::from(out.value()) == founder && out.script_pubkey().0.0 == expected));
        // Only the primary header root is injected into this TEST-ONLY parent.
        // No predecessor frontier, membership witness or connected history is asserted.
        let mut parent = state();
        parent.shielded_roots[1] = root;
        parent.sapling_anchors.insert(root);
        let before = owned_state(&parent);
        let delta = parent.stage_block(transactions.head, transactions.tail, height, time).unwrap();
        assert_eq!((delta.fees, delta.issued, delta.transparent, delta.retained, delta.sapling), (0, reward, i128::from(reward), i128::from(reward), 0));
        assert_eq!(delta.check_sapling_root(height, &root), Ok(()));
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert_eq!(delta.check_sapling_root(height, &wrong_root), Err(SproutLedgerError::WrongSaplingRoot));
        assert_eq!(owned_state(&parent), before);
        let mut overclaim = bundle.clone();
        let miner = overclaim.vout.iter().position(|out| out.script_pubkey().0.0 != expected).unwrap();
        overclaim.vout[miner] = output(u64::from(overclaim.vout[miner].value()) + 1, &overclaim.vout[miner].script_pubkey().0.0);
        let branch = if height == 583_999 { BranchId::Sapling } else { BranchId::Blossom };
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V4, branch, 0, 0.into(), Some(overclaim), None, None, None).freeze().unwrap();
        assert!(matches!(parent.stage_block(tx, vec![], height, time), Err(SproutLedgerError::CoinbaseRewardExceeded)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn blossom_founders_rotate_at_adjusted_584794_not_raw_height() {
    // ZIP208 adjusted584397 ==17709*33. The preceding odd height rounds down.
    for (height, correct, wrong) in [
        (584_000, "a91453dafe420ac703a7ec9cc3f593778054b459a83187", "a91483f7b09df15cf16c8a8c7d744326ed6ff258511f87"),
        (584_793, "a91453dafe420ac703a7ec9cc3f593778054b459a83187", "a91483f7b09df15cf16c8a8c7d744326ed6ff258511f87"),
        (584_794, "a91483f7b09df15cf16c8a8c7d744326ed6ff258511f87", "a91453dafe420ac703a7ec9cc3f593778054b459a83187"),
        (584_795, "a91483f7b09df15cf16c8a8c7d744326ed6ff258511f87", "a91453dafe420ac703a7ec9cc3f593778054b459a83187"),
        (903_799, "a914c6fb0a1ea5887b25b8e1a7b71a1e13c736953a1c87", "a91483f7b09df15cf16c8a8c7d744326ed6ff258511f87"),
    ] {
        for (script, value, expected) in [
            (correct, 125_000_000, Ok(())),
            (wrong, 125_000_000, Err(SproutLedgerError::MissingFoundersReward)),
            (correct, 250_000_000, Err(SproutLedgerError::MissingFoundersReward)),
            (correct, 125_000_001, Err(SproutLedgerError::MissingFoundersReward)),
        ] {
            let mut bundle = blossom_coinbase(height, 0).transparent_bundle().unwrap().clone();
            bundle.vout[1] = output(value, &bytes(script));
            let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Blossom, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
            let parent = state();
            let before = owned_state(&parent);
            assert_eq!(parent.stage_block(transaction, vec![], height, 1_500_000_000).map(|_| ()), expected);
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn independent_blossom_v4_signatures_verify_owned_amount_and_reject_branch_relabeling() {
    for height in [584_000, 903_799] {
        for p2sh in [false, true] {
            for raw_type in [0, 1, 2, 3, 0x81, 0x82, 0x83, 0x41, 0xff] {
                let (transaction, prevout) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Blossom, p2sh, raw_type);
                let hashes = TransactionSignatureHash::Sapling(SaplingSignatureHash::new(&transaction).unwrap());
                assert_eq!(verify_transparent_input(&transaction, Some(&hashes), 0, &prevout), Ok(()));
                let mut wrong_script = prevout.script_pubkey().0.0.clone();
                if p2sh { wrong_script[2] ^= 1; } else { wrong_script.insert(0, 0x61); }
                assert_eq!(verify_transparent_input(&transaction, Some(&hashes), 0, &output(100_002, &wrong_script)), Err(SproutLedgerError::InvalidTransparentScript));
                for changed in [v4(&transaction, BranchId::Sapling, 903_799), v4(&transaction, BranchId::Blossom, 903_798)] {
                    let hashes = TransactionSignatureHash::Sapling(SaplingSignatureHash::new(&changed).unwrap());
                    assert_eq!(verify_transparent_input(&changed, Some(&hashes), 0, &prevout), Err(SproutLedgerError::InvalidTransparentScript));
                }
                let mut parent = state();
                fund(&mut parent, ([0xa1; 32], 3), 100_002, &prevout.script_pubkey().0.0, 0, false);
                let delta = parent.stage_block(blossom_coinbase(height, 0), vec![transaction], height, 1_500_000_000).unwrap();
                assert_eq!((delta.fees, delta.issued), (2, 625_100_000));
                assert_eq!(delta.check_sapling_root(height, &parent.shielded_roots[1]), Ok(()));
                parent.commit(delta);
                assert!(parent.utxo(&[0xa1; 32], 3).is_none());
                assert_eq!((parent.transparent_balance(), parent.utxo_balance(), parent.issued_supply()), (625_100_000, 625_100_000, 625_100_000));
                for amount in [100_001, 100_003] {
                    let mut parent = state();
                    fund(&mut parent, ([0xa1; 32], 3), amount, &prevout.script_pubkey().0.0, 0, false);
                    fund(&mut parent, ([0xfa; 32], 0), 20, &[0x51], 0, false);
                    let before = owned_state(&parent);
                    let good = v4(&spend(&[(([0xfa; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Blossom, 0);
                    let (bad, _) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Blossom, p2sh, raw_type);
                    assert!(matches!(parent.stage_block(blossom_coinbase(height, 0), vec![good, bad], height, 1_500_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
                    assert_eq!(owned_state(&parent), before);
                }
                // Merely relabeling the original Sapling signature is NOT a Blossom positive.
                let (sapling, _) = independently_signed_transparent(TxVersion::V4, p2sh, raw_type);
                let relabeled = v4(&sapling, BranchId::Blossom, 280_021);
                let hashes = TransactionSignatureHash::Sapling(SaplingSignatureHash::new(&relabeled).unwrap());
                assert_eq!(verify_transparent_input(&relabeled, Some(&hashes), 0, &prevout), Err(SproutLedgerError::InvalidTransparentScript));
            }
        }
    }
}

#[test]
fn blossom_keeps_v4_size_finality_expiry_and_preheartwood_coinbase_rules() {
    let key = ([0xfb; 32], 0);
    for (length, accepted) in [(99_918, true), (1_999_917, true), (1_999_918, false)] {
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0; length])], 0), BranchId::Blossom, 0);
        let mut raw = Vec::new();
        transaction.write(&mut raw).unwrap();
        assert_eq!(raw.len(), length + 83);
        assert_eq!(check_transaction(&transaction, 584_000, 1_500_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::TransactionTooLarge) });
    }
    for (lock, sequence, time, expected) in [
        (583_999, 0, 1_500_000_000, Ok(())),
        (584_000, 0, 1_500_000_000, Err(SproutLedgerError::NonfinalTransaction)),
        (584_000, u32::MAX, 1_500_000_000, Ok(())),
        (500_000_000, 0, 500_000_001, Ok(())),
        (500_000_000, 0, 500_000_000, Err(SproutLedgerError::NonfinalTransaction)),
    ] {
        let transaction = v4(&spend(&[(key, &[], sequence)], vec![output(0, &[0x51])], lock), BranchId::Blossom, 0);
        assert_eq!(check_transaction(&transaction, 584_000, time).map(|_| ()), expected);
    }
    for expiry in [0, 1, 583_999, 584_000, 499_999_999] {
        assert_eq!(check_coinbase(&blossom_coinbase(584_000, expiry), 584_000, 1_500_000_000).unwrap().claimed, 625_000_000);
    }
    assert_eq!(check_coinbase(&blossom_coinbase(584_000, 500_000_000), 584_000, 1_500_000_000), Err(SproutLedgerError::InvalidTransaction));
    for version in [TxVersion::Sprout(1), TxVersion::V3] {
        let source = blossom_coinbase(584_000, 0);
        let bad = TransactionData::<Authorized>::from_parts(version, BranchId::Blossom, 0, 0.into(), source.transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        assert_eq!(check_coinbase(&bad, 584_000, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction));
    }
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    for (spends, outputs) in [(true, false), (false, true), (true, true)] {
        let bad = modified_sapling(if spends { bundle.shielded_spends().to_vec() } else { vec![] }, if outputs { bundle.shielded_outputs().to_vec() } else { vec![] }, 0, blossom_coinbase(584_000, 0).transparent_bundle().cloned());
        assert_eq!(check_coinbase(&v4(&bad, BranchId::Blossom, 0), 584_000, 1_500_000_000), Err(SproutLedgerError::InvalidCoinbase));
    }
    let groth = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Blossom).unwrap();
    let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Blossom, 0, 0.into(), blossom_coinbase(584_000, 0).transparent_bundle().cloned(), groth.sprout_bundle().cloned(), None, None).freeze().unwrap();
    assert_eq!(check_coinbase(&bad, 584_000, 1_500_000_000), Err(SproutLedgerError::InvalidCoinbase));
    let mut raw = include_bytes!("../tests/fixtures/testnet-blossom-block-584000.bin").to_vec();
    let end = raw.len();
    raw[end - 11] = 1;
    assert!(matches!(ParsedBlockBody::parse(&raw, &TEST_NETWORK), Err(BodyError::NoncanonicalEncoding)));
}

#[test]
fn blossom_fees_pruned_burns_and_underclaims_change_only_actual_issuance() {
    let key = ([0xfc; 32], 0);
    for (claimed_fee, burn, issued, retained) in [
        (9, 1, 625_000_099, 625_000_098),
        (10, 1, 625_000_100, 625_000_099),
        (9, 0, 625_000_098, 625_000_098),
    ] {
        let mut parent = state();
        fund(&mut parent, key, 100, &[0x51], 0, false);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(90, &[0x51])], 0), BranchId::Blossom, 0);
        let mut bundle = blossom_coinbase(584_000, 0).transparent_bundle().unwrap().clone();
        bundle.vout[0] = output(499_999_999 + claimed_fee, &[0x51]);
        bundle.vout.push(output(burn, &[0x6a]));
        let reward = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Blossom, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
        let delta = parent.stage_block(reward, vec![transaction], 584_000, 1_500_000_000).unwrap();
        assert_eq!(delta.fees, 10);
        parent.commit(delta);
        assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance()), (issued, issued, retained));
        assert_eq!(parent.shielded_balances, [0; 4]);
    }
    let mut parent = state();
    fund(&mut parent, key, 100, &[0x51], 0, false);
    let before = owned_state(&parent);
    let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(90, &[0x51])], 0), BranchId::Blossom, 0);
    let mut bundle = blossom_coinbase(584_000, 0).transparent_bundle().unwrap().clone();
    bundle.vout[0] = output(500_000_011, &[0x51]);
    let reward = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Blossom, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
    assert!(matches!(parent.stage_block(reward, vec![transaction], 584_000, 1_500_000_000), Err(SproutLedgerError::CoinbaseRewardExceeded)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn late_blossom_real_crypto_branch_anchor_nullifier_and_root_failures_keep_all_owned_state() {
    let mut parent = isolated_sapling_parent();
    let (signed, prevout) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Blossom, false, 1);
    fund(&mut parent, ([0xa1; 32], 3), 100_002, &prevout.script_pubkey().0.0, 0, false);
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Blossom, 0);
    // These genuine original proofs retain their old signatures, so Blossom
    // MUST reach the actual new-branch signature equation and reject them.
    let original = recorded_sapling();
    let bad = v4(&original, BranchId::Blossom, 0);
    assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![good(), bad], 584_000, 1_500_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
    raw[155] ^= 0x20;
    let bad = v4(&Transaction::read(raw.as_slice(), BranchId::Blossom).unwrap(), BranchId::Blossom, 0);
    assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![good(), bad], 584_000, 1_500_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let source = original.sapling_bundle().unwrap();
    let good_id: [u8; 32] = good().txid().into();
    let after_good = spend(&[((good_id, 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    // No SpendAuth can mask either output equation in this output-only negative.
    for index in 0..source.shielded_outputs().len() {
        let mut outputs = source.shielded_outputs().to_vec();
        let output = &outputs[index];
        let mut proof = *output.zkproof();
        proof[0] ^= 0x20;
        outputs[index] = sapling_crypto::bundle::OutputDescription::from_parts(output.cv().clone(), *output.cmu(), output.ephemeral_key().clone(), *output.enc_ciphertext(), *output.out_ciphertext(), proof);
        let bad = modified_sapling(vec![], outputs, 0, after_good.transparent_bundle().cloned());
        let bad = v4(&bad, BranchId::Blossom, 0);
        assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![good(), bad], 584_000, 1_500_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index: actual })) if actual == index));
        assert_eq!(owned_state(&parent), before);
    }
    let output_only = modified_sapling(vec![], source.shielded_outputs().to_vec(), 0, good().transparent_bundle().cloned());
    let bad = v4(&output_only, BranchId::Blossom, 0);
    assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![bad], 584_000, 1_500_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature))));
    assert_eq!(owned_state(&parent), before);
    let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
    raw[59] ^= 1;
    let bad = v4(&Transaction::read(raw.as_slice(), BranchId::Blossom).unwrap(), BranchId::Blossom, 0);
    assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![good(), bad], 584_000, 1_500_000_000), Err(SproutLedgerError::UnknownSaplingAnchor)));
    assert_eq!(owned_state(&parent), before);
    let wrong_branch = v4(&good(), BranchId::Sapling, 0);
    assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![good(), wrong_branch], 584_000, 1_500_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
    let delta = parent.stage_block(blossom_coinbase(584_000, 0), vec![good(), signed], 584_000, 1_500_000_000).unwrap();
    let mut wrong_root = parent.shielded_roots[1];
    wrong_root[0] ^= 1;
    assert_eq!(delta.check_sapling_root(584_000, &wrong_root), Err(SproutLedgerError::WrongSaplingRoot));
    assert_eq!(owned_state(&parent), before);
    let nullifier = source.shielded_spends()[0].nullifier().0;
    parent.nullifiers[1].insert(nullifier);
    let before = owned_state(&parent);
    let bad = v4(&original, BranchId::Blossom, 0);
    assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![good(), bad], 584_000, 1_500_000_000), Err(SproutLedgerError::SpentSaplingNullifier)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn blossom_maturity_sigops_and_late_original_sprout_signature_are_not_bypassed() {
    let key = ([0xfd; 32], 0);
    for (created, expected) in [(583_900, SproutLedgerError::UnshieldedCoinbaseSpend), (583_901, SproutLedgerError::ImmatureCoinbase)] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], created, true);
        let before = owned_state(&parent);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Blossom, 0);
        assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![transaction], 584_000, 1_500_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
    for (sigops, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let before = owned_state(&parent);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; sigops])], 0), BranchId::Blossom, 0);
        let mut bundle = blossom_coinbase(584_000, 0).transparent_bundle().unwrap().clone();
        bundle.vout[0] = output(500_000_000, &[0xac]);
        let reward = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Blossom, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
        let result = parent.stage_block(reward, vec![transaction], 584_000, 1_500_000_000);
        if accepted { assert_eq!(result.unwrap().sigops, 20_000); } else { assert!(matches!(result, Err(SproutLedgerError::TooManySigops))); }
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = isolated_sapling_parent();
    let original = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Sapling).unwrap();
    let mut sprout = original.sprout_bundle().unwrap().clone();
    parent.sprout_anchors.insert(*sprout.joinsplits[0].anchor(), Frontier::empty());
    let mut raw = Vec::new();
    sprout.joinsplits[0].write(&mut raw).unwrap();
    raw[..8].fill(0); // Modified statement, copied proof/signature deliberately invalid.
    sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap();
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(([0xe1; 32], 0), &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Blossom, 0);
    let id: [u8; 32] = good().txid().into();
    for (identity_signature, expected) in [
        (false, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (true, SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof })),
    ] {
        let mut sprout = sprout.clone();
        if identity_signature {
            sprout.joinsplit_pubkey = [0; 32];
            sprout.joinsplit_pubkey[0] = 1;
            sprout.joinsplit_sig = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000").try_into().unwrap();
        }
        let source = spend(&[((id, 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
        let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Blossom, 0, 0.into(), source.transparent_bundle().cloned(), Some(sprout), None, None).freeze().unwrap();
        assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![good(), bad], 584_000, 1_500_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn blossom_keeps_ordered_spends_parent_wide_bip30_and_pool_side_bounds() {
    let key = ([0xfe; 32], 0);
    let mut parent = state();
    fund(&mut parent, key, 100, &[0x51], 0, false);
    let first = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(80, &[0x51])], 0), BranchId::Blossom, 0);
    let id: [u8; 32] = first().txid().into();
    let second = || v4(&spend(&[((id, 0), &[], u32::MAX)], vec![output(70, &[0x51])], 0), BranchId::Blossom, 0);
    let before = owned_state(&parent);
    for transactions in [vec![second(), first()], vec![first(), second(), second()]] {
        assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), transactions, 584_000, 1_500_000_000), Err(SproutLedgerError::MissingTransparentInput)));
        assert_eq!(owned_state(&parent), before);
    }
    let delta = parent.stage_block(blossom_coinbase(584_000, 0), vec![first(), second()], 584_000, 1_500_000_000).unwrap();
    assert_eq!((delta.fees, delta.issued), (30, 625_000_070));
    parent.commit(delta);
    assert!(parent.utxo(&key.0, key.1).is_none());
    assert!(parent.utxo(&id, 0).is_none());
    let mut parent = state();
    fund(&mut parent, key, 100, &[0x51], 0, false);
    fund(&mut parent, (id, 7), 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let consume = v4(&spend(&[((id, 7), &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Blossom, 0);
    assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![consume, first()], 584_000, 1_500_000_000), Err(SproutLedgerError::UnspentTransactionOverwrite)));
    assert_eq!(owned_state(&parent), before);
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    let source = spend(&[(key, &[], u32::MAX)], vec![output(MAX_MONEY, &[0x51])], 0);
    let bad = modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), -1, source.transparent_bundle().cloned());
    assert!(matches!(check_transaction(&v4(&bad, BranchId::Blossom, 0), 584_000, 1_500_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    let mut parent = isolated_sapling_parent();
    fund(&mut parent, key, 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let source = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let bad = modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), MAX_MONEY as i64, source.transparent_bundle().cloned());
    assert!(matches!(parent.stage_block(blossom_coinbase(584_000, 0), vec![v4(&bad, BranchId::Blossom, 0)], 584_000, 1_500_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn heartwood_activation_coinbase_remains_valid_before_canopy() {
    // Isolated primary coinbases; no predecessor history/frontier is asserted.
    // Same pinned Zebra source and MIT notice as the numeric fixtures above.
    for (raw, height) in [
        (include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin").as_slice(), 903_800),
        (include_bytes!("../tests/fixtures/testnet-heartwood-block-903801.bin").as_slice(), 903_801),
        (include_bytes!("../tests/fixtures/testnet-heartwood-block-914678.bin").as_slice(), 914_678),
        (include_bytes!("../tests/fixtures/testnet-heartwood-block-925483.bin").as_slice(), 925_483),
        (include_bytes!("../tests/fixtures/testnet-heartwood-block-1028499.bin").as_slice(), 1_028_499),
    ] {
        let body = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap();
        assert_eq!(u32::from(body.block().claimed_height()), height);
        let values = check_coinbase(&body.block().vtx()[0], height, body.block().header().time).unwrap();
        assert_eq!(values.claimed, if height == 925_483 { 625_100_000 } else { 625_000_000 });
        assert_eq!(values.transparent, if matches!(height, 914_678 | 925_483) { 125_000_000 } else { 625_000_000 });
        assert_eq!(values.sapling_balance, match height { 914_678 => -500_000_000, 925_483 => -500_100_000, _ => 0 });
        let founder: [u8; 23] = bytes(if height == 1_028_499 { "a9145c8b8cf51ba3b5e10b63f77e8b8132e058724fd287" } else { "a914c6fb0a1ea5887b25b8e1a7b71a1e13c736953a1c87" }).try_into().unwrap();
        assert!(body.block().vtx()[0].transparent_bundle().unwrap().vout.iter().any(|output| u64::from(output.value()) == 125_000_000 && output.script_pubkey().0.0 == founder));
    }
    assert_eq!(supported_branch(1_028_500), Ok(BranchId::Canopy));
    assert_eq!(supported_branch(2_976_000), Ok(BranchId::Nu6));
}

fn primary_heartwood_coinbase(height: u32) -> Transaction {
    let raw = match height {
        903_800 => include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin").as_slice(),
        903_801 => include_bytes!("../tests/fixtures/testnet-heartwood-block-903801.bin").as_slice(),
        914_678 => include_bytes!("../tests/fixtures/testnet-heartwood-block-914678.bin").as_slice(),
        925_483 => include_bytes!("../tests/fixtures/testnet-heartwood-block-925483.bin").as_slice(),
        1_028_499 => include_bytes!("../tests/fixtures/testnet-heartwood-block-1028499.bin").as_slice(),
        _ => panic!("isolated primary Heartwood height"),
    };
    let (_, transactions) = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap().into_block().into_parts();
    transactions.head
}

fn heartwood_coinbase(height: u32) -> Transaction {
    v4(&blossom_coinbase(height, 0), BranchId::Heartwood, 0)
}

fn primary_heartwood_leaf(raw: &[u8], height: u32, final_root: [u8; 32], count: u64) -> HistoryLeaf {
    use sha2::{Digest, Sha256};
    let time = u32::from_le_bytes(raw[100..104].try_into().unwrap());
    let bits = u32::from_le_bytes(raw[104..108].try_into().unwrap());
    // TEST ONLY: isolated original header metadata, not checked predecessor
    // difficulty, a reconstructed predecessor frontier, or connected history.
    HistoryLeaf {
        consensus_branch_id: u32::from(BranchId::for_height(&TEST_NETWORK, height.into())),
        subtree_commitment: Sha256::digest(Sha256::digest(&raw[..HEADER_BYTES])).into(),
        start_time: time, end_time: time, start_target: bits, end_target: bits,
        start_sapling_root: final_root, end_sapling_root: final_root,
        subtree_total_work: super::super::block_work(super::super::testnet_target_from_compact(bits).unwrap()).unwrap(),
        start_height: height.into(), end_height: height.into(), sapling_tx: count,
    }
}

fn isolated_heartwood_history(parent: &mut SproutTestnetLedger) {
    let leaf = primary_heartwood_leaf(include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin"), 903_800, parent.shielded_roots[1], 0);
    let history = ChainHistoryV1::new(leaf).unwrap();
    parent.history_root = Some(history.root());
    parent.chain_history = Some(history);
}

#[test]
fn original_heartwood_shielded_coinbase_verifies_recovery_proof_binding_and_separate_pool_issuance() {
    let mut parent = state();
    let before = owned_state(&parent);
    let transaction = primary_heartwood_coinbase(914_678);
    let id: [u8; 32] = transaction.txid().into();
    let bundle = transaction.sapling_bundle().unwrap();
    assert!(bundle.shielded_spends().is_empty());
    assert_eq!(bundle.shielded_outputs().len(), 1);
    assert_eq!(recover_sapling_coinbase_output(&bundle.shielded_outputs()[0], 914_678), Ok(500_000_000));
    assert_eq!(verify_sapling_v4_crypto(&SaplingSignatureHash::new(&transaction).unwrap()), Ok(()));
    let values = check_coinbase(&transaction, 914_678, 1_589_338_582).unwrap();
    assert_eq!((values.claimed, values.transparent, values.retained, values.sapling_balance), (625_000_000, 125_000_000, 125_000_000, -500_000_000));
    let mut reference = sapling_crypto::CommitmentTree::empty();
    reference.append(SaplingNode::from_cmu(bundle.shielded_outputs()[0].cmu())).unwrap();
    let delta = parent.stage_block(transaction, vec![], 914_678, 1_589_338_582).unwrap();
    assert_eq!((delta.transparent, delta.retained, delta.sapling, delta.issued, delta.fees), (125_000_000, 125_000_000, 500_000_000, 625_000_000, 0));
    assert_eq!(delta.sapling_tree.tree_size(), 1);
    assert_eq!(delta.sapling_root, reference.root().to_bytes());
    assert_eq!(delta.check_sapling_root(914_678, &[0x5a; 32]), Ok(()));
    assert_eq!(owned_state(&parent), before);
    // Commit only this isolated, actual-crypto delta. This is not a mined
    // genesis-connected914678 history or an authenticated predecessor archive.
    parent.commit(delta);
    assert_eq!((parent.transparent_balance(), parent.utxo_balance(), parent.shielded_balance(ShieldedPool::Sapling), parent.issued_supply()), (125_000_000, 125_000_000, 500_000_000, 625_000_000));
    assert_eq!(parent.sapling_tree_size(), 1);
    assert!(parent.utxo(&id, 0).unwrap().is_coinbase());
    assert!(parent.sapling_anchors.contains(&reference.root().to_bytes()));
    let spend = v4(&modified_sapling(vec![sapling_spend(reference.root().to_bytes(), [0x79; 32])], vec![], 0, None), BranchId::Heartwood, 0);
    // Anchor acceptance has no added Sapling coinbase100-block maturity rule;
    // copied proof here is context-only, not a genuine spend of that note.
    assert_eq!(parent.stage_sapling(&spend, &mut BlockDelta::new(&parent)), Ok(()));
    assert_eq!(parent.history_root(), None);
}

#[test]
fn genuine_shielded_rewards_claim_actual_fees_and_underclaims_destroy_only_unclaimed_value() {
    for (height, fee, expected_issued, expected_transparent, expected_sapling) in [
        (914_678, 100_000, 625_000_000, 125_000_000, 500_000_000),
        (925_483, 100_000, 625_100_000, 125_000_000, 500_100_000),
    ] {
        let mut parent = state();
        let key = ([0x73; 32], 0);
        fund(&mut parent, key, fee, &[0x51], 0, false);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Heartwood, 0);
        let delta = parent.stage_block(primary_heartwood_coinbase(height), vec![transaction], height, 1_600_000_000).unwrap();
        assert_eq!((delta.fees, delta.issued, delta.transparent, delta.sapling), (fee.into(), expected_issued, expected_transparent, expected_sapling));
        parent.commit(delta);
        assert!(parent.utxo(&key.0, key.1).is_none());
        assert_eq!(parent.issued_supply(), expected_issued);
    }
    let parent = state();
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(925_483), vec![], 925_483, 1_600_000_000), Err(SproutLedgerError::CoinbaseRewardExceeded)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn every_primary_coinbase_ciphertext_proof_and_binding_failure_preserves_full_history_and_ledger() {
    let mut parent = state();
    isolated_heartwood_history(&mut parent);
    let before = owned_state(&parent);
    let original = primary_heartwood_coinbase(914_678);
    let mut raw = Vec::new();
    original.write(&mut raw).unwrap();
    // Original numeric transaction: VB97, output107, proof863, binding1056.
    for (offset, mask, expected) in [
        (97, 1, SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature)),
        (139, 1, SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::OutgoingAuthentication }),
        (171, 1, SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::OutgoingAuthentication }),
        (203, 1, SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::NoteAuthentication }),
        (782, 1, SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::NoteAuthentication }),
        (783, 1, SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::OutgoingAuthentication }),
        (862, 1, SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::OutgoingAuthentication }),
        (863, 0x20, SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index: 0 })),
        (1119, 1, SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature)),
    ] {
        let mut changed = raw.clone();
        changed[offset] ^= mask;
        let bad = Transaction::read(changed.as_slice(), BranchId::Heartwood).unwrap();
        assert!(matches!(parent.stage_block(bad, vec![], 914_678, 1_589_338_582), Err(error) if error == expected), "field{offset}");
        assert_eq!(owned_state(&parent), before);
    }
    let source = original.sapling_bundle().unwrap();
    for bad_index in [0, 1] {
        let mut outputs = vec![source.shielded_outputs()[0].clone(); 2];
        let description = &outputs[bad_index];
        let mut proof = *description.zkproof();
        proof[0] ^= 0x20;
        outputs[bad_index] = sapling_crypto::bundle::OutputDescription::from_parts(description.cv().clone(), *description.cmu(), description.ephemeral_key().clone(), *description.enc_ciphertext(), *description.out_ciphertext(), proof);
        let bundle = sapling_crypto::Bundle::from_parts(vec![], outputs, *source.value_balance(), *source.authorization());
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, original.lock_time(), original.expiry_height(), original.transparent_bundle().cloned(), None, bundle, None).freeze().unwrap();
        assert!(matches!(parent.stage_block(transaction, vec![], 914_678, 1_589_338_582), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index })) if index == bad_index));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn heartwood_coinbase_keeps_exact_height_founders_and_no_spend_or_joinsplit_rules() {
    let original = primary_heartwood_coinbase(914_678);
    let sapling = original.sapling_bundle().unwrap();
    let spend = recorded_sapling().sapling_bundle().unwrap().shielded_spends()[0].clone();
    let with_spend = sapling_crypto::Bundle::from_parts(vec![spend], sapling.shielded_outputs().to_vec(), *sapling.value_balance(), *sapling.authorization());
    let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, original.lock_time(), original.expiry_height(), original.transparent_bundle().cloned(), None, with_spend, None).freeze().unwrap();
    assert_eq!(check_coinbase(&bad, 914_678, 1_589_338_582), Err(SproutLedgerError::InvalidCoinbase));
    let groth = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Heartwood).unwrap();
    let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, original.lock_time(), original.expiry_height(), original.transparent_bundle().cloned(), groth.sprout_bundle().cloned(), original.sapling_bundle().cloned(), None).freeze().unwrap();
    assert_eq!(check_coinbase(&bad, 914_678, 1_589_338_582), Err(SproutLedgerError::InvalidCoinbase));
    for length in [1, 101] {
        let mut transparent = original.transparent_bundle().unwrap().clone();
        script_input(&mut transparent, &vec![0; length], u32::MAX);
        let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, original.lock_time(), original.expiry_height(), Some(transparent), None, original.sapling_bundle().cloned(), None).freeze().unwrap();
        assert_eq!(check_coinbase(&bad, 914_678, 1_589_338_582), Err(SproutLedgerError::InvalidCoinbase));
    }
    for (wrong_height, wrong_reward, expected) in [
        (true, false, SproutLedgerError::InvalidCoinbase),
        (false, true, SproutLedgerError::MissingFoundersReward),
    ] {
        let mut transparent = original.transparent_bundle().unwrap().clone();
        if wrong_height {
            let (prefix, length) = coinbase_height_prefix(914_677);
            script_input(&mut transparent, &prefix[..length], u32::MAX);
        } else if wrong_reward {
            transparent.vout[0] = output(124_999_999, &founders_script(914_678));
        }
        let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, original.lock_time(), original.expiry_height(), Some(transparent), None, original.sapling_bundle().cloned(), None).freeze().unwrap();
        assert_eq!(check_coinbase(&bad, 914_678, 1_589_338_582), Err(expected));
    }
    assert_eq!(check_coinbase(&v4(&original, BranchId::Blossom, 0), 914_678, 1_589_338_582), Err(SproutLedgerError::UnsupportedTransaction));
    assert_eq!(check_coinbase(&v4(&original, BranchId::Nu6, 0), 2_976_000, 1_596_488_368), Err(SproutLedgerError::InvalidCoinbase));
    for version in [TxVersion::Sprout(1), TxVersion::V3] {
        let bad = TransactionData::<Authorized>::from_parts(version, BranchId::Heartwood, 0, 0.into(), heartwood_coinbase(903_800).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        assert_eq!(check_coinbase(&bad, 903_800, 1_600_000_000), Err(SproutLedgerError::UnsupportedTransaction));
    }
    for expiry in [0, 1, 903_799, 903_800, 499_999_999] {
        assert_eq!(check_coinbase(&v4(&heartwood_coinbase(903_800), BranchId::Heartwood, expiry), 903_800, 1_600_000_000).unwrap().claimed, 625_000_000);
    }
    assert_eq!(check_coinbase(&v4(&heartwood_coinbase(903_800), BranchId::Heartwood, 500_000_000), 903_800, 1_600_000_000), Err(SproutLedgerError::InvalidTransaction));
}

#[test]
fn heartwood_two_megabyte_v4_finality_expiry_and_actual_zip243_ecdsa_are_enforced() {
    let height = 903_800;
    let key = ([0x74; 32], 0);
    for (length, expected) in [(1_999_917, Ok(())), (1_999_918, Err(SproutLedgerError::TransactionTooLarge))] {
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0; length])], 0), BranchId::Heartwood, 0);
        assert_eq!(check_transaction(&transaction, height, 1_600_000_000).map(|_| ()), expected);
    }
    for (expiry, expected) in [(0, Ok(())), (903_800, Ok(())), (903_799, Err(SproutLedgerError::ExpiredTransaction)), (500_000_000, Err(SproutLedgerError::InvalidTransaction))] {
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Heartwood, expiry);
        assert_eq!(check_transaction(&transaction, height, 1_600_000_000).map(|_| ()), expected);
    }
    for (lock, sequence, expected) in [(903_799, 0, Ok(())), (903_800, 0, Err(SproutLedgerError::NonfinalTransaction)), (903_800, u32::MAX, Ok(()))] {
        let transaction = v4(&spend(&[(key, &[], sequence)], vec![output(0, &[0x51])], lock), BranchId::Heartwood, 0);
        assert_eq!(check_transaction(&transaction, height, 1_600_000_000).map(|_| ()), expected);
    }
    for (p2sh, raw_type) in [(false, 1), (true, 1), (false, 0x41), (true, 0x81)] {
        let (transaction, prevout) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Heartwood, p2sh, raw_type);
        let mut parent = state();
        fund(&mut parent, ([0xa1; 32], 3), 100_002, &prevout.script_pubkey().0.0, 0, false);
        let delta = parent.stage_block(heartwood_coinbase(height), vec![transaction], height, 1_600_000_000).unwrap();
        assert_eq!(delta.fees, 2);
        let before = owned_state(&parent);
        let (transaction, _) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Heartwood, p2sh, raw_type);
        let wrong = v4(&transaction, BranchId::Blossom, 0);
        assert!(matches!(parent.stage_block(heartwood_coinbase(height), vec![wrong], height, 1_600_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
        assert_eq!(owned_state(&parent), before);
        parent.utxos.get_mut(&([0xa1; 32], 3)).unwrap().output = output(100_003, &prevout.script_pubkey().0.0);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_block(heartwood_coinbase(height), vec![transaction], height, 1_600_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn coinbase_sapling_leaves_precede_other_outputs_without_admitting_current_block_anchors() {
    let parent = isolated_sapling_parent();
    let coinbase = primary_heartwood_coinbase(914_678);
    let mut delta = parent.stage_block(coinbase, vec![], 914_678, 1_589_338_582).unwrap();
    let coinbase_root = delta.sapling_root;
    assert!(!parent.sapling_anchors.contains(&coinbase_root));
    let bad = v4(&modified_sapling(vec![sapling_spend(coinbase_root, [0x75; 32])], vec![], 0, None), BranchId::Heartwood, 0);
    assert_eq!(parent.stage_sapling(&bad, &mut delta), Err(SproutLedgerError::UnknownSaplingAnchor));
    let mut delta = parent.stage_block(primary_heartwood_coinbase(914_678), vec![], 914_678, 1_589_338_582).unwrap();
    let original = recorded_sapling();
    let mut reference = sapling_crypto::CommitmentTree::empty();
    let primary = primary_heartwood_coinbase(914_678);
    reference.append(SaplingNode::from_cmu(primary.sapling_bundle().unwrap().shielded_outputs()[0].cmu())).unwrap();
    for description in original.sapling_bundle().unwrap().shielded_outputs() {
        reference.append(SaplingNode::from_cmu(description.cmu())).unwrap();
    }
    // Context/tree only: the old Sapling signature is NOT a Heartwood signature.
    parent.stage_sapling(&v4(&original, BranchId::Heartwood, 0), &mut delta).unwrap();
    assert_eq!(delta.sapling_tree.tree_size(), 3);
    assert_eq!(delta.sapling_tree.root(), reference.root());
    assert!(!parent.sapling_anchors.contains(&reference.root().to_bytes()));
    let original_anchor = original.sapling_bundle().unwrap().shielded_spends()[0].anchor().to_bytes();
    let historical = v4(&modified_sapling(vec![sapling_spend(original_anchor, [0x76; 32])], vec![], 0, None), BranchId::Heartwood, 0);
    assert_eq!(parent.stage_sapling(&historical, &mut delta), Ok(()));
}

#[test]
fn primary_activation_zero_initializes_first_leaf_and_next_header_commits_parent_not_current_root() {
    let raw_first = include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin");
    let raw_next = include_bytes!("../tests/fixtures/testnet-heartwood-block-903801.bin");
    let final_root: [u8; 32] = bytes("e28844f43b7a882ed5f0d9a4cc5575f53ed75bee5226ba3d3d96d55c39446462").try_into().unwrap();
    let mut parent = state();
    assert_eq!(parent.history_root(), None);
    assert!(parent.chain_history.is_none());
    let first = primary_heartwood_leaf(raw_first, 903_800, final_root, 0);
    assert_eq!(first.subtree_total_work, primitive_types::U256::from(32));
    assert_eq!(parent.stage_history(&[1; 32], first.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    let history = parent.stage_history(&[0; 32], first.clone()).unwrap();
    let expected: [u8; 32] = bytes("17d05811e9c5fef7303a453b1e424aeac1a1ed914ec3a2a67f890d897cac61a4").try_into().unwrap();
    assert_eq!(history.root(), expected);
    assert_eq!(history.leaf_count(), 1);
    assert_eq!(&raw_next[68..100], expected);
    parent.history_root = Some(history.root());
    parent.chain_history = Some(history);
    let before = owned_state(&parent);
    let next = primary_heartwood_leaf(raw_next, 903_801, final_root, 0);
    let staged = parent.stage_history(&expected, next.clone()).unwrap();
    assert_eq!(staged.leaf_count(), 2);
    assert_ne!(staged.root(), expected);
    assert_eq!(parent.stage_history(&staged.root(), next).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    for field in 0..7 {
        let mut forged = first.clone();
        match field {
            0 => forged.subtree_commitment[0] ^= 1,
            1 => { forged.start_time += 1; forged.end_time += 1; }
            2 => { forged.start_target ^= 1; forged.end_target ^= 1; }
            3 => { forged.start_sapling_root[0] ^= 1; forged.end_sapling_root[0] ^= 1; }
            4 => forged.subtree_total_work += primitive_types::U256::from(1),
            5 => forged.sapling_tx = 1,
            6 => { forged.start_height += 1; forged.end_height += 1; }
            _ => unreachable!(),
        }
        let forged_history = ChainHistoryV1::new(forged).unwrap();
        assert_ne!(forged_history.root(), expected, "metadata{field}");
        parent.history_root = Some(forged_history.root());
        parent.chain_history = Some(forged_history);
        let before = owned_state(&parent);
        let next = primary_heartwood_leaf(raw_next, 903_801, final_root, 0);
        assert_eq!(parent.stage_history(&expected, next).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn late_history_height_work_count_and_header_failures_never_publish_any_owned_field() {
    let mut parent = state();
    isolated_heartwood_history(&mut parent);
    let root = parent.history_root().unwrap();
    let before = owned_state(&parent);
    let raw_next = include_bytes!("../tests/fixtures/testnet-heartwood-block-903801.bin");
    let leaf = primary_heartwood_leaf(raw_next, 903_802, parent.shielded_roots[1], 0);
    assert_eq!(parent.stage_history(&root, leaf).unwrap_err(), SproutLedgerError::History(HistoryError::NonconsecutiveHeight));
    assert_eq!(owned_state(&parent), before);
    for work_overflow in [false, true] {
        let mut first = primary_heartwood_leaf(include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin"), 903_800, parent.shielded_roots[1], 0);
        if work_overflow { first.subtree_total_work = primitive_types::U256::MAX; } else { first.sapling_tx = u64::MAX; }
        let history = ChainHistoryV1::new(first).unwrap();
        parent.history_root = Some(history.root());
        parent.chain_history = Some(history);
        let before = owned_state(&parent);
        let delta = parent.stage_block(primary_heartwood_coinbase(914_678), vec![], 914_678, 1_589_338_582).unwrap();
        let next = primary_heartwood_leaf(raw_next, 903_801, delta.sapling_root, 1);
        assert_eq!(parent.stage_history(&parent.history_root().unwrap(), next).unwrap_err(), SproutLedgerError::History(if work_overflow { HistoryError::WorkOverflow } else { HistoryError::SaplingCountOverflow }));
        assert_eq!(owned_state(&parent), before);
    }
    // Genuine connected first header stages successfully; an intentionally
    // inconsistent isolated money total fails later without publishing headers.
    parent.issued_supply = 1;
    let before = owned_state(&parent);
    assert_eq!(parent.apply_block(include_bytes!("../tests/fixtures/testnet-block-1.bin")), Err(SproutLedgerError::ValueOutOfRange));
    assert_eq!(owned_state(&parent), before);
    assert_eq!(parent.apply_block(include_bytes!("../tests/fixtures/testnet-heartwood-block-914678.bin")), Err(SproutLedgerError::WrongHeight));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn checked_tip_metadata_uses_actual_block_work_and_final_frontier_not_header_commitment() {
    let mut parent = state();
    let genesis_tip = parent.tip();
    let first = parent.headers.append(include_bytes!("../tests/fixtures/testnet-block-1.bin").split_at(HEADER_BYTES).0).unwrap();
    let transaction = primary_heartwood_coinbase(914_678);
    let delta = parent.stage_block(transaction, vec![], 914_678, 1_589_338_582).unwrap();
    let leaf = history_leaf(genesis_tip, first, delta.sapling_root, 1).unwrap();
    assert_eq!(leaf.consensus_branch_id, 0); // Actual checked tip1 is Sprout, not the isolated coinbase's era.
    assert_eq!(leaf.subtree_commitment.as_slice(), bytes("238d665a062b9007836a7d8f968ba2f3847af5f542733389a952cf9b86795502"));
    assert_eq!((leaf.start_time, leaf.end_time, leaf.start_target, leaf.end_target), (1_477_674_473, 1_477_674_473, 0x2007_ffff, 0x2007_ffff));
    assert_eq!(leaf.subtree_total_work, primitive_types::U256::from(32));
    assert_ne!(leaf.subtree_total_work, first.cumulative_work());
    assert_eq!((leaf.start_height, leaf.end_height, leaf.sapling_tx), (1, 1, 1));
    assert_eq!(leaf.start_sapling_root, delta.sapling_tree.root().to_bytes());
    assert_eq!(leaf.end_sapling_root, leaf.start_sapling_root);
    let header_commitment = ParsedBlockBody::parse(include_bytes!("../tests/fixtures/testnet-heartwood-block-914678.bin"), &TEST_NETWORK).unwrap().block().header().final_sapling_root;
    assert_ne!(leaf.start_sapling_root, header_commitment);
    assert_eq!(history_leaf(first, genesis_tip, delta.sapling_root, 1).unwrap_err(), SproutLedgerError::Header(HeaderError::WorkOverflow));
}

#[test]
fn history_counts_sapling_transactions_once_including_coinbase_and_both_spend_output_kinds() {
    for (raw, count) in [
        (include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin").as_slice(), 0),
        (include_bytes!("../tests/fixtures/testnet-heartwood-block-914678.bin").as_slice(), 1),
        (include_bytes!("../tests/fixtures/testnet-heartwood-block-925483.bin").as_slice(), 2),
    ] {
        let body = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap();
        assert_eq!(sapling_transaction_count(body.block().vtx().iter()), count);
    }
    let original = recorded_sapling();
    assert_eq!(sapling_transaction_count(std::iter::once(&original)), 1);
    let spend_only = modified_sapling(original.sapling_bundle().unwrap().shielded_spends().to_vec(), vec![], 0, None);
    let outputs_only = modified_sapling(vec![], original.sapling_bundle().unwrap().shielded_outputs().to_vec(), 0, None);
    assert_eq!(sapling_transaction_count([&spend_only, &outputs_only, &original].into_iter()), 3);
    // Counting is structural only; copied signatures above are not valid for
    // the modified contexts. Neither this test nor metadata authenticate them.
}

#[test]
fn late_heartwood_spend_output_binding_and_original_joinsplit_equations_preserve_all_owned_fields() {
    let mut parent = isolated_sapling_parent();
    isolated_heartwood_history(&mut parent);
    let before = owned_state(&parent);
    let key = ([0xe1; 32], 0);
    let good = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Heartwood, 0);
    // Real earlier Sapling proofs, deliberately old branch signatures: the
    // Heartwood statement MUST reach the original pre-NU5 authorization check.
    let bad = v4(&recorded_sapling(), BranchId::Heartwood, 0);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![good(), bad], 914_678, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
    raw[155] ^= 0x20;
    let bad = v4(&Transaction::read(raw.as_slice(), BranchId::Heartwood).unwrap(), BranchId::Heartwood, 0);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![good(), bad], 914_678, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    for bad_index in 0..bundle.shielded_outputs().len() {
        let mut outputs = bundle.shielded_outputs().to_vec();
        let description = &outputs[bad_index];
        let mut proof = *description.zkproof();
        proof[0] ^= 0x20;
        outputs[bad_index] = sapling_crypto::bundle::OutputDescription::from_parts(description.cv().clone(), *description.cmu(), description.ephemeral_key().clone(), *description.enc_ciphertext(), *description.out_ciphertext(), proof);
        let source = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
        let bad = v4(&modified_sapling(vec![], outputs, 0, source.transparent_bundle().cloned()), BranchId::Heartwood, 0);
        assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![bad], 914_678, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index })) if index == bad_index));
        assert_eq!(owned_state(&parent), before);
    }
    let source = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let bad = v4(&modified_sapling(vec![], bundle.shielded_outputs().to_vec(), 0, source.transparent_bundle().cloned()), BranchId::Heartwood, 0);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![bad], 914_678, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature))));
    assert_eq!(owned_state(&parent), before);
    let groth = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Heartwood).unwrap();
    let mut sprout = groth.sprout_bundle().unwrap().clone();
    parent.sprout_anchors.insert(*sprout.joinsplits[0].anchor(), Frontier::empty());
    let mut description = Vec::new();
    sprout.joinsplits[0].write(&mut description).unwrap();
    description[..8].fill(0); // Modified statement, copied proof deliberately invalid.
    sprout.joinsplits[0] = JsDescription::read(description.as_slice(), true).unwrap();
    let before = owned_state(&parent);
    let id: [u8; 32] = good().txid().into();
    for (identity_signature, expected) in [
        (false, SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature)),
        (true, SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof })),
    ] {
        let mut sprout = sprout.clone();
        if identity_signature {
            sprout.joinsplit_pubkey = [0; 32];
            sprout.joinsplit_pubkey[0] = 1;
            sprout.joinsplit_sig = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000").try_into().unwrap();
        }
        let source = spend(&[((id, 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
        let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, 0, 0.into(), source.transparent_bundle().cloned(), Some(sprout), None, None).freeze().unwrap();
        assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![good(), bad], 914_678, 1_600_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn shielded_coinbase_capacity_pool_and_late_script_failures_keep_all_parent_fields() {
    let mut parent = state();
    isolated_heartwood_history(&mut parent);
    parent.sapling_tree = Frontier::from_parts(((1_u64 << 32) - 1).into(), SaplingNode::from_scalar(bls12_381::Scalar::from(2)), vec![SaplingNode::from_scalar(bls12_381::Scalar::from(3)); 32]).unwrap();
    parent.shielded_roots[1] = parent.sapling_tree.root().to_bytes();
    parent.sapling_anchors.insert(parent.shielded_roots[1]);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![], 914_678, 1_589_338_582), Err(SproutLedgerError::SaplingTreeFull)));
    assert_eq!(owned_state(&parent), before);
    let mut parent = state();
    isolated_heartwood_history(&mut parent);
    parent.shielded_balances[1] = MAX_MONEY;
    parent.issued_supply = MAX_MONEY;
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![], 914_678, 1_589_338_582), Err(SproutLedgerError::ValueOutOfRange)));
    assert_eq!(owned_state(&parent), before);
    let mut parent = state();
    isolated_heartwood_history(&mut parent);
    let key = ([0x77; 32], 0);
    fund(&mut parent, key, 20, &[0x51], 0, false);
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Heartwood, 0);
    let id: [u8; 32] = good().txid().into();
    let bad = v4(&spend(&[((id, 0), &[0x6a], u32::MAX)], vec![output(18, &[0x51])], 0), BranchId::Heartwood, 0);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![good(), bad], 914_678, 1_589_338_582), Err(SproutLedgerError::InvalidTransparentScript)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn heartwood_maturity_sigops_ordered_utxos_bip30_and_pruned_rewards_keep_original_rules() {
    let height = 903_800;
    let key = ([0x78; 32], 0);
    for (created, expected) in [(903_700, SproutLedgerError::UnshieldedCoinbaseSpend), (903_701, SproutLedgerError::ImmatureCoinbase)] {
        let mut parent = state();
        isolated_heartwood_history(&mut parent);
        fund(&mut parent, key, 0, &[0x51], created, true);
        let before = owned_state(&parent);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Heartwood, 0);
        assert!(matches!(parent.stage_block(heartwood_coinbase(height), vec![transaction], height, 1_600_000_000), Err(error) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
    for (sigops, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = state();
        isolated_heartwood_history(&mut parent);
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let before = owned_state(&parent);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; sigops])], 0), BranchId::Heartwood, 0);
        let mut transparent = heartwood_coinbase(height).transparent_bundle().unwrap().clone();
        transparent.vout[0] = output(500_000_000, &[0xac]);
        let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, 0, 0.into(), Some(transparent), None, None, None).freeze().unwrap();
        let result = parent.stage_block(coinbase, vec![transaction], height, 1_600_000_000);
        if accepted { assert_eq!(result.unwrap().sigops, 20_000); } else { assert!(matches!(result, Err(SproutLedgerError::TooManySigops))); }
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = state();
    isolated_heartwood_history(&mut parent);
    fund(&mut parent, key, 100, &[0x51], 0, false);
    let first = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(80, &[0x51])], 0), BranchId::Heartwood, 0);
    let id: [u8; 32] = first().txid().into();
    let second = || v4(&spend(&[((id, 0), &[], u32::MAX)], vec![output(70, &[0x51])], 0), BranchId::Heartwood, 0);
    let before = owned_state(&parent);
    for transactions in [vec![second(), first()], vec![first(), second(), second()]] {
        assert!(matches!(parent.stage_block(heartwood_coinbase(height), transactions, height, 1_600_000_000), Err(SproutLedgerError::MissingTransparentInput)));
        assert_eq!(owned_state(&parent), before);
    }
    let delta = parent.stage_block(heartwood_coinbase(height), vec![first(), second()], height, 1_600_000_000).unwrap();
    assert_eq!((delta.fees, delta.issued, delta.transparent), (30, 625_000_070, 625_000_070));
    fund(&mut parent, (id, 7), 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let consume = v4(&spend(&[((id, 7), &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Heartwood, 0);
    assert!(matches!(parent.stage_block(heartwood_coinbase(height), vec![consume, first()], height, 1_600_000_000), Err(SproutLedgerError::UnspentTransactionOverwrite)));
    assert_eq!(owned_state(&parent), before);
    for (claimed_fee, burn, issued, retained) in [(9, 1, 625_000_099, 625_000_098), (10, 1, 625_000_100, 625_000_099), (9, 0, 625_000_098, 625_000_098)] {
        let mut parent = state();
        fund(&mut parent, key, 100, &[0x51], 0, false);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(90, &[0x51])], 0), BranchId::Heartwood, 0);
        let mut transparent = heartwood_coinbase(height).transparent_bundle().unwrap().clone();
        transparent.vout[0] = output(499_999_999 + claimed_fee, &[0x51]);
        transparent.vout.push(output(burn, &[0x6a]));
        let coinbase = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, 0, 0.into(), Some(transparent), None, None, None).freeze().unwrap();
        let delta = parent.stage_block(coinbase, vec![transaction], height, 1_600_000_000).unwrap();
        assert_eq!(delta.fees, 10);
        parent.commit(delta);
        assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance()), (issued, issued, retained));
        assert_eq!(parent.shielded_balances, [0; 4]);
    }
}

#[test]
fn heartwood_money_sides_and_changed_coinbase_value_balance_use_real_equations_not_plaintext_totals() {
    let primary = primary_heartwood_coinbase(914_678);
    let source = primary.sapling_bundle().unwrap();
    for balance in [0, 1, -499_999_999, -500_000_001] {
        let sapling = sapling_crypto::Bundle::from_parts(vec![], source.shielded_outputs().to_vec(), zcash_protocol::value::ZatBalance::from_i64(balance).unwrap(), *source.authorization());
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, primary.lock_time(), primary.expiry_height(), primary.transparent_bundle().cloned(), None, sapling, None).freeze().unwrap();
        assert_eq!(check_coinbase(&transaction, 914_678, 1_589_338_582), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature)));
    }
    // Same real ciphertext/proof: total debit bound must reject T+(-VB) before
    // copied binding authorization, not clamp/net either monetary side.
    let mut transparent = primary.transparent_bundle().unwrap().clone();
    transparent.vout.push(output(MAX_MONEY - 125_000_000, &[0x51]));
    let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, primary.lock_time(), primary.expiry_height(), Some(transparent), None, primary.sapling_bundle().cloned(), None).freeze().unwrap();
    assert_eq!(check_coinbase(&transaction, 914_678, 1_589_338_582), Err(SproutLedgerError::ValueOutOfRange));
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    let source = spend(&[(([0x79; 32], 0), &[], u32::MAX)], vec![output(MAX_MONEY, &[0x51])], 0);
    let transaction = v4(&modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), -1, source.transparent_bundle().cloned()), BranchId::Heartwood, 0);
    assert!(matches!(check_transaction(&transaction, 903_800, 1_600_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    let mut parent = isolated_sapling_parent();
    isolated_heartwood_history(&mut parent);
    fund(&mut parent, ([0x79; 32], 0), 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let source = spend(&[(([0x79; 32], 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let transaction = v4(&modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), MAX_MONEY as i64, source.transparent_bundle().cloned()), BranchId::Heartwood, 0);
    assert!(matches!(parent.stage_block(heartwood_coinbase(903_800), vec![transaction], 903_800, 1_600_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    assert_eq!(owned_state(&parent), before);
}

fn changed_public_coinbase_plaintext(field: u8) -> Transaction {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::AeadInPlace};
    use group::GroupEncoding;
    use sapling_crypto::{keys::OutgoingViewingKey, note_encryption::{KDF_SAPLING_PERSONALIZATION, prf_ock}};
    let transaction = primary_heartwood_coinbase(914_678);
    let bundle = transaction.sapling_bundle().unwrap();
    let original = &bundle.shielded_outputs()[0];
    // The fixture's zero OVK makes these ciphertext witnesses public protocol
    // data. Mutations do not introduce an external key or change real proofs.
    let nonce = Nonce::from_slice(&[0; 12]);
    let original_ock = prf_ock(&OutgoingViewingKey([0; 32]), original.cv(), &original.cmu().to_bytes(), original.ephemeral_key());
    let mut outgoing_plain: [u8; 64] = original.out_ciphertext()[..64].try_into().unwrap();
    ChaCha20Poly1305::new_from_slice(&original_ock.0).unwrap().decrypt_in_place_detached(nonce, &[], &mut outgoing_plain, chacha20poly1305::Tag::from_slice(&original.out_ciphertext()[64..])).unwrap();
    let pk_d = jubjub::AffinePoint::from_bytes_pre_zip216_compatibility(outgoing_plain[..32].try_into().unwrap()).unwrap();
    let esk = jubjub::Fr::from_bytes(&outgoing_plain[32..].try_into().unwrap()).unwrap();
    let different_esk = esk + jubjub::Fr::from(1);
    let shared = (jubjub::ExtendedPoint::from(pk_d) * esk).mul_by_cofactor().to_bytes();
    let key = blake2b_simd::Params::new().hash_length(32).personal(KDF_SAPLING_PERSONALIZATION).to_state().update(&shared).update(&original.ephemeral_key().0).finalize();
    let mut note: [u8; 564] = original.enc_ciphertext()[..564].try_into().unwrap();
    ChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap().decrypt_in_place_detached(nonce, &[], &mut note, chacha20poly1305::Tag::from_slice(&original.enc_ciphertext()[564..])).unwrap();
    let mut cmu = *original.cmu();
    let mut cv = original.cv().clone();
    match field {
        0 => outgoing_plain[..32].fill(0xff),
        1 => outgoing_plain[32..].fill(0xff),
        2 => note[20..52].fill(0xff),
        3 => note[0] = 2,
        4 => {
            let invalid = (0..=u8::MAX).map(|first| { let mut d = [0; 11]; d[0] = first; sapling_crypto::Diversifier(d) }).find(|d| d.g_d().is_none()).unwrap();
            note[1..12].copy_from_slice(&invalid.0);
        }
        5 => note[12..20].copy_from_slice(&499_999_999_u64.to_le_bytes()),
        6 => cmu = sapling_crypto::note::ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::from(1).to_bytes()).unwrap(),
        7 => cv = sapling_crypto::value::ValueCommitment::derive(sapling_crypto::value::NoteValue::from_raw(0), sapling_crypto::value::ValueCommitTrapdoor::from_bytes([0; 32]).unwrap()),
        8 => outgoing_plain[32..].copy_from_slice(&different_esk.to_bytes()),
        _ => unreachable!(),
    }
    let mut enc = [0; 580];
    enc[..564].copy_from_slice(&note);
    let key = if field == 8 {
        let shared = (jubjub::ExtendedPoint::from(pk_d) * different_esk).mul_by_cofactor().to_bytes();
        blake2b_simd::Params::new().hash_length(32).personal(KDF_SAPLING_PERSONALIZATION).to_state().update(&shared).update(&original.ephemeral_key().0).finalize()
    } else {
        key
    };
    let tag = ChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap().encrypt_in_place_detached(nonce, &[], &mut enc[..564]).unwrap();
    enc[564..].copy_from_slice(&tag);
    let ock = prf_ock(&OutgoingViewingKey([0; 32]), &cv, &cmu.to_bytes(), original.ephemeral_key());
    let mut out = [0; 80];
    out[..64].copy_from_slice(&outgoing_plain);
    let tag = ChaCha20Poly1305::new_from_slice(&ock.0).unwrap().encrypt_in_place_detached(nonce, &[], &mut out[..64]).unwrap();
    out[64..].copy_from_slice(&tag);
    let description = sapling_crypto::bundle::OutputDescription::from_parts(cv, cmu, original.ephemeral_key().clone(), enc, out, *original.zkproof());
    let sapling = sapling_crypto::Bundle::from_parts(vec![], vec![description], *bundle.value_balance(), *bundle.authorization());
    TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Heartwood, transaction.lock_time(), transaction.expiry_height(), transaction.transparent_bundle().cloned(), None, sapling, None).freeze().unwrap()
}

#[test]
fn authenticated_bad_recovery_fields_and_small_order_cv_cannot_bypass_coinbase_cryptography() {
    let mut parent = state();
    isolated_heartwood_history(&mut parent);
    let before = owned_state(&parent);
    for (field, error) in [
        (0, CoinbaseRecoveryError::InvalidTransmissionKey),
        (1, CoinbaseRecoveryError::InvalidEphemeralSecret),
        (2, CoinbaseRecoveryError::InvalidCommitmentRandomness),
        (3, CoinbaseRecoveryError::InvalidPlaintextVersion),
        (4, CoinbaseRecoveryError::InvalidDiversifier),
        (5, CoinbaseRecoveryError::CommitmentMismatch),
        (6, CoinbaseRecoveryError::CommitmentMismatch),
        (8, CoinbaseRecoveryError::EphemeralKeyMismatch),
    ] {
        let transaction = changed_public_coinbase_plaintext(field);
        assert!(matches!(parent.stage_block(transaction, vec![], 914_678, 1_589_338_582), Err(SproutLedgerError::CoinbaseRecovery { index: 0, error: actual }) if actual == error));
        assert_eq!(owned_state(&parent), before);
    }
    let transaction = changed_public_coinbase_plaintext(7);
    assert_eq!(recover_sapling_coinbase_output(&transaction.sapling_bundle().unwrap().shielded_outputs()[0], 914_678), Ok(500_000_000));
    assert!(matches!(parent.stage_block(transaction, vec![], 914_678, 1_589_338_582), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputValueCommitment { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn a_caller_supplied_history_root_never_replaces_owned_peaks_or_computed_frontier() {
    let mut parent = state();
    let raw = include_bytes!("../tests/fixtures/testnet-heartwood-block-903801.bin");
    let root: [u8; 32] = raw[68..100].try_into().unwrap();
    parent.history_root = Some(root);
    let before = owned_state(&parent);
    let leaf = primary_heartwood_leaf(raw, 903_801, parent.shielded_roots[1], 0);
    assert_eq!(parent.stage_history(&root, leaf).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    isolated_heartwood_history(&mut parent);
    parent.history_root = Some([0; 32]);
    let before = owned_state(&parent);
    let root = parent.chain_history.as_ref().unwrap().root();
    let leaf = primary_heartwood_leaf(raw, 903_801, parent.shielded_roots[1], 0);
    assert_eq!(parent.stage_history(&root, leaf).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    // Heartwood final metadata must hash the actual staged frontier even when
    // the private cache has been deliberately corrupted in this isolated test.
    parent.shielded_roots[1] = [0x5a; 32];
    let delta = parent.stage_block(heartwood_coinbase(903_801), vec![], 903_801, 1_588_624_720).unwrap();
    assert_eq!(delta.sapling_root, sapling_crypto::Anchor::empty_tree().to_bytes());
    assert_ne!(delta.sapling_root, parent.shielded_roots[1]);
}

#[test]
fn heartwood_live_sapling_nullifiers_and_unknown_anchors_are_not_replaced_by_history_roots() {
    let mut parent = isolated_sapling_parent();
    isolated_heartwood_history(&mut parent);
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    let nullifier = bundle.shielded_spends()[0].nullifier().0;
    parent.nullifiers[1].insert(nullifier);
    let before = owned_state(&parent);
    let bad = v4(&original, BranchId::Heartwood, 0);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![bad], 914_678, 1_600_000_000), Err(SproutLedgerError::SpentSaplingNullifier)));
    assert_eq!(owned_state(&parent), before);
    parent.nullifiers[1].remove(&nullifier);
    let before = owned_state(&parent);
    let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
    raw[59] ^= 1;
    let bad = v4(&Transaction::read(raw.as_slice(), BranchId::Heartwood).unwrap(), BranchId::Heartwood, 0);
    assert!(matches!(parent.stage_block(primary_heartwood_coinbase(914_678), vec![bad], 914_678, 1_600_000_000), Err(SproutLedgerError::UnknownSaplingAnchor)));
    assert_eq!(owned_state(&parent), before);
    let history_root = parent.history_root().unwrap();
    assert!(!parent.sapling_anchors.contains(&history_root));
}

#[test]
fn authentic_shielded_coinbase_binding_rejects_other_branch_digest_without_format_masking() {
    let original = primary_heartwood_coinbase(914_678);
    for branch in [BranchId::Sapling, BranchId::Blossom] {
        let transaction = v4(&original, branch, 0);
        let hashes = SaplingSignatureHash::new(&transaction).unwrap();
        assert_eq!(verify_sapling_v4_crypto(&hashes), Err(SaplingCryptoError::InvalidBindingSignature));
    }
    let parent = state();
    let before = owned_state(&parent);
    let delta = parent.stage_block(primary_heartwood_coinbase(903_800), vec![], 903_800, 1_588_624_149).unwrap();
    assert_eq!(delta.check_sapling_root(903_800, &[0; 32]), Ok(()));
    assert_eq!(delta.sapling_root, sapling_crypto::Anchor::empty_tree().to_bytes());
    assert_ne!(delta.sapling_root, [0; 32]);
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn finite_heartwood_preserves_deferred_inactive_pools_and_preexisting_history_until_full_publish() {
    let mut parent = state();
    isolated_heartwood_history(&mut parent);
    parent.shielded_balances[2] = 3;
    parent.shielded_balances[3] = 5;
    parent.deferred_balance = 7;
    parent.issued_supply = 15;
    parent.nullifiers[2].insert([0x81; 32]);
    parent.nullifiers[3].insert([0x82; 32]);
    let history = parent.history_root();
    let peaks = parent.chain_history.as_ref().map(|history| format!("{history:?}"));
    let inactive_roots = [parent.shielded_roots[2], parent.shielded_roots[3]];
    let delta = parent.stage_block(primary_heartwood_coinbase(914_678), vec![], 914_678, 1_589_338_582).unwrap();
    parent.commit(delta);
    assert_eq!(parent.issued_supply(), 625_000_015);
    assert_eq!(parent.shielded_balances, [0, 500_000_000, 3, 5]);
    assert_eq!(parent.deferred_balance(), 7);
    assert_eq!([parent.shielded_roots[2], parent.shielded_roots[3]], inactive_roots);
    assert_eq!(parent.nullifiers[2], BTreeSet::from([[0x81; 32]]));
    assert_eq!(parent.nullifiers[3], BTreeSet::from([[0x82; 32]]));
    // Private ledger-delta commit alone is not full block admission and cannot
    // publish/reset the header or MMR. apply_block owns their atomic publication.
    assert_eq!(parent.history_root(), history);
    assert_eq!(parent.chain_history.as_ref().map(|history| format!("{history:?}")), peaks);
    assert_eq!(parent.tip().height(), 0);
}

#[test]
fn isolated_primary_heartwood_bodies_cannot_enter_the_authenticated_genesis_ledger() {
    let mut parent = state();
    let before = owned_state(&parent);
    for raw in [
        include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin").as_slice(),
        include_bytes!("../tests/fixtures/testnet-heartwood-block-903801.bin").as_slice(),
        include_bytes!("../tests/fixtures/testnet-heartwood-block-914678.bin").as_slice(),
        include_bytes!("../tests/fixtures/testnet-heartwood-block-925483.bin").as_slice(),
        include_bytes!("../tests/fixtures/testnet-heartwood-block-1028499.bin").as_slice(),
    ] {
        assert_eq!(parent.apply_block(raw), Err(SproutLedgerError::WrongHeight));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn canopy_activation_primary_coinbase_uses_funding_streams_before_first_halving() {
    // Exact original primary body, isolated consensus context, no archive claim.
    let raw = include_bytes!("../tests/fixtures/testnet-heartwood-block-1028500.bin");
    let body = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap();
    let values = check_coinbase(&body.block().vtx()[0], 1_028_500, body.block().header().time).unwrap();
    assert_eq!(values.claimed, 625_000_000);
    assert_eq!(subsidy(1_115_999), Ok(625_000_000));
    assert_eq!(subsidy(1_116_000), Ok(312_500_000));
    assert_eq!(supported_branch(2_976_000), Ok(BranchId::Nu6));
}

// Revision0 ZIP214 source pin and authenticated payload acquisition are shared
// with the production table; expected interval starts here are explicit, not
// computed with the production selector. Existing Zebra MIT notice applies to
// the four new unchanged primary block vectors below.
const CANOPY_BP_STARTS: [(u32, &str); 24] = [
    (1_028_500, "02db6bf7d524268b04edbb986ca4b3ba3528045f"),
    (1_046_000, "02db6bf7d524268b04edbb986ca4b3ba3528045f"),
    (1_081_000, "02db6bf7d524268b04edbb986ca4b3ba3528045f"),
    (1_116_000, "02db6bf7d524268b04edbb986ca4b3ba3528045f"),
    (1_151_000, "ad84b615b30f84099596262976e2800b47bf634a"),
    (1_186_000, "fa20a6a0b7edab06ab514cff36cb0bc52eaed041"),
    (1_221_000, "3eeedb2e7ce2df310444924bcf01918e4f2a47e3"),
    (1_256_000, "5ddd554de502ec31f9a342f0ef0b29ae8c4915a1"),
    (1_291_000, "2a901cb9188a8d1758dea1c84b7d8f923da5329a"),
    (1_326_000, "0662cf509103f7ae8e092857a3fb0019038fdab5"),
    (1_361_000, "4fa8788f0e20cbf1f674b61d08cb5bc2d372279f"),
    (1_396_000, "937cd268622af1c23a0cb01aecdc2f101d8e5fe9"),
    (1_431_000, "b443d08189612d442e388fffcf5341563b8d4eb9"),
    (1_466_000, "4a3891169715057e43637c7884ed87b55b5e1de4"),
    (1_501_000, "410393ed05c960807a08101f2f4850638f5b998b"),
    (1_536_000, "1bebd02a605b3393a9b490f4b84de21f4b39cf9c"),
    (1_571_000, "221c95f83bf073cfb76724ed23af737c1ee3bb49"),
    (1_606_000, "5fb236e61aa7e9ec9adb47644cd4f552607791c1"),
    (1_641_000, "5c4436c036abf9fe2931f38d584688acad2567f0"),
    (1_676_000, "133a4f69db2e68509bbc4e7f5c3fe0829d16e179"),
    (1_711_000, "83626b0b62b6484e609ee3715a684722cf0be07b"),
    (1_746_000, "c65e2e32251fe51375f7ccf8d786a3ce73ce4aa5"),
    (1_781_000, "c4ecc389406f3e3df396d8f69c0402554cab3e5e"),
    (1_816_000, "4e3f0d9a33a2721604cbae2de8d9171e21f8fbe4"),
];
const CANOPY_ZF_SCRIPT: &str = "a9140c0bcca02f3cba01a5d7423ac3903d40586399eb87";
const CANOPY_MG_SCRIPT: &str = "a91471e1df05024288a00802de81e08c437859586c8787";

fn canopy_coinbase(height: u32, expiry: u32) -> Transaction {
    let bp = CANOPY_BP_STARTS.iter().rev().find(|(start, _)| height >= *start).unwrap().1;
    let bp = bytes(&format!("a914{bp}87"));
    let (miner, bp_value, zf_value, mg_value) = if height < 1_116_000 {
        (500_000_000, 43_750_000, 31_250_000, 50_000_000)
    } else {
        (250_000_000, 21_875_000, 15_625_000, 25_000_000)
    };
    let (prefix, length) = coinbase_height_prefix(height);
    let reward = changed(TxVersion::Sprout(1), 0, |bundle| {
        script_input(bundle, &prefix[..length], u32::MAX);
        bundle.vout = vec![output(miner, &[0x51]), output(bp_value, &bp), output(zf_value, &bytes(CANOPY_ZF_SCRIPT)), output(mg_value, &bytes(CANOPY_MG_SCRIPT))];
    });
    v4(&reward, BranchId::Canopy, expiry)
}

fn primary_canopy_raw(height: u32) -> &'static [u8] {
    match height {
        1_028_500 => include_bytes!("../tests/fixtures/testnet-heartwood-block-1028500.bin"),
        1_028_501 => include_bytes!("../tests/fixtures/testnet-canopy-block-1028501.bin"),
        1_101_629 => include_bytes!("../tests/fixtures/testnet-canopy-block-1101629.bin"),
        1_115_999 => include_bytes!("../tests/fixtures/testnet-canopy-block-1115999.bin"),
        1_116_000 => include_bytes!("../tests/fixtures/testnet-canopy-block-1116000.bin"),
        _ => panic!("isolated primary Canopy height"),
    }
}

fn primary_canopy_coinbase(height: u32) -> Transaction {
    let (_, transactions) = ParsedBlockBody::parse(primary_canopy_raw(height), &TEST_NETWORK).unwrap().into_block().into_parts();
    transactions.head
}

fn canopy_with_outputs(height: u32, outputs: Vec<TxOut>) -> Transaction {
    let mut transparent = canopy_coinbase(height, 0).transparent_bundle().unwrap().clone();
    transparent.vout = outputs;
    TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), Some(transparent), None, None, None).freeze().unwrap()
}

#[test]
fn all_canopy_funding_period_boundaries_require_exact_current_individual_outputs() {
    let parent = state();
    let before = owned_state(&parent);
    for (index, &(start, current)) in CANOPY_BP_STARTS.iter().enumerate() {
        for height in [start, start + 1] {
            let coinbase = canopy_coinbase(height, 0);
            let outputs = &coinbase.transparent_bundle().unwrap().vout;
            assert_eq!(outputs[1].script_pubkey().0.0, bytes(&format!("a914{current}87")));
            assert_eq!(outputs[2].script_pubkey().0.0, bytes(CANOPY_ZF_SCRIPT));
            assert_eq!(outputs[3].script_pubkey().0.0, bytes(CANOPY_MG_SCRIPT));
            let expected = if height < 1_116_000 { [43_750_000, 31_250_000, 50_000_000] } else { [21_875_000, 15_625_000, 25_000_000] };
            assert_eq!(outputs[1..].iter().map(|output| u64::from(output.value())).collect::<Vec<_>>(), expected);
            assert!(parent.stage_block(coinbase, vec![], height, 1_600_000_000).is_ok());
            assert_eq!(owned_state(&parent), before);
        }
        if index == 0 { continue; }
        let previous = CANOPY_BP_STARTS[index - 1].1;
        let before_switch = canopy_coinbase(start - 1, 0);
        assert_eq!(before_switch.transparent_bundle().unwrap().vout[1].script_pubkey().0.0, bytes(&format!("a914{previous}87")));
        assert!(check_coinbase(&before_switch, start - 1, 1_600_000_000).is_ok());
        if current != previous {
            for (height, incorrect) in [(start - 1, current), (start, previous), (start + 1, previous)] {
                let original = canopy_coinbase(height, 0);
                let mut outputs = original.transparent_bundle().unwrap().vout.clone();
                outputs[1] = output(u64::from(outputs[1].value()), &bytes(&format!("a914{incorrect}87")));
                assert!(matches!(parent.stage_block(canopy_with_outputs(height, outputs), vec![], height, 1_600_000_000), Err(SproutLedgerError::MissingFundingStream { index: 0 })));
                assert_eq!(owned_state(&parent), before);
            }
        }
    }
    assert!(parent.stage_block(canopy_coinbase(1_842_419, 0), vec![], 1_842_419, 1_600_000_000).is_ok());
    assert!(matches!(parent.stage_block(canopy_coinbase(2_976_000, 0), vec![], 2_976_000, 1_600_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_streams_cannot_be_missing_wrong_beneficiaries_amounts_or_split_sums() {
    let parent = state();
    let before = owned_state(&parent);
    for height in [1_028_500, 1_115_999, 1_116_000, 1_842_419] {
        let original = canopy_coinbase(height, 0).transparent_bundle().unwrap().vout.clone();
        for stream in 0..3 {
            for mutation in 0..5 {
                let mut outputs = original.clone();
                let index = stream + 1;
                let value = u64::from(outputs[index].value());
                let script = outputs[index].script_pubkey().0.0.clone();
                match mutation {
                    0 => { outputs.remove(index); }
                    1 => { let mut script = script; script[2] ^= 1; outputs[index] = output(value, &script); }
                    2 => outputs[index] = output(value - 1, &script),
                    3 => outputs[index] = output(value + 1, &script),
                    4 => { outputs[index] = output(value / 2, &script); outputs.push(output(value - value / 2, &script)); }
                    _ => unreachable!(),
                }
                assert!(matches!(parent.stage_block(canopy_with_outputs(height, outputs), vec![], height, 1_600_000_000), Err(SproutLedgerError::MissingFundingStream { index }) if index == stream), "height{height} stream{stream} mutation{mutation}");
                assert_eq!(owned_state(&parent), before);
            }
        }
        // Founders ends at activation, not the later halving: a old-style
        // 20% output is not a replacement for the three required beneficiaries.
        let legacy = vec![output(if height < 1_116_000 { 500_000_000 } else { 250_000_000 }, &[0x51]), output(if height < 1_116_000 { 125_000_000 } else { 62_500_000 }, &founders_script(1_028_499))];
        assert!(matches!(parent.stage_block(canopy_with_outputs(height, legacy), vec![], height, 1_600_000_000), Err(SproutLedgerError::MissingFundingStream { index: 0 })));
    }
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_funding_is_inside_claimed_subsidy_and_never_scales_with_fees_or_pruned_burns() {
    for (height, miner, subsidy_value) in [(1_028_500, 500_000_000, 625_000_000), (1_115_999, 500_000_000, 625_000_000), (1_116_000, 250_000_000, 312_500_000), (1_116_001, 250_000_000, 312_500_000)] {
        for (claimed_fee, burn) in [(9, 1), (10, 1), (9, 0)] {
            let key = ([0x86; 32], 0);
            let mut parent = state();
            fund(&mut parent, key, 100, &[0x51], 0, false);
            let before = owned_state(&parent);
            let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(90, &[0x51])], 0), BranchId::Canopy, 0);
            let mut outputs = canopy_coinbase(height, 0).transparent_bundle().unwrap().vout.clone();
            outputs[0] = output(miner - 1 + claimed_fee, &[0x51]);
            outputs.push(output(burn, &[0x6a]));
            let delta = parent.stage_block(canopy_with_outputs(height, outputs), vec![transaction], height, 1_600_000_000).unwrap();
            assert_eq!(delta.fees, 10);
            let expected = subsidy_value + 89 + claimed_fee + burn;
            assert_eq!((delta.issued, delta.transparent, delta.retained), (expected, i128::from(expected), i128::from(expected - burn)));
            assert_eq!(delta.sapling, 0);
            assert_eq!(owned_state(&parent), before);
            parent.commit(delta);
            assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance()), (expected, expected, expected - burn));
            assert_eq!((parent.shielded_balances, parent.deferred_balance()), ([0; 4], 0));
        }
        let key = ([0x87; 32], 0);
        let mut parent = state();
        fund(&mut parent, key, 100, &[0x51], 0, false);
        let before = owned_state(&parent);
        let transaction = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Canopy, 0);
        let mut outputs = canopy_coinbase(height, 0).transparent_bundle().unwrap().vout.clone();
        outputs[0] = output(miner + 100, &[0x51]);
        assert_eq!(parent.stage_block(canopy_with_outputs(height, outputs.clone()), vec![transaction()], height, 1_600_000_000).unwrap().issued, subsidy_value + 100);
        // A miner incorrectly funding 7/5/8% of fees cannot satisfy the exact
        // subsidy-only values, even though the total claimed amount is allowed.
        for (index, fee_share) in [(0, 7), (1, 5), (2, 8)] {
            let mut wrong = outputs.clone();
            let stream = index + 1;
            let script = wrong[stream].script_pubkey().0.0.clone();
            wrong[stream] = output(u64::from(wrong[stream].value()) + fee_share, &script);
            wrong[0] = output(miner + 100 - fee_share, &[0x51]);
            assert!(matches!(parent.stage_block(canopy_with_outputs(height, wrong), vec![transaction()], height, 1_600_000_000), Err(SproutLedgerError::MissingFundingStream { index: actual }) if actual == index));
        }
        outputs[0] = output(miner + 101, &[0x51]);
        assert!(matches!(parent.stage_block(canopy_with_outputs(height, outputs), vec![transaction()], height, 1_600_000_000), Err(SproutLedgerError::CoinbaseRewardExceeded)));
        let streams_only = canopy_coinbase(height, 0).transparent_bundle().unwrap().vout[1..].to_vec();
        let claimed = if height < 1_116_000 { 125_000_000 } else { 62_500_000 };
        assert_eq!(state().stage_block(canopy_with_outputs(height, streams_only), vec![], height, 1_600_000_000).unwrap().issued, claimed);
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn original_canopy_coinbases_and_first_halving_verify_in_explicitly_isolated_state() {
    for (height, reward, transparent, sapling) in [
        (1_028_500, 625_000_000, 625_000_000, 0),
        (1_028_501, 625_000_000, 625_000_000, 0),
        (1_101_629, 625_000_000, 125_000_000, 500_000_000),
        (1_115_999, 625_000_000, 625_000_000, 0),
        (1_116_000, 312_500_000, 312_500_000, 0),
    ] {
        let raw = primary_canopy_raw(height);
        let body = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap();
        assert_eq!(u32::from(body.block().claimed_height()), height);
        let transaction = &body.block().vtx()[0];
        let values = check_coinbase(transaction, height, body.block().header().time).unwrap();
        assert_eq!((values.claimed, values.transparent, values.retained, values.sapling_balance), (reward, transparent, transparent, -(sapling as i64)));
        assert_eq!(sapling_transaction_count(std::iter::once(transaction)), u64::from(sapling != 0));
        let parent = state();
        let before = owned_state(&parent);
        let delta = parent.stage_block(primary_canopy_coinbase(height), vec![], height, body.block().header().time).unwrap();
        assert_eq!((delta.issued, delta.transparent, delta.retained, delta.sapling, delta.fees), (reward, transparent.into(), transparent.into(), sapling.into(), 0));
        assert_eq!(delta.sapling_root, delta.sapling_tree.root().to_bytes());
        assert_eq!(delta.check_sapling_root(height, &[0x5a; 32]), Ok(()));
        assert_eq!(owned_state(&parent), before);
        // A genuine isolated body cannot replace the missing authenticated
        // genesis-connected predecessor, even with authentic proofs.
        let mut connected = state();
        let before = owned_state(&connected);
        assert_eq!(connected.apply_block(raw), Err(SproutLedgerError::WrongHeight));
        assert_eq!(owned_state(&connected), before);
    }
}

fn isolated_canopy_history(parent: &mut SproutTestnetLedger, height: u32) {
    // Test-private complete peaks from isolated original metadata; this does
    // not claim an actual historical frontier or authenticated predecessor.
    let leaf = primary_heartwood_leaf(primary_canopy_raw(1_028_500), height, parent.sapling_tree.root().to_bytes(), 0);
    let history = ChainHistoryV1::new(leaf).unwrap();
    parent.history_root = Some(history.root());
    parent.chain_history = Some(history);
}

#[test]
fn original_canopy_shielded_coinbase_recovery_proof_binding_and_frontier_are_all_consumed() {
    let height = 1_101_629;
    let original = primary_canopy_coinbase(height);
    let bundle = original.sapling_bundle().unwrap();
    assert!(bundle.shielded_spends().is_empty());
    assert_eq!(bundle.shielded_outputs().len(), 1);
    assert_eq!(recover_sapling_coinbase_output(&bundle.shielded_outputs()[0], height), Ok(500_000_000));
    assert_eq!(verify_sapling_v4_crypto(&SaplingSignatureHash::new(&original).unwrap()), Ok(()));
    for branch in [BranchId::Sapling, BranchId::Blossom, BranchId::Heartwood] {
        assert_eq!(verify_sapling_v4_crypto(&SaplingSignatureHash::new(&v4(&original, branch, 0)).unwrap()), Err(SaplingCryptoError::InvalidBindingSignature));
    }
    let mut parent = state();
    isolated_canopy_history(&mut parent, height - 1);
    let before = owned_state(&parent);
    let id: [u8; 32] = original.txid().into();
    let mut reference = sapling_crypto::CommitmentTree::empty();
    reference.append(SaplingNode::from_cmu(bundle.shielded_outputs()[0].cmu())).unwrap();
    let delta = parent.stage_block(original, vec![], height, 1_600_000_000).unwrap();
    assert_eq!((delta.issued, delta.transparent, delta.retained, delta.sapling), (625_000_000, 125_000_000, 125_000_000, 500_000_000));
    assert_eq!(delta.sapling_tree.tree_size(), 1);
    assert_eq!(delta.sapling_root, reference.root().to_bytes());
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.issued_supply(), parent.transparent_balance(), parent.utxo_balance(), parent.shielded_balance(ShieldedPool::Sapling)), (625_000_000, 125_000_000, 125_000_000, 500_000_000));
    assert_eq!(parent.sapling_tree_size(), 1);
    assert!(parent.sapling_anchors.contains(&reference.root().to_bytes()));
    assert!(parent.utxo(&id, 0).unwrap().is_coinbase());
    assert_eq!(parent.history_root(), before.history); // Private delta commit never publishes MMR.
}

#[test]
fn every_canopy_coinbase_ciphertext_output_proof_and_binding_failure_preserves_full_state() {
    let height = 1_101_629;
    let mut parent = state();
    isolated_canopy_history(&mut parent, height - 1);
    let before = owned_state(&parent);
    let original = primary_canopy_coinbase(height);
    let source = original.sapling_bundle().unwrap();
    for mutation in 0..6 {
        let description = &source.shielded_outputs()[0];
        let mut enc = *description.enc_ciphertext();
        let mut out = *description.out_ciphertext();
        let mut proof = *description.zkproof();
        let mut binding: [u8; 64] = source.authorization().binding_sig.into();
        match mutation {
            0 => enc[0] ^= 1,
            1 => enc[579] ^= 1,
            2 => out[0] ^= 1,
            3 => out[79] ^= 1,
            4 => proof[0] ^= 0x20,
            5 => binding[63] ^= 1,
            _ => unreachable!(),
        }
        let output = sapling_crypto::bundle::OutputDescription::from_parts(description.cv().clone(), *description.cmu(), description.ephemeral_key().clone(), enc, out, proof);
        let bundle = sapling_crypto::Bundle::from_parts(vec![], vec![output], *source.value_balance(), sapling_crypto::bundle::Authorized { binding_sig: binding.into() });
        let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, original.lock_time(), original.expiry_height(), original.transparent_bundle().cloned(), None, bundle, None).freeze().unwrap();
        let expected = match mutation {
            0 | 1 => SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::NoteAuthentication },
            2 | 3 => SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::OutgoingAuthentication },
            4 => SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index: 0 }),
            5 => SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature),
            _ => unreachable!(),
        };
        assert!(matches!(parent.stage_block(bad, vec![], height, 1_600_000_000), Err(actual) if actual == expected), "mutation{mutation}");
        assert_eq!(owned_state(&parent), before);
    }
    for bad_index in [0, 1] {
        let mut outputs = vec![source.shielded_outputs()[0].clone(); 2];
        let description = &outputs[bad_index];
        let mut proof = *description.zkproof();
        proof[0] ^= 0x20;
        outputs[bad_index] = sapling_crypto::bundle::OutputDescription::from_parts(description.cv().clone(), *description.cmu(), description.ephemeral_key().clone(), *description.enc_ciphertext(), *description.out_ciphertext(), proof);
        let bundle = sapling_crypto::Bundle::from_parts(vec![], outputs, *source.value_balance(), *source.authorization());
        let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, original.lock_time(), original.expiry_height(), original.transparent_bundle().cloned(), None, bundle, None).freeze().unwrap();
        assert!(matches!(parent.stage_block(bad, vec![], height, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index })) if index == bad_index));
        assert_eq!(owned_state(&parent), before);
    }
}

fn reauthenticated_canopy_plaintext(field: u8) -> Transaction {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::AeadInPlace};
    use group::GroupEncoding;
    use sapling_crypto::{keys::OutgoingViewingKey, note_encryption::{KDF_SAPLING_PERSONALIZATION, prf_ock}};
    let transaction = primary_canopy_coinbase(1_101_629);
    let bundle = transaction.sapling_bundle().unwrap();
    let original = &bundle.shielded_outputs()[0];
    // Public zero-OVK witnesses, not wallet credentials. Real output proof and
    // binding bytes are retained and never treated as valid after mutation.
    let nonce = Nonce::from_slice(&[0; 12]);
    let ock = prf_ock(&OutgoingViewingKey([0; 32]), original.cv(), &original.cmu().to_bytes(), original.ephemeral_key());
    let mut outgoing: [u8; 64] = original.out_ciphertext()[..64].try_into().unwrap();
    ChaCha20Poly1305::new_from_slice(&ock.0).unwrap().decrypt_in_place_detached(nonce, &[], &mut outgoing, chacha20poly1305::Tag::from_slice(&original.out_ciphertext()[64..])).unwrap();
    let pk_d = jubjub::AffinePoint::from_bytes_pre_zip216_compatibility(outgoing[..32].try_into().unwrap()).unwrap();
    let mut esk = jubjub::Fr::from_bytes(&outgoing[32..].try_into().unwrap()).unwrap();
    let shared = (jubjub::ExtendedPoint::from(pk_d) * esk).mul_by_cofactor().to_bytes();
    let key = blake2b_simd::Params::new().hash_length(32).personal(KDF_SAPLING_PERSONALIZATION).to_state().update(&shared).update(&original.ephemeral_key().0).finalize();
    let mut note: [u8; 564] = original.enc_ciphertext()[..564].try_into().unwrap();
    ChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap().decrypt_in_place_detached(nonce, &[], &mut note, chacha20poly1305::Tag::from_slice(&original.enc_ciphertext()[564..])).unwrap();
    assert_eq!(note[0], 2);
    match field {
        0 => note[0] = 1,
        1 => note[20..52].fill(0xff),
        2 => { esk += jubjub::Fr::from(1); outgoing[32..].copy_from_slice(&esk.to_bytes()); }
        3 => note[12..20].copy_from_slice(&499_999_999_u64.to_le_bytes()),
        _ => unreachable!(),
    }
    let shared = (jubjub::ExtendedPoint::from(pk_d) * esk).mul_by_cofactor().to_bytes();
    let key = blake2b_simd::Params::new().hash_length(32).personal(KDF_SAPLING_PERSONALIZATION).to_state().update(&shared).update(&original.ephemeral_key().0).finalize();
    let mut enc = [0; 580];
    enc[..564].copy_from_slice(&note);
    let tag = ChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap().encrypt_in_place_detached(nonce, &[], &mut enc[..564]).unwrap();
    enc[564..].copy_from_slice(&tag);
    let mut out = [0; 80];
    out[..64].copy_from_slice(&outgoing);
    let tag = ChaCha20Poly1305::new_from_slice(&ock.0).unwrap().encrypt_in_place_detached(nonce, &[], &mut out[..64]).unwrap();
    out[64..].copy_from_slice(&tag);
    let description = sapling_crypto::bundle::OutputDescription::from_parts(original.cv().clone(), *original.cmu(), original.ephemeral_key().clone(), enc, out, *original.zkproof());
    let sapling = sapling_crypto::Bundle::from_parts(vec![], vec![description], *bundle.value_balance(), *bundle.authorization());
    TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, transaction.lock_time(), transaction.expiry_height(), transaction.transparent_bundle().cloned(), None, sapling, None).freeze().unwrap()
}

#[test]
fn canopy_coinbase_requires_lead_two_and_actual_rseed_esk_commitment_at_activation_without_grace() {
    let mut parent = state();
    isolated_canopy_history(&mut parent, 1_101_628);
    let before = owned_state(&parent);
    for (field, error) in [(0, CoinbaseRecoveryError::InvalidPlaintextVersion), (1, CoinbaseRecoveryError::EphemeralSecretMismatch), (2, CoinbaseRecoveryError::EphemeralSecretMismatch), (3, CoinbaseRecoveryError::CommitmentMismatch)] {
        let bad = reauthenticated_canopy_plaintext(field);
        assert!(matches!(parent.stage_block(bad, vec![], 1_101_629, 1_600_000_000), Err(SproutLedgerError::CoinbaseRecovery { index: 0, error: actual }) if actual == error));
        assert_eq!(owned_state(&parent), before);
    }
    // Move genuine lead1 Heartwood output to Canopy activation using valid
    // current height/funding outputs, so no stale height/founder masks recovery.
    let old = primary_heartwood_coinbase(914_678);
    let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), canopy_coinbase(1_028_500, 0).transparent_bundle().cloned(), None, old.sapling_bundle().cloned(), None).freeze().unwrap();
    assert!(matches!(parent.stage_block(bad, vec![], 1_028_500, 1_600_000_000), Err(SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::InvalidPlaintextVersion })));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_shielded_coinbase_capacity_pool_and_late_script_failures_keep_all_peaks_and_fields() {
    let height = 1_101_629;
    for capacity in [false, true] {
        let mut parent = state();
        isolated_canopy_history(&mut parent, height - 1);
        if capacity {
            parent.sapling_tree = Frontier::from_parts(((1_u64 << 32) - 1).into(), SaplingNode::from_scalar(bls12_381::Scalar::from(2)), vec![SaplingNode::from_scalar(bls12_381::Scalar::from(3)); 32]).unwrap();
            parent.shielded_roots[1] = parent.sapling_tree.root().to_bytes();
            parent.sapling_anchors.insert(parent.shielded_roots[1]);
        } else {
            parent.shielded_balances[1] = MAX_MONEY;
            parent.issued_supply = MAX_MONEY;
        }
        let before = owned_state(&parent);
        let expected = if capacity { SproutLedgerError::SaplingTreeFull } else { SproutLedgerError::ValueOutOfRange };
        assert!(matches!(parent.stage_block(primary_canopy_coinbase(height), vec![], height, 1_600_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = state();
    isolated_canopy_history(&mut parent, height - 1);
    let key = ([0x88; 32], 0);
    fund(&mut parent, key, 20, &[0x51], 0, false);
    let before = owned_state(&parent);
    let good = v4(&spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Canopy, 0);
    let id: [u8; 32] = good.txid().into();
    let bad = v4(&spend(&[((id, 0), &[0x6a], u32::MAX)], vec![output(18, &[0x51])], 0), BranchId::Canopy, 0);
    assert!(matches!(parent.stage_block(primary_canopy_coinbase(height), vec![good, bad], height, 1_600_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_preserves_v4_two_megabytes_branch_finality_and_original_expiry_semantics() {
    let height = 1_028_500;
    let key = ([0x89; 32], 0);
    for (length, expected) in [(1_999_917, Ok(())), (1_999_918, Err(SproutLedgerError::TransactionTooLarge))] {
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0; length])], 0), BranchId::Canopy, 0);
        let mut encoded = Vec::new();
        transaction.write(&mut encoded).unwrap();
        assert_eq!(encoded.len(), length + 83);
        assert_eq!(check_transaction(&transaction, height, 1_600_000_000).map(|_| ()), expected);
    }
    for (expiry, expected) in [(0, Ok(())), (1_028_500, Ok(())), (1_028_499, Err(SproutLedgerError::ExpiredTransaction)), (499_999_999, Ok(())), (500_000_000, Err(SproutLedgerError::InvalidTransaction))] {
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Canopy, expiry);
        assert_eq!(check_transaction(&transaction, height, 1_600_000_000).map(|_| ()), expected);
    }
    for (lock, sequence, expected) in [(1_028_499, 0, Ok(())), (1_028_500, 0, Err(SproutLedgerError::NonfinalTransaction)), (1_028_500, u32::MAX, Ok(())), (1_599_999_999, 0, Ok(())), (1_600_000_000, 0, Err(SproutLedgerError::NonfinalTransaction))] {
        let transaction = v4(&spend(&[(key, &[], sequence)], vec![output(0, &[0x51])], lock), BranchId::Canopy, 0);
        assert_eq!(check_transaction(&transaction, height, 1_600_000_000).map(|_| ()), expected);
    }
    let template = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    for branch in [BranchId::Sapling, BranchId::Blossom, BranchId::Heartwood] {
        assert!(matches!(check_transaction(&v4(&template, branch, 0), height, 1_600_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    }
    for version in [TxVersion::Sprout(1), TxVersion::V3] {
        let bad = TransactionData::<Authorized>::from_parts(version, BranchId::Canopy, 0, 0.into(), template.transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        assert!(matches!(check_transaction(&bad, height, 1_600_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    }
    for expiry in [0, 1, 1_028_499, 1_028_500, 499_999_999] {
        assert_eq!(check_coinbase(&canopy_coinbase(height, expiry), height, 1_600_000_000).unwrap().claimed, 625_000_000);
    }
    assert_eq!(check_coinbase(&canopy_coinbase(height, 500_000_000), height, 1_600_000_000), Err(SproutLedgerError::InvalidTransaction));
    let mut raw = primary_canopy_raw(height).to_vec();
    let end = raw.len();
    raw[end - 11] = 1; // Absent Sapling balance must not normalize into accepted bytes.
    assert!(matches!(ParsedBlockBody::parse(&raw, &TEST_NETWORK), Err(BodyError::NoncanonicalEncoding)));
    assert!(matches!(ParsedBlockBody::parse(&vec![0; 2_000_001], &TEST_NETWORK), Err(BodyError::BlockTooLarge)));
}

#[test]
fn independent_canopy_zip243_ecdsa_requires_owned_amount_script_and_current_branch() {
    for height in [1_028_500, 1_842_419] {
        for (p2sh, raw_type) in [(false, 0), (false, 1), (true, 1), (false, 2), (false, 3), (false, 0x41), (true, 0x81), (false, 0xff)] {
            let (transaction, prevout) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Canopy, p2sh, raw_type);
            let mut parent = state();
            isolated_canopy_history(&mut parent, height - 1);
            fund(&mut parent, ([0xa1; 32], 3), 100_002, &prevout.script_pubkey().0.0, 0, false);
            let before = owned_state(&parent);
            assert_eq!(parent.stage_block(canopy_coinbase(height, 0), vec![transaction], height, 1_600_000_000).unwrap().fees, 2);
            assert_eq!(owned_state(&parent), before);
            let (old, _) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Heartwood, p2sh, raw_type);
            // Replacing metadata and expiry does not replace an old real signature.
            let wrong = v4(&old, BranchId::Canopy, 1_842_419);
            assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![wrong], height, 1_600_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
            assert_eq!(owned_state(&parent), before);
            let (transaction, _) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Canopy, p2sh, raw_type);
            parent.utxos.get_mut(&([0xa1; 32], 3)).unwrap().output = output(100_003, &prevout.script_pubkey().0.0);
            let before = owned_state(&parent);
            assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![transaction], height, 1_600_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn canopy_keeps_shielded_cardinality_and_coinbase_shape_without_inventing_wallet_checks() {
    let original = recorded_sapling();
    let bundle = original.sapling_bundle().unwrap();
    let source = spend(&[(([0x90; 32], 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    for (spends, outputs, vin, vout, accepted) in [(false, false, true, true, true), (false, true, false, false, false), (true, false, false, false, false), (true, true, false, false, true), (false, true, true, false, true), (true, false, false, true, true), (true, false, true, false, false), (false, true, false, true, false)] {
        let mut transparent = source.transparent_bundle().unwrap().clone();
        if !vin { transparent.vin.clear(); }
        if !vout { transparent.vout.clear(); }
        let context = modified_sapling(if spends { bundle.shielded_spends().to_vec() } else { vec![] }, if outputs { bundle.shielded_outputs().to_vec() } else { vec![] }, 0, Some(transparent));
        let transaction = v4(&context, BranchId::Canopy, 0);
        assert_eq!(check_transaction(&transaction, 1_028_500, 1_600_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::InvalidTransaction) });
        // These copied ordinary encrypted outputs are not publicly recoverable
        // coinbase notes: no lead-byte wallet-grace rule is applied to them.
    }
    let coinbase = primary_canopy_coinbase(1_101_629);
    let sapling = coinbase.sapling_bundle().unwrap();
    let with_spend = sapling_crypto::Bundle::from_parts(bundle.shielded_spends().to_vec(), sapling.shielded_outputs().to_vec(), *sapling.value_balance(), *sapling.authorization());
    let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), coinbase.transparent_bundle().cloned(), None, with_spend, None).freeze().unwrap();
    assert_eq!(check_coinbase(&bad, 1_101_629, 1_600_000_000), Err(SproutLedgerError::InvalidCoinbase));
    let groth = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Canopy).unwrap();
    let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), coinbase.transparent_bundle().cloned(), groth.sprout_bundle().cloned(), coinbase.sapling_bundle().cloned(), None).freeze().unwrap();
    assert_eq!(check_coinbase(&bad, 1_101_629, 1_600_000_000), Err(SproutLedgerError::InvalidCoinbase));
    for length in [1, 101] {
        let mut transparent = coinbase.transparent_bundle().unwrap().clone();
        script_input(&mut transparent, &vec![0; length], u32::MAX);
        let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), Some(transparent), None, coinbase.sapling_bundle().cloned(), None).freeze().unwrap();
        assert_eq!(check_coinbase(&bad, 1_101_629, 1_600_000_000), Err(SproutLedgerError::InvalidCoinbase));
    }
    let mut transparent = coinbase.transparent_bundle().unwrap().clone();
    let (prefix, length) = coinbase_height_prefix(1_101_628);
    script_input(&mut transparent, &prefix[..length], u32::MAX);
    let bad = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), Some(transparent), None, coinbase.sapling_bundle().cloned(), None).freeze().unwrap();
    assert_eq!(check_coinbase(&bad, 1_101_629, 1_600_000_000), Err(SproutLedgerError::InvalidCoinbase));
}

#[test]
fn canopy_zip211_rejects_every_actual_positive_vpub_old_but_withdrawals_reach_zip215_and_groth() {
    let height = 1_028_500;
    let recorded = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Canopy).unwrap();
    // The original deposit/public statement and Groth bytes remain actual;
    // only expired historical transaction context is replaced for this gate.
    let original = v4(&recorded, BranchId::Canopy, 0);
    assert!(u64::try_from(original.sprout_bundle().unwrap().joinsplits[0].vpub_old()).unwrap() > 0);
    assert_eq!(check_transaction(&original, height, 1_600_000_000).map(|_| ()), Err(SproutLedgerError::SproutDepositDisabled));
    let mut parent = state();
    isolated_canopy_history(&mut parent, height);
    let anchor = *original.sprout_bundle().unwrap().joinsplits[0].anchor();
    parent.sprout_anchors.insert(anchor, Frontier::empty());
    parent.shielded_balances[0] = 10_000;
    parent.issued_supply = 10_000;
    let before = owned_state(&parent);
    for (old, new) in [(1_u64, 0_u64), (0, 0), (0, 10_000)] {
        let mut sprout = original.sprout_bundle().unwrap().clone();
        let mut description = Vec::new();
        sprout.joinsplits[0].write(&mut description).unwrap();
        description[..8].copy_from_slice(&old.to_le_bytes());
        description[8..16].copy_from_slice(&new.to_le_bytes());
        sprout.joinsplits[0] = JsDescription::read(description.as_slice(), true).unwrap();
        for zip215_signature in [false, true] {
            let mut sprout = sprout.clone();
            if zip215_signature {
                // ZIP215 order-four raw-zero A, identity R, zero S. This
                // signature passes the cofactored equation; altered h_sig
                // still MUST reach and reject the actual recorded Groth proof.
                sprout.joinsplit_pubkey = [0; 32];
                sprout.joinsplit_sig = [0; 64];
                sprout.joinsplit_sig[0] = 1;
            }
            let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), None, Some(sprout), None, None).freeze().unwrap();
            let expected = if old != 0 { SproutLedgerError::SproutDepositDisabled } else if zip215_signature {
                SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof })
            } else { SproutLedgerError::JoinSplit(LegacyJoinSplitError::InvalidSignature) };
            assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![transaction], height, 1_600_000_000), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
    }
    // Each description is checked: a later deposit cannot hide behind an
    // earlier valid zero-public-value shape or netted withdrawal total.
    for deposit_index in [0, 1] {
        let mut sprout = original.sprout_bundle().unwrap().clone();
        let mut descriptions = Vec::new();
        for index in 0..2 {
            let mut raw = Vec::new();
            sprout.joinsplits[0].write(&mut raw).unwrap();
            raw[..8].copy_from_slice(&u64::from(index == deposit_index).to_le_bytes());
            raw[8..16].copy_from_slice(&(if index == deposit_index { 0_u64 } else { 10_000 }).to_le_bytes());
            raw[48..80].fill(0x91 + 2 * index as u8);
            raw[80..112].fill(0x92 + 2 * index as u8);
            descriptions.push(JsDescription::read(raw.as_slice(), true).unwrap());
        }
        sprout.joinsplits = descriptions;
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), None, Some(sprout), None, None).freeze().unwrap();
        assert_eq!(check_transaction(&transaction, height, 1_600_000_000).map(|_| ()), Err(SproutLedgerError::SproutDepositDisabled));
    }
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_late_sapling_spend_output_and_binding_equations_preserve_all_owned_state() {
    let height = 1_028_500;
    let mut parent = isolated_sapling_parent();
    isolated_canopy_history(&mut parent, height);
    let key = ([0xe1; 32], 0);
    let good = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Canopy, 0);
    let before = owned_state(&parent);
    let bad = v4(&recorded_sapling(), BranchId::Canopy, 0);
    assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![good(), bad], height, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let mut raw = bytes(sapling_primary::TRANSACTION_HEX);
    raw[155] ^= 0x20;
    let bad = v4(&Transaction::read(raw.as_slice(), BranchId::Canopy).unwrap(), BranchId::Canopy, 0);
    assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![good(), bad], height, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let original = recorded_sapling();
    let source = original.sapling_bundle().unwrap();
    for bad_index in 0..source.shielded_outputs().len() {
        let mut outputs = source.shielded_outputs().to_vec();
        let description = &outputs[bad_index];
        let mut proof = *description.zkproof();
        proof[0] ^= 0x20;
        outputs[bad_index] = sapling_crypto::bundle::OutputDescription::from_parts(description.cv().clone(), *description.cmu(), description.ephemeral_key().clone(), *description.enc_ciphertext(), *description.out_ciphertext(), proof);
        let transaction = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
        let bad = v4(&modified_sapling(vec![], outputs, 0, transaction.transparent_bundle().cloned()), BranchId::Canopy, 0);
        assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![bad], height, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index })) if index == bad_index));
        assert_eq!(owned_state(&parent), before);
    }
    let transaction = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let bad = v4(&modified_sapling(vec![], source.shielded_outputs().to_vec(), 0, transaction.transparent_bundle().cloned()), BranchId::Canopy, 0);
    assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![bad], height, 1_600_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature))));
    assert_eq!(owned_state(&parent), before);
    parent.nullifiers[1].insert(source.shielded_spends()[0].nullifier().0);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![good(), v4(&original, BranchId::Canopy, 0)], height, 1_600_000_000), Err(SproutLedgerError::SpentSaplingNullifier)));
    assert_eq!(owned_state(&parent), before);
    parent.nullifiers[1].clear();
    parent.sapling_anchors.remove(&source.shielded_spends()[0].anchor().to_bytes());
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![good(), v4(&original, BranchId::Canopy, 0)], height, 1_600_000_000), Err(SproutLedgerError::UnknownSaplingAnchor)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_parent_anchors_current_nullifiers_and_coinbase_first_frontier_remain_separate() {
    let height = 1_101_629;
    let parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let original = recorded_sapling();
    let mut delta = BlockDelta::new(&parent);
    let coinbase = primary_canopy_coinbase(height);
    parent.stage_sapling(&coinbase, &mut delta).unwrap();
    let interstitial = delta.sapling_tree.root().to_bytes();
    let spend = v4(&modified_sapling(vec![sapling_spend(interstitial, [0x93; 32])], vec![], 0, None), BranchId::Canopy, 0);
    assert_eq!(parent.stage_sapling(&spend, &mut delta), Err(SproutLedgerError::UnknownSaplingAnchor));
    let mut delta = BlockDelta::new(&parent);
    parent.stage_sapling(&coinbase, &mut delta).unwrap();
    parent.stage_sapling(&v4(&original, BranchId::Canopy, 0), &mut delta).unwrap();
    let mut reference = sapling_crypto::CommitmentTree::empty();
    for output in coinbase.sapling_bundle().unwrap().shielded_outputs().iter().chain(original.sapling_bundle().unwrap().shielded_outputs()) {
        reference.append(SaplingNode::from_cmu(output.cmu())).unwrap();
    }
    assert_eq!(delta.sapling_tree.root().to_bytes(), reference.root().to_bytes());
    assert_eq!(delta.sapling_tree.tree_size(), 3);
    assert_eq!(sapling_transaction_count([&coinbase, &original].into_iter()), 2); // Transactions, not three outputs.
    assert_eq!(parent.stage_sapling(&v4(&original, BranchId::Canopy, 0), &mut delta), Err(SproutLedgerError::SpentSaplingNullifier));
    assert_eq!(owned_state(&parent), before);
    let mut parent = state();
    let mut sprout = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Canopy).unwrap().sprout_bundle().unwrap().clone();
    let mut raw = Vec::new();
    sprout.joinsplits[0].write(&mut raw).unwrap();
    raw[..16].fill(0); // Context-only Sprout internal transfer shape.
    sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap();
    let anchor = *sprout.joinsplits[0].anchor();
    let nullifier = sprout.joinsplits[0].nullifiers()[0];
    parent.sprout_anchors.insert(anchor, Frontier::empty());
    let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), None, Some(sprout), None, None).freeze().unwrap();
    assert_eq!(parent.stage_sprout(&transaction, &mut BlockDelta::new(&parent)), Ok(()));
    parent.nullifiers[0].insert(nullifier);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(canopy_coinbase(1_028_500, 0), vec![transaction], 1_028_500, 1_600_000_000), Err(SproutLedgerError::SpentSproutNullifier)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_maturity_sigops_ordered_utxos_duplicates_and_parent_wide_bip30_are_unchanged() {
    let height = 1_028_500;
    let key = ([0x94; 32], 0);
    for (created, expected) in [(1_028_400, SproutLedgerError::UnshieldedCoinbaseSpend), (1_028_401, SproutLedgerError::ImmatureCoinbase)] {
        let mut parent = state();
        isolated_canopy_history(&mut parent, height);
        fund(&mut parent, key, 0, &[0x51], created, true);
        let before = owned_state(&parent);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Canopy, 0);
        assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![transaction], height, 1_600_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
    for (sigops, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let before = owned_state(&parent);
        let transaction = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; sigops])], 0), BranchId::Canopy, 0);
        let mut outputs = canopy_coinbase(height, 0).transparent_bundle().unwrap().vout.clone();
        outputs[0] = output(500_000_000, &[0xac]);
        let result = parent.stage_block(canopy_with_outputs(height, outputs), vec![transaction], height, 1_600_000_000);
        if accepted { assert_eq!(result.unwrap().sigops, 20_000); } else { assert!(matches!(result, Err(SproutLedgerError::TooManySigops))); }
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = state();
    isolated_canopy_history(&mut parent, height);
    fund(&mut parent, key, 100, &[0x51], 0, false);
    let first = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(80, &[0x51])], 0), BranchId::Canopy, 0);
    let id: [u8; 32] = first().txid().into();
    let second = || v4(&spend(&[((id, 0), &[], u32::MAX)], vec![output(70, &[0x51])], 0), BranchId::Canopy, 0);
    let before = owned_state(&parent);
    for transactions in [vec![second(), first()], vec![first(), second(), second()]] {
        assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), transactions, height, 1_600_000_000), Err(SproutLedgerError::MissingTransparentInput)));
        assert_eq!(owned_state(&parent), before);
    }
    assert_eq!(parent.stage_block(canopy_coinbase(height, 0), vec![first(), second()], height, 1_600_000_000).unwrap().fees, 30);
    let duplicate = v4(&spend(&[(key, &[], u32::MAX), (key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Canopy, 0);
    assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![duplicate], height, 1_600_000_000), Err(SproutLedgerError::DuplicateTransparentInput)));
    assert_eq!(owned_state(&parent), before);
    fund(&mut parent, (id, 7), 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    let consume = v4(&spend(&[((id, 7), &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Canopy, 0);
    assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![consume, first()], height, 1_600_000_000), Err(SproutLedgerError::UnspentTransactionOverwrite)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_separate_money_sides_and_inactive_pool_conservation_do_not_change_at_epoch_reset() {
    let height = 1_028_500;
    let original = recorded_sapling();
    let sapling = original.sapling_bundle().unwrap();
    let source = spend(&[(([0x95; 32], 0), &[], u32::MAX)], vec![output(MAX_MONEY, &[0x51])], 0);
    let bad = v4(&modified_sapling(sapling.shielded_spends().to_vec(), sapling.shielded_outputs().to_vec(), -1, source.transparent_bundle().cloned()), BranchId::Canopy, 0);
    assert_eq!(check_transaction(&bad, height, 1_600_000_000).map(|_| ()), Err(SproutLedgerError::ValueOutOfRange));
    let mut parent = isolated_sapling_parent();
    isolated_canopy_history(&mut parent, height);
    fund(&mut parent, ([0x95; 32], 0), 1, &[0x51], 0, false);
    let source = spend(&[(([0x95; 32], 0), &[], u32::MAX)], vec![output(0, &[0x51])], 0);
    let bad = v4(&modified_sapling(sapling.shielded_spends().to_vec(), sapling.shielded_outputs().to_vec(), MAX_MONEY as i64, source.transparent_bundle().cloned()), BranchId::Canopy, 0);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![bad], height, 1_600_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    assert_eq!(owned_state(&parent), before);
    let mut parent = state();
    isolated_canopy_history(&mut parent, height);
    parent.shielded_balances[2] = 3;
    parent.shielded_balances[3] = 5;
    parent.deferred_balance = 7;
    parent.issued_supply = 15;
    parent.nullifiers[2].insert([0x96; 32]);
    parent.nullifiers[3].insert([0x97; 32]);
    let before = owned_state(&parent);
    let delta = parent.stage_block(primary_canopy_coinbase(1_101_629), vec![], 1_101_629, 1_600_000_000).unwrap();
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!(parent.issued_supply(), 625_000_015);
    assert_eq!(parent.shielded_balances, [0, 500_000_000, 3, 5]);
    assert_eq!(parent.deferred_balance(), 7);
    assert_eq!(&parent.shielded_roots[2..], &before.roots[2..]);
    assert_eq!(&parent.nullifiers[2..], &before.nullifiers[2..]);
    assert_eq!(parent.history_root(), before.history);
    assert_eq!(parent.chain_history.as_ref().map(|history| format!("{history:?}")), before.chain_history);
    assert_eq!(parent.headers, before.headers);
}

fn authenticated_canopy_metadata_root() -> [u8; 32] {
    // Pinned Zebra e3eef2f... vectors/block.rs:932–940, blob
    // 04d43d506e120103bf229e7f314bd82eebec8614, original display endian.
    // This fixed metadata is NOT a caller-supplied production frontier.
    let mut root: [u8; 32] = bytes("580adc0253cd0545250039267b7b49445ca0550df735920b7466bba1a64f7cf7").try_into().unwrap();
    root.reverse();
    root
}

#[test]
fn canopy_activation_compares_owned_heartwood_parent_before_explicit_v1_epoch_reset() {
    let first_raw = primary_canopy_raw(1_028_500);
    let next_raw = primary_canopy_raw(1_028_501);
    let final_root = authenticated_canopy_metadata_root();
    let first = primary_heartwood_leaf(first_raw, 1_028_500, final_root, 0);
    assert_eq!(first.consensus_branch_id, 0xe9ff_75a6);
    assert_eq!(first.subtree_total_work, primitive_types::U256::from(32));
    let expected: [u8; 32] = bytes("50c45960aa319e288f838d938636dba9289b6fb5df6b267d6515449ce6234055").try_into().unwrap();
    assert_eq!(ChainHistoryV1::new(first.clone()).unwrap().root(), expected);
    assert_eq!(next_raw[68..100], expected);
    assert_ne!(&first_raw[68..100], &[0; 32]); // Activation header is the old epoch, never zero.
    let mut parent = state();
    let old_raw = include_bytes!("../tests/fixtures/testnet-heartwood-block-1028499.bin");
    let owned_heartwood = ChainHistoryV1::new(primary_heartwood_leaf(old_raw, 1_028_499, final_root, 0)).unwrap();
    parent.history_root = Some(owned_heartwood.root());
    parent.chain_history = Some(owned_heartwood);
    let before = owned_state(&parent);
    let old_root = parent.history_root().unwrap();
    let staged = parent.stage_history(&old_root, first.clone()).unwrap();
    assert_eq!(staged.consensus_branch_id(), 0xe9ff_75a6);
    assert_eq!(staged.last_height(), 1_028_500);
    assert_eq!(staged.leaf_count(), 1);
    assert_eq!(staged.root(), expected);
    assert_eq!(owned_state(&parent), before);
    for wrong in [[0; 32], expected] {
        assert_eq!(parent.stage_history(&wrong, first.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
        assert_eq!(owned_state(&parent), before);
    }
    // The isolated SINGLE-leaf Heartwood parent is not the original mined
    // Heartwood epoch. Its root cannot manufacture authentic activation admission.
    let genuine_old_root: [u8; 32] = first_raw[68..100].try_into().unwrap();
    assert_ne!(old_root, genuine_old_root);
    assert_eq!(parent.stage_history(&genuine_old_root, first.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    parent.history_root = Some(staged.root());
    parent.chain_history = Some(staged);
    let before = owned_state(&parent);
    let next = primary_heartwood_leaf(next_raw, 1_028_501, final_root, 0);
    let appended = parent.stage_history(&expected, next.clone()).unwrap();
    assert_eq!(appended.leaf_count(), 2);
    assert_eq!(appended.consensus_branch_id(), 0xe9ff_75a6);
    for wrong in [old_root, appended.root()] {
        assert_eq!(parent.stage_history(&wrong, next.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
        assert_eq!(owned_state(&parent), before);
    }
    // Every authenticated field participates in the root checked by the next
    // original header. No commitment/count/work/cache substitution is accepted.
    for field in 0..7 {
        let mut forged = first.clone();
        match field {
            0 => forged.subtree_commitment[0] ^= 1,
            1 => { forged.start_time += 1; forged.end_time += 1; }
            2 => { forged.start_target ^= 1; forged.end_target ^= 1; }
            3 => { forged.start_sapling_root[0] ^= 1; forged.end_sapling_root[0] ^= 1; }
            4 => forged.subtree_total_work += primitive_types::U256::from(1),
            5 => forged.sapling_tx = 1,
            6 => { forged.start_height += 1; forged.end_height += 1; }
            _ => unreachable!(),
        }
        let history = ChainHistoryV1::new(forged).unwrap();
        assert_ne!(history.root(), expected, "metadata{field}");
        parent.history_root = Some(history.root());
        parent.chain_history = Some(history);
        let before = owned_state(&parent);
        assert_eq!(parent.stage_history(&expected, next.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn canopy_activation_without_owned_previous_epoch_or_matching_branch_never_resets_state() {
    let final_root = authenticated_canopy_metadata_root();
    let first = primary_heartwood_leaf(primary_canopy_raw(1_028_500), 1_028_500, final_root, 0);
    let mut parent = state();
    let before = owned_state(&parent);
    assert_eq!(parent.stage_history(&[0; 32], first.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    parent.history_root = Some(primary_canopy_raw(1_028_500)[68..100].try_into().unwrap());
    let before = owned_state(&parent);
    assert_eq!(parent.stage_history(&parent.history_root().unwrap(), first.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    for (height, branch, expected) in [(1_028_498, BranchId::Heartwood, HistoryError::NonconsecutiveHeight), (1_028_499, BranchId::Canopy, HistoryError::BranchMismatch)] {
        let mut leaf = primary_heartwood_leaf(include_bytes!("../tests/fixtures/testnet-heartwood-block-1028499.bin"), height, final_root, 0);
        leaf.consensus_branch_id = u32::from(branch);
        let history = ChainHistoryV1::new(leaf).unwrap();
        parent.history_root = Some(history.root());
        parent.chain_history = Some(history);
        let before = owned_state(&parent);
        assert_eq!(parent.stage_history(&parent.history_root().unwrap(), first.clone()).unwrap_err(), SproutLedgerError::History(expected));
        assert_eq!(owned_state(&parent), before);
    }
    let mut leaf = primary_heartwood_leaf(include_bytes!("../tests/fixtures/testnet-heartwood-block-1028499.bin"), 1_028_499, final_root, 0);
    let history = ChainHistoryV1::new(leaf.clone()).unwrap();
    parent.history_root = Some(history.root());
    parent.chain_history = Some(history);
    let before = owned_state(&parent);
    leaf = first;
    leaf.consensus_branch_id = u32::from(BranchId::Heartwood);
    assert_eq!(parent.stage_history(&parent.history_root().unwrap(), leaf).unwrap_err(), SproutLedgerError::History(HistoryError::BranchMismatch));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn canopy_history_late_height_work_count_and_cached_root_failures_preserve_every_peak_and_header() {
    let height = 1_101_629;
    for work_overflow in [false, true] {
        let mut parent = state();
        let mut first = primary_heartwood_leaf(primary_canopy_raw(1_028_500), height - 1, parent.sapling_tree.root().to_bytes(), 0);
        if work_overflow { first.subtree_total_work = primitive_types::U256::MAX; } else { first.sapling_tx = u64::MAX; }
        let history = ChainHistoryV1::new(first).unwrap();
        parent.history_root = Some(history.root());
        parent.chain_history = Some(history);
        let before = owned_state(&parent);
        // All original output proofs, binding, recovery and money staged first.
        let delta = parent.stage_block(primary_canopy_coinbase(height), vec![], height, 1_600_000_000).unwrap();
        let next = primary_heartwood_leaf(primary_canopy_raw(height), height, delta.sapling_root, 1);
        let expected = if work_overflow { HistoryError::WorkOverflow } else { HistoryError::SaplingCountOverflow };
        assert_eq!(parent.stage_history(&parent.history_root().unwrap(), next).unwrap_err(), SproutLedgerError::History(expected));
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = state();
    isolated_canopy_history(&mut parent, height - 1);
    let before = owned_state(&parent);
    let wrong = primary_heartwood_leaf(primary_canopy_raw(height), height + 1, parent.sapling_tree.root().to_bytes(), 1);
    assert_eq!(parent.stage_history(&parent.history_root().unwrap(), wrong).unwrap_err(), SproutLedgerError::History(HistoryError::NonconsecutiveHeight));
    assert_eq!(owned_state(&parent), before);
    let root = parent.chain_history.as_ref().unwrap().root();
    parent.history_root = Some([0; 32]);
    let before = owned_state(&parent);
    let next = primary_heartwood_leaf(primary_canopy_raw(height), height, parent.sapling_tree.root().to_bytes(), 1);
    assert_eq!(parent.stage_history(&root, next).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    // Same frontier still has to be computed for Canopy metadata, never copied
    // from a corrupted shielded-root cache or the header's parent-MMR field.
    parent.shielded_roots[1] = [0x5a; 32];
    let delta = parent.stage_block(canopy_coinbase(height, 0), vec![], height, 1_600_000_000).unwrap();
    assert_eq!(delta.sapling_root, sapling_crypto::Anchor::empty_tree().to_bytes());
    assert_ne!(delta.sapling_root, parent.shielded_roots[1]);
}

#[test]
fn canopy_mixed_sprout_withdrawal_and_internal_bundles_keep_real_groth_and_sapling_checks() {
    let height = 1_028_500;
    let key = ([0x98; 32], 0);
    let mut parent = state();
    isolated_canopy_history(&mut parent, height);
    fund(&mut parent, key, 20, &[0x51], 0, false);
    let original = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Canopy).unwrap();
    let mut sprout = original.sprout_bundle().unwrap().clone();
    let anchor = *sprout.joinsplits[0].anchor();
    parent.sprout_anchors.insert(anchor, Frontier::empty());
    parent.shielded_balances[0] = 10_000;
    parent.issued_supply += 10_000;
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Canopy, 0);
    let good_id: [u8; 32] = good().txid().into();
    for withdrawn in [0_u64, 10_000] {
        let mut description = Vec::new();
        sprout.joinsplits[0].write(&mut description).unwrap();
        description[..8].fill(0);
        description[8..16].copy_from_slice(&withdrawn.to_le_bytes());
        sprout.joinsplits[0] = JsDescription::read(description.as_slice(), true).unwrap();
        sprout.joinsplit_pubkey = [0; 32];
        sprout.joinsplit_sig = [0; 64];
        sprout.joinsplit_sig[0] = 1;
        let transparent = spend(&[((good_id, 0), &[], u32::MAX)], vec![output(18, &[0x51])], 0);
        let outputs = recorded_sapling().sapling_bundle().unwrap().shielded_outputs().to_vec();
        let context = modified_sapling(vec![], outputs, 0, transparent.transparent_bundle().cloned());
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Canopy, 0, 0.into(), transparent.transparent_bundle().cloned(), Some(sprout.clone()), context.sapling_bundle().cloned(), None).freeze().unwrap();
        let values = check_transaction(&transaction, height, 1_600_000_000).unwrap();
        assert_eq!((values.old, values.new), (0, withdrawn));
        // A genuine earlier spend and Sapling frontier are staged before ZIP215
        // authorization then every real Groth proof. These copied modified
        // statements are explicit negatives, never genuine withdrawal positives.
        assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![good(), transaction], height, 1_600_000_000), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof }))));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn late_canopy_generation_branch_expiry_and_fee_failures_never_commit_prior_spends() {
    let height = 1_028_500;
    let key = ([0x99; 32], 0);
    let mut parent = state();
    isolated_canopy_history(&mut parent, height);
    fund(&mut parent, key, 20, &[0x51], 0, false);
    let before = owned_state(&parent);
    let good = || v4(&spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Canopy, 0);
    let id: [u8; 32] = good().txid().into();
    let template = spend(&[((id, 0), &[], u32::MAX)], vec![output(18, &[0x51])], 0);
    let v3_bad = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Canopy, 0, 0.into(), template.transparent_bundle().cloned(), None, None, None).freeze().unwrap();
    let expired = v4(&template, BranchId::Canopy, height - 1);
    let previous_branch = v4(&template, BranchId::Heartwood, 0);
    let negative_fee = v4(&spend(&[((id, 0), &[], u32::MAX)], vec![output(20, &[0x51])], 0), BranchId::Canopy, 0);
    let second_coinbase = canopy_coinbase(height, 0);
    for (transaction, expected) in [(v3_bad, SproutLedgerError::UnsupportedTransaction), (expired, SproutLedgerError::ExpiredTransaction), (previous_branch, SproutLedgerError::UnsupportedTransaction), (negative_fee, SproutLedgerError::NegativeFee), (second_coinbase, SproutLedgerError::InvalidTransaction)] {
        assert!(matches!(parent.stage_block(canopy_coinbase(height, 0), vec![good(), transaction], height, 1_600_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn original_canopy_funding_offset_rotates_first_distinct_bp_at_1151000_not_1146000() {
    // Original v4.0.0 params.cpp:93–103 derives offset17500. The first
    // four recipient payloads are equal, so activation/halving-only authentic
    // fixtures cannot catch the previously miscomputed offset22500.
    let old_script = bytes("a91402db6bf7d524268b04edbb986ca4b3ba3528045f87");
    let new_script = bytes("a914ad84b615b30f84099596262976e2800b47bf634a87");
    for (height, accepted, rejected) in [(1_146_000, &old_script, &new_script), (1_150_999, &old_script, &new_script), (1_151_000, &new_script, &old_script), (1_151_001, &new_script, &old_script)] {
        let mut outputs = vec![output(250_000_000, &[0x51]), output(21_875_000, accepted), output(15_625_000, &bytes(CANOPY_ZF_SCRIPT)), output(25_000_000, &bytes(CANOPY_MG_SCRIPT))];
        assert_eq!(check_coinbase(&canopy_with_outputs(height, outputs.clone()), height, 1_600_000_000).unwrap().claimed, 312_500_000);
        outputs[1] = output(21_875_000, rejected);
        assert_eq!(check_coinbase(&canopy_with_outputs(height, outputs), height, 1_600_000_000), Err(SproutLedgerError::MissingFundingStream { index: 0 }));
    }
}

#[test]
fn actual_nu5_coinbase_and_subsidy_require_complete_new_era_admission() {
    let raw = include_bytes!("../tests/fixtures/testnet-nu5-block-1842421.bin");
    let height = 1_842_421;
    let body = crate::post_nu5_body::PostNu5Block::parse(raw, height).unwrap();
    let values = check_post_nu5_coinbase(&body.transactions()[0], height, body.header().time).unwrap();
    assert!(values.claimed >= subsidy(height).unwrap());
    assert_eq!(supported_branch(1_842_420), Ok(BranchId::Nu5));
    assert_eq!(subsidy(2_795_999), Ok(312_500_000));
    assert_eq!(subsidy(2_796_000), Ok(156_250_000));
    assert_eq!(supported_branch(2_975_999), Ok(BranchId::Nu5));
    assert_eq!(supported_branch(2_976_000), Ok(BranchId::Nu6));
}

#[test]
fn nu5_real_coinbases_and_original_orchard_transfers_stage_only_in_isolated_authorized_state() {
    for (raw, height) in [
        (include_bytes!("../tests/fixtures/testnet-nu5-block-1842421.bin").as_slice(), 1_842_421),
        (include_bytes!("../tests/fixtures/testnet-nu5-block-1842432.bin").as_slice(), 1_842_432),
        (include_bytes!("../tests/fixtures/testnet-nu5-block-1842462.bin").as_slice(), 1_842_462),
        (include_bytes!("../tests/fixtures/testnet-nu5-block-1842467.bin").as_slice(), 1_842_467),
        (include_bytes!("../tests/fixtures/testnet-nu5-block-1842468.bin").as_slice(), 1_842_468),
    ] {
        let body = crate::post_nu5_body::PostNu5Block::parse(raw, height).unwrap();
        let time = body.header().time;
        let values = check_post_nu5_coinbase(&body.transactions()[0], height, time).unwrap();
        assert!(values.claimed >= 312_500_000);
        let mut transactions = body.into_transactions();
        let coinbase = transactions.remove(0);
        let mut parent = state();
        // An isolated actual authorized spend supplies the coinbase's claimed
        // fees; this does not assert the unknown mined predecessor UTXOs.
        let key = ([0xa4; 32], 0);
        let fee = values.claimed - 312_500_000;
        fund(&mut parent, key, fee, &[0x51], 0, false);
        let fee_tx = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0), BranchId::Nu5, 0);
        let before = owned_state(&parent);
        let delta = parent.stage_post_nu5_block(vec![coinbase, PostNu5Transaction::V4(Box::new(fee_tx))], height, time).unwrap();
        assert_eq!(delta.orchard_tree.tree_size(), 0);
        assert_eq!(owned_state(&parent), before);
    }
    for (original, height) in [
        (include_bytes!("../tests/fixtures/orchard-pure-testnet-1842467.bin").as_slice(), 1_842_467),
        (include_bytes!("../tests/fixtures/nu5-mixed-testnet-1842421.bin").as_slice(), 1_842_421),
    ] {
        let raw = crate::raw_v5::RawV5::parse_exact(original).unwrap();
        let mut parent = state();
        let orchard = raw.orchard().unwrap();
        parent.orchard_anchors.insert(orchard.anchor().to_bytes());
        parent.shielded_balances[2] = i64::from(orchard.value_balance()).max(0) as u64;
        if let Some(bundle) = raw.sapling_bundle() {
            for spend in bundle.shielded_spends() { parent.sapling_anchors.insert(spend.anchor().to_bytes()); }
            parent.shielded_balances[1] = i64::from(*bundle.value_balance()).max(0) as u64;
        }
        parent.issued_supply = parent.shielded_balances.iter().sum();
        let before = owned_state(&parent);
        let mut delta = BlockDelta::new(&parent);
        parent.stage_v5_transaction(crate::raw_v5::RawV5::parse_exact(original).unwrap(), height, 1_700_000_000, &mut delta).unwrap();
        assert_eq!(delta.orchard_tree.tree_size(), 2);
        assert_eq!(parent.shielded_balances[1] as i128 + delta.sapling, 0);
        let orchard_expected = if raw.sapling_bundle().is_some() { 1_000_000_000 } else { 0 };
        assert_eq!(parent.shielded_balances[2] as i128 + delta.orchard, orchard_expected);
        assert_eq!(delta.fees + delta.sapling + delta.orchard, 0);
        assert_eq!(owned_state(&parent), before);
        let complete = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), original_v5(original)], height, 1_700_000_000).unwrap();
        assert_eq!((complete.sapling, complete.orchard), (0, orchard_expected));
        assert_eq!(complete.fees, if raw.sapling_bundle().is_some() { 0 } else { 1000 });
        assert_eq!(owned_state(&parent), before);
    }
}

// Literal original ZIP214 Revision0 interval starts/payloads, independent of
// the production selector. The existing source/MIT notices apply to this table.
const NU5_BP_STARTS: [(u32, &str); 28] = [
    (1_816_000, "4e3f0d9a33a2721604cbae2de8d9171e21f8fbe4"),
    (1_851_000, "39aefc11738ebc253beb6b6423fa39b5a6164ea8"),
    (1_886_000, "7810027ba46897a97462c96839df9126376178a8"),
    (1_921_000, "7d28da7f38180a7699ea588ceaea02420b33f7a8"),
    (1_956_000, "e3bd95ae8854282ca5b7e5e234b88033411b52d6"),
    (1_991_000, "23d9596d1e09eefe5719b4bfc828385d99e48a71"),
    (2_026_000, "c165cf3e05eff286d33a44bc19c98e58b05f736a"),
    (2_061_000, "5d8b6cb94fb7d99363ae0e7114be5208f4792450"),
    (2_096_000, "3f005bce6d56651cd3708f886a54d573d318a840"),
    (2_131_000, "358ec46536cdaa76463efa31d300d30e40701f77"),
    (2_166_000, "339d5d900507930b53439b17b0ffed5e75aa4dfc"),
    (2_201_000, "f5844c0ff6a9793eb1b8f01dc521dd9bb5198f19"),
    (2_236_000, "442ad1b624b7a7ce11d30840b42381f0c13aad7d"),
    (2_271_000, "5b1394ad17e506376f057bd12b1ca5689cbfc3bc"),
    (2_306_000, "6ebb1090755c5222c165eacf3af9004a42d1bdb2"),
    (2_341_000, "93dd2b726c3fa1476a30cbc7a42c7c711f68c0e7"),
    (2_376_000, "5525b63bacc5747c38b351c936c2e019e53c9da8"),
    (2_411_000, "4a0133ecb1911e08d5640fcb2afdf2341ec8c245"),
    (2_446_000, "88bd3454a085acaac8b1ea98071ae69c26f14c81"),
    (2_481_000, "e23dd6edb446bdbabc32939859d74c0c66d404dc"),
    (2_516_000, "bc34a244b8127410cd189b8ea3a483d316a2b8b0"),
    (2_551_000, "fabb4ab15192d0ac76c920d265c78f05a2fcd0e7"),
    (2_586_000, "d244b98ee03ed399019ef9e2a3d2b096cb1b2379"),
    (2_621_000, "86f6f0aa53c0e6ee938051a6785ab8291052ed17"),
    (2_656_000, "f2e61e5da3e899be0f276dd5bdbc9a94ff8fe860"),
    (2_691_000, "5f27c25fb9a4814b2f612786668c4170032ff719"),
    (2_726_000, "629207f95870bb1bd4ee1660b81fbfec6fc64f29"),
    (2_761_000, "93916098d2a161a91f3ddebab69dd5db9587b624"),
];

fn nu5_coinbase(height: u32, version: TxVersion, expiry: u32) -> Transaction {
    let (prefix, length) = coinbase_height_prefix(height);
    let outputs = if height < 2_796_000 {
        let bp = NU5_BP_STARTS.iter().rev().find(|(start, _)| height >= *start).unwrap().1;
        vec![output(250_000_000, &[0x51]), output(21_875_000, &bytes(&format!("a914{bp}87"))),
            output(15_625_000, &bytes(CANOPY_ZF_SCRIPT)), output(25_000_000, &bytes(CANOPY_MG_SCRIPT))]
    } else { vec![output(156_250_000, &[0x51])] };
    let transaction = changed(TxVersion::Sprout(1), 0, |bundle| {
        script_input(bundle, &prefix[..length], u32::MAX);
        bundle.vout = outputs;
    });
    TransactionData::<Authorized>::from_parts(version, BranchId::Nu5, 0, expiry.into(), transaction.transparent_bundle().cloned(), None, None, None).freeze().unwrap()
}

fn nu5_with_outputs(height: u32, version: TxVersion, outputs: Vec<TxOut>) -> Transaction {
    let mut bundle = nu5_coinbase(height, version, height).transparent_bundle().unwrap().clone();
    bundle.vout = outputs;
    TransactionData::<Authorized>::from_parts(version, BranchId::Nu5, 0, height.into(), Some(bundle), None, None, None).freeze().unwrap()
}

fn encoded(transaction: &Transaction) -> Vec<u8> {
    let mut raw = Vec::new();
    transaction.write(&mut raw).unwrap();
    raw
}

fn original_v5(raw: &[u8]) -> PostNu5Transaction<'_> {
    PostNu5Transaction::V5(Box::new(RawV5::parse_exact(raw).unwrap()))
}

#[test]
fn every_nu5_funding_period_and_second_halving_use_original_individual_outputs() {
    for (index, &(start, _)) in NU5_BP_STARTS.iter().enumerate() {
        let first = start.max(1_842_420);
        for height in [first, first + 1, if index == 27 { 2_795_999 } else { NU5_BP_STARTS[index + 1].0 - 1 }] {
            let good = nu5_coinbase(height, TxVersion::V4, height);
            assert_eq!(check_coinbase(&good, height, 1_700_000_000).unwrap().claimed, 312_500_000);
            let outputs = good.transparent_bundle().unwrap().vout.clone();
            for stream in 0..3 {
                for mutation in 0..4 {
                    let mut wrong = outputs.clone();
                    let chosen = stream + 1;
                    let value = u64::from(wrong[chosen].value());
                    let script = wrong[chosen].script_pubkey().0.0.clone();
                    match mutation {
                        0 => { wrong.remove(chosen); }
                        1 => wrong[chosen] = output(value + 1, &script),
                        2 => wrong[chosen] = output(value, &[0x51]),
                        3 => { wrong[chosen] = output(value - 1, &script); wrong.push(output(1, &script)); }
                        _ => unreachable!(),
                    }
                    assert_eq!(check_coinbase(&nu5_with_outputs(height, TxVersion::V4, wrong), height, 1_700_000_000), Err(SproutLedgerError::MissingFundingStream { index: stream }));
                }
            }
            let raw = encoded(&nu5_coinbase(height, TxVersion::V5, height));
            assert_eq!(check_post_nu5_coinbase(&original_v5(&raw), height, 1_700_000_000).unwrap().claimed, 312_500_000);
        }
        if index > 0 {
            for (height, payload) in [(start - 1, NU5_BP_STARTS[index].1), (start, NU5_BP_STARTS[index - 1].1)] {
                let mut wrong = nu5_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
                wrong[1] = output(21_875_000, &bytes(&format!("a914{payload}87")));
                assert_eq!(check_coinbase(&nu5_with_outputs(height, TxVersion::V4, wrong), height, 1_700_000_000), Err(SproutLedgerError::MissingFundingStream { index: 0 }));
            }
        }
    }
    for height in [2_796_000, 2_796_001, 2_975_999] {
        for version in [TxVersion::V4, TxVersion::V5] {
            let transaction = nu5_coinbase(height, version, height);
            let delta = if version == TxVersion::V4 {
                state().stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(transaction))], height, 1_700_000_000).unwrap()
            } else {
                let raw = encoded(&transaction);
                state().stage_post_nu5_block(vec![original_v5(&raw)], height, 1_700_000_000).unwrap()
            };
            assert_eq!((delta.issued, delta.transparent, delta.sapling, delta.orchard), (156_250_000, 156_250_000, 0, 0));
        }
    }
}

#[derive(Debug)]
struct SignerPrevouts(Vec<TxOut>);

impl zcash_transparent::bundle::Authorization for SignerPrevouts { type ScriptSig = Script; }

impl zcash_transparent::sighash::TransparentAuthorizingContext for SignerPrevouts {
    fn input_amounts(&self) -> Vec<Zatoshis> { self.0.iter().map(TxOut::value).collect() }
    fn input_scriptpubkeys(&self) -> Vec<Script> { self.0.iter().map(|output| output.script_pubkey().clone()).collect() }
}

#[derive(Debug)]
struct SignerAuthorization;

impl zcash_primitives::transaction::Authorization for SignerAuthorization {
    type TransparentAuth = SignerPrevouts;
    type SaplingAuth = sapling_crypto::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

struct SignerMap(Vec<TxOut>);

impl zcash_transparent::bundle::MapAuth<zcash_transparent::bundle::Authorized, SignerPrevouts> for SignerMap {
    fn map_script_sig(&self, script: Script) -> Script { script }
    fn map_authorization(&self, _: zcash_transparent::bundle::Authorized) -> SignerPrevouts { SignerPrevouts(self.0.clone()) }
}

fn independently_signed_v5(keys: &[([u8; 32], u32)], p2sh: bool, raw_type: u8) -> (Vec<u8>, Vec<TxOut>) {
    independently_signed_v5_for_branch(keys, BranchId::Nu5, p2sh, raw_type)
}

fn independently_signed_v5_for_branch(keys: &[([u8; 32], u32)], branch: BranchId, p2sh: bool, raw_type: u8) -> (Vec<u8>, Vec<TxOut>) {
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use zcash_primitives::transaction::{sighash::{SignableInput, signature_hash}, txid::TxIdDigester};
    use zcash_transparent::sighash::{SignableInput as TransparentInput, SighashType};
    // Synthetic public scalar1, never a wallet/account or funded-chain claim.
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let signing_key = SecretKey::from_slice(&scalar).unwrap();
    let secp = Secp256k1::new();
    let mut redeem = vec![33];
    redeem.extend_from_slice(&PublicKey::from_secret_key(&secp, &signing_key).serialize());
    redeem.push(0xac);
    let lock = if p2sh {
        let mut lock = vec![0xa9, 20];
        lock.extend_from_slice(&zcash_transparent::util::hash160::hash(&redeem));
        lock.push(0x87);
        lock
    } else { redeem.clone() };
    let prevouts: Vec<_> = keys.iter().enumerate().map(|(index, _)| output(100_002 + index as u64, &lock)).collect();
    let mut transparent = spend(&keys.iter().map(|key| (*key, &[][..], 123)).collect::<Vec<_>>(),
        keys.iter().map(|_| output(100_000, &[0x51])).collect(), 0).transparent_bundle().unwrap().clone();
    let unsigned = TransactionData::<Authorized>::from_parts(TxVersion::V5, branch, 0, 0.into(), Some(transparent.clone()), None, None, None).freeze().unwrap();
    let oracle = unsigned.into_data().map_authorization::<SignerAuthorization>(SignerMap(prevouts.clone()), (), ());
    let parts = oracle.digest(TxIdDigester);
    for index in 0..keys.len() {
        let prevout = &prevouts[index];
        let input = TransparentInput::from_parts(oracle.transparent_bundle().unwrap(), SighashType::parse(raw_type).unwrap(), index,
            prevout.script_pubkey(), prevout.script_pubkey(), prevout.value()).unwrap();
        let digest = signature_hash(&oracle, &SignableInput::Transparent(input), &parts);
        let mut signature = secp.sign_ecdsa(&Message::from_digest_slice(digest.as_ref()).unwrap(), &signing_key).serialize_der().to_vec();
        signature.push(raw_type);
        let mut script = Script::default();
        script.0.0.push(signature.len() as u8);
        script.0.0.extend_from_slice(&signature);
        if p2sh { script.0.0.push(redeem.len() as u8); script.0.0.extend_from_slice(&redeem); }
        transparent.vin[index] = TxIn::from_parts(OutPoint::new(keys[index].0, keys[index].1), script, 123);
    }
    let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V5, branch, 0, 0.into(), Some(transparent), None, None, None).freeze().unwrap();
    (encoded(&transaction), prevouts)
}

#[test]
fn nu5_signed_v4_and_v5_use_actual_parent_amounts_locking_scripts_and_p2sh() {
    let height = 1_842_420;
    for p2sh in [false, true] {
        for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
            let (transaction, prevout) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu5, p2sh, hash_type);
            let mut parent = state();
            fund(&mut parent, ([0xa1; 32], 3), 100_002, &prevout.script_pubkey().0.0, 0, false);
            assert_eq!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(transaction))], height, 1_700_000_000).unwrap().fees, 2);
            let keys = [([0xb2; 32], 3), ([0xb3; 32], 7)];
            let (raw, prevouts) = independently_signed_v5(&keys, p2sh, hash_type);
            let mut parent = state();
            for (key, prevout) in keys.iter().zip(&prevouts) { fund(&mut parent, *key, u64::from(prevout.value()), &prevout.script_pubkey().0.0, 0, false); }
            let before = owned_state(&parent);
            let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), original_v5(&raw)], height, 1_700_000_000).unwrap();
            assert_eq!(delta.fees, 5);
            assert_eq!(owned_state(&parent), before);
            for index in 0..keys.len() {
                for changed_script in [false, true] {
                    let mut parent = state();
                    for (number, (key, prevout)) in keys.iter().zip(&prevouts).enumerate() {
                        let mut script = prevout.script_pubkey().0.0.clone();
                        if number == index && changed_script { if p2sh { script[2] ^= 1; } else { script.insert(0, 0x61); } }
                        let amount = u64::from(prevout.value()) + u64::from(number == index && !changed_script);
                        fund(&mut parent, *key, amount, &script, 0, false);
                    }
                    let before = owned_state(&parent);
                    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), original_v5(&raw)], height, 1_700_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
                    assert_eq!(owned_state(&parent), before);
                }
            }
            let mut corrupted = raw.clone();
            corrupted[68] ^= 1;
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), original_v5(&corrupted)], height, 1_700_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
            assert_eq!(owned_state(&parent), before);
            parent.commit(delta);
            for key in keys { assert!(parent.utxo(&key.0, key.1).is_none()); }
        }
    }
}

#[test]
fn v5_checks_every_earlier_candidate_prevout_before_any_input_becomes_spent() {
    let height = 1_842_420;
    let (prototype, prevouts) = independently_signed_v5(&[([0xb4; 32], 0), ([0xb5; 32], 1)], true, 1);
    let key = ([0xb6; 32], 0);
    let mut parent = state();
    fund(&mut parent, key, 200_010, &[0x51], 0, false);
    let first = v4(&spend(&[(key, &[], u32::MAX)], prevouts.clone(), 0), BranchId::Nu5, 0);
    let first_id: [u8; 32] = first.txid().into();
    let (second, _) = independently_signed_v5(&[(first_id, 0), (first_id, 1)], true, 1);
    assert_ne!(prototype, second);
    let second_id = RawV5::parse_exact(&second).unwrap().effect_id();
    let third = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu5, 0, 0.into(),
        spend(&[((second_id, 0), &[], u32::MAX), ((second_id, 1), &[], u32::MAX)], vec![output(199_999, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
    let third = encoded(&third);
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(first)), original_v5(&second), original_v5(&third)], height, 1_700_000_000).unwrap();
    assert_eq!(delta.fees, 11);
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert!(parent.utxo(&key.0, key.1).is_none());
    assert!(parent.utxo(&first_id, 0).is_none());
    assert!(parent.utxo(&first_id, 1).is_none());
    assert!(parent.utxo(&second_id, 0).is_none());
    assert!(parent.utxo(&second_id, 1).is_none());
}

#[derive(Debug)]
struct UnsignedOrchard;

impl zcash_primitives::transaction::Authorization for UnsignedOrchard {
    type TransparentAuth = zcash_transparent::bundle::Authorized;
    type SaplingAuth = sapling_crypto::bundle::Authorized;
    type OrchardAuth = orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;
}

#[derive(Debug)]
struct UnsignedOrchardPrevouts;

impl zcash_primitives::transaction::Authorization for UnsignedOrchardPrevouts {
    type TransparentAuth = SignerPrevouts;
    type SaplingAuth = sapling_crypto::bundle::Authorized;
    type OrchardAuth = orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;
}

static ORIGINAL_ORCHARD_PK: std::sync::LazyLock<orchard::circuit::ProvingKey> = std::sync::LazyLock::new(|| {
    orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2)
});

static FIXED_ORCHARD_PK: std::sync::LazyLock<orchard::circuit::ProvingKey> = std::sync::LazyLock::new(|| {
    orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2)
});

fn synthetic_original_orchard(coinbase: bool, branch: BranchId) -> Vec<u8> {
    synthetic_original_orchard_at(coinbase, branch, match branch { BranchId::Nu5 => 1_842_420, BranchId::Nu6 => 2_976_000, BranchId::Nu6_1 => 3_536_500, _ => panic!("finite original Orchard branch") })
}

fn synthetic_original_orchard_at(coinbase: bool, branch: BranchId, height: u32) -> Vec<u8> {
    synthetic_orchard_at(coinbase, branch, height, false)
}

fn synthetic_orchard_at(coinbase: bool, branch: BranchId, height: u32, fixed: bool) -> Vec<u8> {
    synthetic_orchard_with_prevouts(coinbase, branch, height, fixed, &[])
}

fn synthetic_orchard_with_prevouts(coinbase: bool, branch: BranchId, height: u32, fixed: bool, previous_outputs: &[TxOut]) -> Vec<u8> {
    use orchard::{builder::{Builder, BundleType}, bundle::{BundleVersion, Flags}, keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendingKey}, value::NoteValue};
    use rand_core::SeedableRng;
    use zcash_primitives::transaction::txid::{TxIdDigester, to_txid};
    let seed = if !previous_outputs.is_empty() { 0x63 } else if branch == BranchId::Nu6_2 { if coinbase { 0x61 } else { 0x62 } } else if coinbase { 0x51 } else { 0x52 };
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([seed; 32]);
    let flags = if coinbase || !previous_outputs.is_empty() { Flags::SPENDS_DISABLED } else { Flags::OUTPUTS_DISABLED };
    let kind = if coinbase { BundleType::Coinbase } else { BundleType::Transactional { bundle_required: true, pad_to_minimum: Some(if branch == BranchId::Nu6_2 { 2 } else { 1 }) } };
    let version = if fixed { BundleVersion::orchard_v2() } else { BundleVersion::orchard_insecure_v1() };
    let mut builder = Builder::new(kind, version, flags, orchard::Anchor::empty_tree()).unwrap();
    if coinbase || !previous_outputs.is_empty() {
        // Public synthetic seed, no wallet or mined/funded-history assertion.
        let sk = SpendingKey::from_bytes([0; 32]).unwrap();
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        for value in [0, 7] { builder.add_output(Some(OutgoingViewingKey::from([0; 32])), recipient, NoteValue::from_raw(value), [0; 512]).unwrap(); }
    }
    let (unproven, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
    let unproven = unproven.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let reward = || match branch {
        BranchId::Nu5 => nu5_coinbase(height, TxVersion::V5, height),
        BranchId::Nu6 => nu6_coinbase(height, TxVersion::V5, height),
        BranchId::Nu6_1 => nu61_coinbase(height, TxVersion::V5, height),
        BranchId::Nu6_2 => nu62_coinbase(height, TxVersion::V5, height),
        _ => unreachable!("finite original Orchard branch"),
    };
    let transparent = if coinbase {
        let mut bundle = reward().transparent_bundle().unwrap().clone();
        bundle.vout[0] = output(if branch == BranchId::Nu5 { 249_999_993 } else { 124_999_993 }, &[0x51]);
        bundle
    } else {
        let mut bundle = reward().transparent_bundle().unwrap().clone();
        bundle.vin = (0..previous_outputs.len()).map(|index| TxIn::from_parts(OutPoint::new([0xea + index as u8; 32], index as u32), Script::default(), u32::MAX)).collect();
        bundle.vout = if previous_outputs.is_empty() { vec![output(0, &[0x51])] } else { vec![] };
        bundle
    };
    let expiry = if coinbase { height } else { 0 };
    let sighash: [u8; 32] = if previous_outputs.is_empty() {
        let data = TransactionData::<UnsignedOrchard>::from_parts(TxVersion::V5, branch, 0, expiry.into(), Some(transparent.clone()), None, None, Some(unproven.clone()));
        to_txid(TxVersion::V5, branch, &data.digest(TxIdDigester)).into()
    } else {
        // Orchard InProgress has no unit MapAuth; retain the real unproven
        // bundle directly while attaching the exact ordered prevout context.
        let oracle = TransactionData::<UnsignedOrchardPrevouts>::from_parts(TxVersion::V5, branch, 0, expiry.into(),
            Some(zcash_transparent::bundle::Bundle {
                vin: transparent.vin.iter().map(|input| TxIn::from_parts(input.prevout().clone(), input.script_sig().clone(), input.sequence())).collect(),
                vout: transparent.vout.clone(),
                authorization: SignerPrevouts(previous_outputs.to_vec()),
            }), None, None, Some(unproven.clone()));
        *zcash_primitives::transaction::sighash::signature_hash(&oracle, &zcash_primitives::transaction::sighash::SignableInput::Shielded, &oracle.digest(TxIdDigester)).as_ref()
    };
    // Genuine Halo2 proving and every dummy/disabled SpendAuth plus binding;
    // the negative-only old-key fixture is also signed under actual NU6.2.
    let pk = if fixed { &*FIXED_ORCHARD_PK } else { &*ORIGINAL_ORCHARD_PK };
    let bundle = unproven.create_proof(pk, &mut rng).unwrap().apply_signatures(&mut rng, sighash, &[]).unwrap();
    encoded(&TransactionData::<Authorized>::from_parts(TxVersion::V5, branch, 0, expiry.into(), Some(transparent), None, None, Some(bundle)).freeze().unwrap())
}

static ORCHARD_COINBASE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_original_orchard(true, BranchId::Nu5));
static ORCHARD_OUTPUTS_DISABLED: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_original_orchard(false, BranchId::Nu5));
static NU6_ORCHARD_COINBASE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_original_orchard(true, BranchId::Nu6));
static NU6_ORCHARD_OUTPUTS_DISABLED: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_original_orchard(false, BranchId::Nu6));
static NU61_ORCHARD_COINBASE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_original_orchard(true, BranchId::Nu6_1));
static NU61_ORCHARD_OUTPUTS_DISABLED: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_original_orchard(false, BranchId::Nu6_1));
static NU62_ORCHARD_COINBASE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_orchard_at(true, BranchId::Nu6_2, 4_052_000, true));
static NU62_ORCHARD_OUTPUTS_DISABLED: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_orchard_at(false, BranchId::Nu6_2, 4_052_000, true));
static NU62_ORCHARD_OLD_KEY: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| synthetic_orchard_at(false, BranchId::Nu6_2, 4_052_000, false));
static NU62_ORCHARD_SHIELD_ONLY: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    synthetic_orchard_with_prevouts(false, BranchId::Nu6_2, 4_052_000, true, &[output(3, &[0x51]), output(4, &[0x61, 0x51])])
});

#[test]
fn original_orchard_coinbase_and_disabled_outputs_execute_every_equation_and_ordered_leaf() {
    let height = 1_842_420;
    let mut parent = state();
    let before = owned_state(&parent);
    let coinbase = RawV5::parse_exact(&ORCHARD_COINBASE).unwrap();
    let bundle = coinbase.orchard().unwrap();
    assert_eq!(bundle.action_count(), 2);
    assert!(!bundle.flags().spends_enabled() && bundle.flags().outputs_enabled());
    assert_eq!(i64::from(bundle.value_balance()), -7);
    let values = check_post_nu5_coinbase(&PostNu5Transaction::V5(Box::new(coinbase)), height, 1_700_000_000).unwrap();
    assert_eq!((values.claimed, values.transparent, values.orchard_balance), (312_500_000, 312_499_993, -7));
    let disabled = RawV5::parse_exact(&ORCHARD_OUTPUTS_DISABLED).unwrap();
    assert!(disabled.orchard().unwrap().flags().spends_enabled() && !disabled.orchard().unwrap().flags().outputs_enabled());
    let mut expected = incrementalmerkletree::frontier::CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for raw in [&ORCHARD_COINBASE, &ORCHARD_OUTPUTS_DISABLED] {
        for action in RawV5::parse_exact(raw).unwrap().orchard().unwrap().actions().as_chunks::<820>().0 {
            expected.append(MerkleHashOrchard::from_bytes(action[96..128].try_into().unwrap()).unwrap()).unwrap();
        }
    }
    let delta = parent.stage_post_nu5_block(vec![original_v5(&ORCHARD_COINBASE), original_v5(&ORCHARD_OUTPUTS_DISABLED)], height, 1_700_000_000).unwrap();
    assert_eq!((delta.issued, delta.transparent, delta.orchard, delta.fees), (312_500_000, 312_499_993, 7, 0));
    assert_eq!(delta.orchard_tree.tree_size(), 3);
    assert_eq!(delta.orchard_root, expected.root().to_bytes());
    assert_eq!(delta.orchard_nullifiers.len(), 3); // Every action, including dummy/disabled.
    assert_eq!(owned_state(&parent), before);
    let root = delta.orchard_root;
    parent.commit(delta);
    assert_eq!((parent.orchard_tree_size(), parent.shielded_balance(ShieldedPool::Orchard)), (3, 7));
    assert!(parent.orchard_anchors.contains(&root));
    assert_eq!(parent.nullifier_count(ShieldedPool::Orchard), 3);
    assert_eq!(parent.history_root(), before.history); // Ledger delta is not block/header admission.
}

#[test]
fn orchard_coinbase_recovery_never_substitutes_for_all_dummy_signatures_proof_or_binding() {
    let height = 1_842_420;
    let original = RawV5::parse_exact(&ORCHARD_COINBASE).unwrap();
    let bundle = original.orchard().unwrap();
    let action_start = bundle.actions().as_ptr() as usize - ORCHARD_COINBASE.as_ptr() as usize;
    let proof_start = bundle.proof().as_ptr() as usize - ORCHARD_COINBASE.as_ptr() as usize;
    let sig_start = bundle.spend_auth_signatures().as_ptr() as usize - ORCHARD_COINBASE.as_ptr() as usize;
    let binding_start = bundle.binding_signature().as_ptr() as usize - ORCHARD_COINBASE.as_ptr() as usize;
    for (offset, error) in [
        (action_start + 160, RawV5Error::CoinbaseRecovery { index: 0 }),
        (action_start + 820 + 819, RawV5Error::CoinbaseRecovery { index: 1 }),
        (proof_start, RawV5Error::InvalidOrchardProof),
        (sig_start + 63, RawV5Error::InvalidOrchardSpendAuth { index: 0 }),
        (sig_start + 64 + 63, RawV5Error::InvalidOrchardSpendAuth { index: 1 }),
        (binding_start + 63, RawV5Error::InvalidOrchardBindingSignature),
    ] {
        let parent = state();
        let before = owned_state(&parent);
        let mut changed = ORCHARD_COINBASE.to_vec();
        changed[offset] ^= 1;
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&changed)], height, 1_700_000_000), Err(SproutLedgerError::Orchard(actual)) if actual == error), "offset {offset}");
        assert_eq!(owned_state(&parent), before);
    }
    let mut changed = ORCHARD_COINBASE.to_vec();
    changed[action_start + 2 * 820] = 3;
    assert!(matches!(state().stage_post_nu5_block(vec![original_v5(&changed)], height, 1_700_000_000), Err(SproutLedgerError::InvalidCoinbase)));
}

fn isolated_original_nu5_parent(raw: &[u8]) -> SproutTestnetLedger {
    let transaction = RawV5::parse_exact(raw).unwrap();
    let mut parent = state();
    if let Some(orchard) = transaction.orchard() {
        parent.orchard_anchors.insert(orchard.anchor().to_bytes());
        parent.shielded_balances[2] = i64::from(orchard.value_balance()).max(0) as u64;
    }
    if let Some(sapling) = transaction.sapling_bundle() {
        for spend in sapling.shielded_spends() { parent.sapling_anchors.insert(spend.anchor().to_bytes()); }
        parent.shielded_balances[1] = i64::from(*sapling.value_balance()).max(0) as u64;
    }
    parent.issued_supply = parent.shielded_balances.iter().sum();
    parent
}

#[test]
fn orchard_all_action_nullifiers_parent_only_anchors_and_full_tree_fail_atomically() {
    let height = 1_842_420;
    let raw = RawV5::parse_exact(&ORCHARD_COINBASE).unwrap();
    let orchard = raw.orchard().unwrap();
    let actions_start = orchard.actions().as_ptr() as usize - ORCHARD_COINBASE.as_ptr() as usize;
    let nf: [u8; 32] = orchard.actions()[32..64].try_into().unwrap();
    let parent = state();
    let before = owned_state(&parent);
    let mut delta = BlockDelta::new(&parent);
    parent.stage_orchard(Some(orchard), &mut delta).unwrap();
    let intermediate = delta.orchard_tree.root().to_bytes();
    assert_ne!(intermediate, parent.shielded_roots[2]);
    assert_eq!(parent.stage_orchard(Some(orchard), &mut delta), Err(SproutLedgerError::SpentOrchardNullifier));
    assert_eq!(owned_state(&parent), before);
    let mut changed = ORCHARD_OUTPUTS_DISABLED.to_vec();
    let parsed = RawV5::parse_exact(&changed).unwrap();
    let bundle = parsed.orchard().unwrap();
    let anchor_offset = bundle.actions().as_ptr() as usize - changed.as_ptr() as usize + bundle.action_count() * 820 + 9;
    changed[anchor_offset..anchor_offset + 32].copy_from_slice(&intermediate);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&ORCHARD_COINBASE), original_v5(&changed)], height, 1_700_000_000), Err(SproutLedgerError::UnknownOrchardAnchor)));
    assert_eq!(owned_state(&parent), before);
    let mut duplicate = ORCHARD_COINBASE.to_vec();
    duplicate[actions_start + 820 + 32..actions_start + 820 + 64].copy_from_slice(&nf);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&duplicate)], height, 1_700_000_000), Err(SproutLedgerError::Orchard(RawV5Error::CoinbaseRecovery { index: 1 }))));
    // Test the actual state predicate independently: changed rho invalidates
    // coinbase encryption, but cannot bypass the all-action duplicate gate.
    let transaction = RawV5::parse_exact(&duplicate).unwrap();
    assert_eq!(parent.stage_orchard(transaction.orchard(), &mut BlockDelta::new(&parent)), Err(SproutLedgerError::SpentOrchardNullifier));
    let mut spent = state();
    spent.nullifiers[2].insert(nf);
    let before = owned_state(&spent);
    assert!(matches!(spent.stage_post_nu5_block(vec![original_v5(&ORCHARD_COINBASE)], height, 1_700_000_000), Err(SproutLedgerError::SpentOrchardNullifier)));
    assert_eq!(owned_state(&spent), before);
    let mut full = state();
    let leaf = MerkleHashOrchard::from_bytes(orchard.actions()[96..128].try_into().unwrap()).unwrap();
    full.orchard_tree = Frontier::from_parts(((1_u64 << 32) - 1).into(), leaf, vec![leaf; 32]).unwrap();
    full.shielded_roots[2] = full.orchard_tree.root().to_bytes();
    full.orchard_anchors.insert(full.shielded_roots[2]);
    let before = owned_state(&full);
    assert!(matches!(full.stage_post_nu5_block(vec![original_v5(&ORCHARD_COINBASE)], height, 1_700_000_000), Err(SproutLedgerError::OrchardTreeFull)));
    assert_eq!(owned_state(&full), before);
    let mut last = state();
    last.orchard_tree = Frontier::from_parts(((1_u64 << 32) - 2).into(), leaf, vec![leaf; 31]).unwrap();
    let before = owned_state(&last);
    // First append reaches the final leaf; second append must reject without
    // publishing the first action's nullifier, frontier or money transition.
    assert!(matches!(last.stage_post_nu5_block(vec![original_v5(&ORCHARD_COINBASE)], height, 1_700_000_000), Err(SproutLedgerError::OrchardTreeFull)));
    assert_eq!(owned_state(&last), before);
}

#[test]
fn genuine_orchard_and_mixed_crypto_failures_leave_every_owned_field_unchanged() {
    for original in [include_bytes!("../tests/fixtures/orchard-pure-testnet-1842467.bin").as_slice(), include_bytes!("../tests/fixtures/nu5-mixed-testnet-1842421.bin").as_slice()] {
        let parent = isolated_original_nu5_parent(original);
        let raw = RawV5::parse_exact(original).unwrap();
        let bundle = raw.orchard().unwrap();
        let proof = bundle.proof().as_ptr() as usize - original.as_ptr() as usize;
        let signatures = bundle.spend_auth_signatures().as_ptr() as usize - original.as_ptr() as usize;
        let binding = bundle.binding_signature().as_ptr() as usize - original.as_ptr() as usize;
        let before = owned_state(&parent);
        for (offset, expected) in [(proof, RawV5Error::InvalidOrchardProof), (signatures + 63, RawV5Error::InvalidOrchardSpendAuth { index: 0 }),
            (signatures + 64 + 63, RawV5Error::InvalidOrchardSpendAuth { index: 1 }), (binding + 63, RawV5Error::InvalidOrchardBindingSignature)] {
            let mut changed = original.to_vec();
            changed[offset] ^= 1;
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(1_842_420, TxVersion::V4, 1_842_420))), original_v5(&changed)], 1_842_420, 1_700_000_000), Err(SproutLedgerError::Orchard(actual)) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
        let nf: [u8; 32] = bundle.actions()[32..64].try_into().unwrap();
        let mut parent = isolated_original_nu5_parent(original);
        parent.nullifiers[2].insert(nf);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(1_842_420, TxVersion::V4, 1_842_420))), original_v5(original)], 1_842_420, 1_700_000_000), Err(SproutLedgerError::SpentOrchardNullifier)));
        assert_eq!(owned_state(&parent), before);
    }
}

fn post_nu5_leaf(height: u32, sapling_root: [u8; 32], orchard_root: [u8; 32], sapling_tx: u64, orchard_tx: u64) -> HistoryLeafV2 {
    HistoryLeafV2 {
        v1: primary_heartwood_leaf(include_bytes!("../tests/fixtures/testnet-nu5-block-1842421.bin"), height, sapling_root, sapling_tx),
        start_orchard_root: orchard_root, end_orchard_root: orchard_root, orchard_tx,
    }
}

fn block_commitment(history: [u8; 32], auth: [u8; 32]) -> [u8; 32] {
    blake2b_simd::Params::new().hash_length(32).personal(b"ZcashBlockCommit")
        .to_state().update(&history).update(&auth).update(&[0; 32]).finalize().as_bytes().try_into().unwrap()
}

#[test]
fn nu5_activation_requires_owned_last_canopy_v1_then_explicit_actual_v2_leaf() {
    use zcash_history::{V2, Version};
    let mut parent = state();
    let last = primary_heartwood_leaf(primary_canopy_raw(1_116_000), 1_842_419, parent.sapling_tree.root().to_bytes(), 0);
    let history = ChainHistoryV1::new(last.clone()).unwrap();
    parent.history_root = Some(history.root());
    parent.chain_history = Some(history);
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(vec![original_v5(&ORCHARD_COINBASE), original_v5(&ORCHARD_OUTPUTS_DISABLED)], 1_842_420, 1_700_000_000).unwrap();
    let first = post_nu5_leaf(1_842_420, delta.sapling_root, delta.orchard_root, 0, 2);
    let auth = [0x75; 32]; // Isolated header-commitment subrelation, not supplied admission authority.
    let commitment = block_commitment(parent.history_root().unwrap(), auth);
    let history = parent.stage_post_nu5_history(&commitment, &auth, first.clone()).unwrap();
    assert_eq!(history.root(), V2::hash(&first));
    assert_eq!((history.leaf_count(), history.last_height()), (1, 1_842_420));
    assert_eq!(history.consensus_branch_id(), u32::from(BranchId::Nu5));
    assert_eq!(owned_state(&parent), before);
    assert_ne!(history.root(), parent.history_root().unwrap());
    for (height, branch, expected) in [(1_842_418, BranchId::Canopy, HistoryError::NonconsecutiveHeight), (1_842_419, BranchId::Heartwood, HistoryError::BranchMismatch)] {
        let mut bad = last.clone();
        bad.start_height = height;
        bad.end_height = height;
        bad.consensus_branch_id = u32::from(branch);
        let old = ChainHistoryV1::new(bad).unwrap();
        parent.history_root = Some(old.root());
        parent.chain_history = Some(old);
        let before = owned_state(&parent);
        assert_eq!(parent.stage_post_nu5_history(&block_commitment(parent.history_root().unwrap(), auth), &auth, first.clone()).unwrap_err(), SproutLedgerError::History(expected));
        assert_eq!(owned_state(&parent), before);
    }
    parent.chain_history = None;
    let before = owned_state(&parent);
    assert_eq!(parent.stage_post_nu5_history(&commitment, &auth, first.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    parent.chain_history_v2 = Some(history);
    parent.history_root = parent.chain_history_v2.as_ref().map(ChainHistoryV2::root);
    let next = post_nu5_leaf(1_842_421, delta.sapling_root, delta.orchard_root, 1, 1);
    let before = owned_state(&parent);
    let root = parent.history_root().unwrap();
    let combined = parent.stage_post_nu5_history(&block_commitment(root, auth), &auth, next.clone()).unwrap();
    assert_eq!(combined.root(), V2::hash(&V2::combine(&first, &next)));
    assert_eq!(combined.leaf_count(), 2);
    assert_eq!(owned_state(&parent), before);
    let mut changed_auth = auth;
    changed_auth[0] ^= 1;
    assert_eq!(parent.stage_post_nu5_history(&block_commitment(root, auth), &changed_auth, next).unwrap_err(), SproutLedgerError::Body(BodyError::BlockCommitmentMismatch));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu5_late_history_work_counts_height_and_cache_failures_preserve_whole_state() {
    let height = 1_842_421;
    let auth = [0x76; 32];
    for failure in 0..5 {
        let mut parent = state();
        let mut first = post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0);
        if failure == 0 { first.v1.subtree_total_work = primitive_types::U256::MAX; }
        if failure == 1 { first.v1.sapling_tx = u64::MAX; }
        if failure == 2 { first.orchard_tx = u64::MAX; }
        let history = ChainHistoryV2::new(first).unwrap();
        let root = history.root();
        parent.history_root = Some(root);
        parent.chain_history_v2 = Some(history);
        if failure == 4 { parent.history_root = Some([0; 32]); }
        let before = owned_state(&parent);
        let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height)))], height, 1_700_000_000).unwrap();
        let next = post_nu5_leaf(height + u32::from(failure == 3), delta.sapling_root, delta.orchard_root, 1, 1);
        let expected = match failure {
            0 => SproutLedgerError::History(HistoryError::WorkOverflow),
            1 => SproutLedgerError::History(HistoryError::SaplingCountOverflow),
            2 => SproutLedgerError::History(HistoryError::OrchardCountOverflow),
            3 => SproutLedgerError::History(HistoryError::NonconsecutiveHeight),
            4 => SproutLedgerError::WrongHistoryRoot,
            _ => unreachable!(),
        };
        assert_eq!(parent.stage_post_nu5_history(&block_commitment(root, auth), &auth, next).unwrap_err(), expected);
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = state();
    parent.shielded_roots[1] = [0x5a; 32];
    parent.shielded_roots[2] = [0x5b; 32];
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height)))], height, 1_700_000_000).unwrap();
    assert_eq!(delta.sapling_root, sapling_crypto::Anchor::empty_tree().to_bytes());
    assert_eq!(delta.orchard_root, orchard::Anchor::empty_tree().to_bytes());
    assert_ne!(delta.sapling_root, parent.shielded_roots[1]);
    assert_ne!(delta.orchard_root, parent.shielded_roots[2]);
    let mut parent = state();
    let before = owned_state(&parent);
    for raw in [include_bytes!("../tests/fixtures/testnet-nu5-block-1842421.bin").as_slice(), include_bytes!("../tests/fixtures/testnet-nu5-block-1842467.bin").as_slice()] {
        assert_eq!(parent.apply_block(raw), Err(SproutLedgerError::WrongHeight));
        assert_eq!(owned_state(&parent), before);
    }
    let parent_tip = parent.tip();
    let tip = parent.headers.append(include_bytes!("../tests/fixtures/testnet-header-1.bin")).unwrap();
    let leaf = history_leaf(parent_tip, tip, delta.sapling_root, 1).unwrap();
    assert_eq!(leaf.subtree_total_work, primitive_types::U256::from(32));
    assert_eq!(leaf.subtree_commitment, tip.hash());
    assert_ne!(leaf.subtree_total_work, tip.cumulative_work());
}

#[test]
fn nu5_expiry_finality_maturity_and_null_input_are_exact_for_both_wire_versions() {
    let height = 1_842_420;
    let key = ([0xb7; 32], 0);
    for version in [TxVersion::V4, TxVersion::V5] {
        for expiry in [0, height - 1, height, height + 1, 499_999_999, 500_000_000] {
            let reward = nu5_coinbase(height, version, expiry);
            let result = if version == TxVersion::V4 { check_coinbase(&reward, height, 1_700_000_000) }
                else { let raw = encoded(&reward); check_post_nu5_coinbase(&original_v5(&raw), height, 1_700_000_000) };
            assert_eq!(result.map(|_| ()), if expiry == height { Ok(()) } else { Err(SproutLedgerError::InvalidCoinbase) });
            let transaction = TransactionData::<Authorized>::from_parts(version, BranchId::Nu5, 0, expiry.into(),
                spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let result = if version == TxVersion::V4 { check_transaction(&transaction, height, 1_700_000_000).map(|_| ()) }
                else { let raw = encoded(&transaction); check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), height, 1_700_000_000).map(|_| ()) };
            let expected = if expiry >= 500_000_000 { Err(SproutLedgerError::InvalidTransaction) } else if expiry != 0 && expiry < height { Err(SproutLedgerError::ExpiredTransaction) } else { Ok(()) };
            assert_eq!(result, expected);
        }
        for (lock, sequence, accepted) in [(height - 1, 0, true), (height, 0, false), (height, u32::MAX, true), (1_699_999_999, 0, true), (1_700_000_000, 0, false)] {
            let transaction = TransactionData::<Authorized>::from_parts(version, BranchId::Nu5, lock, 0.into(),
                spend(&[(key, &[], sequence)], vec![output(0, &[0x51])], lock).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let result = if version == TxVersion::V4 { check_transaction(&transaction, height, 1_700_000_000).map(|_| ()) }
                else { let raw = encoded(&transaction); check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), height, 1_700_000_000).map(|_| ()) };
            assert_eq!(result, if accepted { Ok(()) } else { Err(SproutLedgerError::NonfinalTransaction) });
        }
        for (created, expected) in [(height - 100, SproutLedgerError::UnshieldedCoinbaseSpend), (height - 99, SproutLedgerError::ImmatureCoinbase)] {
            let mut parent = state();
            fund(&mut parent, key, 0, &[0x51], created, true);
            let before = owned_state(&parent);
            let transaction = TransactionData::<Authorized>::from_parts(version, BranchId::Nu5, 0, 0.into(),
                spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let result = if version == TxVersion::V4 { parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(transaction))], height, 1_700_000_000) }
                else { let raw = encoded(&transaction); parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), original_v5(&raw)], height, 1_700_000_000) };
            assert!(matches!(result, Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
    }
    let mut parent = state();
    fund(&mut parent, key, 0, &[0x51], 0, false);
    let before = owned_state(&parent);
    for (inputs, expected) in [(vec![(key, &[][..], u32::MAX), (key, &[][..], u32::MAX)], SproutLedgerError::DuplicateTransparentInput),
        (vec![(([0; 32], u32::MAX), &[][..], u32::MAX)], SproutLedgerError::InvalidCoinbase)] {
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu5, 0, 0.into(), spend(&inputs, vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        let raw = encoded(&transaction);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), original_v5(&raw)], height, 1_700_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu5_claimed_burns_underclaims_fees_and_all_pool_totals_remain_distinct() {
    for (height, subsidy_value, miner) in [(1_842_420, 312_500_000, 250_000_000), (2_795_999, 312_500_000, 250_000_000), (2_796_000, 156_250_000, 156_250_000), (2_975_999, 156_250_000, 156_250_000)] {
        for (fee_claim, burn) in [(9, 1), (10, 1), (9, 0)] {
            let mut parent = state();
            let key = ([0xb8; 32], 0);
            fund(&mut parent, key, 100, &[0x51], 0, false);
            parent.shielded_balances[0] = 3;
            parent.shielded_balances[1] = 5;
            parent.shielded_balances[2] = 7;
            parent.shielded_balances[3] = 11;
            parent.deferred_balance = 13;
            parent.issued_supply += 39;
            let before = owned_state(&parent);
            let mut outputs = nu5_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
            outputs[0] = output(miner - 1 + fee_claim, &[0x51]);
            outputs.push(output(burn, &[0x6a]));
            let tx = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu5, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(90, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let raw = encoded(&tx);
            let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_with_outputs(height, TxVersion::V4, outputs))), original_v5(&raw)], height, 1_700_000_000).unwrap();
            let total = subsidy_value + 89 + fee_claim + burn;
            assert_eq!((delta.fees, delta.issued, delta.transparent, delta.retained), (10, total + 39, total.into(), (total - burn).into()));
            assert_eq!((delta.sprout, delta.sapling, delta.orchard), (3, 5, 7));
            assert_eq!(owned_state(&parent), before);
            parent.commit(delta);
            assert_eq!(parent.shielded_balances, [3, 5, 7, 11]);
            assert_eq!(parent.deferred_balance(), 13);
        }
        let parent = state();
        let mut outputs = nu5_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
        outputs[0] = output(miner + 1, &[0x51]);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_with_outputs(height, TxVersion::V4, outputs)))], height, 1_700_000_000), Err(SproutLedgerError::CoinbaseRewardExceeded)));
    }
    for overflowing_pool in 0..5 {
        let mut parent = state();
        if overflowing_pool < 4 { parent.shielded_balances[overflowing_pool] = MAX_MONEY; } else { parent.deferred_balance = MAX_MONEY; }
        parent.issued_supply = MAX_MONEY;
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&ORCHARD_COINBASE)], 1_842_420, 1_700_000_000), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = isolated_original_nu5_parent(include_bytes!("../tests/fixtures/orchard-pure-testnet-1842467.bin"));
    parent.shielded_balances[2] -= 1;
    parent.issued_supply -= 1;
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(1_842_420, TxVersion::V4, 1_842_420))), original_v5(include_bytes!("../tests/fixtures/orchard-pure-testnet-1842467.bin"))], 1_842_420, 1_700_000_000), Err(SproutLedgerError::ValueOutOfRange)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu5_v5_single_without_output_is_false_not_constant_one_or_strict_encoding_abort() {
    let key = ([0xb9; 32], 0);
    let (raw, prevouts) = independently_signed_v5(&[key], false, 3);
    let parsed = Transaction::read(raw.as_slice(), BranchId::Nu5).unwrap();
    let mut bundle = parsed.transparent_bundle().unwrap().clone();
    let lock = prevouts[0].script_pubkey().0.0.clone();
    let mut false_lock = lock.clone();
    false_lock.push(0x91); // CHECKSIG NOT accepts the checker false result.
    for (outputs, previous_script, accepted) in [(0, lock.clone(), false), (0, false_lock.clone(), true), (1, lock.clone(), true)] {
        bundle.vout.truncate(outputs);
        let source = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu5, 0, 0.into(), Some(bundle.clone()), None, None, None).freeze().unwrap();
        let mut bundle = source.transparent_bundle().unwrap().clone();
        if outputs == 1 { bundle.vout = parsed.transparent_bundle().unwrap().vout.clone(); }
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu5, 0, 0.into(), Some(bundle), None, None, None).freeze().unwrap();
        let raw = encoded(&tx);
        let context = RawV5::parse_exact(&raw).unwrap().into_signature_context(vec![output(100_002, &previous_script)]).unwrap();
        assert_eq!(verify_v5_transparent_input(&context, 0, &output(100_002, &previous_script)).is_ok(), accepted);
    }
    let mut invalid = parsed.transparent_bundle().unwrap().clone();
    let mut script = invalid.vin[0].script_sig().clone();
    let last = script.0.0.len() - 1;
    script.0.0[last] = 0;
    invalid.vin[0] = TxIn::from_parts(OutPoint::new(key.0, key.1), script, 123);
    let tx = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu5, 0, 0.into(), Some(invalid), None, None, None).freeze().unwrap();
    let raw = encoded(&tx);
    let context = RawV5::parse_exact(&raw).unwrap().into_signature_context(vec![output(100_002, &false_lock)]).unwrap();
    assert_eq!(verify_v5_transparent_input(&context, 0, &output(100_002, &false_lock)), Ok(()));
}

#[test]
fn nu5_shielded_source_sink_cardinality_two_megabytes_sigops_and_bip30_are_not_skipped() {
    let height = 1_842_420;
    let key = ([0xba; 32], 0);
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    for (spends, outputs) in [(65_536, 0), (0, 65_536)] {
        let transaction = v4(&modified_sapling(vec![bundle.shielded_spends()[0].clone(); spends], vec![bundle.shielded_outputs()[0].clone(); outputs], 0,
            spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned()), BranchId::Nu5, 0);
        assert_eq!(check_transaction(&transaction, height, 1_700_000_000).map(|_| ()), Err(SproutLedgerError::InvalidTransaction));
    }
    for (spends, outputs, vin, vout, accepted) in [(false, false, true, true, true), (false, true, false, false, false), (true, false, false, false, false), (true, true, false, false, true), (false, true, true, false, true), (true, false, false, true, true)] {
        let mut transparent = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().unwrap().clone();
        if !vin { transparent.vin.clear(); }
        if !vout { transparent.vout.clear(); }
        let transaction = v4(&modified_sapling(if spends { bundle.shielded_spends().to_vec() } else { vec![] }, if outputs { bundle.shielded_outputs().to_vec() } else { vec![] }, 0, Some(transparent)), BranchId::Nu5, 0);
        assert_eq!(check_transaction(&transaction, height, 1_700_000_000).is_ok(), accepted);
    }
    for (length, accepted) in [(1_999_917, true), (1_999_918, false)] {
        let tx = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0; length])], 0), BranchId::Nu5, 0);
        assert_eq!(check_transaction(&tx, height, 1_700_000_000).is_ok(), accepted);
    }
    for (count, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let before = owned_state(&parent);
        let mut outputs = nu5_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
        outputs[0] = output(250_000_000, &[0xac]);
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu5, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; count])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        let raw = encoded(&tx);
        let result = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_with_outputs(height, TxVersion::V4, outputs))), original_v5(&raw)], height, 1_700_000_000);
        if accepted { assert_eq!(result.unwrap().sigops, 20_000); } else { assert!(matches!(result, Err(SproutLedgerError::TooManySigops))); }
        assert_eq!(owned_state(&parent), before);
    }
    let transaction = nu5_coinbase(height, TxVersion::V5, height);
    let raw = encoded(&transaction);
    let id = RawV5::parse_exact(&raw).unwrap().effect_id();
    let mut parent = state();
    fund(&mut parent, (id, 999), 1, &[0x51], 0, false);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&raw)], height, 1_700_000_000), Err(SproutLedgerError::UnspentTransactionOverwrite)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu5_v4_joinsplit_deposits_stay_disabled_and_zip215_still_checks_real_groth() {
    let height = 1_842_420;
    let original = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Nu5).unwrap();
    assert_eq!(check_transaction(&v4(&original, BranchId::Nu5, 0), height, 1_700_000_000).map(|_| ()), Err(SproutLedgerError::SproutDepositDisabled));
    for new in [0_u64, 10_000] {
        let mut sprout = original.sprout_bundle().unwrap().clone();
        let mut raw = Vec::new();
        sprout.joinsplits[0].write(&mut raw).unwrap();
        raw[..8].fill(0);
        raw[8..16].copy_from_slice(&new.to_le_bytes());
        sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap();
        sprout.joinsplit_pubkey = [0; 32];
        sprout.joinsplit_sig = [0; 64];
        sprout.joinsplit_sig[0] = 1;
        let mut parent = state();
        parent.sprout_anchors.insert(*sprout.joinsplits[0].anchor(), Frontier::empty());
        parent.shielded_balances[0] = new;
        parent.issued_supply = new;
        let before = owned_state(&parent);
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu5, 0, 0.into(), None, Some(sprout), None, None).freeze().unwrap();
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(transaction))], height, 1_700_000_000), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof }))));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu5_mixed_sapling_every_spend_proof_auth_and_binding_are_actual_before_commit() {
    let original = include_bytes!("../tests/fixtures/nu5-mixed-testnet-1842421.bin");
    let transaction = RawV5::parse_exact(original).unwrap();
    let sapling = transaction.sapling_bundle().unwrap();
    assert!(transaction.transparent_bundle().is_none());
    let spends = sapling.shielded_spends().len();
    let outputs = sapling.shielded_outputs().len();
    assert_eq!(spends, 4);
    assert!(spends < 253 && outputs < 253);
    let anchor = 24 + spends * 96 + outputs * 756 + 8;
    let spend_proofs = anchor + 32;
    let spend_sigs = spend_proofs + spends * 192;
    let output_proofs = spend_sigs + spends * 64;
    let binding = output_proofs + outputs * 192;
    let mut mutations = Vec::new();
    for index in 0..spends {
        mutations.push((spend_proofs + index * 192, SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index }), 0x20));
        mutations.push((spend_sigs + index * 64 + 63, SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index }), 1));
    }
    for index in 0..outputs { mutations.push((output_proofs + index * 192, SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index }), 0x20)); }
    mutations.push((binding + 63, SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature), 1));
    for (offset, expected, mask) in mutations {
        let mut changed = original.to_vec();
        changed[offset] ^= mask;
        let mut parent = isolated_original_nu5_parent(original);
        let key = ([0xbb; 32], 0);
        fund(&mut parent, key, 20, &[0x51], 0, false);
        let good = v4(&spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Nu5, 0);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(1_842_420, TxVersion::V4, 1_842_420))), PostNu5Transaction::V4(Box::new(good)), original_v5(&changed)], 1_842_420, 1_700_000_000), Err(actual) if actual == expected), "offset {offset}");
        assert_eq!(owned_state(&parent), before);
    }
    let nf = sapling.shielded_spends()[0].nullifier().0;
    let mut parent = isolated_original_nu5_parent(original);
    parent.nullifiers[1].insert(nf);
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(1_842_420, TxVersion::V4, 1_842_420))), original_v5(original)], 1_842_420, 1_700_000_000), Err(SproutLedgerError::SpentSaplingNullifier)));
    assert_eq!(owned_state(&parent), before);
    let mut parent = isolated_original_nu5_parent(original);
    parent.sapling_anchors.remove(&sapling.shielded_spends()[0].anchor().to_bytes());
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(1_842_420, TxVersion::V4, 1_842_420))), original_v5(original)], 1_842_420, 1_700_000_000), Err(SproutLedgerError::UnknownSaplingAnchor)));
    assert_eq!(owned_state(&parent), before);
    let parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let old = v4(&recorded_sapling(), BranchId::Nu5, 0);
    // The real old fixed-key proof still verifies, but the actual current-branch
    // ZIP243 SpendAuth signature must fail, with no previous-branch fallback.
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu5_coinbase(1_842_420, TxVersion::V4, 1_842_420))), PostNu5Transaction::V4(Box::new(old))], 1_842_420, 1_700_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu5_coinbase_sapling_recovery_survives_both_wire_formats_but_never_skips_binding() {
    let original = primary_canopy_coinbase(1_101_629);
    let bundle = original.sapling_bundle().unwrap();
    for height in [1_842_420, 2_121_199, 2_121_200, 2_975_999] {
        let value = recover_sapling_coinbase_output(&bundle.shielded_outputs()[0], height).unwrap();
        assert_eq!(value, 500_000_000);
        for version in [TxVersion::V4, TxVersion::V5] {
            let reward = nu5_coinbase(height, version, height);
            let transaction = TransactionData::<Authorized>::from_parts(version, BranchId::Nu5, 0, height.into(), reward.transparent_bundle().cloned(), None, Some(bundle.clone()), None).freeze().unwrap();
            let parent = state();
            let before = owned_state(&parent);
            let result = if version == TxVersion::V4 { parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(transaction))], height, 1_700_000_000) }
                else { let raw = encoded(&transaction); parent.stage_post_nu5_block(vec![original_v5(&raw)], height, 1_700_000_000) };
            assert!(matches!(result, Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature))));
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn post_nu5_aggregate_money_sides_never_cancel_signed_sapling_and_orchard_balances() {
    let original = include_bytes!("../tests/fixtures/nu5-mixed-testnet-1842421.bin");
    let parsed = RawV5::parse_exact(original).unwrap();
    let sapling = parsed.sapling_bundle().unwrap();
    assert_eq!(sapling.shielded_outputs().len(), 0);
    let sapling_balance = 24 + sapling.shielded_spends().len() * 96;
    let orchard = parsed.orchard().unwrap();
    let orchard_balance = orchard.actions().as_ptr() as usize - original.as_ptr() as usize + orchard.action_count() * 820 + 1;
    for (sapling_value, orchard_value, accepted) in [
        (MAX_MONEY as i64, MAX_MONEY as i64, false),
        (-(MAX_MONEY as i64), -(MAX_MONEY as i64), false),
        (MAX_MONEY as i64, -(MAX_MONEY as i64), true),
        (-(MAX_MONEY as i64), MAX_MONEY as i64, true),
    ] {
        for (branch, height) in [(BranchId::Nu5, 1_842_420_u32), (BranchId::Nu6, 2_976_000)] {
            let mut changed = original.to_vec();
            // Monetary shape ONLY; copied NU5 authorizations do not sign NU6.
            changed[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
            changed[16..20].copy_from_slice(&height.to_le_bytes());
            changed[sapling_balance..sapling_balance + 8].copy_from_slice(&sapling_value.to_le_bytes());
            changed[orchard_balance..orchard_balance + 8].copy_from_slice(&orchard_value.to_le_bytes());
            let raw = RawV5::parse_exact(&changed).unwrap();
            assert_eq!(u32::from(raw.expiry_height()), height);
            assert_eq!(check_v5_transaction(&raw, height, 1_700_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::ValueOutOfRange) });
        }
    }
}

#[test]
fn nu6_activation_requires_real_deferred_issuance_and_exact_coinbase_claim() {
    let height = 2_976_000;
    let total = subsidy(height).unwrap();
    assert_eq!(total, 156_250_000);
    let fpf = bytes("a9147a86d6c7eb12ce0aa309d7391a6f338eba3c242b87");
    let source = nu5_coinbase(2_975_999, TxVersion::V4, 2_975_999);
    let mut transparent = source.transparent_bundle().unwrap().clone();
    let (prefix, len) = coinbase_height_prefix(height);
    let mut script = Script::default();
    script.0.0.extend_from_slice(&prefix[..len]);
    script.0.0.push(0);
    transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
    transparent.vout = vec![output(125_000_000, &[0x51]), output(12_500_000, &fpf)];
    let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6,
        0, height.into(), Some(transparent), None, None, None).freeze().unwrap();
    let parent = state();
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(transaction))],
        height, 1_800_000_000).unwrap();
    assert_eq!(delta.issued, total);
    assert_eq!(delta.transparent, 137_500_000);
    assert_eq!(delta.deferred, 18_750_000);
    assert_eq!(parent.deferred_balance(), 0);
    let mut parent = parent;
    parent.commit(delta);
    assert_eq!(parent.deferred_balance(), 18_750_000);
    assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
}

const NU6_FPF_SCRIPT: &str = "a9147a86d6c7eb12ce0aa309d7391a6f338eba3c242b87";

fn nu6_coinbase(height: u32, version: TxVersion, expiry: u32) -> Transaction {
    let mut transparent = nu5_coinbase(2_975_999, TxVersion::V4, 2_975_999).transparent_bundle().unwrap().clone();
    let (prefix, length) = coinbase_height_prefix(height);
    let mut script = Script::default();
    script.0.0.extend_from_slice(&prefix[..length]);
    script.0.0.push(0);
    transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
    transparent.vout = if height < 3_396_000 {
        vec![output(125_000_000, &[0x51]), output(12_500_000, &bytes(NU6_FPF_SCRIPT))]
    } else {
        vec![output(156_250_000, &[0x51])]
    };
    TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, expiry.into(), Some(transparent), None, None, None).freeze().unwrap()
}

fn nu6_with_outputs(height: u32, version: TxVersion, outputs: Vec<TxOut>) -> Transaction {
    let mut transparent = nu6_coinbase(height, version, height).transparent_bundle().unwrap().clone();
    transparent.vout = outputs;
    TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap()
}

fn stage_nu6_transactions(parent: &SproutTestnetLedger, transactions: &[Transaction], height: u32) -> Result<BlockDelta, SproutLedgerError> {
    let bytes: Vec<_> = transactions.iter().map(encoded).collect();
    let parsed = transactions.iter().zip(&bytes).map(|(transaction, raw)| {
        if transaction.version() == TxVersion::V5 {
            original_v5(raw)
        } else {
            let mut reader = raw.as_slice();
            let parsed = Transaction::read(&mut reader, transaction.consensus_branch_id()).unwrap();
            assert!(reader.is_empty());
            assert_eq!(encoded(&parsed), *raw);
            if transaction.version() == TxVersion::V6 { PostNu5Transaction::V6(Box::new(parsed)) }
            else { PostNu5Transaction::V4(Box::new(parsed)) }
        }
    }).collect();
    parent.stage_post_nu5_block(parsed, height, 1_800_000_000)
}

#[test]
fn nu6_exact_claim_and_individual_fpf_output_cover_every_stream_edge_in_both_formats() {
    // All thirteen source recipient periods use the SAME literal beneficiary.
    for height in [2_976_000, 2_976_001, 3_005_999, 3_006_000, 3_040_999, 3_041_000,
        3_075_999, 3_076_000, 3_110_999, 3_111_000, 3_145_999, 3_146_000,
        3_180_999, 3_181_000, 3_215_999, 3_216_000, 3_250_999, 3_251_000,
        3_285_999, 3_286_000, 3_320_999, 3_321_000, 3_355_999, 3_356_000,
        3_390_999, 3_391_000, 3_395_999, 3_396_000, 3_396_001, 3_536_499] {
        for version in [TxVersion::V4, TxVersion::V5] {
            let mut parent = state();
            parent.deferred_balance = 13;
            parent.issued_supply = 13;
            let before = owned_state(&parent);
            let reward = nu6_coinbase(height, version, height);
            let delta = stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height).unwrap();
            let deferred = if height < 3_396_000 { 18_750_013 } else { 13 };
            let claim = if height < 3_396_000 { 137_500_000 } else { 156_250_000 };
            assert_eq!((delta.issued, delta.transparent, delta.deferred), (156_250_013, claim, deferred));
            assert_eq!(owned_state(&parent), before);
            for change in [-1_i64, 1] {
                let mut outputs = reward.transparent_bundle().unwrap().vout.clone();
                outputs[0] = output((u64::from(outputs[0].value()) as i64 + change) as u64, &[0x51]);
                assert!(matches!(stage_nu6_transactions(&parent, &[nu6_with_outputs(height, version, outputs)], height), Err(SproutLedgerError::CoinbaseRewardExceeded)));
                assert_eq!(owned_state(&parent), before);
            }
            if height < 3_396_000 {
                for mutation in 0..5 {
                    let mut outputs = reward.transparent_bundle().unwrap().vout.clone();
                    match mutation {
                        0 => { outputs.remove(1); }
                        1 => outputs[1] = output(12_500_001, &bytes(NU6_FPF_SCRIPT)),
                        2 => outputs[1] = output(12_499_999, &bytes(NU6_FPF_SCRIPT)),
                        3 => outputs[1] = output(12_500_000, &[0x51]),
                        4 => {
                            outputs[1] = output(12_499_999, &bytes(NU6_FPF_SCRIPT));
                            outputs.push(output(1, &bytes(NU6_FPF_SCRIPT)));
                        }
                        _ => unreachable!(),
                    }
                    assert!(matches!(stage_nu6_transactions(&parent, &[nu6_with_outputs(height, version, outputs)], height), Err(SproutLedgerError::MissingFundingStream { index: 0 })));
                    assert_eq!(owned_state(&parent), before);
                }
            }
            parent.commit(delta);
            assert_eq!(parent.deferred_balance(), deferred as u64);
            assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
        }
    }
}

#[test]
fn nu6_full_stream_schedule_accumulates_actual_deferred_deltas_then_freezes_without_backfill() {
    // Source schedule count, NOT mined blocks, archive replay, or predecessor authority.
    let mut parent = state();
    // Every stream height has this identical checked coinbase structure/value;
    // count the actual finalized scheduled deltas without rehashing it420000 times.
    let values = check_coinbase(&nu6_coinbase(2_976_000, TxVersion::V4, 2_976_000), 2_976_000, 1_800_000_000).unwrap();
    for height in 2_976_000..3_396_000 {
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = values.transparent.into();
        delta.retained = values.retained.into();
        delta.deferred = deferred_subsidy(height).into();
        let delta = parent.finish_delta(delta, values, height).unwrap();
        parent.commit(delta);
    }
    assert_eq!(parent.deferred_balance(), 7_875_000_000_000);
    assert_eq!(parent.transparent_balance(), 57_750_000_000_000);
    assert_eq!(parent.issued_supply(), 65_625_000_000_000);
    for height in [3_396_000, 3_396_001, 3_536_499] {
        let delta = stage_nu6_transactions(&parent, &[nu6_coinbase(height, TxVersion::V5, height)], height).unwrap();
        assert_eq!(delta.deferred, 7_875_000_000_000);
        assert_eq!(delta.issued, parent.issued_supply() + 156_250_000);
        parent.commit(delta);
    }
    let before = owned_state(&parent);
    assert!(matches!(stage_nu6_transactions(&parent, &[nu6_coinbase(3_536_500, TxVersion::V4, 3_536_500)], 3_536_500), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);

    let mut parent = state();
    let old = nu5_with_outputs(2_975_999, TxVersion::V4, vec![output(1, &[0x51])]);
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(old))], 2_975_999, 1_800_000_000).unwrap();
    parent.commit(delta);
    let delta = stage_nu6_transactions(&parent, &[nu6_coinbase(2_976_000, TxVersion::V4, 2_976_000)], 2_976_000).unwrap();
    parent.commit(delta);
    assert_eq!((parent.issued_supply(), parent.deferred_balance()), (156_250_001, 18_750_000));
}

#[test]
fn nu6_finalization_checks_signed_deferred_exact_claim_issuance_and_every_pool_atomically() {
    let height = 2_976_000;
    let reward = nu6_coinbase(height, TxVersion::V4, height);
    let values = check_coinbase(&reward, height, 1_800_000_000).unwrap();
    for (deferred, expected) in [(18_749_999, SproutLedgerError::CoinbaseRewardExceeded), (18_750_001, SproutLedgerError::CoinbaseRewardExceeded), (-1, SproutLedgerError::CoinbaseRewardExceeded)] {
        let parent = state();
        let before = owned_state(&parent);
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = values.transparent.into();
        delta.retained = values.retained.into();
        delta.deferred = deferred;
        assert!(matches!(parent.finish_delta(delta, values, height), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
    for pool in 0..6 {
        let mut parent = state();
        if pool == 0 { parent.transparent_balance = MAX_MONEY; }
        else if pool < 5 { parent.shielded_balances[pool - 1] = MAX_MONEY; }
        else { parent.deferred_balance = MAX_MONEY; }
        parent.issued_supply = MAX_MONEY;
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
    // GetValueOut does NOT subtract a positive shielded balance. Its exact
    // reward predicate and the separate signed-pool conservation must both run.
    let parent = state();
    let mut delta = BlockDelta::new(&parent);
    delta.transparent = 156_250_000;
    delta.sapling = -18_750_000;
    delta.deferred = 18_750_000;
    let wrong = CoinbaseValues { claimed: 156_250_000, transparent: 156_250_000, sapling_balance: 18_750_000, orchard_balance: 0, ironwood_balance: 0, retained: 0, sigops: 0 };
    assert!(matches!(parent.finish_delta(delta, wrong, height), Err(SproutLedgerError::CoinbaseRewardExceeded)));
}

#[test]
fn nu6_interleaved_independently_signed_v4_v5_preserve_every_prevout_and_branch_authorization() {
    let height = 2_976_000;
    let keys = [([0xc2; 32], 3), ([0xc3; 32], 7)];
    for p2sh in [false, true] {
        for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
            let (v4_tx, v4_prevout) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu6, p2sh, hash_type);
            let (v5_raw, prevouts) = independently_signed_v5_for_branch(&keys, BranchId::Nu6, p2sh, hash_type);
            let mut parent = state();
            fund(&mut parent, ([0xa1; 32], 3), 100_002, &v4_prevout.script_pubkey().0.0, 0, false);
            for (key, prevout) in keys.iter().zip(&prevouts) {
                fund(&mut parent, *key, u64::from(prevout.value()), &prevout.script_pubkey().0.0, 0, false);
            }
            parent.deferred_balance = 13;
            parent.issued_supply += 13;
            let before = owned_state(&parent);
            let mut outputs = nu6_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
            outputs[0] = output(125_000_007, &[0x51]);
            let reward = nu6_with_outputs(height, TxVersion::V4, outputs);
            let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(v4_tx.clone())), original_v5(&v5_raw)], height, 1_800_000_000).unwrap();
            assert_eq!((delta.fees, delta.deferred, delta.issued), (7, 18_750_013, 156_550_020));
            assert_eq!(owned_state(&parent), before);
            for index in 0..keys.len() {
                for change_script in [false, true] {
                    let mut bad = state();
                    fund(&mut bad, ([0xa1; 32], 3), 100_002, &v4_prevout.script_pubkey().0.0, 0, false);
                    for (number, (key, prevout)) in keys.iter().zip(&prevouts).enumerate() {
                        let mut script = prevout.script_pubkey().0.0.clone();
                        if number == index && change_script { if p2sh { script[2] ^= 1; } else { script.insert(0, 0x61); } }
                        let amount = u64::from(prevout.value()) + u64::from(number == index && !change_script);
                        fund(&mut bad, *key, amount, &script, 0, false);
                    }
                    let before = owned_state(&bad);
                    assert!(matches!(bad.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(v4_tx.clone())), original_v5(&v5_raw)], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
                    assert_eq!(owned_state(&bad), before);
                }
            }
            // Old authorizations are not made valid by current candidate context.
            let (old_v4, _) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu5, p2sh, hash_type);
            let relabeled = v4(&old_v4, BranchId::Nu6, 0);
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(relabeled))], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
            let (old_v5, _) = independently_signed_v5(&keys, p2sh, hash_type);
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&old_v5)], height, 1_800_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
            let mut relabeled = old_v5;
            relabeled[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward)), original_v5(&relabeled)], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
            assert_eq!(owned_state(&parent), before);
            parent.commit(delta);
            assert!(parent.utxo(&[0xa1; 32], 3).is_none());
            for key in keys { assert!(parent.utxo(&key.0, key.1).is_none()); }
            assert_eq!(parent.deferred_balance(), 18_750_013);
        }
    }
}

#[test]
fn nu6_exact_actual_fee_claim_and_pruned_burns_conserve_all_pools_without_backfilling() {
    for (height, miner, deferred) in [(2_976_000, 125_000_000, 18_750_013), (3_395_999, 125_000_000, 18_750_013), (3_396_000, 156_250_000, 13), (3_536_499, 156_250_000, 13)] {
        for version in [TxVersion::V4, TxVersion::V5] {
            let mut parent = state();
            let key = ([0xc4; 32], 0);
            fund(&mut parent, key, 100, &[0x51], 0, false);
            parent.shielded_balances = [3, 5, 7, 11];
            parent.deferred_balance = 13;
            parent.issued_supply += 39;
            let before = owned_state(&parent);
            let fee_tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(90, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            for claim in [9, 10, 11] {
                let mut outputs = nu6_coinbase(height, version, height).transparent_bundle().unwrap().vout.clone();
                outputs[0] = output(miner - 1 + claim, &[0x51]);
                outputs.push(output(1, &[0x6a]));
                let result = stage_nu6_transactions(&parent, &[nu6_with_outputs(height, version, outputs), fee_tx.clone()], height);
                if claim == 10 {
                    let delta = result.unwrap();
                    let transparent = if height < 3_396_000 { 137_500_100 } else { 156_250_100 };
                    assert_eq!((delta.fees, delta.issued, delta.transparent, delta.retained, delta.deferred), (10, 156_250_139, transparent, transparent - 1, deferred));
                    assert_eq!((delta.sprout, delta.sapling, delta.orchard), (3, 5, 7));
                    assert_eq!(owned_state(&parent), before);
                } else {
                    assert!(matches!(result, Err(SproutLedgerError::CoinbaseRewardExceeded)));
                    assert_eq!(owned_state(&parent), before);
                }
            }
            let mut outputs = nu6_coinbase(height, version, height).transparent_bundle().unwrap().vout.clone();
            outputs[0] = output(miner + 9, &[0x51]);
            outputs.push(output(1, &[0x6a]));
            let delta = stage_nu6_transactions(&parent, &[nu6_with_outputs(height, version, outputs), fee_tx], height).unwrap();
            parent.commit(delta);
            assert_eq!(parent.shielded_balances, [3, 5, 7, 11]);
            assert_eq!(parent.deferred_balance(), deferred as u64);
            assert_eq!(parent.transparent_balance() + parent.shielded_balances.iter().sum::<u64>() + parent.deferred_balance(), parent.issued_supply());
            assert_eq!(parent.utxo_balance() + 1, parent.transparent_balance());
        }
    }
}

#[test]
fn nu6_ordered_v4_v5_spends_resolve_earlier_outputs_and_reject_future_duplicate_or_negative_fee() {
    let height = 2_976_000;
    let key = ([0xc5; 32], 0);
    let (_, prevouts) = independently_signed_v5_for_branch(&[([0; 32], 0), ([1; 32], 1)], BranchId::Nu6, true, 1);
    let first = v4(&spend(&[(key, &[], u32::MAX)], prevouts.clone(), 0), BranchId::Nu6, 0);
    let first_id: [u8; 32] = first.txid().into();
    let (second, _) = independently_signed_v5_for_branch(&[(first_id, 0), (first_id, 1)], BranchId::Nu6, true, 1);
    let second_id = RawV5::parse_exact(&second).unwrap().effect_id();
    let third = v4(&spend(&[((second_id, 0), &[], u32::MAX), ((second_id, 1), &[], u32::MAX)], vec![output(199_999, &[0x51])], 0), BranchId::Nu6, 0);
    let mut parent = state();
    fund(&mut parent, key, 200_010, &[0x51], 0, false);
    let before = owned_state(&parent);
    let mut outputs = nu6_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
    outputs[0] = output(125_000_011, &[0x51]);
    let reward = nu6_with_outputs(height, TxVersion::V4, outputs);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&second), PostNu5Transaction::V4(Box::new(first.clone()))], height, 1_800_000_000), Err(SproutLedgerError::MissingTransparentInput)));
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(first.clone())), original_v5(&second), original_v5(&second)], height, 1_800_000_000), Err(SproutLedgerError::MissingTransparentInput)));
    let negative = v4(&spend(&[(key, &[], u32::MAX)], vec![output(200_011, &[0x51])], 0), BranchId::Nu6, 0);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(negative))], height, 1_800_000_000), Err(SproutLedgerError::NegativeFee)));
    assert_eq!(owned_state(&parent), before);
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward)), PostNu5Transaction::V4(Box::new(first)), original_v5(&second), PostNu5Transaction::V4(Box::new(third))], height, 1_800_000_000).unwrap();
    assert_eq!(delta.fees, 11);
    parent.commit(delta);
    for (id, index) in [(key.0, key.1), (first_id, 0), (first_id, 1), (second_id, 0), (second_id, 1)] { assert!(parent.utxo(&id, index).is_none()); }
}

#[test]
fn nu6_coinbase_generation_branch_expiry_finality_and_maturity_keep_full_parent_state() {
    let height = 2_976_000;
    let key = ([0xc6; 32], 0);
    for version in [TxVersion::V4, TxVersion::V5] {
        for expiry in [0, height - 1, height, height + 1, 499_999_999, 500_000_000] {
            let reward = nu6_coinbase(height, version, expiry);
            let parent = state();
            let before = owned_state(&parent);
            let result = stage_nu6_transactions(&parent, &[reward], height);
            if expiry == height { assert!(result.is_ok()); } else { assert!(matches!(result, Err(SproutLedgerError::InvalidCoinbase))); }
            assert_eq!(owned_state(&parent), before);
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, expiry.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let raw = encoded(&tx);
            let result = if version == TxVersion::V4 { check_transaction(&tx, height, 1_800_000_000).map(|_| ()) } else { check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), height, 1_800_000_000).map(|_| ()) };
            assert_eq!(result, if expiry >= 500_000_000 { Err(SproutLedgerError::InvalidTransaction) } else if expiry != 0 && expiry < height { Err(SproutLedgerError::ExpiredTransaction) } else { Ok(()) });
        }
        for (lock, sequence, accepted) in [(height - 1, 0, true), (height, 0, false), (height, u32::MAX, true), (1_799_999_999, 0, true), (1_800_000_000, 0, false)] {
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, lock, 0.into(), spend(&[(key, &[], sequence)], vec![output(0, &[0x51])], lock).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let raw = encoded(&tx);
            let result = if version == TxVersion::V4 { check_transaction(&tx, height, 1_800_000_000).map(|_| ()) } else { check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), height, 1_800_000_000).map(|_| ()) };
            assert_eq!(result, if accepted { Ok(()) } else { Err(SproutLedgerError::NonfinalTransaction) });
        }
        for (created, expected) in [(height - 100, SproutLedgerError::UnshieldedCoinbaseSpend), (height - 99, SproutLedgerError::ImmatureCoinbase)] {
            let mut parent = state();
            fund(&mut parent, key, 0, &[0x51], created, true);
            parent.deferred_balance = 13;
            parent.issued_supply += 13;
            let before = owned_state(&parent);
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[nu6_coinbase(height, version, height), tx], height), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
        let mut parent = state();
        parent.deferred_balance = 13;
        parent.issued_supply = 13;
        let before = owned_state(&parent);
        let source = nu6_coinbase(height + 1, version, height);
        assert!(matches!(stage_nu6_transactions(&parent, &[source], height), Err(SproutLedgerError::InvalidCoinbase)));
        assert_eq!(owned_state(&parent), before);
        let reward = nu6_coinbase(height, version, height);
        let id: [u8; 32] = reward.txid().into();
        fund(&mut parent, (id, 999), 1, &[0x51], 0, false);
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, &[reward], height), Err(SproutLedgerError::UnspentTransactionOverwrite)));
        assert_eq!(owned_state(&parent), before);
    }
}

fn post_nu5_structural_body(transactions: &[&[u8]], height: u32, parent_root: [u8; 32]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use zcash_encoding::CompactSize;
    // Reuse an actual header ONLY for its framing. Its altered Merkle/auth
    // fields invalidate PoW; this is never a mined/connected NU6 candidate.
    let mut raw = include_bytes!("../tests/fixtures/testnet-nu5-block-1842421.bin")[..HEADER_BYTES].to_vec();
    let mut nodes: Vec<[u8; 32]> = transactions.iter().map(|raw| {
        if raw[..4] == [5, 0, 0, 0x80] { RawV5::parse_exact(raw).unwrap().effect_id() }
        else if raw[..4] == [6, 0, 0, 0x80] { Transaction::read(*raw, BranchId::Nu6_3).unwrap().txid().into() }
        else { Sha256::digest(Sha256::digest(raw)).into() }
    }).collect();
    while nodes.len() > 1 {
        nodes = nodes.chunks(2).map(|pair| {
            let mut hash = Sha256::new();
            hash.update(pair[0]);
            hash.update(pair.get(1).unwrap_or(&pair[0]));
            Sha256::digest(hash.finalize()).into()
        }).collect();
    }
    raw[36..68].copy_from_slice(&nodes[0]);
    CompactSize::write(&mut raw, transactions.len()).unwrap();
    for transaction in transactions { raw.extend_from_slice(transaction); }
    let auth = PostNu5Block::parse(&raw, height).unwrap().auth_data_root();
    raw[68..100].copy_from_slice(&block_commitment(parent_root, auth));
    raw
}

#[test]
fn nu6_activation_authenticates_owned_nu5_parent_and_actual_full_auth_before_v2_reset() {
    use zcash_history::{V2, Version};
    let height = 2_976_000;
    let mut parent = state();
    parent.deferred_balance = 13;
    parent.issued_supply = 13;
    // Private isolated metadata, NOT a caller checkpoint or connected history.
    let last = post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0);
    let history = ChainHistoryV2::new(last.clone()).unwrap();
    parent.history_root = Some(history.root());
    parent.chain_history_v2 = Some(history);
    let body_bytes = post_nu5_structural_body(&[&NU6_ORCHARD_COINBASE, &NU6_ORCHARD_OUTPUTS_DISABLED], height, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&body_bytes, height).unwrap();
    let auth = body.auth_data_root();
    let commitment = body.header().final_sapling_root;
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
    assert_eq!((delta.deferred, delta.issued, delta.transparent, delta.orchard), (18_750_013, 156_250_013, 137_499_993, 7));
    let first = post_nu5_leaf(height, delta.sapling_root, delta.orchard_root, 0, 2);
    let history = parent.stage_post_nu5_history(&commitment, &auth, first.clone()).unwrap();
    assert_eq!((history.consensus_branch_id(), history.leaf_count(), history.last_height()), (u32::from(BranchId::Nu6), 1, height));
    assert_eq!(history.root(), V2::hash(&first));
    assert_ne!(history.root(), parent.history_root().unwrap());
    assert_eq!(owned_state(&parent), before);

    for (last_height, branch, expected) in [(height - 2, BranchId::Nu5, HistoryError::NonconsecutiveHeight), (height - 1, BranchId::Nu6, HistoryError::BranchMismatch)] {
        let mut bad = last.clone();
        bad.v1.start_height = last_height.into();
        bad.v1.end_height = last_height.into();
        bad.v1.consensus_branch_id = u32::from(branch);
        let mut wrong = state();
        let bad_history = ChainHistoryV2::new(bad).unwrap();
        wrong.history_root = Some(bad_history.root());
        wrong.chain_history_v2 = Some(bad_history);
        let before = owned_state(&wrong);
        assert_eq!(wrong.stage_post_nu5_history(&block_commitment(wrong.history_root().unwrap(), auth), &auth, first.clone()).unwrap_err(), SproutLedgerError::History(expected));
        assert_eq!(owned_state(&wrong), before);
    }
    let mut wrong = state();
    wrong.history_root = parent.history_root;
    let before = owned_state(&wrong);
    assert_eq!(wrong.stage_post_nu5_history(&commitment, &auth, first.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&wrong), before);
    parent.history_root = Some([0; 32]);
    let before = owned_state(&parent);
    assert_eq!(parent.stage_post_nu5_history(&commitment, &auth, first.clone()).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
    parent.history_root = parent.chain_history_v2.as_ref().map(ChainHistoryV2::root);
    parent.commit(delta);
    parent.history_root = Some(history.root());
    parent.chain_history_v2 = Some(history);
    let next_height = height + 1;
    let reward = encoded(&nu6_coinbase(next_height, TxVersion::V4, next_height));
    let next_bytes = post_nu5_structural_body(&[&reward], next_height, parent.history_root().unwrap());
    let next_body = PostNu5Block::parse(&next_bytes, next_height).unwrap();
    let next_auth = next_body.auth_data_root();
    let commitment = next_body.header().final_sapling_root;
    let before = owned_state(&parent);
    let next_delta = parent.stage_post_nu5_block(next_body.into_transactions(), next_height, 1_800_000_000).unwrap();
    let next = post_nu5_leaf(next_height, next_delta.sapling_root, next_delta.orchard_root, 0, 0);
    let appended = parent.stage_post_nu5_history(&commitment, &next_auth, next.clone()).unwrap();
    assert_eq!(appended.root(), V2::hash(&V2::combine(&first, &next)));
    assert_eq!(appended.leaf_count(), 2);
    assert_eq!(owned_state(&parent), before);
    let old_history = ChainHistoryV2::new(post_nu5_leaf(2_975_999, next_delta.sapling_root, next_delta.orchard_root, 0, 0)).unwrap();
    parent.history_root = Some(old_history.root());
    parent.chain_history_v2 = Some(old_history);
    let before = owned_state(&parent);
    assert_eq!(parent.stage_post_nu5_history(&block_commitment(parent.history_root().unwrap(), next_auth), &next_auth, next).unwrap_err(), SproutLedgerError::History(HistoryError::BranchMismatch));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu6_original_halo2_suffix_remains_valid_but_full_auth_header_commitment_rejects_it_atomically() {
    let height = 2_976_000;
    let mut parent = state();
    let last = post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0);
    let history = ChainHistoryV2::new(last).unwrap();
    parent.history_root = Some(history.root());
    parent.chain_history_v2 = Some(history);
    let original = RawV5::parse_exact(&NU6_ORCHARD_COINBASE).unwrap();
    let orchard = original.orchard().unwrap();
    let proof = orchard.proof().as_ptr() as usize - NU6_ORCHARD_COINBASE.as_ptr() as usize;
    let signatures = orchard.spend_auth_signatures().as_ptr() as usize - NU6_ORCHARD_COINBASE.as_ptr() as usize;
    assert_eq!(NU6_ORCHARD_COINBASE[proof - 3], 0xfd);
    let mut padded = NU6_ORCHARD_COINBASE.to_vec();
    let length = u16::try_from(orchard.proof().len() + 1).unwrap();
    padded[proof - 2..proof].copy_from_slice(&length.to_le_bytes());
    padded.insert(signatures, 0x42);
    let changed = RawV5::parse_exact(&padded).unwrap();
    assert_eq!(changed.effect_id(), original.effect_id());
    assert_ne!(changed.auth_digest(), original.auth_digest());
    let before = owned_state(&parent);
    let old_bytes = post_nu5_structural_body(&[&NU6_ORCHARD_COINBASE], height, parent.history_root().unwrap());
    let old_body = PostNu5Block::parse(&old_bytes, height).unwrap();
    let commitment = old_body.header().final_sapling_root;
    let mut changed_bytes = old_bytes[..HEADER_BYTES + 1].to_vec();
    changed_bytes.extend_from_slice(&padded);
    let body = PostNu5Block::parse(&changed_bytes, height).unwrap();
    assert_eq!(body.header().merkle_root, old_body.header().merkle_root);
    assert_ne!(body.auth_data_root(), old_body.auth_data_root());
    let auth = body.auth_data_root();
    // Actual original Halo2, both dummy SpendAuth and binding equations must
    // pass here. Only full authorizing-byte block authentication rejects it.
    let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
    let leaf = post_nu5_leaf(height, delta.sapling_root, delta.orchard_root, 0, 1);
    assert_eq!(parent.stage_post_nu5_history(&commitment, &auth, leaf.clone()).unwrap_err(), SproutLedgerError::Body(BodyError::BlockCommitmentMismatch));
    assert_eq!(owned_state(&parent), before);
    let accepted = parent.stage_post_nu5_history(&block_commitment(parent.history_root().unwrap(), auth), &auth, leaf).unwrap();
    assert_eq!(accepted.leaf_count(), 1);
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu6_history_failure_preserves_deferred_work_counts_height_cached_root_and_retry_rights() {
    let height = 2_976_001;
    let reward = encoded(&nu6_coinbase(height, TxVersion::V4, height));
    for failure in 0..6 {
        let mut parent = state();
        parent.deferred_balance = 18_750_000;
        parent.issued_supply = 18_750_000;
        let mut first = post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0);
        if failure == 0 { first.v1.subtree_total_work = primitive_types::U256::MAX; }
        if failure == 1 { first.v1.sapling_tx = u64::MAX; }
        if failure == 2 { first.orchard_tx = u64::MAX; }
        let history = ChainHistoryV2::new(first).unwrap();
        let root = history.root();
        parent.history_root = Some(root);
        parent.chain_history_v2 = Some(history);
        if failure == 4 { parent.history_root = Some([0; 32]); }
        let bytes = post_nu5_structural_body(&[&reward], height, root);
        let body = PostNu5Block::parse(&bytes, height).unwrap();
        let mut auth = body.auth_data_root();
        let commitment = body.header().final_sapling_root;
        if failure == 5 { auth[0] ^= 1; }
        let before = owned_state(&parent);
        let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
        assert_eq!(delta.deferred, 37_500_000);
        let leaf = post_nu5_leaf(height + u32::from(failure == 3), delta.sapling_root, delta.orchard_root, 1, 1);
        let expected = match failure {
            0 => SproutLedgerError::History(HistoryError::WorkOverflow),
            1 => SproutLedgerError::History(HistoryError::SaplingCountOverflow),
            2 => SproutLedgerError::History(HistoryError::OrchardCountOverflow),
            3 => SproutLedgerError::History(HistoryError::NonconsecutiveHeight),
            4 => SproutLedgerError::WrongHistoryRoot,
            5 => SproutLedgerError::Body(BodyError::BlockCommitmentMismatch),
            _ => unreachable!(),
        };
        assert_eq!(parent.stage_post_nu5_history(&commitment, &auth, leaf).unwrap_err(), expected);
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = state();
    parent.deferred_balance = 13;
    parent.issued_supply = 13;
    let before = owned_state(&parent);
    let bytes = post_nu5_structural_body(&[&encoded(&nu6_coinbase(2_976_000, TxVersion::V4, 2_976_000))], 2_976_000, [0; 32]);
    assert_eq!(parent.apply_block(&bytes), Err(SproutLedgerError::WrongHeight));
    assert_eq!(owned_state(&parent), before);
    let mut header = include_bytes!("../tests/fixtures/testnet-block-1.bin").to_vec();
    header[4] ^= 1;
    assert_eq!(parent.apply_block(&header), Err(SproutLedgerError::Header(HeaderError::WrongParent)));
    assert_eq!(owned_state(&parent), before);
    parent.issued_supply += 1;
    let before = owned_state(&parent);
    // The authentic first header stages successfully; only later pool
    // conservation fails. No header or deferred value may be half-published.
    assert_eq!(parent.apply_block(include_bytes!("../tests/fixtures/testnet-block-1.bin")), Err(SproutLedgerError::ValueOutOfRange));
    assert_eq!(owned_state(&parent), before);
    parent.issued_supply -= 1;
    parent.apply_block(include_bytes!("../tests/fixtures/testnet-block-1.bin")).unwrap();
    assert_eq!((parent.tip().height(), parent.deferred_balance()), (1, 13));
}

#[test]
fn nu6_original_orchard_crypto_consumes_all_leaves_nullifiers_signatures_and_deferred_value() {
    let height = 2_976_000;
    let mut parent = state();
    parent.deferred_balance = 13;
    parent.issued_supply = 13;
    let before = owned_state(&parent);
    let mut expected = incrementalmerkletree::frontier::CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for raw in [&NU6_ORCHARD_COINBASE, &NU6_ORCHARD_OUTPUTS_DISABLED] {
        let parsed = RawV5::parse_exact(raw).unwrap();
        assert_eq!(parsed.consensus_branch_id(), BranchId::Nu6);
        for action in parsed.orchard().unwrap().actions().as_chunks::<820>().0 {
            expected.append(MerkleHashOrchard::from_bytes(action[96..128].try_into().unwrap()).unwrap()).unwrap();
        }
    }
    let delta = parent.stage_post_nu5_block(vec![original_v5(&NU6_ORCHARD_COINBASE), original_v5(&NU6_ORCHARD_OUTPUTS_DISABLED)], height, 1_800_000_000).unwrap();
    assert_eq!((delta.issued, delta.transparent, delta.orchard, delta.deferred, delta.fees), (156_250_013, 137_499_993, 7, 18_750_013, 0));
    assert_eq!(delta.orchard_tree.tree_size(), 3);
    assert_eq!(delta.orchard_root, expected.root().to_bytes());
    assert_eq!(delta.orchard_nullifiers.len(), 3);
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.orchard_tree_size(), parent.shielded_balance(ShieldedPool::Orchard), parent.deferred_balance()), (3, 7, 18_750_013));
    assert_eq!(parent.nullifier_count(ShieldedPool::Orchard), 3);
    assert_eq!(parent.transparent_balance() + parent.shielded_balance(ShieldedPool::Orchard) + parent.deferred_balance(), parent.issued_supply());
    assert_eq!(parent.history_root(), before.history);
}

#[test]
fn nu6_orchard_recovery_proof_every_spendauth_binding_anchor_and_tree_failure_is_atomic() {
    let height = 2_976_000;
    let original = RawV5::parse_exact(&NU6_ORCHARD_COINBASE).unwrap();
    let orchard = original.orchard().unwrap();
    let actions = orchard.actions().as_ptr() as usize - NU6_ORCHARD_COINBASE.as_ptr() as usize;
    let proof = orchard.proof().as_ptr() as usize - NU6_ORCHARD_COINBASE.as_ptr() as usize;
    let signatures = orchard.spend_auth_signatures().as_ptr() as usize - NU6_ORCHARD_COINBASE.as_ptr() as usize;
    let binding = orchard.binding_signature().as_ptr() as usize - NU6_ORCHARD_COINBASE.as_ptr() as usize;
    for (offset, expected) in [(actions + 160, RawV5Error::CoinbaseRecovery { index: 0 }), (actions + 820 + 819, RawV5Error::CoinbaseRecovery { index: 1 }), (proof, RawV5Error::InvalidOrchardProof), (signatures + 63, RawV5Error::InvalidOrchardSpendAuth { index: 0 }), (signatures + 64 + 63, RawV5Error::InvalidOrchardSpendAuth { index: 1 }), (binding + 63, RawV5Error::InvalidOrchardBindingSignature)] {
        let mut changed = NU6_ORCHARD_COINBASE.to_vec();
        changed[offset] ^= 1;
        let mut parent = state();
        parent.deferred_balance = 13;
        parent.issued_supply = 13;
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(actual)) if actual == expected), "offset {offset}");
        assert_eq!(owned_state(&parent), before);
    }
    for action in orchard.actions().as_chunks::<820>().0 {
        let mut parent = state();
        parent.nullifiers[2].insert(action[32..64].try_into().unwrap());
        parent.deferred_balance = 13;
        parent.issued_supply = 13;
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU6_ORCHARD_COINBASE)], height, 1_800_000_000), Err(SproutLedgerError::SpentOrchardNullifier)));
        assert_eq!(owned_state(&parent), before);
    }
    for free_leaves in [0, 1] {
        let mut parent = state();
        let leaf = MerkleHashOrchard::from_bytes(orchard.actions()[96..128].try_into().unwrap()).unwrap();
        let position = (1_u64 << 32) - 1 - free_leaves;
        parent.orchard_tree = Frontier::from_parts(position.into(), leaf, vec![leaf; 32 - free_leaves as usize]).unwrap();
        parent.shielded_roots[2] = parent.orchard_tree.root().to_bytes();
        parent.orchard_anchors.insert(parent.shielded_roots[2]);
        parent.deferred_balance = 13;
        parent.issued_supply = 13;
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU6_ORCHARD_COINBASE)], height, 1_800_000_000), Err(SproutLedgerError::OrchardTreeFull)));
        assert_eq!(owned_state(&parent), before);
    }
    let parent = state();
    let before = owned_state(&parent);
    let mut delta = BlockDelta::new(&parent);
    parent.stage_orchard(Some(orchard), &mut delta).unwrap();
    let intermediate = delta.orchard_tree.root().to_bytes();
    let mut changed = NU6_ORCHARD_OUTPUTS_DISABLED.to_vec();
    let parsed = RawV5::parse_exact(&changed).unwrap();
    let bundle = parsed.orchard().unwrap();
    let anchor = bundle.actions().as_ptr() as usize - changed.as_ptr() as usize + bundle.action_count() * 820 + 9;
    changed[anchor..anchor + 32].copy_from_slice(&intermediate);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU6_ORCHARD_COINBASE), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::UnknownOrchardAnchor)));
    assert_eq!(owned_state(&parent), before);
    let mut duplicate = NU6_ORCHARD_COINBASE.to_vec();
    duplicate[actions + 820 + 32..actions + 820 + 64].copy_from_slice(&orchard.actions()[32..64]);
    let parsed = RawV5::parse_exact(&duplicate).unwrap();
    assert_eq!(parent.stage_orchard(parsed.orchard(), &mut BlockDelta::new(&parent)), Err(SproutLedgerError::SpentOrchardNullifier));
    assert_eq!(owned_state(&parent), before);
    let mut old = NU6_ORCHARD_OUTPUTS_DISABLED.to_vec();
    old[8..12].copy_from_slice(&u32::from(BranchId::Nu5).to_le_bytes());
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU6_ORCHARD_COINBASE), original_v5(&old)], height, 1_800_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu6_v4_sapling_recovery_and_original_proofs_never_replace_current_branch_authorization() {
    let height = 2_976_000;
    let original = primary_canopy_coinbase(1_101_629);
    let bundle = original.sapling_bundle().unwrap();
    for version in [TxVersion::V4, TxVersion::V5] {
        let reward = nu6_coinbase(height, version, height);
        let transaction = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, height.into(), reward.transparent_bundle().cloned(), None, Some(bundle.clone()), None).freeze().unwrap();
        let mut parent = state();
        parent.deferred_balance = 13;
        parent.issued_supply = 13;
        let before = owned_state(&parent);
        // Every genuine output recovers and its original fixed-key proof is
        // valid. Old binding signs a different branch/transaction and fails.
        assert!(matches!(stage_nu6_transactions(&parent, &[transaction], height), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature))));
        assert_eq!(owned_state(&parent), before);
        for (index, original) in bundle.shielded_outputs().iter().enumerate() {
            assert!(recover_sapling_coinbase_output(original, height).is_ok());
            for mutation in 0..2 {
                let mut outputs = bundle.shielded_outputs().to_vec();
                let mut enc = *original.enc_ciphertext();
                let mut proof = *original.zkproof();
                if mutation == 0 { enc[579] ^= 1; } else { proof[0] ^= 0x20; }
                outputs[index] = sapling_crypto::bundle::OutputDescription::from_parts(original.cv().clone(), *original.cmu(), original.ephemeral_key().clone(), enc, *original.out_ciphertext(), proof);
                let changed = sapling_crypto::Bundle::from_parts(vec![], outputs, *bundle.value_balance(), *bundle.authorization());
                let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, height.into(), reward.transparent_bundle().cloned(), None, changed, None).freeze().unwrap();
                let expected = if mutation == 0 { SproutLedgerError::CoinbaseRecovery { index, error: CoinbaseRecoveryError::NoteAuthentication } } else { SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index }) };
                assert!(matches!(stage_nu6_transactions(&parent, &[tx], height), Err(actual) if actual == expected));
                assert_eq!(owned_state(&parent), before);
            }
        }
    }
    let parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let old = v4(&recorded_sapling(), BranchId::Nu6, 0);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu6_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(old))], height, 1_800_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu6_v4_sprout_deposits_remain_disabled_and_zip215_reaches_every_actual_groth_proof() {
    let height = 2_976_000;
    let original = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Nu6).unwrap();
    assert_eq!(check_transaction(&v4(&original, BranchId::Nu6, 0), height, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::SproutDepositDisabled));
    for new in [0_u64, 10_000] {
        let mut sprout = original.sprout_bundle().unwrap().clone();
        let mut raw = Vec::new();
        sprout.joinsplits[0].write(&mut raw).unwrap();
        raw[..8].fill(0);
        raw[8..16].copy_from_slice(&new.to_le_bytes());
        sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap();
        sprout.joinsplit_pubkey = [0; 32];
        sprout.joinsplit_sig = [0; 64];
        sprout.joinsplit_sig[0] = 1;
        let mut parent = state();
        parent.sprout_anchors.insert(*sprout.joinsplits[0].anchor(), Frontier::empty());
        parent.shielded_balances[0] = new;
        parent.deferred_balance = 13;
        parent.issued_supply = new + 13;
        let before = owned_state(&parent);
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6, 0, 0.into(), None, Some(sprout), None, None).freeze().unwrap();
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu6_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(tx))], height, 1_800_000_000), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof }))));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu6_sapling_parent_anchors_global_nullifiers_every_leaf_and_capacity_remain_separate() {
    let height = 2_976_000;
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    let mut parent = isolated_sapling_parent();
    parent.deferred_balance = 13;
    parent.issued_supply += 13;
    let anchor = bundle.shielded_spends()[0].anchor().to_bytes();
    let nf = bundle.shielded_spends()[0].nullifier().0;
    let before = owned_state(&parent);
    let mut delta = BlockDelta::new(&parent);
    parent.stage_sapling(&source, &mut delta).unwrap();
    let mut expected = incrementalmerkletree::frontier::CommitmentTree::<SaplingNode, 32>::empty();
    for output in bundle.shielded_outputs() { expected.append(SaplingNode::from_cmu(output.cmu())).unwrap(); }
    assert_eq!(delta.sapling_tree.tree_size(), 2);
    assert_eq!(delta.sapling_tree.root().to_bytes(), expected.root().to_bytes());
    assert_eq!(parent.stage_sapling(&source, &mut delta), Err(SproutLedgerError::SpentSaplingNullifier));
    assert_eq!(owned_state(&parent), before);
    let current = delta.sapling_tree.root().to_bytes();
    let current_spend = sapling_spend(current, [0xcd; 32]);
    let tx = v4(&modified_sapling(vec![current_spend], bundle.shielded_outputs().to_vec(), 0, None), BranchId::Nu6, 0);
    assert_eq!(parent.stage_sapling(&tx, &mut delta), Err(SproutLedgerError::UnknownSaplingAnchor));
    assert_eq!(owned_state(&parent), before);
    for historical_spent in [false, true] {
        let mut bad = isolated_sapling_parent();
        bad.deferred_balance = 13;
        bad.issued_supply += 13;
        if historical_spent { bad.nullifiers[1].insert(nf); } else { bad.sapling_anchors.remove(&anchor); }
        let before = owned_state(&bad);
        let old = v4(&source, BranchId::Nu6, 0);
        let expected = if historical_spent { SproutLedgerError::SpentSaplingNullifier } else { SproutLedgerError::UnknownSaplingAnchor };
        assert!(matches!(bad.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu6_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(old))], height, 1_800_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&bad), before);
    }
    let leaf = SaplingNode::from_cmu(bundle.shielded_outputs()[0].cmu());
    parent.sapling_tree = Frontier::from_parts(((1_u64 << 32) - 2).into(), leaf, vec![leaf; 31]).unwrap();
    parent.shielded_roots[1] = parent.sapling_tree.root().to_bytes();
    parent.sapling_anchors.insert(parent.shielded_roots[1]);
    let before = owned_state(&parent);
    let tx = v4(&source, BranchId::Nu6, 0);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu6_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(tx))], height, 1_800_000_000), Err(SproutLedgerError::SaplingTreeFull)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu6_v4_cardinality_size_sigops_and_each_money_side_are_not_netted_or_waived() {
    let height = 2_976_000;
    let key = ([0xc7; 32], 0);
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    for (spends, outputs) in [(65_536, 0), (0, 65_536)] {
        let tx = v4(&modified_sapling(vec![bundle.shielded_spends()[0].clone(); spends], vec![bundle.shielded_outputs()[0].clone(); outputs], 0, spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned()), BranchId::Nu6, 0);
        assert_eq!(check_transaction(&tx, height, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::InvalidTransaction));
    }
    for (spends, outputs, vin, vout, accepted) in [(false, false, true, true, true), (false, true, false, false, false), (true, false, false, false, false), (true, true, false, false, true), (false, true, true, false, true), (true, false, false, true, true)] {
        let mut transparent = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().unwrap().clone();
        if !vin { transparent.vin.clear(); }
        if !vout { transparent.vout.clear(); }
        let tx = v4(&modified_sapling(if spends { bundle.shielded_spends().to_vec() } else { vec![] }, if outputs { bundle.shielded_outputs().to_vec() } else { vec![] }, 0, Some(transparent)), BranchId::Nu6, 0);
        assert_eq!(check_transaction(&tx, height, 1_800_000_000).is_ok(), accepted);
    }
    for (length, accepted) in [(1_999_917, true), (1_999_918, false)] {
        let tx = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0; length])], 0), BranchId::Nu6, 0);
        assert_eq!(check_transaction(&tx, height, 1_800_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::TransactionTooLarge) });
    }
    for (count, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = state();
        fund(&mut parent, key, 0, &[0x51], 0, false);
        parent.deferred_balance = 13;
        parent.issued_supply += 13;
        let before = owned_state(&parent);
        let mut outputs = nu6_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
        outputs[0] = output(125_000_000, &[0xac]);
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu6, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; count])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        let result = stage_nu6_transactions(&parent, &[nu6_with_outputs(height, TxVersion::V4, outputs), tx], height);
        if accepted { assert_eq!(result.unwrap().sigops, 20_000); } else { assert!(matches!(result, Err(SproutLedgerError::TooManySigops))); }
        assert_eq!(owned_state(&parent), before);
    }
    for balance in [-(MAX_MONEY as i64), MAX_MONEY as i64] {
        let mut parent = state();
        fund(&mut parent, key, 1, &[0x51], 0, false);
        let before = owned_state(&parent);
        let tx = v4(&modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), balance, spend(&[(key, &[], u32::MAX)], vec![output(1, &[0x51])], 0).transparent_bundle().cloned()), BranchId::Nu6, 0);
        // Each debit/credit side exceeds MAX before netting or actual equations.
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu6_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(tx))], height, 1_800_000_000), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu6_signed_pool_conservation_cannot_replace_negative_only_getvalueout_or_actual_deferred() {
    let height = 2_976_000;
    // Test the two distinct final monetary predicates directly; no plaintext,
    // mocked crypto or fabricated proof is asserted valid by these candidates.
    for pool in [ShieldedPool::Sapling, ShieldedPool::Orchard] {
        let mut parent = state();
        parent.shielded_balances[pool.index()] = 1;
        parent.issued_supply = 1;
        let before = owned_state(&parent);
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = 137_500_000;
        delta.retained = 137_500_000;
        delta.deferred = 18_750_000;
        if pool == ShieldedPool::Sapling { delta.sapling = -1; } else { delta.orchard = -1; }
        let values = CoinbaseValues { claimed: 137_500_000, transparent: 137_500_000, sapling_balance: i64::from(pool == ShieldedPool::Sapling), orchard_balance: i64::from(pool == ShieldedPool::Orchard), ironwood_balance: 0, retained: 137_500_000, sigops: 0 };
        // Exact original claim passes, but signed pools cannot silently lose1.
        assert!(matches!(parent.finish_delta(delta, values, height), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu6_no_deferred_recipient_or_disbursement_is_invented_before_nu61_activation() {
    let parent = state();
    for version in [TxVersion::V4, TxVersion::V5] {
        let height = 2_976_000;
        // Exact claim fails if a purported deferred recipient is added as a
        // separate reward rather than issued into the actual deferred pool.
        let mut outputs = nu6_coinbase(height, version, height).transparent_bundle().unwrap().vout.clone();
        outputs.push(output(18_750_000, &[0x51]));
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, &[nu6_with_outputs(height, version, outputs)], height), Err(SproutLedgerError::CoinbaseRewardExceeded)));
        assert_eq!(owned_state(&parent), before);
        let height = 3_396_000;
        // Old funding payments may be voluntary outputs after the stream ends,
        // but cannot add to the now-full miner subsidy or unfreeze deferred.
        let reward = nu6_with_outputs(height, version, vec![output(143_750_000, &[0x51]), output(12_500_000, &bytes(NU6_FPF_SCRIPT))]);
        let delta = stage_nu6_transactions(&parent, &[reward], height).unwrap();
        assert_eq!((delta.issued, delta.transparent, delta.deferred), (156_250_000, 156_250_000, 0));
        assert_eq!(owned_state(&parent), before);
        let cutoff = 3_536_500;
        let mut outputs = vec![output(125_000_000, &[0x51]), output(12_500_000, &bytes(NU6_FPF_SCRIPT))];
        for _ in 0..10 { outputs.push(output(787_500_000_000, &bytes("a914d2f1b436490d63fc078d8aed2d966bd3e40d79f087"))); }
        let tx = nu6_with_outputs(cutoff, version, outputs);
        assert!(matches!(stage_nu6_transactions(&parent, &[tx], cutoff), Err(SproutLedgerError::UnsupportedTransaction)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu6_coinbase_getvalueout_uses_actual_negative_balances_not_recovered_note_sum_or_positive_ban() {
    let height = 2_976_000;
    let original = RawV5::parse_exact(&NU6_ORCHARD_COINBASE).unwrap();
    let orchard = original.orchard().unwrap();
    let balance = orchard.actions().as_ptr() as usize - NU6_ORCHARD_COINBASE.as_ptr() as usize + orchard.action_count() * 820 + 1;
    for (value_balance, claimed) in [(-7_i64, 137_500_000), (0, 137_499_993), (7, 137_499_993)] {
        let mut changed = NU6_ORCHARD_COINBASE.to_vec();
        changed[balance..balance + 8].copy_from_slice(&value_balance.to_le_bytes());
        // The SAME zero-OVK ciphertexts still recover notes0+7. That recovered
        // sum may not replace raw GetValueOut or impose a new positive-VB ban.
        let values = check_post_nu5_coinbase(&original_v5(&changed), height, 1_800_000_000).unwrap();
        assert_eq!((values.claimed, values.transparent, values.orchard_balance), (claimed, 137_499_993, value_balance));
        let parent = state();
        let before = owned_state(&parent);
        if value_balance == -7 {
            let delta = parent.stage_post_nu5_block(vec![original_v5(&changed)], height, 1_800_000_000).unwrap();
            assert_eq!((delta.issued, delta.orchard, delta.deferred), (156_250_000, 7, 18_750_000));
        } else {
            assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(RawV5Error::InvalidOrchardSpendAuth { index: 0 }))));
        }
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu6_late_real_v4_sapling_proof_failure_preserves_prior_inputs_leaves_and_deferred_state() {
    let height = 2_976_000;
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    for field in 0..4 {
        let mut spends = bundle.shielded_spends().to_vec();
        let mut outputs = bundle.shielded_outputs().to_vec();
        let expected = if field == 0 {
            let spend = &spends[0];
            let mut proof = *spend.zkproof();
            proof[0] ^= 0x20;
            spends[0] = sapling_crypto::bundle::SpendDescription::from_parts(spend.cv().clone(), *spend.anchor(), *spend.nullifier(), *spend.rk(), proof, *spend.spend_auth_sig());
            SaplingCryptoError::InvalidSpendProof { index: 0 }
        } else if field == 1 {
            let spend = &spends[0];
            let mut signature = <[u8; 64]>::from(*spend.spend_auth_sig());
            signature[63] ^= 1;
            spends[0] = sapling_crypto::bundle::SpendDescription::from_parts(spend.cv().clone(), *spend.anchor(), *spend.nullifier(), *spend.rk(), *spend.zkproof(), signature.into());
            SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }
        } else {
            let index = field - 2;
            let output = &outputs[index];
            let mut proof = *output.zkproof();
            proof[0] ^= 0x20;
            outputs[index] = sapling_crypto::bundle::OutputDescription::from_parts(output.cv().clone(), *output.cmu(), output.ephemeral_key().clone(), *output.enc_ciphertext(), *output.out_ciphertext(), proof);
            // ZIP243 also signs the output proof. Its unchanged genuine
            // SpendAuth must reject that changed proof before output equations.
            SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }
        };
        let changed = sapling_crypto::Bundle::from_parts(spends, outputs, *bundle.value_balance(), *bundle.authorization());
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6, 0, 0.into(), None, None, changed, None).freeze().unwrap();
        let mut parent = isolated_sapling_parent();
        parent.deferred_balance = 13;
        parent.issued_supply += 13;
        let key = ([0xca; 32], 0);
        fund(&mut parent, key, 20, &[0x51], 0, false);
        let good = v4(&spend(&[(key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Nu6, 0);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu6_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(good)), PostNu5Transaction::V4(Box::new(transaction))], height, 1_800_000_000), Err(SproutLedgerError::Sapling(actual)) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu6_wrong_encoded_branch_and_duplicate_null_inputs_never_change_any_parent_field() {
    let height = 2_976_000;
    let key = ([0xcb; 32], 0);
    let mut parent = state();
    fund(&mut parent, key, 0, &[0x51], 0, false);
    parent.deferred_balance = 13;
    parent.issued_supply += 13;
    let before = owned_state(&parent);
    for version in [TxVersion::V4, TxVersion::V5] {
        let old = nu5_coinbase(2_975_999, version, height);
        assert!(matches!(stage_nu6_transactions(&parent, &[old], height), Err(SproutLedgerError::UnsupportedTransaction)));
        assert_eq!(owned_state(&parent), before);
        for (inputs, expected) in [(vec![(key, &[][..], u32::MAX), (key, &[][..], u32::MAX)], SproutLedgerError::DuplicateTransparentInput), (vec![(([0; 32], u32::MAX), &[][..], u32::MAX)], SproutLedgerError::InvalidCoinbase)] {
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, 0.into(), spend(&inputs, vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[nu6_coinbase(height, version, height), tx], height), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn nu6_pruned_script_boundary_counts_claimed_value_not_retained_utxo_or_deferred_output() {
    let height = 2_976_000;
    for version in [TxVersion::V4, TxVersion::V5] {
        for (script, retained) in [(vec![0x6a], 12_500_000), (vec![0; 10_001], 12_500_000), (vec![0; 10_000], 137_500_000)] {
            let reward = nu6_with_outputs(height, version, vec![output(125_000_000, &script), output(12_500_000, &bytes(NU6_FPF_SCRIPT))]);
            let id: [u8; 32] = reward.txid().into();
            let mut parent = state();
            let delta = stage_nu6_transactions(&parent, &[reward], height).unwrap();
            assert_eq!((delta.transparent, delta.retained, delta.deferred, delta.issued), (137_500_000, retained, 18_750_000, 156_250_000));
            parent.commit(delta);
            assert_eq!(parent.utxo(&id, 0).is_some(), retained == 137_500_000);
            assert_eq!(parent.utxo_count(), if retained == 137_500_000 { 2 } else { 1 });
            assert!(parent.utxo(&id, 2).is_none()); // No deferred outpoint exists.
        }
        for mutation in 0..3 {
            let good = nu6_coinbase(height, version, height);
            let mut transparent = good.transparent_bundle().unwrap().clone();
            let mut script = transparent.vin[0].script_sig().clone();
            match mutation {
                0 => script.0.0 = vec![0x51],
                1 => script.0.0.resize(101, 0),
                2 => script.0.0[1] ^= 1,
                _ => unreachable!(),
            }
            transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
            let bad = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap();
            let parent = state();
            let before = owned_state(&parent);
            assert!(matches!(stage_nu6_transactions(&parent, &[bad], height), Err(SproutLedgerError::InvalidCoinbase)));
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn nu6_old_orchard_authorizations_cannot_be_relabeled_as_current_noncoinbase_messages() {
    let height = 2_976_000;
    let mut changed = ORCHARD_OUTPUTS_DISABLED.to_vec();
    changed[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
    let mut parent = state();
    parent.deferred_balance = 13;
    parent.issued_supply = 13;
    let before = owned_state(&parent);
    // The original Halo2 statement is branch-independent and remains real;
    // dummy SpendAuth signs a changed NU6 message and MUST reject before commit.
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU6_ORCHARD_COINBASE), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(RawV5Error::InvalidOrchardSpendAuth { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu61_activation_redistributes_existing_deferred_without_minting_withdrawal() {
    // Isolated synthetic monetary parent, NOT an authenticated archive.
    let height = 3_536_500u32;
    let withdrawn = 7_875_000_000_000u64;
    let mut parent = state();
    parent.deferred_balance = withdrawn;
    parent.issued_supply = withdrawn;
    let mut transparent = nu6_coinbase(3_536_499, TxVersion::V4, 3_536_499).transparent_bundle().unwrap().clone();
    let (prefix, length) = coinbase_height_prefix(height);
    let mut script = Script::default();
    script.0.0.extend_from_slice(&prefix[..length]);
    script.0.0.push(0);
    transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
    transparent.vout = vec![output(125_000_000, &[0x51]), output(12_500_000, &bytes(NU6_FPF_SCRIPT))];
    for _ in 0..10 {
        transparent.vout.push(output(787_500_000_000, &bytes("a914d2f1b436490d63fc078d8aed2d966bd3e40d79f087")));
    }
    let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6_1,
        0, height.into(), Some(transparent), None, None, None).freeze().unwrap();
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(transaction))], height, 1_800_000_000).unwrap();
    assert_eq!(delta.issued, withdrawn + 156_250_000);
    assert_eq!(delta.transparent, i128::from(withdrawn + 137_500_000));
    assert_eq!(delta.deferred, 18_750_000);
    parent.commit(delta);
    assert_eq!(parent.deferred_balance(), 18_750_000);
    assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
}

const NU61_DISBURSEMENT_SCRIPT: &str = "a914d2f1b436490d63fc078d8aed2d966bd3e40d79f087";

fn isolated_deferred_parent(deferred: u64) -> SproutTestnetLedger {
    let mut parent = state();
    parent.deferred_balance = deferred;
    parent.issued_supply = deferred;
    parent
}

fn nu61_coinbase(height: u32, version: TxVersion, expiry: u32) -> Transaction {
    let mut transparent = nu6_coinbase(3_536_499, TxVersion::V4, 3_536_499).transparent_bundle().unwrap().clone();
    let (prefix, length) = coinbase_height_prefix(height);
    let mut script = Script::default();
    script.0.0.extend_from_slice(&prefix[..length]);
    script.0.0.push(0);
    transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
    transparent.vout = vec![output(125_000_000, &[0x51]), output(12_500_000, &bytes(NU6_FPF_SCRIPT))];
    if height == 3_536_500 {
        transparent.vout.extend((0..10).map(|_| output(787_500_000_000, &bytes(NU61_DISBURSEMENT_SCRIPT))));
    }
    TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, 0, expiry.into(), Some(transparent), None, None, None).freeze().unwrap()
}

fn nu61_with_outputs(height: u32, version: TxVersion, outputs: Vec<TxOut>) -> Transaction {
    let mut transparent = nu61_coinbase(height, version, height).transparent_bundle().unwrap().clone();
    transparent.vout = outputs;
    TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap()
}

#[test]
fn nu61_ten_distinct_disbursement_outputs_are_an_unordered_multiset_not_a_total_or_address_sum() {
    let height = 3_536_500;
    for version in [TxVersion::V4, TxVersion::V5] {
        let parent = isolated_deferred_parent(7_875_000_000_000);
        let before = owned_state(&parent);
        let original = nu61_coinbase(height, version, height).transparent_bundle().unwrap().vout.clone();
        for mutation in 0..7 {
            let mut outputs = original.clone();
            match mutation {
                0 => { outputs.remove(2); outputs[0] = output(787_625_000_000, &[0x51]); }
                1 => { outputs.truncate(3); outputs[2] = output(7_875_000_000_000, &bytes(NU61_DISBURSEMENT_SCRIPT)); }
                2 => {
                    outputs[2] = output(393_750_000_000, &bytes(NU61_DISBURSEMENT_SCRIPT));
                    outputs.push(output(393_750_000_000, &bytes(NU61_DISBURSEMENT_SCRIPT)));
                }
                3 => { outputs[2] = output(787_500_000_001, &bytes(NU61_DISBURSEMENT_SCRIPT)); outputs[0] = output(124_999_999, &[0x51]); }
                4 => { outputs[2] = output(787_499_999_999, &bytes(NU61_DISBURSEMENT_SCRIPT)); outputs[0] = output(125_000_001, &[0x51]); }
                5 => outputs[2] = output(787_500_000_000, &[0x51]),
                6 => { outputs.truncate(2); outputs.push(output(7_875_000_000_000, &[0x51])); }
                _ => unreachable!(),
            }
            assert!(matches!(stage_nu6_transactions(&parent, &[nu61_with_outputs(height, version, outputs)], height), Err(SproutLedgerError::MissingDeferredDisbursement)), "mutation {mutation}");
            assert_eq!(owned_state(&parent), before);
        }
        // Extra outputs, zero outputs, and any ordering are allowed when money
        // still holds. Twelve is not an exact consensus output-count ceiling.
        let mut reordered = original;
        reordered[0] = output(124_999_999, &[0x51]);
        reordered.push(output(1, &[0x51]));
        reordered.push(output(0, &[0x51]));
        reordered.reverse();
        let delta = stage_nu6_transactions(&parent, &[nu61_with_outputs(height, version, reordered)], height).unwrap();
        assert_eq!((delta.transparent, delta.deferred, delta.issued), (7_875_137_500_000, 18_750_000, 7_875_156_250_000));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu61_activation_debits_the_actual_parent_before_new_credit_in_isolated_synthetic_state() {
    let height = 3_536_500;
    for version in [TxVersion::V4, TxVersion::V5] {
        let reward = nu61_coinbase(height, version, height);
        // W-D <= parent < W is unreachable from the fixed default-testnet
        // schedule. These are synthetic corruption tests, not mined evidence
        // or disagreement with original final-net-balance implementations.
        for balance in [0, 7_874_981_250_000, 7_874_981_250_001, 7_874_999_999_999] {
            let parent = isolated_deferred_parent(balance);
            let before = owned_state(&parent);
            assert!(matches!(stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height), Err(SproutLedgerError::InsufficientDeferredBalance)));
            assert_eq!(owned_state(&parent), before);
        }
        for (balance, deferred, issued) in [(7_875_000_000_000, 18_750_000, 7_875_156_250_000), (7_875_000_000_100, 18_750_100, 7_875_156_250_100)] {
            let mut parent = isolated_deferred_parent(balance);
            let before = owned_state(&parent);
            let delta = stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height).unwrap();
            assert_eq!((delta.transparent, delta.deferred, delta.issued), (7_875_137_500_000, deferred, issued));
            assert_eq!(owned_state(&parent), before);
            parent.commit(delta);
            assert_eq!(parent.deferred_balance(), deferred as u64);
            assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
        }
    }
}

#[test]
fn nu61_restarted_funding_requires_each_exact_output_at_all_fifteen_bounded_periods() {
    // Literal source period edges: the +5500 offset switches first3566000.
    // The repeated beneficiary does not turn exact amounts into summed sums.
    for height in [3_536_500, 3_536_501, 3_565_999, 3_566_000, 3_600_999, 3_601_000,
        3_635_999, 3_636_000, 3_670_999, 3_671_000, 3_705_999, 3_706_000,
        3_740_999, 3_741_000, 3_775_999, 3_776_000, 3_810_999, 3_811_000,
        3_845_999, 3_846_000, 3_880_999, 3_881_000, 3_915_999, 3_916_000,
        3_950_999, 3_951_000, 3_985_999, 3_986_000, 4_020_999, 4_021_000,
        4_048_499, 4_048_500, 4_051_999] {
        for version in [TxVersion::V4, TxVersion::V5] {
            let parent = isolated_deferred_parent(if height == 3_536_500 { 7_875_000_000_000 } else { 13 });
            let before = owned_state(&parent);
            let reward = nu61_coinbase(height, version, height);
            let delta = stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height).unwrap();
            let expected = if height == 3_536_500 { (7_875_156_250_000, 7_875_137_500_000, 18_750_000) } else { (156_250_013, 137_500_000, 18_750_013) };
            assert_eq!((delta.issued, delta.transparent, delta.deferred), expected);
            for mutation in 0..5 {
                let mut outputs = reward.transparent_bundle().unwrap().vout.clone();
                match mutation {
                    0 => { outputs.remove(1); outputs[0] = output(137_500_000, &[0x51]); }
                    1 => outputs[1] = output(12_500_000, &[0x51]),
                    2 => { outputs[1] = output(12_500_001, &bytes(NU6_FPF_SCRIPT)); outputs[0] = output(124_999_999, &[0x51]); }
                    3 => { outputs[1] = output(12_499_999, &bytes(NU6_FPF_SCRIPT)); outputs[0] = output(125_000_001, &[0x51]); }
                    4 => { outputs[1] = output(12_499_999, &bytes(NU6_FPF_SCRIPT)); outputs.push(output(1, &bytes(NU6_FPF_SCRIPT))); }
                    _ => unreachable!(),
                }
                assert!(matches!(stage_nu6_transactions(&parent, &[nu61_with_outputs(height, version, outputs)], height), Err(SproutLedgerError::MissingFundingStream { index: 0 })));
                assert_eq!(owned_state(&parent), before);
            }
            for change in [-1_i64, 1] {
                let mut outputs = reward.transparent_bundle().unwrap().vout.clone();
                outputs[0] = output((125_000_000 + change) as u64, &[0x51]);
                assert!(matches!(stage_nu6_transactions(&parent, &[nu61_with_outputs(height, version, outputs)], height), Err(SproutLedgerError::CoinbaseRewardExceeded)));
                assert_eq!(owned_state(&parent), before);
            }
        }
    }
}

#[test]
fn nu61_all_515500_scheduled_credits_are_bounded_arithmetic_not_archive_replay() {
    let mut parent = isolated_deferred_parent(7_875_000_000_000);
    let activation = nu61_coinbase(3_536_500, TxVersion::V4, 3_536_500);
    let delta = stage_nu6_transactions(&parent, &[activation], 3_536_500).unwrap();
    parent.commit(delta);
    let values = check_coinbase(&nu61_coinbase(3_536_501, TxVersion::V4, 3_536_501), 3_536_501, 1_800_000_000).unwrap();
    for height in 3_536_501..4_052_000 {
        // Identical exact reward structure after the one activation debit;
        // finalize each scheduled credit, without claiming authenticated bodies.
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = values.transparent.into();
        delta.retained = values.retained.into();
        delta.deferred = deferred_subsidy(height).into();
        let delta = parent.finish_delta(delta, values, height).unwrap();
        parent.commit(delta);
    }
    assert_eq!(parent.deferred_balance(), 9_665_625_000_000);
    assert_eq!(parent.transparent_balance(), 78_756_250_000_000);
    assert_eq!(parent.issued_supply(), 88_421_875_000_000);
    let before = owned_state(&parent);
    // A last-epoch branch label cannot select the fixed candidate's verifier.
    assert!(matches!(stage_nu6_transactions(&parent, &[nu61_coinbase(4_052_000, TxVersion::V4, 4_052_000)], 4_052_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
    assert_eq!(deferred_subsidy(3_536_499), 0);
    assert_eq!(deferred_subsidy(4_052_000), 18_750_000);
    assert_eq!(deferred_subsidy(4_133_999), 18_750_000);
    assert_eq!(deferred_subsidy(4_134_000), 18_750_000);
    assert_eq!(deferred_subsidy(4_465_025), 18_750_000);
    assert_eq!(deferred_subsidy(4_465_026), 0);
}

#[test]
fn nu61_exact_actual_fee_claim_burn_and_old_underclaim_never_mint_withdrawal_or_backfill() {
    for height in [3_536_500, 3_536_501, 4_048_500, 4_051_999] {
        for version in [TxVersion::V4, TxVersion::V5] {
            let mut parent = isolated_deferred_parent(if height == 3_536_500 { 7_875_000_000_000 } else { 13 });
            let key = ([0xd1; 32], 0);
            fund(&mut parent, key, 100, &[0x51], 0, false);
            parent.shielded_balances = [3, 5, 7, 11];
            parent.issued_supply += 26;
            let before = owned_state(&parent);
            let fee_tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(90, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            for claim in [9, 10, 11] {
                let mut outputs = nu61_coinbase(height, version, height).transparent_bundle().unwrap().vout.clone();
                outputs[0] = output(124_999_999 + claim, &[0x51]);
                outputs.push(output(1, &[0x6a]));
                let result = stage_nu6_transactions(&parent, &[nu61_with_outputs(height, version, outputs), fee_tx.clone()], height);
                if claim == 10 {
                    let delta = result.unwrap();
                    let expected = if height == 3_536_500 { (7_875_137_500_100, 7_875_137_500_099, 18_750_000, 7_875_156_250_126) } else { (137_500_100, 137_500_099, 18_750_013, 156_250_139) };
                    assert_eq!((delta.transparent, delta.retained, delta.deferred, delta.issued), expected);
                    assert_eq!((delta.fees, delta.sprout, delta.sapling, delta.orchard), (10, 3, 5, 7));
                } else {
                    assert!(matches!(result, Err(SproutLedgerError::CoinbaseRewardExceeded)));
                }
                assert_eq!(owned_state(&parent), before);
            }
            let mut outputs = nu61_coinbase(height, version, height).transparent_bundle().unwrap().vout.clone();
            outputs[0] = output(125_000_009, &[0x51]);
            outputs.push(output(1, &[0x6a]));
            let delta = stage_nu6_transactions(&parent, &[nu61_with_outputs(height, version, outputs), fee_tx], height).unwrap();
            parent.commit(delta);
            assert_eq!(parent.shielded_balances, [3, 5, 7, 11]);
            assert_eq!(parent.utxo_balance() + 1, parent.transparent_balance());
            assert_eq!(parent.transparent_balance() + parent.shielded_balances.iter().sum::<u64>() + parent.deferred_balance(), parent.issued_supply());
        }
    }
    let mut parent = state();
    let old = nu5_with_outputs(2_975_999, TxVersion::V4, vec![output(1, &[0x51])]);
    let delta = stage_nu6_transactions(&parent, &[old], 2_975_999).unwrap();
    parent.commit(delta);
    // Isolated synthetic deferred parent injection, not a skipped history proof.
    parent.deferred_balance = 7_875_000_000_000;
    parent.issued_supply += 7_875_000_000_000;
    let delta = stage_nu6_transactions(&parent, &[nu61_coinbase(3_536_500, TxVersion::V4, 3_536_500)], 3_536_500).unwrap();
    assert_eq!(delta.issued, 7_875_156_250_001);
}

#[test]
fn nu61_signed_pools_cannot_replace_original_negative_only_getvalueout() {
    let height = 3_536_500;
    for pool in [ShieldedPool::Sapling, ShieldedPool::Orchard] {
        let mut parent = isolated_deferred_parent(7_875_000_000_000);
        parent.shielded_balances[pool.index()] = 1;
        parent.issued_supply += 1;
        let before = owned_state(&parent);
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = 7_875_137_500_000;
        delta.retained = 7_875_137_500_000;
        delta.deferred = -7_874_981_250_000;
        if pool == ShieldedPool::Sapling { delta.sapling = -1; } else { delta.orchard = -1; }
        // The negative-only GetValueOut claim passes exact reward, while the
        // separate signed-pool invariant rejects loss1. No proof is mocked valid.
        let values = CoinbaseValues { claimed: 7_875_137_500_000, transparent: 7_875_137_500_000, sapling_balance: i64::from(pool == ShieldedPool::Sapling), orchard_balance: i64::from(pool == ShieldedPool::Orchard), ironwood_balance: 0, retained: 7_875_137_500_000, sigops: 0 };
        assert!(matches!(parent.finish_delta(delta, values, height), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu61_independently_signed_v4_v5_bind_each_actual_prevout_script_amount_and_current_branch() {
    let keys = [([0xd2; 32], 3), ([0xd3; 32], 7)];
    for height in [3_536_500, 3_536_501, 4_048_500, 4_051_999] {
        for p2sh in [false, true] {
            for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
                let (transaction, prevout) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu6_1, p2sh, hash_type);
                let (raw, prevouts) = independently_signed_v5_for_branch(&keys, BranchId::Nu6_1, p2sh, hash_type);
                let balance = if height == 3_536_500 { 7_875_000_000_000 } else { 13 };
                let make_parent = |bad: Option<(usize, bool)>| {
                    let mut parent = isolated_deferred_parent(balance);
                    for (index, (key, previous)) in std::iter::once((([0xa1; 32], 3), &prevout)).chain(keys.iter().copied().zip(&prevouts)).enumerate() {
                        let mut script = previous.script_pubkey().0.0.clone();
                        if bad == Some((index, true)) { if p2sh { script[2] ^= 1; } else { script.insert(0, 0x61); } }
                        let amount = u64::from(previous.value()) + u64::from(bad == Some((index, false)));
                        fund(&mut parent, key, amount, &script, 0, false);
                    }
                    parent
                };
                let mut parent = make_parent(None);
                let mut outputs = nu61_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
                outputs[0] = output(125_000_007, &[0x51]);
                let reward = nu61_with_outputs(height, TxVersion::V4, outputs);
                let before = owned_state(&parent);
                let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(transaction.clone())), original_v5(&raw)], height, 1_800_000_000).unwrap();
                let expected = if height == 3_536_500 { (7, 18_750_000, 7_875_156_550_007) } else { (7, 18_750_013, 156_550_020) };
                assert_eq!((delta.fees, delta.deferred, delta.issued), expected);
                assert_eq!(owned_state(&parent), before);
                for index in 0..3 {
                    for changed_script in [false, true] {
                        let bad = make_parent(Some((index, changed_script)));
                        let snapshot = owned_state(&bad);
                        assert!(matches!(bad.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(transaction.clone())), original_v5(&raw)], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
                        assert_eq!(owned_state(&bad), snapshot);
                    }
                }
                let (old, _) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu6, p2sh, hash_type);
                assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(v4(&old, BranchId::Nu6_1, 0)))], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
                let (mut old, _) = independently_signed_v5_for_branch(&keys, BranchId::Nu6, p2sh, hash_type);
                assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&old)], height, 1_800_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
                old[8..12].copy_from_slice(&u32::from(BranchId::Nu6_1).to_le_bytes());
                assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward)), original_v5(&old)], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
                assert_eq!(owned_state(&parent), before);
                parent.commit(delta);
                for key in [([0xa1; 32], 3), keys[0], keys[1]] { assert!(parent.utxo(&key.0, key.1).is_none()); }
                assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
            }
        }
    }
}

#[test]
fn nu61_generated_original_halo2_authorizations_move_real_leaves_nullifiers_and_deferred_money() {
    let height = 3_536_500;
    let mut parent = isolated_deferred_parent(7_875_000_000_000);
    let before = owned_state(&parent);
    let mut expected = incrementalmerkletree::frontier::CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for raw in [&NU61_ORCHARD_COINBASE, &NU61_ORCHARD_OUTPUTS_DISABLED] {
        let transaction = RawV5::parse_exact(raw).unwrap();
        assert_eq!(transaction.consensus_branch_id(), BranchId::Nu6_1);
        for action in transaction.orchard().unwrap().actions().as_chunks::<820>().0 {
            expected.append(MerkleHashOrchard::from_bytes(action[96..128].try_into().unwrap()).unwrap()).unwrap();
        }
    }
    let delta = parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE), original_v5(&NU61_ORCHARD_OUTPUTS_DISABLED)], height, 1_800_000_000).unwrap();
    assert_eq!((delta.issued, delta.transparent, delta.orchard, delta.deferred, delta.fees), (7_875_156_250_000, 7_875_137_499_993, 7, 18_750_000, 0));
    assert_eq!(delta.orchard_tree.tree_size(), 3);
    assert_eq!(delta.orchard_root, expected.root().to_bytes());
    assert_eq!(delta.orchard_nullifiers.len(), 3);
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.orchard_tree_size(), parent.shielded_balance(ShieldedPool::Orchard), parent.nullifier_count(ShieldedPool::Orchard), parent.deferred_balance()), (3, 7, 3, 18_750_000));
    assert_eq!(parent.transparent_balance() + parent.shielded_balance(ShieldedPool::Orchard) + parent.deferred_balance(), parent.issued_supply());
}

#[test]
fn nu61_every_original_orchard_recovery_proof_spendauth_binding_and_late_failure_keeps_all_owned_state() {
    let height = 3_536_500;
    let original = RawV5::parse_exact(&NU61_ORCHARD_COINBASE).unwrap();
    let bundle = original.orchard().unwrap();
    let actions = bundle.actions().as_ptr() as usize - NU61_ORCHARD_COINBASE.as_ptr() as usize;
    let proof = bundle.proof().as_ptr() as usize - NU61_ORCHARD_COINBASE.as_ptr() as usize;
    let signatures = bundle.spend_auth_signatures().as_ptr() as usize - NU61_ORCHARD_COINBASE.as_ptr() as usize;
    let binding = bundle.binding_signature().as_ptr() as usize - NU61_ORCHARD_COINBASE.as_ptr() as usize;
    for (offset, expected) in [
        (actions + 160, RawV5Error::CoinbaseRecovery { index: 0 }),
        (actions + 820 + 819, RawV5Error::CoinbaseRecovery { index: 1 }),
        (proof, RawV5Error::InvalidOrchardProof),
        (signatures + 63, RawV5Error::InvalidOrchardSpendAuth { index: 0 }),
        (signatures + 64 + 63, RawV5Error::InvalidOrchardSpendAuth { index: 1 }),
        (binding + 63, RawV5Error::InvalidOrchardBindingSignature),
    ] {
        let parent = isolated_deferred_parent(7_875_000_000_000);
        let before = owned_state(&parent);
        let mut changed = NU61_ORCHARD_COINBASE.to_vec();
        changed[offset] ^= 1;
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(actual)) if actual == expected), "offset {offset}");
        assert_eq!(owned_state(&parent), before);
    }
    let original = RawV5::parse_exact(&NU61_ORCHARD_OUTPUTS_DISABLED).unwrap();
    let bundle = original.orchard().unwrap();
    let signatures = bundle.spend_auth_signatures().as_ptr() as usize - NU61_ORCHARD_OUTPUTS_DISABLED.as_ptr() as usize;
    let binding = bundle.binding_signature().as_ptr() as usize - NU61_ORCHARD_OUTPUTS_DISABLED.as_ptr() as usize;
    for (offset, expected) in [(signatures + 63, RawV5Error::InvalidOrchardSpendAuth { index: 0 }), (binding + 63, RawV5Error::InvalidOrchardBindingSignature)] {
        let mut parent = isolated_deferred_parent(7_875_000_000_000);
        let key = ([0xd4; 32], 0);
        fund(&mut parent, key, 20, &[0x51], 0, false);
        let good = v4(&spend(&[(key, &[], u32::MAX)], vec![output(20, &[0x51])], 0), BranchId::Nu6_1, 0);
        let before = owned_state(&parent);
        let mut changed = NU61_ORCHARD_OUTPUTS_DISABLED.to_vec();
        changed[offset] ^= 1;
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE), PostNu5Transaction::V4(Box::new(good.clone())), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(actual)) if actual == expected));
        assert_eq!(owned_state(&parent), before);
        let delta = parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE), PostNu5Transaction::V4(Box::new(good)), original_v5(&NU61_ORCHARD_OUTPUTS_DISABLED)], height, 1_800_000_000).unwrap();
        parent.commit(delta);
        assert!(parent.utxo(&key.0, key.1).is_none());
        assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard), parent.deferred_balance()), (3, 3, 18_750_000));
    }
    let parent = isolated_deferred_parent(7_875_000_000_000);
    let before = owned_state(&parent);
    let mut old = NU6_ORCHARD_OUTPUTS_DISABLED.to_vec();
    old[8..12].copy_from_slice(&u32::from(BranchId::Nu6_1).to_le_bytes());
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE), original_v5(&old)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(RawV5Error::InvalidOrchardSpendAuth { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu61_activation_binds_owned_last_nu6_history_and_full_auth_before_one_leaf_epoch() {
    use zcash_history::{V2, Version};
    let height = 3_536_500;
    let mut parent = isolated_deferred_parent(7_875_000_000_000);
    // Isolated synthetic history metadata, never imported predecessor authority.
    let last = post_nu5_leaf(3_536_499, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0);
    let old = ChainHistoryV2::new(last.clone()).unwrap();
    parent.history_root = Some(old.root());
    parent.chain_history_v2 = Some(old);
    let bytes = post_nu5_structural_body(&[&NU61_ORCHARD_COINBASE, &NU61_ORCHARD_OUTPUTS_DISABLED], height, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&bytes, height).unwrap();
    let auth = body.auth_data_root();
    let commitment = body.header().final_sapling_root;
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
    let first = post_nu5_leaf(height, delta.sapling_root, delta.orchard_root, 0, 2);
    let history = parent.stage_post_nu5_history(&commitment, &auth, first.clone()).unwrap();
    assert_eq!((history.consensus_branch_id(), history.leaf_count(), history.last_height()), (0x4dec_4df0, 1, 3_536_500));
    assert_eq!(history.root(), V2::hash(&first));
    assert_eq!((delta.deferred, delta.issued), (18_750_000, 7_875_156_250_000));
    assert_eq!(owned_state(&parent), before);
    for (height, branch, expected) in [(3_536_498_u32, BranchId::Nu6, HistoryError::NonconsecutiveHeight), (3_536_499, BranchId::Nu5, HistoryError::BranchMismatch), (3_536_499, BranchId::Nu6_1, HistoryError::BranchMismatch)] {
        let mut leaf = last.clone();
        leaf.v1.start_height = height.into();
        leaf.v1.end_height = height.into();
        leaf.v1.consensus_branch_id = u32::from(branch);
        let mut bad = isolated_deferred_parent(7_875_000_000_000);
        let wrong = ChainHistoryV2::new(leaf).unwrap();
        bad.history_root = Some(wrong.root());
        bad.chain_history_v2 = Some(wrong);
        let snapshot = owned_state(&bad);
        assert_eq!(bad.stage_post_nu5_history(&block_commitment(bad.history_root().unwrap(), auth), &auth, first.clone()).unwrap_err(), SproutLedgerError::History(expected));
        assert_eq!(owned_state(&bad), snapshot);
    }
    for failure in 0..4 {
        let mut wrong_auth = auth;
        let mut wrong_commitment = commitment;
        if failure == 0 { wrong_auth[0] ^= 1; }
        if failure == 1 { wrong_commitment[0] ^= 1; }
        if failure == 2 { parent.history_root = Some([0; 32]); }
        if failure == 3 { parent.chain_history = Some(ChainHistoryV1::new(primary_heartwood_leaf(include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin"), 903_800, parent.shielded_roots[1], 0)).unwrap()); }
        let snapshot = owned_state(&parent);
        let error = match failure {
            0 | 1 => SproutLedgerError::Body(BodyError::BlockCommitmentMismatch),
            2 => SproutLedgerError::WrongHistoryRoot,
            _ => SproutLedgerError::History(HistoryError::BranchMismatch),
        };
        assert_eq!(parent.stage_post_nu5_history(&wrong_commitment, &wrong_auth, first.clone()).unwrap_err(), error);
        assert_eq!(owned_state(&parent), snapshot);
        parent.history_root = parent.chain_history_v2.as_ref().map(ChainHistoryV2::root);
        parent.chain_history = None;
    }
    parent.commit(delta);
    parent.history_root = Some(history.root());
    parent.chain_history_v2 = Some(history);
    // Reset history did not clear a single actual pool leaf or nullifier.
    assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard)), (3, 3));
    let reward = encoded(&nu61_coinbase(height + 1, TxVersion::V4, height + 1));
    let bytes = post_nu5_structural_body(&[&reward], height + 1, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&bytes, height + 1).unwrap();
    let next_auth = body.auth_data_root();
    let commitment = body.header().final_sapling_root;
    let before = owned_state(&parent);
    let next_delta = parent.stage_post_nu5_block(body.into_transactions(), height + 1, 1_800_000_000).unwrap();
    let next = post_nu5_leaf(height + 1, next_delta.sapling_root, next_delta.orchard_root, 0, 0);
    let appended = parent.stage_post_nu5_history(&commitment, &next_auth, next.clone()).unwrap();
    assert_eq!(appended.root(), V2::hash(&V2::combine(&first, &next)));
    assert_eq!(appended.leaf_count(), 2);
    assert_eq!(owned_state(&parent), before);
    assert_eq!((next_delta.orchard_tree.tree_size(), next_delta.orchard_nullifiers.len(), next_delta.orchard), (3, 0, 7));
}

#[test]
fn nu61_original_proof_suffix_is_valid_but_changed_full_auth_cannot_commit_history_or_money() {
    let height = 3_536_500;
    let mut parent = isolated_deferred_parent(7_875_000_000_000);
    let old = ChainHistoryV2::new(post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0)).unwrap();
    parent.history_root = Some(old.root());
    parent.chain_history_v2 = Some(old);
    let original = RawV5::parse_exact(&NU61_ORCHARD_COINBASE).unwrap();
    let bundle = original.orchard().unwrap();
    let proof = bundle.proof().as_ptr() as usize - NU61_ORCHARD_COINBASE.as_ptr() as usize;
    let signatures = bundle.spend_auth_signatures().as_ptr() as usize - NU61_ORCHARD_COINBASE.as_ptr() as usize;
    let mut padded = NU61_ORCHARD_COINBASE.to_vec();
    assert_eq!(padded[proof - 3], 0xfd);
    padded[proof - 2..proof].copy_from_slice(&u16::try_from(bundle.proof().len() + 1).unwrap().to_le_bytes());
    padded.insert(signatures, 0x42);
    let changed = RawV5::parse_exact(&padded).unwrap();
    assert_eq!(changed.effect_id(), original.effect_id());
    assert_ne!(changed.auth_digest(), original.auth_digest());
    let bytes = post_nu5_structural_body(&[&NU61_ORCHARD_COINBASE], height, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&bytes, height).unwrap();
    let commitment = body.header().final_sapling_root;
    let old_auth = body.auth_data_root();
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(vec![original_v5(&padded)], height, 1_800_000_000).unwrap();
    let changed_bytes = post_nu5_structural_body(&[&padded], height, parent.history_root().unwrap());
    let changed_body = PostNu5Block::parse(&changed_bytes, height).unwrap();
    let auth = changed_body.auth_data_root();
    assert_ne!(old_auth, auth);
    let leaf = post_nu5_leaf(height, delta.sapling_root, delta.orchard_root, 0, 1);
    assert_eq!(parent.stage_post_nu5_history(&commitment, &auth, leaf.clone()).unwrap_err(), SproutLedgerError::Body(BodyError::BlockCommitmentMismatch));
    assert_eq!(owned_state(&parent), before);
    let history = parent.stage_post_nu5_history(&block_commitment(parent.history_root().unwrap(), auth), &auth, leaf).unwrap();
    parent.commit(delta);
    parent.history_root = Some(history.root());
    parent.chain_history_v2 = Some(history);
    assert_eq!((parent.deferred_balance(), parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard)), (18_750_000, 2, 2));
}

#[test]
fn nu61_orchard_disable_is_presence_based_before_recovery_or_proof_even_after_bad_earlier_coinbase() {
    for height in [4_048_500, 4_048_501, 4_051_999] {
        let parent = isolated_deferred_parent(13);
        let before = owned_state(&parent);
        for original in [&NU61_ORCHARD_COINBASE, &NU61_ORCHARD_OUTPUTS_DISABLED] {
            let parsed = RawV5::parse_exact(original).unwrap();
            let bundle = parsed.orchard().unwrap();
            let proof = bundle.proof().as_ptr() as usize - original.as_ptr() as usize;
            let actions = bundle.actions().as_ptr() as usize - original.as_ptr() as usize;
            for mutation in 0..6 {
                let mut raw = original.to_vec();
                match mutation {
                    0 => {}
                    1 => raw[proof] ^= 1,
                    2 => raw[actions + bundle.action_count() * 820] = 1,
                    3 => raw[actions + bundle.action_count() * 820] = 2,
                    4 => raw[actions + bundle.action_count() * 820] = 3,
                    5 => {
                        let value_balance = actions + bundle.action_count() * 820 + 1;
                        raw[value_balance..value_balance + 8].copy_from_slice(&7_i64.to_le_bytes());
                    }
                    _ => unreachable!(),
                }
                // The ledger's own guard applies even to raw standalone parses
                // bypassing PostNu5Block's contextual boundary and old expiry.
                assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&raw)], height, 1_800_000_000), Err(SproutLedgerError::OrchardDisabled)));
                let bad_reward = nu61_with_outputs(height, TxVersion::V4, vec![output(0, &[0x51])]);
                assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(bad_reward)), original_v5(&raw)], height, 1_800_000_000), Err(SproutLedgerError::OrchardDisabled)));
                assert_eq!(owned_state(&parent), before);
            }
        }
    }
    // Before the disable boundary the original circuit remains enabled. Only
    // ordinary expiry/branch/authorization rules decide an actual message.
    let parent = isolated_deferred_parent(13);
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu61_coinbase(4_048_499, TxVersion::V4, 4_048_499))), original_v5(&NU61_ORCHARD_OUTPUTS_DISABLED)], 4_048_499, 1_800_000_000).unwrap();
    assert_eq!((delta.orchard_tree.tree_size(), delta.orchard_nullifiers.len(), delta.deferred), (1, 1, 18_750_013));
}

#[test]
fn nu61_disabled_window_preserves_orchard_money_frontier_nullifiers_and_zero_history_count() {
    use zcash_history::{V2, Version};
    // Isolated generated proof state, NOT a mined/connected predecessor.
    let mut parent = isolated_deferred_parent(7_875_000_000_000);
    let delta = parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE), original_v5(&NU61_ORCHARD_OUTPUTS_DISABLED)], 3_536_500, 1_800_000_000).unwrap();
    parent.commit(delta);
    for height in [4_048_500, 4_051_999] {
        let first = post_nu5_leaf(height - 1, parent.shielded_roots[1], parent.shielded_roots[2], 0, 9);
        let history = ChainHistoryV2::new(first.clone()).unwrap();
        parent.history_root = Some(history.root());
        parent.chain_history_v2 = Some(history);
        for version in [TxVersion::V4, TxVersion::V5] {
            let reward = encoded(&nu61_coinbase(height, version, height));
            let bytes = post_nu5_structural_body(&[&reward], height, parent.history_root().unwrap());
            let body = PostNu5Block::parse(&bytes, height).unwrap();
            assert_eq!(body.transactions().iter().filter(|tx| matches!(tx, PostNu5Transaction::V5(raw) if raw.orchard().is_some())).count(), 0);
            let auth = body.auth_data_root();
            let commitment = body.header().final_sapling_root;
            let before = owned_state(&parent);
            let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
            assert_eq!((delta.orchard, delta.orchard_tree.tree_size(), delta.orchard_nullifiers.len()), (7, 3, 0));
            assert_eq!(delta.orchard_root, before.roots[2]);
            let leaf = post_nu5_leaf(height, delta.sapling_root, delta.orchard_root, 0, 0);
            let history = parent.stage_post_nu5_history(&commitment, &auth, leaf.clone()).unwrap();
            assert_eq!(history.root(), V2::hash(&V2::combine(&first, &leaf)));
            assert_eq!(history.leaf_count(), 2);
            assert_eq!(owned_state(&parent), before);
        }
        let delta = stage_nu6_transactions(&parent, &[nu61_coinbase(height, TxVersion::V5, height)], height).unwrap();
        let before = owned_state(&parent);
        parent.commit(delta);
        assert_eq!(parent.orchard_tree, before.orchard_tree);
        assert_eq!(parent.orchard_anchors, before.orchard_anchors);
        assert_eq!(parent.nullifiers[2], before.nullifiers[2]);
        assert_eq!((parent.shielded_roots[2], parent.shielded_balances[2]), (before.roots[2], 7));
    }
}

#[test]
fn nu61_late_history_height_branch_work_counts_and_cached_root_failures_preserve_retry() {
    let height = 3_536_501;
    for failure in 0..7 {
        let mut parent = isolated_deferred_parent(18_750_000);
        let mut first = post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0);
        if failure == 0 { first.v1.subtree_total_work = primitive_types::U256::MAX; }
        if failure == 1 { first.v1.sapling_tx = u64::MAX; }
        if failure == 2 { first.orchard_tx = u64::MAX; }
        let history = ChainHistoryV2::new(first).unwrap();
        let root = history.root();
        parent.history_root = Some(root);
        parent.chain_history_v2 = Some(history);
        let reward = encoded(&nu61_coinbase(height, TxVersion::V5, height));
        let bytes = post_nu5_structural_body(&[&reward], height, root);
        let body = PostNu5Block::parse(&bytes, height).unwrap();
        let mut auth = body.auth_data_root();
        let commitment = body.header().final_sapling_root;
        if failure == 4 { parent.history_root = Some([0; 32]); }
        if failure == 5 { auth[0] ^= 1; }
        let before = owned_state(&parent);
        let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
        let mut leaf = post_nu5_leaf(height + u32::from(failure == 3), delta.sapling_root, delta.orchard_root, 1, 1);
        if failure == 6 { leaf.v1.consensus_branch_id = u32::from(BranchId::Nu6); }
        let expected = match failure {
            0 => SproutLedgerError::History(HistoryError::WorkOverflow),
            1 => SproutLedgerError::History(HistoryError::SaplingCountOverflow),
            2 => SproutLedgerError::History(HistoryError::OrchardCountOverflow),
            3 => SproutLedgerError::History(HistoryError::NonconsecutiveHeight),
            4 => SproutLedgerError::WrongHistoryRoot,
            5 => SproutLedgerError::Body(BodyError::BlockCommitmentMismatch),
            _ => SproutLedgerError::History(HistoryError::BranchMismatch),
        };
        assert_eq!(parent.stage_post_nu5_history(&commitment, &auth, leaf).unwrap_err(), expected);
        assert_eq!(owned_state(&parent), before);
        // Repair the injected metadata fault before retrying the same staged
        // money/body. This is a private synthetic state, not checkpoint import.
        let repaired = ChainHistoryV2::new(post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0)).unwrap();
        let repaired_root = repaired.root();
        parent.history_root = Some(repaired_root);
        parent.chain_history_v2 = Some(repaired);
        let leaf = post_nu5_leaf(height, delta.sapling_root, delta.orchard_root, 0, 0);
        let auth = PostNu5Block::parse(&bytes, height).unwrap().auth_data_root();
        let retry = parent.stage_post_nu5_history(&block_commitment(repaired_root, auth), &auth, leaf).unwrap();
        parent.commit(delta);
        parent.history_root = Some(retry.root());
        parent.chain_history_v2 = Some(retry);
        assert_eq!((parent.deferred_balance(), parent.chain_history_v2.as_ref().unwrap().leaf_count()), (37_500_000, 2));
    }
}

#[test]
fn nu61_and_nu62_sapling_zero_ovk_recovery_fixed_proofs_and_binding_stay_distinct_in_both_formats() {
    let original = primary_canopy_coinbase(1_101_629);
    let bundle = original.sapling_bundle().unwrap();
    for height in [3_536_500, 3_536_501, 4_048_500, 4_051_999, 4_052_000, 4_133_999] {
        let branch = if height < 4_052_000 { BranchId::Nu6_1 } else { BranchId::Nu6_2 };
        for version in [TxVersion::V4, TxVersion::V5] {
            let parent = isolated_deferred_parent(if height == 3_536_500 { 7_875_000_000_000 } else { 13 });
            let reward = if branch == BranchId::Nu6_1 { nu61_coinbase(height, version, height) } else { nu62_coinbase(height, version, height) };
            let before = owned_state(&parent);
            let make = |outputs, binding| {
                let changed = sapling_crypto::Bundle::from_parts(vec![], outputs, *bundle.value_balance(), binding);
                TransactionData::<Authorized>::from_parts(version, branch, 0, height.into(), reward.transparent_bundle().cloned(), None, changed, None).freeze().unwrap()
            };
            let old = make(bundle.shielded_outputs().to_vec(), *bundle.authorization());
            assert!(matches!(stage_nu6_transactions(&parent, &[old], height), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature))));
            assert_eq!(owned_state(&parent), before);
            for (index, output_description) in bundle.shielded_outputs().iter().enumerate() {
                assert!(recover_sapling_coinbase_output(output_description, height).is_ok());
                for mutation in 0..3 {
                    let mut outputs = bundle.shielded_outputs().to_vec();
                    let mut enc = *output_description.enc_ciphertext();
                    let mut out = *output_description.out_ciphertext();
                    let mut proof = *output_description.zkproof();
                    if mutation == 0 { enc[579] ^= 1; }
                    if mutation == 1 { out[79] ^= 1; }
                    if mutation == 2 { proof[0] ^= 0x20; }
                    outputs[index] = sapling_crypto::bundle::OutputDescription::from_parts(output_description.cv().clone(), *output_description.cmu(), output_description.ephemeral_key().clone(), enc, out, proof);
                    let expected = match mutation {
                        0 => SproutLedgerError::CoinbaseRecovery { index, error: CoinbaseRecoveryError::NoteAuthentication },
                        1 => SproutLedgerError::CoinbaseRecovery { index, error: CoinbaseRecoveryError::OutgoingAuthentication },
                        _ => SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index }),
                    };
                    assert!(matches!(stage_nu6_transactions(&parent, &[make(outputs, *bundle.authorization())], height), Err(actual) if actual == expected));
                    assert_eq!(owned_state(&parent), before);
                }
            }
        }
    }
}

#[test]
fn nu61_late_v4_sapling_proof_and_authorization_failures_keep_prior_money_and_retry() {
    let height = 3_536_500;
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    for mutation in 0..4 {
        let mut spends = bundle.shielded_spends().to_vec();
        let mut outputs = bundle.shielded_outputs().to_vec();
        let expected = if mutation == 0 {
            let spend = &spends[0];
            let mut proof = *spend.zkproof();
            proof[0] ^= 0x20;
            spends[0] = sapling_crypto::bundle::SpendDescription::from_parts(spend.cv().clone(), *spend.anchor(), *spend.nullifier(), *spend.rk(), proof, *spend.spend_auth_sig());
            SaplingCryptoError::InvalidSpendProof { index: 0 }
        } else if mutation == 1 {
            let spend = &spends[0];
            let mut signature = <[u8; 64]>::from(*spend.spend_auth_sig());
            signature[63] ^= 1;
            spends[0] = sapling_crypto::bundle::SpendDescription::from_parts(spend.cv().clone(), *spend.anchor(), *spend.nullifier(), *spend.rk(), *spend.zkproof(), signature.into());
            SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }
        } else {
            let index = mutation - 2;
            let output_description = &outputs[index];
            let mut proof = *output_description.zkproof();
            proof[0] ^= 0x20;
            outputs[index] = sapling_crypto::bundle::OutputDescription::from_parts(output_description.cv().clone(), *output_description.cmu(), output_description.ephemeral_key().clone(), *output_description.enc_ciphertext(), *output_description.out_ciphertext(), proof);
            SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }
        };
        let changed = sapling_crypto::Bundle::from_parts(spends, outputs, *bundle.value_balance(), *bundle.authorization());
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6_1, 0, 0.into(), None, None, changed, None).freeze().unwrap();
        let mut parent = isolated_sapling_parent();
        parent.deferred_balance = 7_875_000_000_000;
        parent.issued_supply += 7_875_000_000_000;
        let key = ([0xd5; 32], 0);
        fund(&mut parent, key, 20, &[0x51], 0, false);
        let good = v4(&spend(&[(key, &[], u32::MAX)], vec![output(20, &[0x51])], 0), BranchId::Nu6_1, 0);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu61_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(good.clone())), PostNu5Transaction::V4(Box::new(transaction))], height, 1_800_000_000), Err(SproutLedgerError::Sapling(actual)) if actual == expected));
        assert_eq!(owned_state(&parent), before);
        let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu61_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(good))], height, 1_800_000_000).unwrap();
        parent.commit(delta);
        assert!(parent.utxo(&key.0, key.1).is_none());
        assert_eq!(parent.nullifiers[1], before.nullifiers[1]);
        assert_eq!(parent.sapling_tree, before.sapling_tree);
        assert_eq!(parent.deferred_balance(), 18_750_000);
    }
}

#[test]
fn nu61_all_sapling_anchors_nullifiers_leaves_and_tree_capacity_precede_current_branch_crypto() {
    let height = 3_536_500;
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    let anchor = bundle.shielded_spends()[0].anchor().to_bytes();
    let nullifier = bundle.shielded_spends()[0].nullifier().0;
    for mutation in 0..3 {
        let mut parent = isolated_sapling_parent();
        parent.deferred_balance = 7_875_000_000_000;
        parent.issued_supply += 7_875_000_000_000;
        if mutation == 0 { parent.sapling_anchors.remove(&anchor); }
        if mutation == 1 { parent.nullifiers[1].insert(nullifier); }
        if mutation == 2 {
            let leaf = SaplingNode::from_cmu(bundle.shielded_outputs()[0].cmu());
            parent.sapling_tree = Frontier::from_parts(((1_u64 << 32) - 2).into(), leaf, vec![leaf; 31]).unwrap();
            parent.shielded_roots[1] = parent.sapling_tree.root().to_bytes();
            parent.sapling_anchors.insert(parent.shielded_roots[1]);
        }
        let expected = [SproutLedgerError::UnknownSaplingAnchor, SproutLedgerError::SpentSaplingNullifier, SproutLedgerError::SaplingTreeFull][mutation];
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu61_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(v4(&source, BranchId::Nu6_1, 0)))], height, 1_800_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
    let parent = isolated_sapling_parent();
    let before = owned_state(&parent);
    let mut delta = BlockDelta::new(&parent);
    parent.stage_sapling(&source, &mut delta).unwrap();
    let mut expected = incrementalmerkletree::frontier::CommitmentTree::<SaplingNode, 32>::empty();
    for output_description in bundle.shielded_outputs() { expected.append(SaplingNode::from_cmu(output_description.cmu())).unwrap(); }
    assert_eq!((delta.sapling_tree.tree_size(), delta.sapling_nullifiers.len()), (2, 1));
    assert_eq!(delta.sapling_tree.root().to_bytes(), expected.root().to_bytes());
    assert_eq!(parent.stage_sapling(&source, &mut delta), Err(SproutLedgerError::SpentSaplingNullifier));
    let current = delta.sapling_tree.root().to_bytes();
    let current_spend = sapling_spend(current, [0xd6; 32]);
    let transaction = v4(&modified_sapling(vec![current_spend], bundle.shielded_outputs().to_vec(), 0, None), BranchId::Nu6_1, 0);
    assert_eq!(parent.stage_sapling(&transaction, &mut delta), Err(SproutLedgerError::UnknownSaplingAnchor));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu61_v4_joinsplit_positive_deposits_stay_disabled_and_zip215_never_bypasses_groth() {
    let height = 3_536_500;
    let original = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Nu6_1).unwrap();
    assert_eq!(check_transaction(&v4(&original, BranchId::Nu6_1, 0), height, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::SproutDepositDisabled));
    for credit in [0_u64, 10_000] {
        let mut sprout = original.sprout_bundle().unwrap().clone();
        let mut raw = Vec::new();
        sprout.joinsplits[0].write(&mut raw).unwrap();
        raw[..8].fill(0);
        raw[8..16].copy_from_slice(&credit.to_le_bytes());
        sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap();
        sprout.joinsplit_pubkey = [0; 32];
        sprout.joinsplit_sig = [0; 64];
        sprout.joinsplit_sig[0] = 1;
        let mut parent = isolated_deferred_parent(7_875_000_000_000);
        parent.sprout_anchors.insert(*sprout.joinsplits[0].anchor(), Frontier::empty());
        parent.shielded_balances[0] = credit;
        parent.issued_supply += credit;
        let before = owned_state(&parent);
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6_1, 0, 0.into(), None, Some(sprout), None, None).freeze().unwrap();
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu61_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(tx))], height, 1_800_000_000), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof }))));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu61_expiry_finality_maturity_generation_and_parent_wide_bip30_keep_original_rules() {
    let height = 3_536_501;
    let key = ([0xd7; 32], 0);
    for version in [TxVersion::V4, TxVersion::V5] {
        for expiry in [0, height - 1, height, height + 1, 499_999_999, 500_000_000] {
            let parent = isolated_deferred_parent(13);
            let before = owned_state(&parent);
            let result = stage_nu6_transactions(&parent, &[nu61_coinbase(height, version, expiry)], height);
            if expiry == height { assert!(result.is_ok()); } else { assert!(matches!(result, Err(SproutLedgerError::InvalidCoinbase))); }
            assert_eq!(owned_state(&parent), before);
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, 0, expiry.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let raw = encoded(&tx);
            let result = if version == TxVersion::V4 { check_transaction(&tx, height, 1_800_000_000).map(|_| ()) } else { check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), height, 1_800_000_000).map(|_| ()) };
            assert_eq!(result, if expiry >= 500_000_000 { Err(SproutLedgerError::InvalidTransaction) } else if expiry != 0 && expiry < height { Err(SproutLedgerError::ExpiredTransaction) } else { Ok(()) });
        }
        for (lock, sequence, accepted) in [(height - 1, 0, true), (height, 0, false), (height, u32::MAX, true), (1_799_999_999, 0, true), (1_800_000_000, 0, false)] {
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, lock, 0.into(), spend(&[(key, &[], sequence)], vec![output(0, &[0x51])], lock).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let raw = encoded(&tx);
            let result = if version == TxVersion::V4 { check_transaction(&tx, height, 1_800_000_000).map(|_| ()) } else { check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), height, 1_800_000_000).map(|_| ()) };
            assert_eq!(result, if accepted { Ok(()) } else { Err(SproutLedgerError::NonfinalTransaction) });
        }
        for (created, expected) in [(height - 100, SproutLedgerError::UnshieldedCoinbaseSpend), (height - 99, SproutLedgerError::ImmatureCoinbase)] {
            let mut parent = isolated_deferred_parent(13);
            fund(&mut parent, key, 0, &[0x51], created, true);
            let before = owned_state(&parent);
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[nu61_coinbase(height, version, height), tx], height), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
        let mut parent = isolated_deferred_parent(13);
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, &[nu61_coinbase(height + 1, version, height)], height), Err(SproutLedgerError::InvalidCoinbase)));
        for old_branch in [BranchId::Nu5, BranchId::Nu6] {
            let old = TransactionData::<Authorized>::from_parts(version, old_branch, 0, height.into(), nu61_coinbase(height, version, height).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[old], height), Err(SproutLedgerError::UnsupportedTransaction)));
        }
        assert_eq!(owned_state(&parent), before);
        let reward = nu61_coinbase(height, version, height);
        let id: [u8; 32] = reward.txid().into();
        fund(&mut parent, (id, 999), 1, &[0x51], 0, false);
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, &[reward], height), Err(SproutLedgerError::UnspentTransactionOverwrite)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu61_ordered_v4_v5_spends_resolve_prior_outputs_without_future_duplicate_or_negative_fees() {
    let height = 3_536_500;
    let key = ([0xd8; 32], 0);
    let (_, prevouts) = independently_signed_v5_for_branch(&[([0; 32], 0), ([1; 32], 1)], BranchId::Nu6_1, true, 1);
    let first = v4(&spend(&[(key, &[], u32::MAX)], prevouts, 0), BranchId::Nu6_1, 0);
    let first_id: [u8; 32] = first.txid().into();
    let (second, _) = independently_signed_v5_for_branch(&[(first_id, 0), (first_id, 1)], BranchId::Nu6_1, true, 1);
    let second_id = RawV5::parse_exact(&second).unwrap().effect_id();
    let third = v4(&spend(&[((second_id, 0), &[], u32::MAX), ((second_id, 1), &[], u32::MAX)], vec![output(199_999, &[0x51])], 0), BranchId::Nu6_1, 0);
    let mut parent = isolated_deferred_parent(7_875_000_000_000);
    fund(&mut parent, key, 200_010, &[0x51], 0, false);
    let before = owned_state(&parent);
    let mut outputs = nu61_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
    outputs[0] = output(125_000_011, &[0x51]);
    let reward = nu61_with_outputs(height, TxVersion::V4, outputs);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&second), PostNu5Transaction::V4(Box::new(first.clone()))], height, 1_800_000_000), Err(SproutLedgerError::MissingTransparentInput)));
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(first.clone())), original_v5(&second), original_v5(&second)], height, 1_800_000_000), Err(SproutLedgerError::MissingTransparentInput)));
    let negative = v4(&spend(&[(key, &[], u32::MAX)], vec![output(200_011, &[0x51])], 0), BranchId::Nu6_1, 0);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(negative))], height, 1_800_000_000), Err(SproutLedgerError::NegativeFee)));
    assert_eq!(owned_state(&parent), before);
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward)), PostNu5Transaction::V4(Box::new(first)), original_v5(&second), PostNu5Transaction::V4(Box::new(third))], height, 1_800_000_000).unwrap();
    assert_eq!((delta.fees, delta.deferred, delta.issued), (11, 18_750_000, 7_875_156_450_010));
    parent.commit(delta);
    for (id, index) in [(key.0, key.1), (first_id, 0), (first_id, 1), (second_id, 0), (second_id, 1)] { assert!(parent.utxo(&id, index).is_none()); }
}

#[test]
fn nu61_cardinality_two_megabytes_sigops_and_each_money_side_are_not_netted_or_waived() {
    let height = 3_536_501;
    let key = ([0xd9; 32], 0);
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    for (spends, outputs) in [(65_536, 0), (0, 65_536)] {
        let tx = v4(&modified_sapling(vec![bundle.shielded_spends()[0].clone(); spends], vec![bundle.shielded_outputs()[0].clone(); outputs], 0, spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned()), BranchId::Nu6_1, 0);
        assert_eq!(check_transaction(&tx, height, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::InvalidTransaction));
    }
    for (spends, outputs, vin, vout, accepted) in [(false, false, true, true, true), (false, true, false, false, false), (true, false, false, false, false), (true, true, false, false, true), (false, true, true, false, true), (true, false, false, true, true)] {
        let mut transparent = spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().unwrap().clone();
        if !vin { transparent.vin.clear(); }
        if !vout { transparent.vout.clear(); }
        let tx = v4(&modified_sapling(if spends { bundle.shielded_spends().to_vec() } else { vec![] }, if outputs { bundle.shielded_outputs().to_vec() } else { vec![] }, 0, Some(transparent)), BranchId::Nu6_1, 0);
        assert_eq!(check_transaction(&tx, height, 1_800_000_000).is_ok(), accepted);
    }
    for (length, accepted) in [(1_999_917, true), (1_999_918, false)] {
        let tx = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0; length])], 0), BranchId::Nu6_1, 0);
        assert_eq!(check_transaction(&tx, height, 1_800_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::TransactionTooLarge) });
    }
    for (count, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = isolated_deferred_parent(13);
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let before = owned_state(&parent);
        let mut outputs = nu61_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
        outputs[0] = output(125_000_000, &[0xac]);
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu6_1, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; count])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        let result = stage_nu6_transactions(&parent, &[nu61_with_outputs(height, TxVersion::V4, outputs), tx], height);
        if accepted { assert_eq!(result.unwrap().sigops, 20_000); } else { assert!(matches!(result, Err(SproutLedgerError::TooManySigops))); }
        assert_eq!(owned_state(&parent), before);
    }
    for balance in [-(MAX_MONEY as i64), MAX_MONEY as i64] {
        let mut parent = isolated_deferred_parent(13);
        fund(&mut parent, key, 1, &[0x51], 0, false);
        let before = owned_state(&parent);
        let tx = v4(&modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), balance, spend(&[(key, &[], u32::MAX)], vec![output(1, &[0x51])], 0).transparent_bundle().cloned()), BranchId::Nu6_1, 0);
        assert!(matches!(stage_nu6_transactions(&parent, &[nu61_coinbase(height, TxVersion::V4, height), tx], height), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu61_all_orchard_nullifiers_parent_anchors_and_capacity_remain_independent_before_disable() {
    let height = 3_536_500;
    let original = RawV5::parse_exact(&NU61_ORCHARD_COINBASE).unwrap();
    let bundle = original.orchard().unwrap();
    for action in bundle.actions().as_chunks::<820>().0 {
        let mut parent = isolated_deferred_parent(7_875_000_000_000);
        parent.nullifiers[2].insert(action[32..64].try_into().unwrap());
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE)], height, 1_800_000_000), Err(SproutLedgerError::SpentOrchardNullifier)));
        assert_eq!(owned_state(&parent), before);
    }
    for free in [0, 1] {
        let mut parent = isolated_deferred_parent(7_875_000_000_000);
        let leaf = MerkleHashOrchard::from_bytes(bundle.actions()[96..128].try_into().unwrap()).unwrap();
        parent.orchard_tree = Frontier::from_parts(((1_u64 << 32) - 1 - free).into(), leaf, vec![leaf; 32 - free as usize]).unwrap();
        parent.shielded_roots[2] = parent.orchard_tree.root().to_bytes();
        parent.orchard_anchors.insert(parent.shielded_roots[2]);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE)], height, 1_800_000_000), Err(SproutLedgerError::OrchardTreeFull)));
        assert_eq!(owned_state(&parent), before);
    }
    let parent = isolated_deferred_parent(7_875_000_000_000);
    let before = owned_state(&parent);
    let mut delta = BlockDelta::new(&parent);
    parent.stage_orchard(Some(bundle), &mut delta).unwrap();
    let current = delta.orchard_tree.root().to_bytes();
    let mut changed = NU61_ORCHARD_OUTPUTS_DISABLED.to_vec();
    let transaction = RawV5::parse_exact(&changed).unwrap();
    let ordinary = transaction.orchard().unwrap();
    let anchor = ordinary.actions().as_ptr() as usize - changed.as_ptr() as usize + ordinary.action_count() * 820 + 9;
    changed[anchor..anchor + 32].copy_from_slice(&current);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::UnknownOrchardAnchor)));
    assert_eq!(owned_state(&parent), before);
    let mut bad = isolated_deferred_parent(7_875_000_000_000);
    bad.orchard_anchors.clear();
    let snapshot = owned_state(&bad);
    assert!(matches!(bad.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE)], height, 1_800_000_000), Err(SproutLedgerError::UnknownOrchardAnchor)));
    assert_eq!(owned_state(&bad), snapshot);
    let offset = bundle.actions().as_ptr() as usize - NU61_ORCHARD_COINBASE.as_ptr() as usize;
    let mut duplicate = NU61_ORCHARD_COINBASE.to_vec();
    duplicate[offset + 820 + 32..offset + 820 + 64].copy_from_slice(&bundle.actions()[32..64]);
    // Changing the dummy nullifier also changes rho, invalidating coinbase
    // recovery before state staging. Exercise the duplicate predicate directly.
    let parsed = RawV5::parse_exact(&duplicate).unwrap();
    let mut delta = BlockDelta::new(&parent);
    assert_eq!(parent.stage_orchard(parsed.orchard(), &mut delta), Err(SproutLedgerError::SpentOrchardNullifier));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu61_signed_deferred_delta_and_every_pool_range_are_independent_atomic_predicates() {
    let height = 3_536_500;
    let reward = nu61_coinbase(height, TxVersion::V4, height);
    let values = check_coinbase(&reward, height, 1_800_000_000).unwrap();
    for deferred in [-7_874_981_250_001_i128, -7_874_981_249_999, 18_750_000] {
        let parent = isolated_deferred_parent(7_875_000_000_000);
        let before = owned_state(&parent);
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = values.transparent.into();
        delta.retained = values.retained.into();
        delta.deferred = deferred;
        assert!(matches!(parent.finish_delta(delta, values, height), Err(SproutLedgerError::CoinbaseRewardExceeded)));
        assert_eq!(owned_state(&parent), before);
    }
    for pool in 0..6 {
        let mut parent = isolated_deferred_parent(7_875_000_000_000);
        if pool == 0 { parent.transparent_balance = MAX_MONEY - 7_875_000_000_000; }
        else if pool < 5 { parent.shielded_balances[pool - 1] = MAX_MONEY - 7_875_000_000_000; }
        else { parent.deferred_balance = MAX_MONEY; }
        parent.issued_supply = MAX_MONEY;
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
    for version in [TxVersion::V4, TxVersion::V5] {
        let parent = isolated_deferred_parent(13);
        let before = owned_state(&parent);
        let mut outputs = nu61_coinbase(height + 1, version, height + 1).transparent_bundle().unwrap().vout.clone();
        outputs.push(output(18_750_000, &[0x51]));
        assert!(matches!(stage_nu6_transactions(&parent, &[nu61_with_outputs(height + 1, version, outputs)], height + 1), Err(SproutLedgerError::CoinbaseRewardExceeded)));
        assert_eq!(owned_state(&parent), before);
        // Required withdrawal chunks are activation-only; after activation they
        // cannot be appended as newly minted reward or consume old deferred.
        let mut outputs = nu61_coinbase(height + 1, version, height + 1).transparent_bundle().unwrap().vout.clone();
        outputs.extend((0..10).map(|_| output(787_500_000_000, &bytes(NU61_DISBURSEMENT_SCRIPT))));
        assert!(matches!(stage_nu6_transactions(&parent, &[nu61_with_outputs(height + 1, version, outputs)], height + 1), Err(SproutLedgerError::CoinbaseRewardExceeded)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu61_pruned_claims_are_issued_not_retained_and_activation_outputs_are_actual_owned_coins() {
    let height = 3_536_500;
    for version in [TxVersion::V4, TxVersion::V5] {
        for (script, retained, count) in [(vec![0x6a], 7_875_012_500_000, 11), (vec![0; 10_001], 7_875_012_500_000, 11), (vec![0; 10_000], 7_875_137_500_000, 12)] {
            let mut outputs = nu61_coinbase(height, version, height).transparent_bundle().unwrap().vout.clone();
            outputs[0] = output(125_000_000, &script);
            let reward = nu61_with_outputs(height, version, outputs);
            let id: [u8; 32] = reward.txid().into();
            let mut parent = isolated_deferred_parent(7_875_000_000_000);
            let before = owned_state(&parent);
            let delta = stage_nu6_transactions(&parent, &[reward], height).unwrap();
            assert_eq!((delta.transparent, delta.retained, delta.deferred, delta.issued), (7_875_137_500_000, retained, 18_750_000, 7_875_156_250_000));
            assert_eq!(owned_state(&parent), before);
            parent.commit(delta);
            assert_eq!(parent.utxo_count(), count);
            assert_eq!(parent.utxo(&id, 0).is_some(), count == 12);
            for index in 2..12 {
                let coin = parent.utxo(&id, index).unwrap();
                assert_eq!(u64::from(coin.output().value()), 787_500_000_000);
                assert_eq!(coin.output().script_pubkey().0.0, bytes(NU61_DISBURSEMENT_SCRIPT));
                assert_eq!((coin.created_height(), coin.is_coinbase()), (height, true));
            }
            assert!(parent.utxo(&id, 12).is_none()); // D creates no output.
        }
    }
}

#[test]
fn nu61_original_orchard_coinbase_still_admits_immediately_before_disable() {
    let height = 4_048_499;
    let raw = synthetic_original_orchard_at(true, BranchId::Nu6_1, height);
    let mut parent = isolated_deferred_parent(13);
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(vec![original_v5(&raw)], height, 1_800_000_000).unwrap();
    assert_eq!((delta.transparent, delta.orchard, delta.deferred, delta.issued), (137_499_993, 7, 18_750_013, 156_250_013));
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard)), (2, 2));
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&raw)], 4_048_500, 1_800_000_000), Err(SproutLedgerError::OrchardDisabled)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu61_v5_original_sapling_proofs_still_reach_each_real_equation_without_old_signature_fallback() {
    let height = 3_536_500;
    let source = include_bytes!("../tests/fixtures/nu5-mixed-testnet-1842421.bin");
    let original = RawV5::parse_exact(source).unwrap();
    let sapling = original.sapling_bundle().unwrap();
    let mut changed = source.to_vec();
    changed[8..12].copy_from_slice(&u32::from(BranchId::Nu6_1).to_le_bytes());
    changed[16..20].fill(0); // Unlimited ordinary expiry, not old wallet expiry.
    let raw = RawV5::parse_exact(&changed).unwrap();
    // Genuine fixed-key proofs survive the branch change, but every old
    // SpendAuth message must not be relabeled. No fallback to original digest.
    let mut parent = isolated_original_nu5_parent(source);
    parent.deferred_balance = 7_875_000_000_000;
    parent.issued_supply += 7_875_000_000_000;
    let before = owned_state(&parent);
    let hashes = raw.into_signature_context(vec![]).unwrap();
    assert_eq!(verify_sapling_post_nu5_crypto(&hashes), Err(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }));
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu61_coinbase(height, TxVersion::V4, height))), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let spends = sapling.shielded_spends().len();
    let outputs = sapling.shielded_outputs().len();
    assert_eq!(spends, 4);
    let anchor = 24 + spends * 96 + outputs * 756 + 8;
    let proof = anchor + 32;
    let mut bad = changed.clone();
    bad[proof] ^= 0x20;
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu61_coinbase(height, TxVersion::V4, height))), original_v5(&bad)], height, 1_800_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    for spend in sapling.shielded_spends() {
        let mut bad = isolated_original_nu5_parent(source);
        bad.deferred_balance = 7_875_000_000_000;
        bad.issued_supply += 7_875_000_000_000;
        bad.nullifiers[1].insert(spend.nullifier().0);
        let snapshot = owned_state(&bad);
        assert!(matches!(bad.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu61_coinbase(height, TxVersion::V4, height))), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::SpentSaplingNullifier)));
        assert_eq!(owned_state(&bad), snapshot);
    }
}

#[test]
fn nu61_negative_only_coinbase_claim_does_not_use_recovered_orchard_note_sum() {
    let height = 3_536_500;
    let original = RawV5::parse_exact(&NU61_ORCHARD_COINBASE).unwrap();
    let bundle = original.orchard().unwrap();
    let balance = bundle.actions().as_ptr() as usize - NU61_ORCHARD_COINBASE.as_ptr() as usize + bundle.action_count() * 820 + 1;
    for (value_balance, claimed) in [(-7_i64, 7_875_137_500_000), (0, 7_875_137_499_993), (7, 7_875_137_499_993)] {
        let mut raw = NU61_ORCHARD_COINBASE.to_vec();
        raw[balance..balance + 8].copy_from_slice(&value_balance.to_le_bytes());
        let values = check_post_nu5_coinbase(&original_v5(&raw), height, 1_800_000_000).unwrap();
        assert_eq!((values.claimed, values.transparent, values.orchard_balance), (claimed, 7_875_137_499_993, value_balance));
        let parent = isolated_deferred_parent(7_875_000_000_000);
        let before = owned_state(&parent);
        if value_balance == -7 {
            let delta = parent.stage_post_nu5_block(vec![original_v5(&raw)], height, 1_800_000_000).unwrap();
            assert_eq!((delta.issued, delta.orchard, delta.deferred), (7_875_156_250_000, 7, 18_750_000));
        } else {
            assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&raw)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(RawV5Error::InvalidOrchardSpendAuth { index: 0 }))));
        }
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu61_expiry_branch_and_late_script_errors_roll_back_all_staged_fees_outputs_and_deferred() {
    let height = 3_536_500;
    let first_key = ([0xda; 32], 0);
    let second_key = ([0xdb; 32], 0);
    for version in [TxVersion::V4, TxVersion::V5] {
        let first = v4(&spend(&[(first_key, &[], u32::MAX)], vec![output(19, &[0x51])], 0), BranchId::Nu6_1, 0);
        let late = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, 0, 0.into(), spend(&[(second_key, &[], u32::MAX)], vec![output(29, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        let mut outputs = nu61_coinbase(height, TxVersion::V4, height).transparent_bundle().unwrap().vout.clone();
        outputs[0] = output(125_000_002, &[0x51]);
        let reward = nu61_with_outputs(height, TxVersion::V4, outputs);
        for mutation in 0..3 {
            let mut parent = isolated_deferred_parent(7_875_000_000_000);
            fund(&mut parent, first_key, 20, &[0x51], 0, false);
            fund(&mut parent, second_key, 30, if mutation == 2 { &[0x00] } else { &[0x51] }, 0, false);
            let transaction = TransactionData::<Authorized>::from_parts(version,
                if mutation == 1 { BranchId::Nu6 } else { BranchId::Nu6_1 },
                0, (if mutation == 0 { height - 1 } else { 0 }).into(), late.transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let before = owned_state(&parent);
            let expected = [SproutLedgerError::ExpiredTransaction, SproutLedgerError::UnsupportedTransaction, SproutLedgerError::InvalidTransparentScript][mutation];
            assert!(matches!(stage_nu6_transactions(&parent, &[reward.clone(), first.clone(), transaction], height), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
            if mutation == 2 {
                parent.utxos.get_mut(&second_key).unwrap().output = output(30, &[0x51]);
            }
            let delta = stage_nu6_transactions(&parent, &[reward.clone(), first.clone(), late.clone()], height).unwrap();
            assert_eq!((delta.fees, delta.deferred, delta.issued), (2, 18_750_000, 7_875_156_250_050));
            parent.commit(delta);
            assert!(parent.utxo(&first_key.0, first_key.1).is_none());
            assert!(parent.utxo(&second_key.0, second_key.1).is_none());
            assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
        }
    }
}

#[test]
fn nu61_shape_rejects_every_duplicate_null_input_and_wrong_coinbase_generation_atomically() {
    let height = 3_536_500;
    let key = ([0xdc; 32], 0);
    for version in [TxVersion::V4, TxVersion::V5] {
        let mut parent = isolated_deferred_parent(7_875_000_000_000);
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let before = owned_state(&parent);
        for (inputs, expected) in [
            (vec![(key, &[][..], u32::MAX), (key, &[][..], u32::MAX)], SproutLedgerError::DuplicateTransparentInput),
            (vec![(([0; 32], u32::MAX), &[][..], u32::MAX)], SproutLedgerError::InvalidCoinbase),
        ] {
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, 0, 0.into(), spend(&inputs, vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[nu61_coinbase(height, version, height), tx], height), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
        for mutation in 0..3 {
            let reward = nu61_coinbase(height, version, height);
            let mut transparent = reward.transparent_bundle().unwrap().clone();
            let mut script = transparent.vin[0].script_sig().clone();
            match mutation {
                0 => script.0.0 = vec![0x51],
                1 => script.0.0.resize(101, 0),
                2 => script.0.0[1] ^= 1,
                _ => unreachable!(),
            }
            transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_1, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[tx], height), Err(SproutLedgerError::InvalidCoinbase)));
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn nu61_activation_requires_owned_nu6_metadata_not_a_root_only_checkpoint() {
    let height = 3_536_500;
    let auth = [0x31; 32];
    let parent = isolated_deferred_parent(7_875_000_000_000);
    let leaf = post_nu5_leaf(height, parent.shielded_roots[1], parent.shielded_roots[2], 0, 0);
    let root = ChainHistoryV2::new(post_nu5_leaf(height - 1, parent.shielded_roots[1], parent.shielded_roots[2], 0, 0)).unwrap().root();
    let commitment = block_commitment(root, auth);
    let mut parent = parent;
    parent.history_root = Some(root);
    let before = owned_state(&parent);
    assert_eq!(parent.stage_post_nu5_history(&commitment, &auth, leaf).unwrap_err(), SproutLedgerError::WrongHistoryRoot);
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu61_disable_guard_rejects_present_orchard_even_in_a_misclassified_typed_variant() {
    let parent = isolated_deferred_parent(13);
    let before = owned_state(&parent);
    let transaction = Transaction::read(NU61_ORCHARD_COINBASE.as_slice(), BranchId::Nu6_1).unwrap();
    assert!(transaction.orchard_bundle().is_some());
    // The internal enum's variant name is not an authentication certificate.
    // Detect presence before trusting its claimed V4 classification or crypto.
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(transaction))], 4_048_500, 1_800_000_000), Err(SproutLedgerError::OrchardDisabled)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu62_activation_continues_deferred_credit_without_repeating_disbursement() {
    // Monetary staging only; this parent is synthetic, not a connected archive.
    let height = 4_052_000u32;
    let initial = 9_665_625_000_000u64;
    let mut parent = isolated_deferred_parent(initial);
    let source = nu61_coinbase(4_051_999, TxVersion::V4, 4_051_999);
    let mut transparent = source.transparent_bundle().unwrap().clone();
    let (prefix, length) = coinbase_height_prefix(height);
    let mut script = Script::default();
    script.0.0.extend_from_slice(&prefix[..length]);
    script.0.0.push(0);
    transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
    let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6_2,
        0, height.into(), Some(transparent), None, None, None).freeze().unwrap();
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(transaction))], height, 1_800_000_000).unwrap();
    assert_eq!(delta.issued, initial + 156_250_000);
    assert_eq!(delta.transparent, 137_500_000);
    assert_eq!(delta.deferred, i128::from(initial + 18_750_000));
    parent.commit(delta);
    assert_eq!(parent.deferred_balance(), initial + 18_750_000);
    assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
}

fn nu62_coinbase(height: u32, version: TxVersion, expiry: u32) -> Transaction {
    let source = nu61_coinbase(height, version, expiry);
    TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, 0, expiry.into(), source.transparent_bundle().cloned(), None, None, None).freeze().unwrap()
}

fn nu62_with_outputs(height: u32, version: TxVersion, outputs: Vec<TxOut>) -> Transaction {
    let mut transparent = nu62_coinbase(height, version, height).transparent_bundle().unwrap().clone();
    transparent.vout = outputs;
    TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap()
}

#[test]
fn nu62_real_fixed_two_action_coinbase_and_ordinary_execute_all_equations_and_state() {
    let height = 4_052_000;
    let mut parent = isolated_deferred_parent(13);
    let before = owned_state(&parent);
    let verifier = FixedOrchardVerifier::new();
    let mut expected = incrementalmerkletree::frontier::CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for (raw, flags, balance) in [(&NU62_ORCHARD_COINBASE, 2, -7), (&NU62_ORCHARD_OUTPUTS_DISABLED, 1, 0)] {
        let transaction = RawV5::parse_exact(raw).unwrap();
        assert_eq!(transaction.consensus_branch_id(), BranchId::Nu6_2);
        let bundle = transaction.orchard().copied().unwrap();
        assert_eq!((bundle.action_count(), bundle.proof().len(), i64::from(bundle.value_balance())), (2, 7_264, balance));
        assert_eq!(bundle.flags().to_byte(orchard::bundle::BundleVersion::orchard_v2()), Some(flags));
        let sighash = transaction.into_signature_context(vec![]).unwrap().shielded();
        assert_eq!(bundle.verify_orchard_fixed(&verifier, &sighash), Ok(()));
        assert_eq!(bundle.verify_orchard(&OriginalOrchardVerifier::new(), &sighash), Err(RawV5Error::OrchardVerifierModeMismatch));
        let mut wrong = sighash;
        wrong[0] ^= 1;
        assert_eq!(bundle.verify_orchard_fixed(&verifier, &wrong), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
        for action in bundle.actions().as_chunks::<820>().0 {
            expected.append(MerkleHashOrchard::from_bytes(action[96..128].try_into().unwrap()).unwrap()).unwrap();
        }
    }
    let values = check_post_nu5_coinbase(&original_v5(&NU62_ORCHARD_COINBASE), height, 1_800_000_000).unwrap();
    assert_eq!((values.claimed, values.transparent, values.orchard_balance), (137_500_000, 137_499_993, -7));
    let delta = parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_OUTPUTS_DISABLED)], height, 1_800_000_000).unwrap();
    assert_eq!((delta.transparent, delta.orchard, delta.deferred, delta.issued, delta.fees), (137_499_993, 7, 18_750_013, 156_250_013, 0));
    assert_eq!((delta.orchard_tree.tree_size(), delta.orchard_nullifiers.len()), (4, 4));
    assert_eq!(delta.orchard_root, expected.root().to_bytes());
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard), parent.shielded_balance(ShieldedPool::Orchard)), (4, 4, 7));
    assert_eq!(parent.transparent_balance() + parent.shielded_balance(ShieldedPool::Orchard) + parent.deferred_balance(), parent.issued_supply());
    assert!(!parent.pool_is_active(ShieldedPool::Ironwood));
}

#[test]
fn nu62_actual_old_circuit_signed_for_new_branch_never_falls_back_from_fixed_key() {
    let height = 4_052_000;
    let parent = isolated_deferred_parent(13);
    let before = owned_state(&parent);
    let old = RawV5::parse_exact(&NU62_ORCHARD_OLD_KEY).unwrap();
    let bundle = old.orchard().copied().unwrap();
    let sighash = old.into_signature_context(vec![]).unwrap().shielded();
    // This proof was actually made with the original PK, while its real dummy
    // SpendAuth and binding signatures authenticate a NU6.2 message.
    assert_eq!(bundle.verify_orchard_fixed(&FixedOrchardVerifier::new(), &sighash), Err(RawV5Error::InvalidOrchardProof));
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_OLD_KEY)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(RawV5Error::InvalidOrchardProof))));
    for old in [&NU61_ORCHARD_COINBASE, &NU61_ORCHARD_OUTPUTS_DISABLED] {
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(old)], height, 1_800_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    }
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu62_each_fixed_proof_dummy_spendauth_binding_and_full_coinbase_ciphertext_is_required() {
    let height = 4_052_000;
    let verifier = FixedOrchardVerifier::new();
    for (raw, coinbase) in [(&NU62_ORCHARD_COINBASE, true), (&NU62_ORCHARD_OUTPUTS_DISABLED, false)] {
        let original = RawV5::parse_exact(raw).unwrap();
        let bundle = original.orchard().copied().unwrap();
        let actions = bundle.actions().as_ptr() as usize - raw.as_ptr() as usize;
        let proof = bundle.proof().as_ptr() as usize - raw.as_ptr() as usize;
        let signatures = bundle.spend_auth_signatures().as_ptr() as usize - raw.as_ptr() as usize;
        let binding = bundle.binding_signature().as_ptr() as usize - raw.as_ptr() as usize;
        let sighash = original.into_signature_context(vec![]).unwrap().shielded();
        let mut mutations = vec![(proof, RawV5Error::InvalidOrchardProof), (binding + 63, RawV5Error::InvalidOrchardBindingSignature)];
        for index in 0..2 { mutations.push((signatures + index * 64 + 63, RawV5Error::InvalidOrchardSpendAuth { index })); }
        for (offset, expected) in mutations {
            let mut parent = isolated_deferred_parent(13);
            let key = ([0xe3; 32], 0);
            fund(&mut parent, key, 20, &[0x51], 0, false);
            let good = v4(&spend(&[(key, &[], u32::MAX)], vec![output(20, &[0x51])], 0), BranchId::Nu6_2, 0);
            let before = owned_state(&parent);
            let mut changed = raw.to_vec();
            changed[offset] ^= 1;
            let parsed = RawV5::parse_exact(&changed).unwrap();
            assert_eq!(parsed.orchard().unwrap().verify_orchard_fixed(&verifier, &sighash), Err(expected));
            let mut transactions = if coinbase { vec![original_v5(&changed)] } else { vec![original_v5(&NU62_ORCHARD_COINBASE)] };
            transactions.push(PostNu5Transaction::V4(Box::new(good.clone())));
            if !coinbase { transactions.push(original_v5(&changed)); }
            assert!(matches!(parent.stage_post_nu5_block(transactions, height, 1_800_000_000), Err(SproutLedgerError::Orchard(actual)) if actual == expected));
            assert_eq!(owned_state(&parent), before);
            let delta = parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), PostNu5Transaction::V4(Box::new(good)), original_v5(&NU62_ORCHARD_OUTPUTS_DISABLED)], height, 1_800_000_000).unwrap();
            parent.commit(delta);
            assert!(parent.utxo(&key.0, key.1).is_none());
            assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard), parent.deferred_balance()), (4, 4, 18_750_013));
        }
        if coinbase {
            for index in 0..2 {
                for byte in [160, 739, 740, 819] {
                    let parent = isolated_deferred_parent(13);
                    let before = owned_state(&parent);
                    let mut changed = raw.to_vec();
                    changed[actions + index * 820 + byte] ^= 1;
                    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(RawV5Error::CoinbaseRecovery { index: actual })) if actual == index));
                    assert_eq!(owned_state(&parent), before);
                }
            }
        }
    }
}

#[test]
fn nu62_real_fixed_framing_flags_rk_epk_and_identity_cv_have_the_exact_admission_predicate() {
    use zcash_note_encryption::{Domain, EphemeralKeyBytes};
    let raw = &NU62_ORCHARD_OUTPUTS_DISABLED;
    let original = RawV5::parse_exact(raw).unwrap();
    let bundle = original.orchard().unwrap();
    let actions = bundle.actions().as_ptr() as usize - raw.as_ptr() as usize;
    let proof = bundle.proof().as_ptr() as usize - raw.as_ptr() as usize;
    let signatures = bundle.spend_auth_signatures().as_ptr() as usize - raw.as_ptr() as usize;
    let parent = isolated_deferred_parent(13);
    let before = owned_state(&parent);
    for extra in [-1_isize, 1, 16] {
        let mut changed = raw.to_vec();
        assert_eq!(changed[proof - 3], 0xfd);
        changed[proof - 2..proof].copy_from_slice(&u16::try_from(bundle.proof().len().checked_add_signed(extra).unwrap()).unwrap().to_le_bytes());
        if extra < 0 { changed.remove(signatures - 1); }
        else { changed.splice(signatures..signatures, std::iter::repeat_n(0x42, extra as usize)); }
        assert!(matches!(RawV5::parse_exact(&changed), Err(RawV5Error::InvalidOrchardProofLength)));
    }
    for flags in [0, 4, 5, 6, 7, 0x80, 0xff] {
        let mut changed = raw.to_vec();
        changed[actions + 2 * 820] = flags;
        assert!(matches!(RawV5::parse_exact(&changed), Err(RawV5Error::InvalidOrchardFlags)));
    }
    let off_curve = (1_u8..=255).find_map(|coordinate| {
        let mut epk = [0; 32];
        epk[0] = coordinate;
        let decoded = orchard::note_encryption::OrchardDomain::epk(&EphemeralKeyBytes(epk));
        decoded.is_none().then_some(epk)
    }).unwrap();
    for index in 0..2 {
        for key in [[0; 32], [0xff; 32]] {
            let mut changed = raw.to_vec();
            changed[actions + index * 820 + 64..actions + index * 820 + 96].copy_from_slice(&key);
            assert!(matches!(RawV5::parse_exact(&changed), Err(RawV5Error::InvalidOrchardRandomizedKey { index: actual }) if actual == index));
        }
        for epk in [[0; 32], [0xff; 32], off_curve] {
            let mut changed = raw.to_vec();
            changed[actions + index * 820 + 128..actions + index * 820 + 160].copy_from_slice(&epk);
            assert!(matches!(RawV5::parse_exact(&changed), Err(RawV5Error::InvalidOrchardEphemeralKey { index: actual }) if actual == index));
        }
        // Identity cv is valid curve data; no invented cv/binding nonidentity
        // ban. The real unchanged authorization must reject the changed effect.
        let mut changed = raw.to_vec();
        changed[actions + index * 820..actions + index * 820 + 32].fill(0);
        let parsed = RawV5::parse_exact(&changed).unwrap();
        let bundle = parsed.orchard().copied().unwrap();
        let sighash = parsed.into_signature_context(vec![]).unwrap().shielded();
        assert_eq!(bundle.verify_orchard_fixed(&FixedOrchardVerifier::new(), &sighash), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
    }
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu62_every_dummy_nullifier_commitment_parent_anchor_and_depth32_capacity_stay_required() {
    let height = 4_052_000;
    for (raw, coinbase) in [(&NU62_ORCHARD_COINBASE, true), (&NU62_ORCHARD_OUTPUTS_DISABLED, false)] {
        let parsed = RawV5::parse_exact(raw).unwrap();
        let bundle = parsed.orchard().unwrap();
        for action in bundle.actions().as_chunks::<820>().0 {
            let mut parent = isolated_deferred_parent(13);
            parent.nullifiers[2].insert(action[32..64].try_into().unwrap());
            let before = owned_state(&parent);
            let transactions = if coinbase { vec![original_v5(raw)] } else { vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(raw)] };
            assert!(matches!(parent.stage_post_nu5_block(transactions, height, 1_800_000_000), Err(SproutLedgerError::SpentOrchardNullifier)));
            assert_eq!(owned_state(&parent), before);
        }
    }
    let parsed = RawV5::parse_exact(&NU62_ORCHARD_COINBASE).unwrap();
    let bundle = parsed.orchard().unwrap();
    for free in [0, 1] {
        let mut parent = isolated_deferred_parent(13);
        let leaf = MerkleHashOrchard::from_bytes(bundle.actions()[96..128].try_into().unwrap()).unwrap();
        parent.orchard_tree = Frontier::from_parts(((1_u64 << 32) - 1 - free).into(), leaf, vec![leaf; 32 - free as usize]).unwrap();
        parent.shielded_roots[2] = parent.orchard_tree.root().to_bytes();
        parent.orchard_anchors.insert(parent.shielded_roots[2]);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE)], height, 1_800_000_000), Err(SproutLedgerError::OrchardTreeFull)));
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = isolated_deferred_parent(13);
    let before = owned_state(&parent);
    let mut delta = BlockDelta::new(&parent);
    parent.stage_orchard(Some(bundle), &mut delta).unwrap();
    let current = delta.orchard_tree.root().to_bytes();
    let mut changed = NU62_ORCHARD_OUTPUTS_DISABLED.to_vec();
    let ordinary = RawV5::parse_exact(&changed).unwrap();
    let ordinary = ordinary.orchard().unwrap();
    let actions = ordinary.actions().as_ptr() as usize - changed.as_ptr() as usize;
    let anchor = actions + ordinary.action_count() * 820 + 9;
    changed[anchor..anchor + 32].copy_from_slice(&current);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::UnknownOrchardAnchor)));
    let mut duplicate = NU62_ORCHARD_OUTPUTS_DISABLED.to_vec();
    duplicate[actions + 820 + 32..actions + 820 + 64].copy_from_slice(&NU62_ORCHARD_OUTPUTS_DISABLED[actions + 32..actions + 64]);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&duplicate)], height, 1_800_000_000), Err(SproutLedgerError::SpentOrchardNullifier)));
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_OUTPUTS_DISABLED), original_v5(&NU62_ORCHARD_OUTPUTS_DISABLED)], height, 1_800_000_000), Err(SproutLedgerError::SpentOrchardNullifier)));
    assert_eq!(owned_state(&parent), before);
    parent.orchard_anchors.clear();
    let before = owned_state(&parent);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE)], height, 1_800_000_000), Err(SproutLedgerError::UnknownOrchardAnchor)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu62_funding_exact_reward_fees_and_pruned_claims_continue_without_second_disbursement() {
    for height in [4_052_000, 4_055_999, 4_056_000, 4_090_999, 4_091_000, 4_125_999, 4_126_000, 4_133_999] {
        for version in [TxVersion::V4, TxVersion::V5] {
            let mut parent = isolated_deferred_parent(13);
            let key = ([0xe4; 32], 0);
            fund(&mut parent, key, 100, &[0x51], 0, false);
            let fee_tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(90, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let before = owned_state(&parent);
            let reward = nu62_coinbase(height, version, height);
            assert_eq!(reward.transparent_bundle().unwrap().vout.len(), 2);
            assert_eq!(subsidy(height), Ok(156_250_000));
            for claim in [9, 10, 11] {
                let mut outputs = reward.transparent_bundle().unwrap().vout.clone();
                outputs[0] = output(124_999_999 + claim, &[0x51]);
                outputs.push(output(1, &[0x6a]));
                let result = stage_nu6_transactions(&parent, &[nu62_with_outputs(height, version, outputs), fee_tx.clone()], height);
                if claim == 10 {
                    let delta = result.unwrap();
                    assert_eq!((delta.fees, delta.transparent, delta.retained, delta.deferred, delta.issued), (10, 137_500_100, 137_500_099, 18_750_013, 156_250_113));
                } else { assert!(matches!(result, Err(SproutLedgerError::CoinbaseRewardExceeded))); }
                assert_eq!(owned_state(&parent), before);
            }
            for mutation in 0..5 {
                let mut outputs = reward.transparent_bundle().unwrap().vout.clone();
                match mutation {
                    0 => { outputs.remove(1); outputs[0] = output(137_500_000, &[0x51]); }
                    1 => outputs[1] = output(12_500_000, &[0x51]),
                    2 => { outputs[1] = output(12_500_001, &bytes(NU6_FPF_SCRIPT)); outputs[0] = output(124_999_999, &[0x51]); }
                    3 => { outputs[1] = output(12_499_999, &bytes(NU6_FPF_SCRIPT)); outputs[0] = output(125_000_001, &[0x51]); }
                    _ => { outputs[1] = output(12_499_999, &bytes(NU6_FPF_SCRIPT)); outputs.push(output(1, &bytes(NU6_FPF_SCRIPT))); }
                }
                assert!(matches!(stage_nu6_transactions(&parent, &[nu62_with_outputs(height, version, outputs)], height), Err(SproutLedgerError::MissingFundingStream { index: 0 })));
                assert_eq!(owned_state(&parent), before);
            }
            for extra in [vec![output(18_750_000, &[0x51])], (0..10).map(|_| output(787_500_000_000, &bytes(NU61_DISBURSEMENT_SCRIPT))).collect()] {
                let mut outputs = reward.transparent_bundle().unwrap().vout.clone();
                outputs.extend(extra);
                assert!(matches!(stage_nu6_transactions(&parent, &[nu62_with_outputs(height, version, outputs)], height), Err(SproutLedgerError::CoinbaseRewardExceeded)));
                assert_eq!(owned_state(&parent), before);
            }
            let reward = nu62_with_outputs(height, version, vec![output(125_000_009, &[0x51]), output(12_500_000, &bytes(NU6_FPF_SCRIPT)), output(1, &[0x6a])]);
            let delta = stage_nu6_transactions(&parent, &[reward, fee_tx], height).unwrap();
            parent.commit(delta);
            assert!(parent.utxo(&key.0, key.1).is_none());
            assert_eq!(parent.utxo_balance() + 1, parent.transparent_balance());
            assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
        }
    }
}

#[test]
fn nu62_signed_pool_bounds_stay_separate_from_negative_only_getvalueout_and_old_underclaims() {
    let height = 4_052_000;
    for pool in [ShieldedPool::Sapling, ShieldedPool::Orchard] {
        let mut parent = isolated_deferred_parent(13);
        parent.shielded_balances[pool.index()] = 1;
        parent.issued_supply += 1;
        let before = owned_state(&parent);
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = 137_500_000;
        delta.retained = 137_500_000;
        delta.deferred = 18_750_000;
        if pool == ShieldedPool::Sapling { delta.sapling = -1; } else { delta.orchard = -1; }
        let values = CoinbaseValues { claimed: 137_500_000, transparent: 137_500_000, sapling_balance: i64::from(pool == ShieldedPool::Sapling), orchard_balance: i64::from(pool == ShieldedPool::Orchard), ironwood_balance: 0, retained: 137_500_000, sigops: 0 };
        assert!(matches!(parent.finish_delta(delta, values, height), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
    let original = RawV5::parse_exact(&NU62_ORCHARD_COINBASE).unwrap();
    let bundle = original.orchard().unwrap();
    let balance = bundle.actions().as_ptr() as usize - NU62_ORCHARD_COINBASE.as_ptr() as usize + bundle.action_count() * 820 + 1;
    for (value_balance, claimed) in [(-7_i64, 137_500_000), (0, 137_499_993), (7, 137_499_993)] {
        let mut raw = NU62_ORCHARD_COINBASE.to_vec();
        raw[balance..balance + 8].copy_from_slice(&value_balance.to_le_bytes());
        let values = check_post_nu5_coinbase(&original_v5(&raw), height, 1_800_000_000).unwrap();
        assert_eq!((values.claimed, values.transparent, values.orchard_balance), (claimed, 137_499_993, value_balance));
        if value_balance != -7 {
            assert!(matches!(isolated_deferred_parent(13).stage_post_nu5_block(vec![original_v5(&raw)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(RawV5Error::InvalidOrchardSpendAuth { index: 0 }))));
        }
    }
    let reward = nu62_coinbase(height, TxVersion::V4, height);
    for pool in 0..6 {
        let mut parent = isolated_deferred_parent(13);
        if pool == 0 { parent.transparent_balance = MAX_MONEY - 13; }
        else if pool < 5 { parent.shielded_balances[pool - 1] = MAX_MONEY - 13; }
        else { parent.deferred_balance = MAX_MONEY; }
        parent.issued_supply = MAX_MONEY;
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
    let mut parent = state();
    let delta = stage_nu6_transactions(&parent, &[nu5_with_outputs(2_975_999, TxVersion::V4, vec![output(1, &[0x51])])], 2_975_999).unwrap();
    parent.commit(delta);
    let delta = stage_nu6_transactions(&parent, &[reward], height).unwrap();
    assert_eq!(delta.issued, 156_250_001); // Never backfill an old unclaimed subsidy.
}

#[test]
fn nu62_independent_v4_v5_signatures_bind_each_actual_prevout_script_amount_and_candidate() {
    let height = 4_052_000;
    let keys = [([0xe5; 32], 3), ([0xe6; 32], 7)];
    for p2sh in [false, true] {
        for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
            let (transaction, previous) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu6_2, p2sh, hash_type);
            let (raw, prevouts) = independently_signed_v5_for_branch(&keys, BranchId::Nu6_2, p2sh, hash_type);
            let make_parent = |bad: Option<(usize, bool)>| {
                let mut parent = isolated_deferred_parent(13);
                for (index, (key, previous)) in std::iter::once((([0xa1; 32], 3), &previous)).chain(keys.iter().copied().zip(&prevouts)).enumerate() {
                    let mut script = previous.script_pubkey().0.0.clone();
                    if bad == Some((index, true)) { if p2sh { script[2] ^= 1; } else { script.insert(0, 0x61); } }
                    fund(&mut parent, key, u64::from(previous.value()) + u64::from(bad == Some((index, false))), &script, 0, false);
                }
                parent
            };
            let reward = nu62_with_outputs(height, TxVersion::V4, vec![output(125_000_007, &[0x51]), output(12_500_000, &bytes(NU6_FPF_SCRIPT))]);
            let mut parent = make_parent(None);
            let before = owned_state(&parent);
            let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(transaction.clone())), original_v5(&raw)], height, 1_800_000_000).unwrap();
            assert_eq!((delta.fees, delta.deferred, delta.issued), (7, 18_750_013, 156_550_020));
            for index in 0..3 {
                for changed_script in [false, true] {
                    let bad = make_parent(Some((index, changed_script)));
                    let snapshot = owned_state(&bad);
                    assert!(matches!(bad.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(transaction.clone())), original_v5(&raw)], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
                    assert_eq!(owned_state(&bad), snapshot);
                }
            }
            let (old, _) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu6_1, p2sh, hash_type);
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(v4(&old, BranchId::Nu6_2, 0)))], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
            let (mut old, _) = independently_signed_v5_for_branch(&keys, BranchId::Nu6_1, p2sh, hash_type);
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&old)], height, 1_800_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
            old[8..12].copy_from_slice(&u32::from(BranchId::Nu6_2).to_le_bytes());
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward)), original_v5(&old)], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript)));
            assert_eq!(owned_state(&parent), before);
            parent.commit(delta);
            for key in [([0xa1; 32], 3), keys[0], keys[1]] { assert!(parent.utxo(&key.0, key.1).is_none()); }
        }
    }
}

#[test]
fn nu62_last_disabled_nu61_parent_full_auth_and_single_epoch_reset_preserve_asset_state() {
    use zcash_history::{V2, Version};
    let height = 4_052_000;
    // Real original and fixed crypto in isolated synthetic state, not archival
    // predecessor authority or connected PoW/full-history qualification.
    let mut parent = isolated_deferred_parent(7_875_000_000_000);
    let delta = parent.stage_post_nu5_block(vec![original_v5(&NU61_ORCHARD_COINBASE), original_v5(&NU61_ORCHARD_OUTPUTS_DISABLED)], 3_536_500, 1_800_000_000).unwrap();
    parent.commit(delta);
    let prior = ChainHistoryV2::new(post_nu5_leaf(height - 2, parent.shielded_roots[1], parent.shielded_roots[2], 0, 9)).unwrap();
    parent.history_root = Some(prior.root());
    parent.chain_history_v2 = Some(prior);
    let reward = encoded(&nu61_coinbase(height - 1, TxVersion::V5, height - 1));
    let bytes = post_nu5_structural_body(&[&reward], height - 1, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&bytes, height - 1).unwrap();
    let auth = body.auth_data_root();
    let commitment = body.header().final_sapling_root;
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(body.into_transactions(), height - 1, 1_800_000_000).unwrap();
    assert_eq!((delta.orchard_tree.tree_size(), delta.orchard_nullifiers.len(), delta.orchard), (3, 0, 7));
    let last = post_nu5_leaf(height - 1, delta.sapling_root, delta.orchard_root, 0, 0);
    let old = parent.stage_post_nu5_history(&commitment, &auth, last.clone()).unwrap();
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    parent.history_root = Some(old.root());
    parent.chain_history_v2 = Some(old);
    assert_eq!(parent.orchard_tree, before.orchard_tree);
    assert_eq!(parent.orchard_anchors, before.orchard_anchors);
    assert_eq!(parent.nullifiers[2], before.nullifiers[2]);
    assert_eq!(parent.chain_history_v2.as_ref().unwrap().last_height(), 4_051_999);

    let bytes = post_nu5_structural_body(&[&NU62_ORCHARD_COINBASE, &NU62_ORCHARD_OUTPUTS_DISABLED], height, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&bytes, height).unwrap();
    let auth = body.auth_data_root();
    let commitment = body.header().final_sapling_root;
    let orchard_tx = body.transactions().iter().filter(|transaction| matches!(transaction, PostNu5Transaction::V5(raw) if raw.orchard().is_some())).count() as u64;
    assert_eq!(orchard_tx, 2); // Transaction count, never four Action count.
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
    let first = post_nu5_leaf(height, delta.sapling_root, delta.orchard_root, 0, orchard_tx);
    let new = parent.stage_post_nu5_history(&commitment, &auth, first.clone()).unwrap();
    assert_eq!((new.consensus_branch_id(), new.leaf_count(), new.last_height()), (0x5437_f330, 1, 4_052_000));
    assert_eq!(new.root(), V2::hash(&first));
    assert_eq!((delta.orchard_tree.tree_size(), delta.orchard_nullifiers.len(), delta.orchard, delta.deferred), (7, 4, 14, 56_250_000));
    assert_eq!(owned_state(&parent), before);
    for (old_height, branch, expected) in [
        (4_051_998_u32, BranchId::Nu6_1, HistoryError::NonconsecutiveHeight),
        (4_051_999, BranchId::Nu6, HistoryError::BranchMismatch),
        (4_051_999, BranchId::Nu6_2, HistoryError::BranchMismatch),
    ] {
        let mut bad = isolated_deferred_parent(13);
        let mut wrong = last.clone();
        wrong.v1.start_height = old_height.into();
        wrong.v1.end_height = old_height.into();
        wrong.v1.consensus_branch_id = u32::from(branch);
        let history = ChainHistoryV2::new(wrong).unwrap();
        bad.history_root = Some(history.root());
        bad.chain_history_v2 = Some(history);
        let snapshot = owned_state(&bad);
        assert_eq!(bad.stage_post_nu5_history(&block_commitment(bad.history_root().unwrap(), auth), &auth, first.clone()).unwrap_err(), SproutLedgerError::History(expected));
        assert_eq!(owned_state(&bad), snapshot);
    }
    for failure in 0..5 {
        let mut bad = isolated_deferred_parent(13);
        bad.chain_history_v2 = parent.chain_history_v2.clone();
        bad.history_root = parent.history_root;
        let mut wrong_auth = auth;
        let mut wrong_commitment = commitment;
        if failure == 0 { wrong_auth[0] ^= 1; }
        if failure == 1 { wrong_commitment[0] ^= 1; }
        if failure == 2 { bad.history_root = Some([0; 32]); }
        if failure == 3 { bad.chain_history_v2 = None; }
        if failure == 4 { bad.chain_history = Some(ChainHistoryV1::new(primary_heartwood_leaf(include_bytes!("../tests/fixtures/testnet-heartwood-block-903800.bin"), 903_800, bad.shielded_roots[1], 0)).unwrap()); }
        let snapshot = owned_state(&bad);
        let expected = match failure {
            0 | 1 => SproutLedgerError::Body(BodyError::BlockCommitmentMismatch),
            2 | 3 => SproutLedgerError::WrongHistoryRoot,
            _ => SproutLedgerError::History(HistoryError::BranchMismatch),
        };
        assert_eq!(bad.stage_post_nu5_history(&wrong_commitment, &wrong_auth, first.clone()).unwrap_err(), expected);
        assert_eq!(owned_state(&bad), snapshot);
    }
    let coinbase = RawV5::parse_exact(&NU62_ORCHARD_COINBASE).unwrap();
    let bundle = coinbase.orchard().unwrap();
    for part in [bundle.proof(), bundle.spend_auth_signatures(), bundle.binding_signature().as_slice()] {
        let offset = part.as_ptr() as usize - NU62_ORCHARD_COINBASE.as_ptr() as usize;
        let mut changed = NU62_ORCHARD_COINBASE.to_vec();
        changed[offset] ^= 1;
        let changed_bytes = post_nu5_structural_body(&[&changed, &NU62_ORCHARD_OUTPUTS_DISABLED], height, parent.history_root().unwrap());
        let changed_auth = PostNu5Block::parse(&changed_bytes, height).unwrap().auth_data_root();
        assert_ne!(changed_auth, auth);
        assert_eq!(parent.stage_post_nu5_history(&commitment, &changed_auth, first.clone()).unwrap_err(), SproutLedgerError::Body(BodyError::BlockCommitmentMismatch));
        assert_eq!(owned_state(&parent), before);
    }
    parent.commit(delta);
    parent.history_root = Some(new.root());
    parent.chain_history_v2 = Some(new);
    assert!(before.nullifiers[2].is_subset(&parent.nullifiers[2]));
    assert!(before.orchard_anchors.is_subset(&parent.orchard_anchors));
    assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard)), (7, 7));
    let reward = encoded(&nu62_coinbase(height + 1, TxVersion::V4, height + 1));
    let bytes = post_nu5_structural_body(&[&reward], height + 1, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&bytes, height + 1).unwrap();
    let auth = body.auth_data_root();
    let commitment = body.header().final_sapling_root;
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(body.into_transactions(), height + 1, 1_800_000_000).unwrap();
    let second = post_nu5_leaf(height + 1, delta.sapling_root, delta.orchard_root, 0, 0);
    let new = parent.stage_post_nu5_history(&commitment, &auth, second.clone()).unwrap();
    assert_eq!(new.root(), V2::hash(&V2::combine(&first, &second)));
    assert_eq!(new.leaf_count(), 2);
    assert_eq!((delta.orchard_tree.tree_size(), delta.orchard_nullifiers.len(), delta.orchard), (7, 0, 14));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu62_late_history_height_branch_work_count_and_full_auth_failures_preserve_money_retry() {
    let height = 4_052_001;
    for failure in 0..7 {
        let mut parent = isolated_deferred_parent(18_750_000);
        let mut first = post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0);
        if failure == 0 { first.v1.subtree_total_work = primitive_types::U256::MAX; }
        if failure == 1 { first.v1.sapling_tx = u64::MAX; }
        if failure == 2 { first.orchard_tx = u64::MAX; }
        let history = ChainHistoryV2::new(first).unwrap();
        let root = history.root();
        parent.history_root = Some(root);
        parent.chain_history_v2 = Some(history);
        let reward = encoded(&nu62_coinbase(height, TxVersion::V5, height));
        let bytes = post_nu5_structural_body(&[&reward, &NU62_ORCHARD_OUTPUTS_DISABLED], height, root);
        let body = PostNu5Block::parse(&bytes, height).unwrap();
        let mut auth = body.auth_data_root();
        let commitment = body.header().final_sapling_root;
        if failure == 4 { parent.history_root = Some([0; 32]); }
        if failure == 5 { auth[0] ^= 1; }
        let before = owned_state(&parent);
        let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
        let mut leaf = post_nu5_leaf(height + u32::from(failure == 3), delta.sapling_root, delta.orchard_root, 1, 1);
        if failure == 6 { leaf.v1.consensus_branch_id = u32::from(BranchId::Nu6_1); }
        let expected = match failure {
            0 => SproutLedgerError::History(HistoryError::WorkOverflow),
            1 => SproutLedgerError::History(HistoryError::SaplingCountOverflow),
            2 => SproutLedgerError::History(HistoryError::OrchardCountOverflow),
            3 => SproutLedgerError::History(HistoryError::NonconsecutiveHeight),
            4 => SproutLedgerError::WrongHistoryRoot,
            5 => SproutLedgerError::Body(BodyError::BlockCommitmentMismatch),
            _ => SproutLedgerError::History(HistoryError::BranchMismatch),
        };
        assert_eq!(parent.stage_post_nu5_history(&commitment, &auth, leaf).unwrap_err(), expected);
        assert_eq!(owned_state(&parent), before);
        let repaired = ChainHistoryV2::new(post_nu5_leaf(height - 1, parent.sapling_tree.root().to_bytes(), parent.orchard_tree.root().to_bytes(), 0, 0)).unwrap();
        let root = repaired.root();
        parent.history_root = Some(root);
        parent.chain_history_v2 = Some(repaired);
        let auth = PostNu5Block::parse(&bytes, height).unwrap().auth_data_root();
        let leaf = post_nu5_leaf(height, delta.sapling_root, delta.orchard_root, 0, 1);
        let new = parent.stage_post_nu5_history(&block_commitment(root, auth), &auth, leaf).unwrap();
        parent.commit(delta);
        parent.history_root = Some(new.root());
        parent.chain_history_v2 = Some(new);
        assert_eq!((parent.deferred_balance(), parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard), parent.chain_history_v2.as_ref().unwrap().leaf_count()), (37_500_000, 2, 2, 2));
    }
}

#[test]
fn nu62_both_formats_require_exact_coinbase_expiry_and_actual_finality_maturity_generation() {
    let height = 4_052_001;
    let key = ([0xe7; 32], 0);
    for version in [TxVersion::V4, TxVersion::V5] {
        for expiry in [0, height - 1, height, height + 1, 499_999_999, 500_000_000] {
            let parent = isolated_deferred_parent(13);
            let before = owned_state(&parent);
            let result = stage_nu6_transactions(&parent, &[nu62_coinbase(height, version, expiry)], height);
            if expiry == height { assert!(result.is_ok()); } else { assert!(matches!(result, Err(SproutLedgerError::InvalidCoinbase))); }
            assert_eq!(owned_state(&parent), before);
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, 0, expiry.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let raw = encoded(&tx);
            let result = if version == TxVersion::V4 { check_transaction(&tx, height, 1_800_000_000).map(|_| ()) } else { check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), height, 1_800_000_000).map(|_| ()) };
            assert_eq!(result, if expiry >= 500_000_000 { Err(SproutLedgerError::InvalidTransaction) } else if expiry != 0 && expiry < height { Err(SproutLedgerError::ExpiredTransaction) } else { Ok(()) });
        }
        for (lock, sequence, accepted) in [(height - 1, 0, true), (height, 0, false), (height, u32::MAX, true), (1_799_999_999, 0, true), (1_800_000_000, 0, false)] {
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, lock, 0.into(), spend(&[(key, &[], sequence)], vec![output(0, &[0x51])], lock).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let raw = encoded(&tx);
            let result = if version == TxVersion::V4 { check_transaction(&tx, height, 1_800_000_000).map(|_| ()) } else { check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), height, 1_800_000_000).map(|_| ()) };
            assert_eq!(result, if accepted { Ok(()) } else { Err(SproutLedgerError::NonfinalTransaction) });
        }
        for (created, expected) in [(height - 100, SproutLedgerError::UnshieldedCoinbaseSpend), (height - 99, SproutLedgerError::ImmatureCoinbase)] {
            let mut parent = isolated_deferred_parent(13);
            fund(&mut parent, key, 0, &[0x51], created, true);
            let before = owned_state(&parent);
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[nu62_coinbase(height, version, height), tx], height), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
        let mut parent = isolated_deferred_parent(13);
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, &[nu62_coinbase(height + 1, version, height)], height), Err(SproutLedgerError::InvalidCoinbase)));
        for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1] {
            let old = TransactionData::<Authorized>::from_parts(version, branch, 0, height.into(), nu62_coinbase(height, version, height).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[old], height), Err(SproutLedgerError::UnsupportedTransaction)));
        }
        for mutation in 0..3 {
            let reward = nu62_coinbase(height, version, height);
            let mut transparent = reward.transparent_bundle().unwrap().clone();
            let mut script = transparent.vin[0].script_sig().clone();
            if mutation == 0 { script.0.0 = vec![0x51]; }
            if mutation == 1 { script.0.0.resize(101, 0); }
            if mutation == 2 { script.0.0[1] ^= 1; }
            transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
            let bad = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[bad], height), Err(SproutLedgerError::InvalidCoinbase)));
            assert_eq!(owned_state(&parent), before);
        }
        let reward = nu62_coinbase(height, version, height);
        let id: [u8; 32] = reward.txid().into();
        fund(&mut parent, (id, 999), 1, &[0x51], 0, false);
        let before = owned_state(&parent);
        assert!(matches!(stage_nu6_transactions(&parent, &[reward], height), Err(SproutLedgerError::UnspentTransactionOverwrite)));
        assert_eq!(owned_state(&parent), before);
    }
    let mut changed = NU62_ORCHARD_COINBASE.to_vec();
    changed[16..20].copy_from_slice(&4_051_999_u32.to_le_bytes());
    // The structural body retains actual expiry. Financial admission rejects it
    // before recovery, fixed key construction, dummy signatures or proofs.
    let bytes = post_nu5_structural_body(&[&changed], 4_052_000, [0; 32]);
    let body = PostNu5Block::parse(&bytes, 4_052_000).unwrap();
    assert!(matches!(isolated_deferred_parent(13).stage_post_nu5_block(body.into_transactions(), 4_052_000, 1_800_000_000), Err(SproutLedgerError::InvalidCoinbase)));
    for (height, expected) in [(4_134_000, SproutLedgerError::UnsupportedTransaction), (u32::MAX, SproutLedgerError::UnsupportedEra)] {
        let parent = isolated_deferred_parent(13);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE)], height, 1_800_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu62_ordered_actual_spends_reject_future_second_duplicate_null_and_negative_fee_paths() {
    let height = 4_052_000;
    let key = ([0xe8; 32], 0);
    let (_, prevouts) = independently_signed_v5_for_branch(&[([0; 32], 0), ([1; 32], 1)], BranchId::Nu6_2, true, 1);
    let first = v4(&spend(&[(key, &[], u32::MAX)], prevouts, 0), BranchId::Nu6_2, 0);
    let first_id: [u8; 32] = first.txid().into();
    let (second, _) = independently_signed_v5_for_branch(&[(first_id, 0), (first_id, 1)], BranchId::Nu6_2, true, 1);
    let second_id = RawV5::parse_exact(&second).unwrap().effect_id();
    let third = v4(&spend(&[((second_id, 0), &[], u32::MAX), ((second_id, 1), &[], u32::MAX)], vec![output(199_999, &[0x51])], 0), BranchId::Nu6_2, 0);
    let mut parent = isolated_deferred_parent(13);
    fund(&mut parent, key, 200_010, &[0x51], 0, false);
    let before = owned_state(&parent);
    let reward = nu62_with_outputs(height, TxVersion::V4, vec![output(125_000_011, &[0x51]), output(12_500_000, &bytes(NU6_FPF_SCRIPT))]);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&second), PostNu5Transaction::V4(Box::new(first.clone()))], height, 1_800_000_000), Err(SproutLedgerError::MissingTransparentInput)));
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), PostNu5Transaction::V4(Box::new(first.clone())), original_v5(&second), original_v5(&second)], height, 1_800_000_000), Err(SproutLedgerError::MissingTransparentInput)));
    for version in [TxVersion::V4, TxVersion::V5] {
        for (inputs, amount, expected) in [
            (vec![(key, &[][..], u32::MAX)], 200_011, SproutLedgerError::NegativeFee),
            (vec![(key, &[][..], u32::MAX), (key, &[][..], u32::MAX)], 0, SproutLedgerError::DuplicateTransparentInput),
            (vec![(([0; 32], u32::MAX), &[][..], u32::MAX)], 0, SproutLedgerError::InvalidCoinbase),
        ] {
            let tx = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, 0, 0.into(), spend(&inputs, vec![output(amount, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            assert!(matches!(stage_nu6_transactions(&parent, &[reward.clone(), tx], height), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
        }
    }
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward)), PostNu5Transaction::V4(Box::new(first)), original_v5(&second), PostNu5Transaction::V4(Box::new(third))], height, 1_800_000_000).unwrap();
    assert_eq!((delta.fees, delta.deferred, delta.issued), (11, 18_750_013, 156_450_023));
    parent.commit(delta);
    for (id, index) in [(key.0, key.1), (first_id, 0), (first_id, 1), (second_id, 0), (second_id, 1)] { assert!(parent.utxo(&id, index).is_none()); }
}

#[test]
fn nu62_counts_two_megabytes_sigops_and_each_money_side_stay_independent() {
    let height = 4_052_001;
    let key = ([0xe9; 32], 0);
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    for (spends, outputs) in [(65_536, 0), (0, 65_536)] {
        let tx = v4(&modified_sapling(vec![bundle.shielded_spends()[0].clone(); spends], vec![bundle.shielded_outputs()[0].clone(); outputs], 0, spend(&[(key, &[], u32::MAX)], vec![output(0, &[0x51])], 0).transparent_bundle().cloned()), BranchId::Nu6_2, 0);
        assert_eq!(check_transaction(&tx, height, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::InvalidTransaction));
    }
    for (length, accepted) in [(1_999_917, true), (1_999_918, false)] {
        let tx = v4(&spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0; length])], 0), BranchId::Nu6_2, 0);
        assert_eq!(check_transaction(&tx, height, 1_800_000_000).map(|_| ()), if accepted { Ok(()) } else { Err(SproutLedgerError::TransactionTooLarge) });
    }
    for (count, accepted) in [(19_999, true), (20_000, false)] {
        let mut parent = isolated_deferred_parent(13);
        fund(&mut parent, key, 0, &[0x51], 0, false);
        let before = owned_state(&parent);
        let reward = nu62_with_outputs(height, TxVersion::V4, vec![output(125_000_000, &[0xac]), output(12_500_000, &bytes(NU6_FPF_SCRIPT))]);
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu6_2, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(0, &vec![0xac; count])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        let result = stage_nu6_transactions(&parent, &[reward, tx], height);
        if accepted { assert_eq!(result.unwrap().sigops, 20_000); } else { assert!(matches!(result, Err(SproutLedgerError::TooManySigops))); }
        assert_eq!(owned_state(&parent), before);
    }
    for balance in [-(MAX_MONEY as i64), MAX_MONEY as i64] {
        let mut parent = isolated_deferred_parent(13);
        fund(&mut parent, key, 1, &[0x51], 0, false);
        let before = owned_state(&parent);
        let tx = v4(&modified_sapling(bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), balance, spend(&[(key, &[], u32::MAX)], vec![output(1, &[0x51])], 0).transparent_bundle().cloned()), BranchId::Nu6_2, 0);
        assert!(matches!(stage_nu6_transactions(&parent, &[nu62_coinbase(height, TxVersion::V4, height), tx], height), Err(SproutLedgerError::ValueOutOfRange)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu62_fixed_proof_authenticates_actual_anchor_nullifier_and_cmx_not_only_signatures() {
    let raw = &NU62_ORCHARD_OUTPUTS_DISABLED;
    let original = RawV5::parse_exact(raw).unwrap();
    let bundle = original.orchard().copied().unwrap();
    let actions = bundle.actions().as_ptr() as usize - raw.as_ptr() as usize;
    let anchor = actions + bundle.action_count() * 820 + 9;
    let sighash = original.into_signature_context(vec![]).unwrap().shielded();
    for (offset, replacement) in [
        (anchor, [0; 32]),
        (actions + 32, [0; 32]),
        (actions + 820 + 32, [0; 32]),
        (actions + 96, [0; 32]),
        (actions + 820 + 96, [0; 32]),
    ] {
        let mut changed = raw.to_vec();
        assert_ne!(&changed[offset..offset + 32], &replacement);
        changed[offset..offset + 32].copy_from_slice(&replacement);
        let parsed = RawV5::parse_exact(&changed).unwrap();
        // Keep the actual original signed message to isolate the fixed proof
        // relation; full ledger derives the changed message independently.
        assert_eq!(parsed.orchard().unwrap().verify_orchard_fixed(&FixedOrchardVerifier::new(), &sighash), Err(RawV5Error::InvalidOrchardProof));
    }
}

#[test]
fn nu62_genuine_fixed_shield_only_spend_binds_all_prevouts_and_exact_coinbase_maturity() {
    let height = 4_052_000;
    let keys = [([0xea; 32], 0), ([0xeb; 32], 1)];
    let previous = [output(3, &[0x51]), output(4, &[0x61, 0x51])];
    let parsed = RawV5::parse_exact(&NU62_ORCHARD_SHIELD_ONLY).unwrap();
    let bundle = parsed.orchard().copied().unwrap();
    assert_eq!((bundle.action_count(), bundle.proof().len(), i64::from(bundle.value_balance())), (2, 7_264, -7));
    assert!(parsed.transparent_bundle().unwrap().vout.is_empty());
    let hashes = parsed.into_signature_context(previous.to_vec()).unwrap();
    assert_eq!(bundle.verify_orchard_fixed(&FixedOrchardVerifier::new(), &hashes.shielded()), Ok(()));
    for index in 0..2 {
        for bad_script in [false, true] {
            let mut wrong = previous.clone();
            let mut script = wrong[index].script_pubkey().0.0.clone();
            if bad_script { script.insert(0, 0x61); }
            wrong[index] = output(u64::from(wrong[index].value()) + u64::from(!bad_script), &script);
            let hashes = RawV5::parse_exact(&NU62_ORCHARD_SHIELD_ONLY).unwrap().into_signature_context(wrong.to_vec()).unwrap();
            assert_eq!(bundle.verify_orchard_fixed(&FixedOrchardVerifier::new(), &hashes.shielded()), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
            let mut parent = isolated_deferred_parent(13);
            for (key, output) in keys.iter().zip(&wrong) { fund(&mut parent, *key, u64::from(output.value()), &output.script_pubkey().0.0, 0, false); }
            let before = owned_state(&parent);
            assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_SHIELD_ONLY)], height, 1_800_000_000), Err(SproutLedgerError::Orchard(RawV5Error::InvalidOrchardSpendAuth { index: 0 }))));
            assert_eq!(owned_state(&parent), before);
        }
    }
    for (created, mature) in [(height - 99, false), (height - 100, true)] {
        let mut parent = isolated_deferred_parent(13);
        for (key, output) in keys.iter().zip(&previous) { fund(&mut parent, *key, u64::from(output.value()), &output.script_pubkey().0.0, created, true); }
        let before = owned_state(&parent);
        let result = parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_SHIELD_ONLY)], height, 1_800_000_000);
        if mature {
            let delta = result.unwrap();
            assert_eq!((delta.fees, delta.transparent, delta.orchard, delta.deferred, delta.issued), (0, 137_499_993, 14, 18_750_013, 156_250_020));
            assert_eq!(owned_state(&parent), before);
            parent.commit(delta);
            for key in keys { assert!(parent.utxo(&key.0, key.1).is_none()); }
            assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard)), (4, 4));
        } else {
            assert!(matches!(result, Err(SproutLedgerError::ImmatureCoinbase)));
            assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn nu62_sapling_parent_state_and_v4_zip215_are_never_bypassed_by_current_branch() {
    let height = 4_052_000;
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    let anchor = bundle.shielded_spends()[0].anchor().to_bytes();
    let nullifier = bundle.shielded_spends()[0].nullifier().0;
    for mutation in 0..3 {
        let mut parent = isolated_sapling_parent();
        parent.deferred_balance = 13;
        parent.issued_supply += 13;
        if mutation == 0 { parent.sapling_anchors.remove(&anchor); }
        if mutation == 1 { parent.nullifiers[1].insert(nullifier); }
        if mutation == 2 {
            let leaf = SaplingNode::from_cmu(bundle.shielded_outputs()[0].cmu());
            parent.sapling_tree = Frontier::from_parts(((1_u64 << 32) - 2).into(), leaf, vec![leaf; 31]).unwrap();
            parent.shielded_roots[1] = parent.sapling_tree.root().to_bytes();
            parent.sapling_anchors.insert(parent.shielded_roots[1]);
        }
        let expected = [SproutLedgerError::UnknownSaplingAnchor, SproutLedgerError::SpentSaplingNullifier, SproutLedgerError::SaplingTreeFull][mutation];
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(nu62_coinbase(height, TxVersion::V4, height))), PostNu5Transaction::V4(Box::new(v4(&source, BranchId::Nu6_2, 0)))], height, 1_800_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
    let original = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Nu6_2).unwrap();
    assert_eq!(check_transaction(&v4(&original, BranchId::Nu6_2, 0), height, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::SproutDepositDisabled));
    for credit in [0_u64, 10_000] {
        let mut sprout = original.sprout_bundle().unwrap().clone();
        let mut raw = Vec::new();
        sprout.joinsplits[0].write(&mut raw).unwrap();
        raw[..8].fill(0);
        raw[8..16].copy_from_slice(&credit.to_le_bytes());
        sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap();
        sprout.joinsplit_pubkey = [0; 32];
        sprout.joinsplit_sig = [0; 64];
        sprout.joinsplit_sig[0] = 1;
        let mut parent = isolated_deferred_parent(13);
        parent.sprout_anchors.insert(*sprout.joinsplits[0].anchor(), Frontier::empty());
        parent.shielded_balances[0] = credit;
        parent.issued_supply += credit;
        let before = owned_state(&parent);
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6_2, 0, 0.into(), None, Some(sprout), None, None).freeze().unwrap();
        assert!(matches!(stage_nu6_transactions(&parent, &[nu62_coinbase(height, TxVersion::V4, height), tx], height), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof }))));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu62_late_actual_sapling_proof_and_spendauth_failures_preserve_all_prior_state_retry() {
    let height = 4_052_000;
    let source = recorded_sapling();
    let bundle = source.sapling_bundle().unwrap();
    for mutation in 0..4 {
        let mut spends = bundle.shielded_spends().to_vec();
        let mut outputs = bundle.shielded_outputs().to_vec();
        let expected = if mutation == 0 {
            let spend = &spends[0];
            let mut proof = *spend.zkproof();
            proof[0] ^= 0x20;
            spends[0] = sapling_crypto::bundle::SpendDescription::from_parts(spend.cv().clone(), *spend.anchor(), *spend.nullifier(), *spend.rk(), proof, *spend.spend_auth_sig());
            SaplingCryptoError::InvalidSpendProof { index: 0 }
        } else if mutation == 1 {
            let spend = &spends[0];
            let mut signature = <[u8; 64]>::from(*spend.spend_auth_sig());
            signature[63] ^= 1;
            spends[0] = sapling_crypto::bundle::SpendDescription::from_parts(spend.cv().clone(), *spend.anchor(), *spend.nullifier(), *spend.rk(), *spend.zkproof(), signature.into());
            SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }
        } else {
            let index = mutation - 2;
            let output = &outputs[index];
            let mut proof = *output.zkproof();
            proof[0] ^= 0x20;
            outputs[index] = sapling_crypto::bundle::OutputDescription::from_parts(output.cv().clone(), *output.cmu(), output.ephemeral_key().clone(), *output.enc_ciphertext(), *output.out_ciphertext(), proof);
            SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }
        };
        let changed = sapling_crypto::Bundle::from_parts(spends, outputs, *bundle.value_balance(), *bundle.authorization());
        let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6_2, 0, 0.into(), None, None, changed, None).freeze().unwrap();
        let mut parent = isolated_sapling_parent();
        parent.deferred_balance = 13;
        parent.issued_supply += 13;
        let key = ([0xec; 32], 0);
        fund(&mut parent, key, 20, &[0x51], 0, false);
        let good = v4(&spend(&[(key, &[], u32::MAX)], vec![output(20, &[0x51])], 0), BranchId::Nu6_2, 0);
        let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_OUTPUTS_DISABLED), PostNu5Transaction::V4(Box::new(good.clone())), PostNu5Transaction::V4(Box::new(transaction))], height, 1_800_000_000), Err(SproutLedgerError::Sapling(actual)) if actual == expected));
        assert_eq!(owned_state(&parent), before);
        let delta = parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_OUTPUTS_DISABLED), PostNu5Transaction::V4(Box::new(good))], height, 1_800_000_000).unwrap();
        parent.commit(delta);
        assert!(parent.utxo(&key.0, key.1).is_none());
        assert_eq!(parent.nullifiers[1], before.nullifiers[1]);
        assert_eq!(parent.sapling_tree, before.sapling_tree);
    }
}

#[test]
fn nu62_late_expiry_branch_and_actual_script_failures_roll_back_fixed_leaves_money_and_retry() {
    let height = 4_052_000;
    let first_key = ([0xed; 32], 0);
    let second_key = ([0xee; 32], 0);
    for version in [TxVersion::V4, TxVersion::V5] {
        let first = v4(&spend(&[(first_key, &[], u32::MAX)], vec![output(20, &[0x51])], 0), BranchId::Nu6_2, 0);
        let late = TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_2, 0, 0.into(), spend(&[(second_key, &[], u32::MAX)], vec![output(30, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
        for mutation in 0..3 {
            let mut parent = isolated_deferred_parent(13);
            fund(&mut parent, first_key, 20, &[0x51], 0, false);
            fund(&mut parent, second_key, 30, if mutation == 2 { &[0x00] } else { &[0x51] }, 0, false);
            let transaction = TransactionData::<Authorized>::from_parts(version,
                if mutation == 1 { BranchId::Nu6_1 } else { BranchId::Nu6_2 },
                0, (if mutation == 0 { height - 1 } else { 0 }).into(), late.transparent_bundle().cloned(), None, None, None).freeze().unwrap();
            let before = owned_state(&parent);
            let bad_raw = encoded(&transaction);
            let bad = if version == TxVersion::V4 { PostNu5Transaction::V4(Box::new(transaction)) } else { original_v5(&bad_raw) };
            let expected = [SproutLedgerError::ExpiredTransaction, SproutLedgerError::UnsupportedTransaction, SproutLedgerError::InvalidTransparentScript][mutation];
            assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_OUTPUTS_DISABLED), PostNu5Transaction::V4(Box::new(first.clone())), bad], height, 1_800_000_000), Err(actual) if actual == expected));
            assert_eq!(owned_state(&parent), before);
            if mutation == 2 { parent.utxos.get_mut(&second_key).unwrap().output = output(30, &[0x51]); }
            let late_raw = encoded(&late);
            let good = if version == TxVersion::V4 { PostNu5Transaction::V4(Box::new(late.clone())) } else { original_v5(&late_raw) };
            let delta = parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE), original_v5(&NU62_ORCHARD_OUTPUTS_DISABLED), PostNu5Transaction::V4(Box::new(first.clone())), good], height, 1_800_000_000).unwrap();
            assert_eq!((delta.fees, delta.orchard, delta.deferred, delta.issued), (0, 7, 18_750_013, 156_250_063));
            parent.commit(delta);
            assert!(parent.utxo(&first_key.0, first_key.1).is_none());
            assert!(parent.utxo(&second_key.0, second_key.1).is_none());
            assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard)), (4, 4));
        }
    }
}

#[test]
fn nu62_v5_every_original_sapling_spend_proof_authorization_and_nullifier_is_still_required() {
    let height = 4_052_000;
    let source = include_bytes!("../tests/fixtures/nu5-mixed-testnet-1842421.bin");
    let original = RawV5::parse_exact(source).unwrap();
    let sapling = original.sapling_bundle().unwrap();
    let mut changed = source.to_vec();
    changed[8..12].copy_from_slice(&u32::from(BranchId::Nu6_2).to_le_bytes());
    changed[16..20].fill(0);
    // Sapling fixed proofs are branch-independent; these negatives explicitly
    // keep stale real signatures, never pretend branch flipping creates a proof.
    let mut parent = isolated_original_nu5_parent(source);
    parent.deferred_balance = 13;
    parent.issued_supply += 13;
    let before = owned_state(&parent);
    let reward = nu62_coinbase(height, TxVersion::V4, height);
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    let spends = sapling.shielded_spends().len();
    let outputs = sapling.shielded_outputs().len();
    let proof = 24 + spends * 96 + outputs * 756 + 8 + 32;
    let mut bad = changed.clone();
    bad[proof] ^= 0x20;
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&bad)], height, 1_800_000_000), Err(SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index: 0 }))));
    assert_eq!(owned_state(&parent), before);
    for spend in sapling.shielded_spends() {
        let mut bad = isolated_original_nu5_parent(source);
        bad.deferred_balance = 13;
        bad.issued_supply += 13;
        bad.nullifiers[1].insert(spend.nullifier().0);
        let snapshot = owned_state(&bad);
        assert!(matches!(bad.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward.clone())), original_v5(&changed)], height, 1_800_000_000), Err(SproutLedgerError::SpentSaplingNullifier)));
        assert_eq!(owned_state(&bad), snapshot);
    }
}

#[test]
fn nu62_exact_signed_deferred_delta_and_value_balance_bounds_never_net_away_errors() {
    let height = 4_052_000;
    let parent = isolated_deferred_parent(13);
    let values = check_coinbase(&nu62_coinbase(height, TxVersion::V4, height), height, 1_800_000_000).unwrap();
    let before = owned_state(&parent);
    for deferred in [18_749_999_i128, 18_750_001, -1] {
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = values.transparent.into();
        delta.retained = values.retained.into();
        delta.deferred = deferred;
        assert!(matches!(parent.finish_delta(delta, values, height), Err(SproutLedgerError::CoinbaseRewardExceeded)));
        assert_eq!(owned_state(&parent), before);
    }
    let original = RawV5::parse_exact(&NU62_ORCHARD_OUTPUTS_DISABLED).unwrap();
    let bundle = original.orchard().unwrap();
    let balance = bundle.actions().as_ptr() as usize - NU62_ORCHARD_OUTPUTS_DISABLED.as_ptr() as usize + bundle.action_count() * 820 + 1;
    for value in [i64::MIN, -(MAX_MONEY as i64) - 1, MAX_MONEY as i64 + 1, i64::MAX] {
        let mut changed = NU62_ORCHARD_OUTPUTS_DISABLED.to_vec();
        changed[balance..balance + 8].copy_from_slice(&value.to_le_bytes());
        assert!(matches!(RawV5::parse_exact(&changed), Err(RawV5Error::InvalidOrchardValueBalance)));
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu62_fixed_authorization_only_uses_checked_candidate_branch_before_any_key_choice() {
    let parent = isolated_deferred_parent(13);
    let before = owned_state(&parent);
    for height in [4_048_499, 4_048_500, 4_051_999] {
        let expected = if height < 4_048_500 { SproutLedgerError::UnsupportedTransaction } else { SproutLedgerError::OrchardDisabled };
        assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&NU62_ORCHARD_COINBASE)], height, 1_800_000_000), Err(actual) if actual == expected));
        assert_eq!(owned_state(&parent), before);
    }
    let original = RawV5::parse_exact(&NU62_ORCHARD_COINBASE).unwrap();
    let typed = Transaction::read(NU62_ORCHARD_COINBASE.as_slice(), BranchId::Nu6_2).unwrap();
    // Misclassifying a typed V5 as V4 cannot bypass the guarded wire version,
    // then silently use an absent/fallback Orchard proof verifier.
    assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(typed))], 4_052_000, 1_800_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    let independent = Transaction::read(NU62_ORCHARD_COINBASE.as_slice(), BranchId::Nu6_2).unwrap();
    assert_eq!(original.effect_id(), <[u8; 32]>::from(independent.txid()));
    assert_eq!(original.auth_digest().as_slice(), independent.auth_commitment().as_bytes());
    let raw_hash = original.into_signature_context(vec![]).unwrap().shielded();
    assert_eq!(raw_hash, PostNu5SignatureHash::new(independent, vec![]).unwrap().shielded());
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu62_entire_82000_height_reward_schedule_continues_finite_credit_without_archive_claim() {
    let initial = 9_665_625_000_000;
    let mut parent = isolated_deferred_parent(initial);
    let values = check_coinbase(&nu62_coinbase(4_052_000, TxVersion::V4, 4_052_000), 4_052_000, 1_800_000_000).unwrap();
    for height in 4_052_000..4_134_000 {
        let mut delta = BlockDelta::new(&parent);
        delta.transparent = values.transparent.into();
        delta.retained = values.retained.into();
        delta.deferred = deferred_subsidy(height).into();
        let delta = parent.finish_delta(delta, values, height).unwrap();
        parent.commit(delta);
    }
    assert_eq!(parent.deferred_balance(), 11_203_125_000_000);
    assert_eq!(parent.transparent_balance(), 11_275_000_000_000);
    assert_eq!(parent.issued_supply(), 22_478_125_000_000);
    let before = owned_state(&parent);
    assert!(matches!(stage_nu6_transactions(&parent, &[nu62_coinbase(4_134_000, TxVersion::V4, 4_134_000)], 4_134_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu62_genuine_fixed_coinbase_at_last_finite_height_rejects_only_next_upgrade_context() {
    let height = 4_133_999;
    let raw = synthetic_orchard_at(true, BranchId::Nu6_2, height, true);
    let mut parent = isolated_deferred_parent(13);
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(vec![original_v5(&raw)], height, 1_800_000_000).unwrap();
    assert_eq!((delta.transparent, delta.orchard, delta.deferred, delta.issued), (137_499_993, 7, 18_750_013, 156_250_013));
    assert_eq!(owned_state(&parent), before);
    assert!(matches!(parent.stage_post_nu5_block(vec![original_v5(&raw)], 4_134_000, 1_800_000_000), Err(SproutLedgerError::UnsupportedTransaction)));
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.orchard_tree_size(), parent.nullifier_count(ShieldedPool::Orchard)), (2, 2));
    assert!(!parent.pool_is_active(ShieldedPool::Ironwood));
}

#[test]
fn nu63_activation_initializes_independent_ironwood_state_and_keeps_deferred_credit() {
    // Isolated monetary parent, not a connected predecessor archive.
    let height = 4_134_000u32;
    let mut parent = isolated_deferred_parent(13);
    let source = nu62_coinbase(4_133_999, TxVersion::V4, 4_133_999);
    let mut transparent = source.transparent_bundle().unwrap().clone();
    let (prefix, length) = coinbase_height_prefix(height);
    let mut script = Script::default();
    script.0.0.extend_from_slice(&prefix[..length]);
    script.0.0.push(0);
    transparent.vin[0] = TxIn::from_parts(OutPoint::NULL, script, u32::MAX);
    let transaction = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6_3,
        0, height.into(), Some(transparent), None, None, None).freeze().unwrap();
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(transaction))], height, 1_800_000_000).unwrap();
    assert_eq!((delta.transparent, delta.deferred, delta.issued), (137_500_000, 18_750_013, 156_250_013));
    parent.commit(delta);
    // Monetary staging does not move the authenticated header tip. Pool activity
    // remains keyed to that tip, never a test-supplied candidate branch flag.
    assert!(!parent.pool_is_active(ShieldedPool::Ironwood));
    assert_eq!(parent.ironwood_tree_size(), 0);
    assert_eq!(parent.shielded_root(ShieldedPool::Ironwood), orchard::Anchor::empty_tree().to_bytes());
    assert_eq!(parent.ironwood_anchors, BTreeSet::from([orchard::Anchor::empty_tree().to_bytes()]));
    assert_eq!(parent.nullifier_count(ShieldedPool::Ironwood), 0);
    assert_eq!(parent.shielded_balance(ShieldedPool::Ironwood), 0);
    assert_eq!(parent.transparent_balance() + parent.deferred_balance(), parent.issued_supply());
}

const NU63_HEIGHT: u32 = 4_134_000;
type OrchardBundle = orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>;
type UnprovenBundle = orchard::builder::UnauthorizedBundle<zcash_protocol::value::ZatBalance>;

static POST_NU63_PK: std::sync::LazyLock<orchard::circuit::ProvingKey> = std::sync::LazyLock::new(|| {
    orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
});

struct Nu63LedgerFixtures {
    orchard_funding: Vec<u8>,
    ironwood_coinbase: Transaction,
    mixed: Transaction,
    restricted_v5: Vec<u8>,
    restricted_ironwood: Transaction,
    negative_orchard: Transaction,
    old_key_coinbase: Transaction,
    shield_only: Transaction,
}

// Genuine locally generated proofs/signatures and note witnesses. The owning
// parent below admits these synthetic funding transactions; none of these
// bytes, injected transparent prevouts or isolated metadata are a mined archive.
static NU63_LEDGER_FIXTURES: std::sync::LazyLock<Nu63LedgerFixtures> = std::sync::LazyLock::new(|| {
    use orchard::{builder::{Builder, BundleType}, bundle::{BundleVersion, Flags}, keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey}, value::NoteValue};
    use rand_core::SeedableRng;
    use zcash_primitives::transaction::txid::{TxIdDigester, to_txid};
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x73; 32]);
    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let ask = SpendAuthorizingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);
    let zero = Some(OutgoingViewingKey::from([0; 32]));
    let transactional = BundleType::Transactional { bundle_required: true, pad_to_minimum: Some(2) };

    let mut old = Builder::new(BundleType::Coinbase, BundleVersion::orchard_v2(), Flags::SPENDS_DISABLED, orchard::Anchor::empty_tree()).unwrap();
    for value in [3, 4] { old.add_output(zero.clone(), recipient, NoteValue::from_raw(value), [0; 512]).unwrap(); }
    let unproven = old.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let mut transparent = nu62_coinbase(NU63_HEIGHT - 1, TxVersion::V5, NU63_HEIGHT - 1).transparent_bundle().unwrap().clone();
    transparent.vout[0] = output(124_999_993, &[0x51]);
    let data = TransactionData::<UnsignedOrchard>::from_parts(TxVersion::V5, BranchId::Nu6_2, 0, (NU63_HEIGHT - 1).into(), Some(transparent.clone()), None, None, Some(unproven.clone()));
    let sighash = to_txid(TxVersion::V5, BranchId::Nu6_2, &data.digest(TxIdDigester)).into();
    let old = unproven.create_proof(&FIXED_ORCHARD_PK, &mut rng).unwrap().apply_signatures(&mut rng, sighash, &[]).unwrap();
    let orchard_funding = encoded(&TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu6_2, 0, (NU63_HEIGHT - 1).into(), Some(transparent), None, None, Some(old.clone())).freeze().unwrap());
    let old_notes = [3, 4].map(|value| {
        let (index, note) = old.actions().iter().enumerate().filter_map(|(index, _)| old.recover_output_with_ovk(index, zero.as_ref().unwrap()).map(|(note, _, _)| (index, note)))
            .find(|(_, note)| note.value().inner() == value).unwrap();
        #[cfg(not(target_os = "zkvm"))]
        let path = isolated_note_path(isolated_deferred_parent(13), original_v5(&orchard_funding), ShieldedPool::Orchard, NU63_HEIGHT - 1, index, note.nullifier(&fvk).to_bytes());
        #[cfg(target_os = "zkvm")]
        let path = orchard_path(&old, index);
        (note, path)
    });

    let mut builder = Builder::new(BundleType::Coinbase, BundleVersion::ironwood_v3(), Flags::SPENDS_DISABLED, orchard::Anchor::empty_tree()).unwrap();
    for value in [5, 7] { builder.add_output(zero.clone(), recipient, NoteValue::from_raw(value), [0; 512]).unwrap(); }
    let ironwood = builder.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let mut transparent = nu63_coinbase(NU63_HEIGHT, TxVersion::V6, NU63_HEIGHT).transparent_bundle().unwrap().clone();
    transparent.vout[0] = output(124_999_988, &[0x51]);
    let data = TransactionData::<UnsignedOrchard>::from_parts_v6(BranchId::Nu6_3, 0, NU63_HEIGHT.into(), Some(transparent.clone()), None, None, Some(ironwood.clone()));
    let sighash = to_txid(TxVersion::V6, BranchId::Nu6_3, &data.digest(TxIdDigester)).into();
    let ironwood = ironwood.create_proof(&POST_NU63_PK, &mut rng).unwrap().apply_signatures(&mut rng, sighash, &[]).unwrap();
    let ironwood_coinbase = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, NU63_HEIGHT.into(), Some(transparent), None, None, Some(ironwood.clone())).freeze().unwrap();
    let ironwood_notes = [5, 7].map(|value| {
        let (index, note) = ironwood.actions().iter().enumerate().filter_map(|(index, _)| ironwood.recover_output_with_ovk(index, zero.as_ref().unwrap()).map(|(note, _, _)| (index, note)))
            .find(|(_, note)| note.value().inner() == value).unwrap();
        #[cfg(not(target_os = "zkvm"))]
        let path = isolated_note_path(isolated_deferred_parent(13), PostNu5Transaction::V6(Box::new(ironwood_coinbase.clone())), ShieldedPool::Ironwood, NU63_HEIGHT, index, note.nullifier(&fvk).to_bytes());
        #[cfg(target_os = "zkvm")]
        let path = orchard_path(&ironwood, index);
        (note, path)
    });

    let mut restricted = Builder::new(transactional, BundleVersion::orchard_v3(), Flags::CROSS_ADDRESS_DISABLED, old_notes[0].1.root(old_notes[0].0.commitment().into())).unwrap();
    restricted.add_spend(fvk.clone(), old_notes[0].0, old_notes[0].1.clone()).unwrap();
    let orchard = restricted.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let mut transfer = Builder::new(transactional, BundleVersion::ironwood_v3(), Flags::ENABLED, ironwood_notes[0].1.root(ironwood_notes[0].0.commitment().into())).unwrap();
    transfer.add_spend(fvk.clone(), ironwood_notes[0].0, ironwood_notes[0].1.clone()).unwrap();
    transfer.add_output(zero.clone(), fvk.address_at(1u32, Scope::External), NoteValue::from_raw(8), [0x37; 512]).unwrap();
    let ironwood_transfer = transfer.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let keys = [([0xe1; 32], 0), ([0xe2; 32], 1)];
    let (mut transparent, prevouts) = nu63_transparent_template(&keys);
    transparent.vout[0] = output(99_995, &[0x51]);
    let mixed = authorize_nu63(TxVersion::V6, transparent, prevouts, Some(orchard), Some(ironwood_transfer), Some(nu63_synthetic_sapling_output()), &ask, &mut rng);

    let mut restricted = Builder::new(transactional, BundleVersion::orchard_v3(), Flags::from_byte(1, BundleVersion::orchard_v3()).unwrap(), old_notes[1].1.root(old_notes[1].0.commitment().into())).unwrap();
    restricted.add_spend(fvk.clone(), old_notes[1].0, old_notes[1].1.clone()).unwrap();
    let restricted = restricted.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let transparent = zcash_transparent::bundle::Bundle { vin: vec![], vout: vec![output(4, &[0x51])], authorization: zcash_transparent::bundle::Authorized };
    let restricted_v5 = encoded(&authorize_nu63(TxVersion::V5, transparent, vec![], Some(restricted), None, None, &ask, &mut rng));

    let flags = Flags::from_byte(1, BundleVersion::ironwood_v3()).unwrap();
    let mut restricted = Builder::new(transactional, BundleVersion::ironwood_v3(), flags, ironwood_notes[1].1.root(ironwood_notes[1].0.commitment().into())).unwrap();
    restricted.add_spend(fvk.clone(), ironwood_notes[1].0, ironwood_notes[1].1.clone()).unwrap();
    let restricted = restricted.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let transparent = zcash_transparent::bundle::Bundle { vin: vec![], vout: vec![output(7, &[0x51])], authorization: zcash_transparent::bundle::Authorized };
    let restricted_ironwood = authorize_nu63(TxVersion::V6, transparent, vec![], None, Some(restricted), None, &ask, &mut rng);

    let mut negative = Builder::new(transactional, BundleVersion::orchard_v3(), Flags::CROSS_ADDRESS_DISABLED, orchard::Anchor::empty_tree()).unwrap();
    negative.add_change_output(fvk, zero, recipient, NoteValue::from_raw(1), [0; 512]).unwrap();
    let negative = negative.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let transparent = spend(&[(([0xe3; 32], 0), &[], u32::MAX)], vec![], 0).transparent_bundle().unwrap().clone();
    let negative_orchard = authorize_nu63(TxVersion::V6, transparent, vec![output(1, &[0x51])], Some(negative), None, None, &ask, &mut rng);
    // A genuine FixedPostNu6_2 proof and signatures over the actual V6/Nu6_3
    // message, deliberately placed under the new Ironwood field. Its old V2
    // plaintexts are NOT a valid NU6.3 coinbase; proof-only route must still fail.
    let old_key = Builder::new(transactional, BundleVersion::orchard_v2(), Flags::SPENDS_DISABLED, orchard::Anchor::empty_tree()).unwrap();
    let old_key = old_key.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let flags = Flags::SPENDS_DISABLED;
    let effects = orchard::Bundle::from_parts(old_key.actions().clone().map(|action| action.map(|_| ())), flags,
        *old_key.value_balance(), *old_key.anchor(), orchard::bundle::EffectsOnly, BundleVersion::ironwood_v3()).unwrap();
    let reward = nu63_coinbase(NU63_HEIGHT, TxVersion::V6, NU63_HEIGHT);
    let transparent = reward.transparent_bundle().unwrap().clone();
    let mut parts = reward.digest(TxIdDigester);
    parts.ironwood_digest = Some(effects.commitment(orchard::bundle::TxVersion::V6).unwrap().0);
    let sighash = to_txid(TxVersion::V6, BranchId::Nu6_3, &parts).into();
    let old_key = old_key.create_proof(&FIXED_ORCHARD_PK, &mut rng).unwrap().apply_signatures(&mut rng, sighash, &[]).unwrap();
    let old_key = orchard::Bundle::try_from_parts(old_key.actions().clone(), flags, *old_key.value_balance(), *old_key.anchor(), old_key.authorization().clone(), BundleVersion::ironwood_v3()).unwrap();
    let old_key_coinbase = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, NU63_HEIGHT.into(), Some(transparent), None, None, Some(old_key)).freeze().unwrap();
    let mut shield = Builder::new(transactional, BundleVersion::ironwood_v3(), Flags::SPENDS_DISABLED, orchard::Anchor::empty_tree()).unwrap();
    shield.add_output(Some(OutgoingViewingKey::from([0; 32])), recipient, NoteValue::from_raw(7), [0; 512]).unwrap();
    let shield = shield.build::<i64>(&mut rng).unwrap().unwrap().0.try_map_value_balance(zcash_protocol::value::ZatBalance::from_i64).unwrap();
    let transparent = spend(&[(([0xe4; 32], 0), &[], u32::MAX), (([0xe5; 32], 1), &[], u32::MAX)], vec![], 0).transparent_bundle().unwrap().clone();
    let shield_only = authorize_nu63(TxVersion::V6, transparent, vec![output(3, &[0x51]), output(4, &[0x61, 0x51])], None, Some(shield), None, &ask, &mut rng);
    Nu63LedgerFixtures { orchard_funding, ironwood_coinbase, mixed, restricted_v5, restricted_ironwood, negative_orchard, old_key_coinbase, shield_only }
});

fn nu63_coinbase(height: u32, version: TxVersion, expiry: u32) -> Transaction {
    let transparent = nu61_coinbase(height, TxVersion::V4, expiry).transparent_bundle().cloned();
    if version == TxVersion::V6 { TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, expiry.into(), transparent, None, None, None).freeze().unwrap() }
    else { TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_3, 0, expiry.into(), transparent, None, None, None).freeze().unwrap() }
}

#[cfg(target_os = "zkvm")]
fn orchard_path(bundle: &OrchardBundle, position: usize) -> orchard::tree::MerklePath {
    use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut witness = None;
    for (index, action) in bundle.actions().iter().enumerate() {
        let node = MerkleHashOrchard::from_cmx(action.cmx());
        tree.append(node).unwrap();
        if let Some(witness) = witness.as_mut() { IncrementalWitness::append(witness, node).unwrap(); }
        if index == position { witness = IncrementalWitness::from_tree(tree.clone()); }
    }
    witness.unwrap().path().unwrap().into()
}

// This path feeds genuine proof generation above, but its parent is deliberately
// isolated monetary state. It cannot seal HeaderTip or publish replay evidence.
#[cfg(not(target_os = "zkvm"))]
fn isolated_note_path(mut parent: SproutTestnetLedger, transaction: PostNu5Transaction<'_>, pool: ShieldedPool, height: u32, action_index: usize, nullifier: [u8; 32]) -> orchard::tree::MerklePath {
    use crate::source_note::{SourceFundingLocator, SourceNoteSelection, TrackedNoteState};
    let commitment = match &transaction {
        PostNu5Transaction::V5(raw) => raw.orchard().unwrap().actions().as_chunks::<820>().0[action_index][96..128].try_into().unwrap(),
        PostNu5Transaction::V6(transaction) => transaction.ironwood_bundle().unwrap().actions()[action_index].cmx().to_bytes(),
        PostNu5Transaction::V4(_) => unreachable!(),
    };
    let selection = SourceNoteSelection { pool, commitment, nullifier, funding: SourceFundingLocator {
        block_height: height, transaction_index: 0, action_index: u32::try_from(action_index).unwrap(),
        effect_id: transaction.effect_id(), auth_digest: transaction.auth_digest().unwrap(),
    } };
    let tracker = TrackedNoteState::new(selection).unwrap();
    let staged = tracker.stage(&parent, std::slice::from_ref(&transaction), height).unwrap().unwrap();
    let delta = parent.stage_post_nu5_block(vec![transaction], height, 1_800_000_000).unwrap();
    parent.commit(delta);
    staged.checked_path(&parent).unwrap()
}

fn nu63_transparent_template(keys: &[([u8; 32], u32)]) -> (zcash_transparent::bundle::Bundle<zcash_transparent::bundle::Authorized>, Vec<TxOut>) {
    let (raw, prevouts) = independently_signed_v5_for_branch(keys, BranchId::Nu6_3, true, 1);
    (RawV5::parse_exact(&raw).unwrap().transparent_bundle().unwrap().clone(), prevouts)
}

type SyntheticSaplingOutput = (sapling_crypto::bundle::OutputDescription<[u8; 192]>, redjubjub::SigningKey<redjubjub::Binding>);

// Public synthetic output generated locally2026-10-04 with the actual original
// Sapling OutputParameters and known public value5/rcv19/rseed[0x74;32]/ivk17,
// zero OVK and memo[0x75;512]. Exact 948B V4 descriptor captured only after all
// three shielded-pool equations, both P2SH inputs and actual ledger staging
// passed (parent capture63); the captured mixed V6 also matched the CPU guest
// journal and rejected an auth mutation (artifact2080). Not a mined archive.
// Original complete3592860B PK SHA2562f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4,
// https://download.z.cash/downloads/sapling-output.params, independently pinned
// by zcash/e8f5e592b864b341391c9becf80bbe3e0e930a33/zcutil/fetch-params.sh and
// librustzcash/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_proofs/src/lib.rs.
// Complete BLAKE2b512657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028;
// full EOF/hash authenticated before typed point checking. Original network VK
// remains sapling-output-vk.bin. No temporary PK, files or circuits are read by
// permanent tests: every current binding signature is newly made over the actual
// V4/V5/V6 transaction and complete ordered previous-output context.
fn nu63_synthetic_sapling_output() -> SyntheticSaplingOutput {
    use sha2::{Digest, Sha256};
    const OUTPUT: &[u8; 948] = include_bytes!("../tests/fixtures/nu63-sapling-output.bin");
    assert_eq!(Sha256::digest(OUTPUT).as_slice(), bytes("e0fbe144133d2a184db7e5a4df82050d1989d27ff86f649c7fa33455ad468770"));
    let mut reader = OUTPUT.as_slice();
    let description = zcash_primitives::transaction::components::sapling::temporary_zcashd_read_output_v4(&mut reader).unwrap();
    assert!(reader.is_empty());
    let key = redjubjub::SigningKey::<redjubjub::Binding>::try_from((-jubjub::Fr::from(19)).to_bytes()).unwrap();
    (description, key)
}

#[allow(clippy::too_many_arguments)]
fn authorize_nu63(version: TxVersion, mut transparent: zcash_transparent::bundle::Bundle<zcash_transparent::bundle::Authorized>, previous_outputs: Vec<TxOut>, orchard: Option<UnprovenBundle>, ironwood: Option<UnprovenBundle>, sapling: Option<SyntheticSaplingOutput>, ask: &orchard::keys::SpendAuthorizingKey, rng: &mut rand_chacha::ChaCha20Rng) -> Transaction {
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use zcash_primitives::transaction::{sighash::{SignableInput, signature_hash}, txid::TxIdDigester};
    use zcash_transparent::sighash::{SignableInput as TransparentInput, SighashType};
    let contextual = zcash_transparent::bundle::Bundle { vin: transparent.vin.iter().map(|input| TxIn::from_parts(input.prevout().clone(), input.script_sig().clone(), input.sequence())).collect(), vout: transparent.vout.clone(), authorization: SignerPrevouts(previous_outputs.clone()) };
    let sapling_bundle = sapling.as_ref().and_then(|(description, _)| sapling_crypto::Bundle::from_parts(vec![], vec![description.clone()], zcash_protocol::value::ZatBalance::from_i64(-5).unwrap(), sapling_crypto::bundle::Authorized { binding_sig: [0; 64].into() }));
    let data = if version == TxVersion::V6 { TransactionData::<UnsignedOrchardPrevouts>::from_parts_v6(BranchId::Nu6_3, 0, 0.into(), Some(contextual), sapling_bundle, orchard.clone(), ironwood.clone()) }
        else { TransactionData::<UnsignedOrchardPrevouts>::from_parts(version, BranchId::Nu6_3, 0, 0.into(), Some(contextual), None, sapling_bundle, orchard.clone()) };
    let digests = data.digest(TxIdDigester);
    let sighash = *signature_hash(&data, &SignableInput::Shielded, &digests).as_ref();
    let mut scalar = [0; 32]; scalar[31] = 1;
    let signing_key = SecretKey::from_slice(&scalar).unwrap();
    let secp = Secp256k1::new();
    let mut redeem = vec![33]; redeem.extend_from_slice(&PublicKey::from_secret_key(&secp, &signing_key).serialize()); redeem.push(0xac);
    let mut p2sh = vec![0xa9, 20]; p2sh.extend_from_slice(&zcash_transparent::util::hash160::hash(&redeem)); p2sh.push(0x87);
    for (index, prevout) in previous_outputs.iter().enumerate() {
        if prevout.script_pubkey().0.0 != p2sh { continue; }
        let input = TransparentInput::from_parts(data.transparent_bundle().unwrap(), SighashType::ALL, index, prevout.script_pubkey(), prevout.script_pubkey(), prevout.value()).unwrap();
        let digest = signature_hash(&data, &SignableInput::Transparent(input), &digests);
        let mut signature = secp.sign_ecdsa(&Message::from_digest_slice(digest.as_ref()).unwrap(), &signing_key).serialize_der().to_vec(); signature.push(1);
        let mut script = Script::default(); script.0.0.push(signature.len() as u8); script.0.0.extend_from_slice(&signature); script.0.0.push(redeem.len() as u8); script.0.0.extend_from_slice(&redeem);
        let input = &transparent.vin[index];
        transparent.vin[index] = TxIn::from_parts(input.prevout().clone(), script, input.sequence());
    }
    let orchard = orchard.map(|bundle| bundle.create_proof(&POST_NU63_PK, &mut *rng).unwrap().apply_signatures(&mut *rng, sighash, std::slice::from_ref(ask)).unwrap());
    let ironwood = ironwood.map(|bundle| bundle.create_proof(&POST_NU63_PK, &mut *rng).unwrap().apply_signatures(&mut *rng, sighash, std::slice::from_ref(ask)).unwrap());
    let sapling = sapling.and_then(|(description, key)| sapling_crypto::Bundle::from_parts(vec![], vec![description], zcash_protocol::value::ZatBalance::from_i64(-5).unwrap(), sapling_crypto::bundle::Authorized { binding_sig: key.sign(&mut *rng, &sighash) }));
    if version == TxVersion::V6 { TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, 0.into(), Some(transparent), sapling, orchard, ironwood).freeze().unwrap() }
    else { TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_3, 0, 0.into(), Some(transparent), None, sapling, orchard).freeze().unwrap() }
}

fn nu63_funded_parent() -> SproutTestnetLedger {
    let mut parent = isolated_deferred_parent(13);
    let delta = parent.stage_post_nu5_block(vec![original_v5(&NU63_LEDGER_FIXTURES.orchard_funding)], NU63_HEIGHT - 1, 1_800_000_000).unwrap();
    parent.commit(delta);
    parent
}

fn nu63_mixed_parent() -> SproutTestnetLedger {
    let mut parent = nu63_funded_parent();
    let delta = stage_nu6_transactions(&parent, std::slice::from_ref(&NU63_LEDGER_FIXTURES.ironwood_coinbase), NU63_HEIGHT).unwrap();
    parent.commit(delta);
    let (_, prevouts) = nu63_transparent_template(&[([0xe1; 32], 0), ([0xe2; 32], 1)]);
    for (key, prevout) in [([0xe1; 32], 0), ([0xe2; 32], 1)].into_iter().zip(prevouts) {
        fund(&mut parent, key, u64::from(prevout.value()), &prevout.script_pubkey().0.0, 0, false);
    }
    parent
}

fn nu63_reward_with_fee(height: u32, fee: u64) -> Transaction {
    let reward = nu63_coinbase(height, TxVersion::V6, height);
    let mut transparent = reward.transparent_bundle().unwrap().clone(); transparent.vout[0] = output(125_000_000 + fee, &[0x51]);
    TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap()
}

#[test]
fn nu63_genuine_ironwood_coinbase_mixed_both_pools_and_raw_restricted_v5_consume_owned_assets() {
    use incrementalmerkletree::frontier::CommitmentTree;
    let fixture = &*NU63_LEDGER_FIXTURES;
    let mut parent = nu63_mixed_parent();
    let before = owned_state(&parent);
    assert_eq!((parent.orchard_tree_size(), parent.ironwood_tree_size(), parent.shielded_balances[2], parent.shielded_balances[3]), (2, 2, 7, 12));
    assert_eq!(check_v6_coinbase(&fixture.ironwood_coinbase, NU63_HEIGHT, 1_800_000_000).map(|values| (values.transparent, values.ironwood_balance)), Ok((137_499_988, -12)));
    let hashes = PostNu5SignatureHash::new(fixture.mixed.clone(), nu63_transparent_template(&[([0xe1; 32], 0), ([0xe2; 32], 1)]).1).unwrap();
    assert_eq!(verify_post_nu63_crypto(&hashes), Ok(()));
    assert_eq!(verify_sapling_post_nu5_crypto(&hashes), Ok(()));
    assert_eq!((i64::from(*hashes.transaction().orchard_bundle().unwrap().value_balance()), i64::from(*hashes.transaction().ironwood_bundle().unwrap().value_balance())), (3, -3));
    let delta = stage_nu6_transactions(&parent, &[nu63_reward_with_fee(NU63_HEIGHT + 1, 5), fixture.mixed.clone()], NU63_HEIGHT + 1).unwrap();
    assert_eq!((delta.fees, delta.orchard, delta.ironwood, delta.deferred, delta.issued), (5, 4, 15, 56_250_013, 468_950_018));
    assert_eq!((delta.orchard_tree.tree_size(), delta.ironwood_tree.tree_size(), delta.orchard_nullifiers.len(), delta.ironwood_nullifiers.len()), (4, 4, 2, 2));
    assert_eq!((delta.sapling, delta.sapling_tree.tree_size()), (5, 1));
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    let raw = RawV5::parse_exact(&fixture.restricted_v5).unwrap();
    let bundle = raw.orchard().copied().unwrap();
    let hashes = raw.into_signature_context(vec![]).unwrap();
    assert_eq!(bundle.verify_orchard_post_nu63(&PostNu63OrchardVerifier::new(), &hashes.shielded()), Ok(()));
    assert_eq!(bundle.verify_orchard_fixed(&FixedOrchardVerifier::new(), &hashes.shielded()), Err(RawV5Error::OrchardVerifierModeMismatch));
    assert!(!fixture.restricted_ironwood.ironwood_bundle().unwrap().flags().outputs_enabled());
    let before = owned_state(&parent);
    let reward = nu63_coinbase(NU63_HEIGHT + 2, TxVersion::V4, NU63_HEIGHT + 2);
    let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V4(Box::new(reward)), original_v5(&fixture.restricted_v5), PostNu5Transaction::V6(Box::new(fixture.restricted_ironwood.clone()))], NU63_HEIGHT + 2, 1_800_000_000).unwrap();
    assert_eq!((delta.fees, delta.orchard, delta.ironwood, delta.orchard_tree.tree_size(), delta.ironwood_tree.tree_size()), (0, 0, 8, 6, 6));
    let mut orchard = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for raw in [&fixture.orchard_funding, &fixture.restricted_v5] {
        if std::ptr::eq(raw, &fixture.restricted_v5) {
            for action in fixture.mixed.orchard_bundle().unwrap().actions().iter() { orchard.append(MerkleHashOrchard::from_cmx(action.cmx())).unwrap(); }
        }
        for action in RawV5::parse_exact(raw).unwrap().orchard().unwrap().actions().as_chunks::<820>().0 {
            orchard.append(MerkleHashOrchard::from_bytes(action[96..128].try_into().unwrap()).unwrap()).unwrap();
        }
    }
    let mut ironwood = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for transaction in [&fixture.ironwood_coinbase, &fixture.mixed, &fixture.restricted_ironwood] {
        for action in transaction.ironwood_bundle().unwrap().actions().iter() { ironwood.append(MerkleHashOrchard::from_cmx(action.cmx())).unwrap(); }
    }
    assert_eq!((delta.orchard_root, delta.ironwood_root), (orchard.root().to_bytes(), ironwood.root().to_bytes()));
    assert_eq!(owned_state(&parent), before);
    parent.commit(delta);
    assert_eq!((parent.nullifier_count(ShieldedPool::Orchard), parent.nullifier_count(ShieldedPool::Ironwood)), (6, 6));
    assert_eq!(parent.transparent_balance() + parent.shielded_balances.iter().sum::<u64>() + parent.deferred_balance(), parent.issued_supply());
}

fn with_nu63_bundles(transaction: &Transaction, orchard: Option<OrchardBundle>, ironwood: Option<OrchardBundle>) -> Transaction {
    TransactionData::<Authorized>::from_parts_v6(transaction.consensus_branch_id(), transaction.lock_time(), transaction.expiry_height(),
        transaction.transparent_bundle().cloned(), transaction.sapling_bundle().cloned(), orchard, ironwood).freeze().unwrap()
}

fn changed_bundle(bundle: &OrchardBundle, anchor: Option<[u8; 32]>, mut change: impl FnMut(usize, &mut orchard::Action<orchard::primitives::redpallas::Signature<orchard::primitives::redpallas::SpendAuth>>)) -> OrchardBundle {
    let mut actions = bundle.actions().clone();
    for (index, action) in actions.iter_mut().enumerate() { change(index, action); }
    orchard::Bundle::try_from_parts(actions, *bundle.flags(), *bundle.value_balance(), anchor.map_or(*bundle.anchor(), |anchor| orchard::Anchor::from_bytes(anchor).unwrap()), bundle.authorization().clone(), bundle.bundle_version()).unwrap()
}

fn replace_action(action: &mut orchard::Action<orchard::primitives::redpallas::Signature<orchard::primitives::redpallas::SpendAuth>>, nullifier: Option<orchard::note::Nullifier>, ciphertext: Option<orchard::note::TransmittedNoteCiphertext>) {
    *action = orchard::Action::from_parts(nullifier.unwrap_or(*action.nullifier()), action.rk().clone(), *action.cmx(), ciphertext.unwrap_or_else(|| action.encrypted_note().clone()), action.cv_net().clone(), action.authorization().clone()).unwrap();
}

#[test]
fn nu63_each_pool_uses_current_own_nullifiers_parent_only_anchors_and_every_padding_leaf() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    let mut parent = nu63_mixed_parent();
    let orchard = fixture.mixed.orchard_bundle().unwrap();
    let ironwood = fixture.mixed.ironwood_bundle().unwrap();
    let nf = orchard.actions().first().nullifier().to_bytes();
    // Equal raw N bytes in two pools are independent. This direct state check
    // makes no crypto claim for the mutation; genuine originals are used above.
    let changed = changed_bundle(ironwood, None, |index, action| { if index == 0 { replace_action(action, Some(*orchard.actions().first().nullifier()), None); } });
    let before = owned_state(&parent);
    let mut delta = BlockDelta::new(&parent);
    parent.stage_typed_pool(Some(orchard), ShieldedPool::Orchard, &mut delta).unwrap();
    parent.stage_typed_pool(Some(&changed), ShieldedPool::Ironwood, &mut delta).unwrap();
    assert!(delta.orchard_nullifiers.contains(&nf) && delta.ironwood_nullifiers.contains(&nf));
    assert_eq!((delta.orchard_tree.tree_size(), delta.ironwood_tree.tree_size()), (4, 4));
    assert_eq!(owned_state(&parent), before);
    for pool in [ShieldedPool::Orchard, ShieldedPool::Ironwood] {
        let bundle = if pool == ShieldedPool::Orchard { orchard } else { ironwood };
        let first_nf = bundle.actions().first().nullifier().to_bytes();
        for scenario in 0..5 {
            let mut test_parent = nu63_mixed_parent();
            if scenario == 0 { test_parent.nullifiers[pool.index()].insert(first_nf); }
            if scenario == 1 {
                let leaf = MerkleHashOrchard::from_cmx(bundle.actions().first().cmx());
                let full = Frontier::from_parts(((1_u64 << 32) - 2).into(), leaf, vec![leaf; 31]).unwrap();
                if pool == ShieldedPool::Orchard { test_parent.orchard_tree = full; test_parent.shielded_roots[2] = test_parent.orchard_tree.root().to_bytes(); }
                else { test_parent.ironwood_tree = full; test_parent.shielded_roots[3] = test_parent.ironwood_tree.root().to_bytes(); }
            }
            let changed = match scenario {
                2 => changed_bundle(bundle, Some(if pool == ShieldedPool::Orchard { parent.shielded_roots[3] } else { parent.shielded_roots[2] }), |_, _| {}),
                3 => changed_bundle(bundle, None, |index, action| { if index == 1 { replace_action(action, Some(*bundle.actions().first().nullifier()), None); } }),
                4 => {
                    let mut candidate = BlockDelta::new(&parent);
                    parent.stage_typed_pool(Some(bundle), pool, &mut candidate).unwrap();
                    let anchor = if pool == ShieldedPool::Orchard { candidate.orchard_tree.root().to_bytes() } else { candidate.ironwood_tree.root().to_bytes() };
                    changed_bundle(bundle, Some(anchor), |_, _| {})
                }
                _ => bundle.clone(),
            };
            let snapshot = owned_state(&test_parent);
            let expected = match (pool, scenario) {
                (ShieldedPool::Orchard, 0 | 3) => SproutLedgerError::SpentOrchardNullifier,
                (ShieldedPool::Ironwood, 0 | 3) => SproutLedgerError::SpentIronwoodNullifier,
                (ShieldedPool::Orchard, 1) => SproutLedgerError::OrchardTreeFull,
                (ShieldedPool::Ironwood, 1) => SproutLedgerError::IronwoodTreeFull,
                (ShieldedPool::Orchard, _) => SproutLedgerError::UnknownOrchardAnchor,
                _ => SproutLedgerError::UnknownIronwoodAnchor,
            };
            let mut candidate = BlockDelta::new(&test_parent);
            assert!(matches!(test_parent.stage_typed_pool(Some(&changed), pool, &mut candidate), Err(error) if error == expected));
            assert_eq!(owned_state(&test_parent), snapshot);
        }
    }
    parent.nullifiers[3].insert(nf);
    let mut delta = BlockDelta::new(&parent);
    assert!(parent.stage_typed_pool(Some(orchard), ShieldedPool::Orchard, &mut delta).is_ok());
}

#[test]
fn nu63_negative_orchard_and_every_orchard_coinbase_are_contextually_forbidden() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    let parent = nu63_mixed_parent();
    let before = owned_state(&parent);
    let hashes = PostNu5SignatureHash::new(fixture.negative_orchard.clone(), vec![output(1, &[0x51])]).unwrap();
    assert_eq!(verify_post_nu63_crypto(&hashes), Ok(()));
    assert_eq!(check_v6_transaction(&fixture.negative_orchard, NU63_HEIGHT + 1, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::NegativeOrchardBalance));
    let v5 = TransactionData::<Authorized>::from_parts(TxVersion::V5, BranchId::Nu6_3, 0, 0.into(), fixture.negative_orchard.transparent_bundle().cloned(), None, None, fixture.negative_orchard.orchard_bundle().cloned()).freeze().unwrap();
    let raw = encoded(&v5);
    assert_eq!(check_v5_transaction(&RawV5::parse_exact(&raw).unwrap(), NU63_HEIGHT + 1, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::NegativeOrchardBalance));
    for version in [TxVersion::V5, TxVersion::V6] {
        let reward = nu63_coinbase(NU63_HEIGHT, version, NU63_HEIGHT);
        let orchard = fixture.mixed.orchard_bundle().cloned();
        let tx = if version == TxVersion::V6 { TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, NU63_HEIGHT.into(), reward.transparent_bundle().cloned(), None, orchard, None).freeze().unwrap() }
            else { TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_3, 0, NU63_HEIGHT.into(), reward.transparent_bundle().cloned(), None, None, orchard).freeze().unwrap() };
        assert!(matches!(stage_nu6_transactions(&parent, &[tx], NU63_HEIGHT), Err(SproutLedgerError::InvalidCoinbase)));
    }
    assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu63_every_pool_proof_spendauth_binding_and_sapling_output_are_required_atomically() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    for pool in [orchard::ValuePool::Orchard, orchard::ValuePool::Ironwood] {
        let bundle = if pool == orchard::ValuePool::Orchard { fixture.mixed.orchard_bundle().unwrap() } else { fixture.mixed.ironwood_bundle().unwrap() };
        for field in 0..bundle.actions().len() + 2 {
            let changed = if field < bundle.actions().len() {
                let mut index = 0;
                bundle.clone().map_authorization(&mut (), |_, _, signature| {
                    let mut bytes = <[u8; 64]>::from(&signature);
                    if index == field { bytes[63] ^= 1; }
                    index += 1;
                    bytes.into()
                }, |_, auth| auth)
            } else {
                let mut proof = bundle.authorization().proof().as_ref().to_vec();
                let mut binding = <[u8; 64]>::from(bundle.authorization().binding_signature());
                if field == bundle.actions().len() { binding[63] ^= 1; } else { proof[0] ^= 1; }
                orchard::Bundle::try_from_parts(bundle.actions().clone(), *bundle.flags(), *bundle.value_balance(), *bundle.anchor(), orchard::bundle::Authorized::from_parts(orchard::Proof::new(proof), binding.into()), bundle.bundle_version()).unwrap()
            };
            let tx = with_nu63_bundles(&fixture.mixed, if pool == orchard::ValuePool::Orchard { Some(changed.clone()) } else { fixture.mixed.orchard_bundle().cloned() },
                if pool == orchard::ValuePool::Ironwood { Some(changed) } else { fixture.mixed.ironwood_bundle().cloned() });
            let parent = nu63_mixed_parent();
            let before = owned_state(&parent);
            let expected = if field < bundle.actions().len() { PostNu63CryptoError::InvalidSpendAuth { pool, index: field } }
                else if field == bundle.actions().len() { PostNu63CryptoError::InvalidBindingSignature { pool } }
                else { PostNu63CryptoError::Proof { pool, error: crate::orchard_original::PostNu63OrchardError::InvalidProof } };
            assert!(matches!(stage_nu6_transactions(&parent, &[nu63_reward_with_fee(NU63_HEIGHT + 1, 5), tx], NU63_HEIGHT + 1), Err(SproutLedgerError::PostNu63(error)) if error == expected));
            assert_eq!(owned_state(&parent), before);
            let retry = stage_nu6_transactions(&parent, &[nu63_reward_with_fee(NU63_HEIGHT + 1, 5), fixture.mixed.clone()], NU63_HEIGHT + 1).unwrap();
            assert_eq!((retry.fees, retry.ironwood), (5, 15));
        }
    }
    let source = fixture.mixed.sapling_bundle().unwrap();
    for field in 0..2 {
        let mut outputs = source.shielded_outputs().to_vec();
        let mut binding = <[u8; 64]>::from(source.authorization().binding_sig);
        if field == 0 {
            let output = &outputs[0]; let mut proof = *output.zkproof(); proof[0] ^= 0x20;
            outputs[0] = sapling_crypto::bundle::OutputDescription::from_parts(output.cv().clone(), *output.cmu(), output.ephemeral_key().clone(), *output.enc_ciphertext(), *output.out_ciphertext(), proof);
        } else { binding[63] ^= 1; }
        let sapling = sapling_crypto::Bundle::from_parts(vec![], outputs, *source.value_balance(), sapling_crypto::bundle::Authorized { binding_sig: binding.into() });
        let tx = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, 0.into(), fixture.mixed.transparent_bundle().cloned(), sapling, fixture.mixed.orchard_bundle().cloned(), fixture.mixed.ironwood_bundle().cloned()).freeze().unwrap();
        let parent = nu63_mixed_parent(); let before = owned_state(&parent);
        let expected = if field == 0 { SaplingCryptoError::InvalidOutputProof { index: 0 } } else { SaplingCryptoError::InvalidBindingSignature };
        assert!(matches!(stage_nu6_transactions(&parent, &[nu63_reward_with_fee(NU63_HEIGHT + 1, 5), tx], NU63_HEIGHT + 1), Err(SproutLedgerError::Sapling(error)) if error == expected));
        assert_eq!(owned_state(&parent), before);
    }
}

#[path = "../tests/fixtures/ironwood-testnet-4410000.rs"]
mod ironwood_primary;

#[test]
fn nu63_acquired_4410000_coinbase_qualifies_actual_crypto_without_archive_authority() {
    use sha2::{Digest, Sha256};
    let raw = bytes(ironwood_primary::TRANSACTION_HEX);
    assert_eq!(raw.len(), 6_104);
    assert_eq!(Sha256::digest(&raw).as_slice(), bytes("621bec450ff838f5dda03cfe18bc850a1824f75d1bfa5b0c4a2eb93572cb77d7"));
    let mut remaining = raw.as_slice(); let transaction = Transaction::read(&mut remaining, BranchId::Nu6_3).unwrap();
    assert!(remaining.is_empty()); assert_eq!(encoded(&transaction), raw);
    assert_eq!(transaction.txid().as_ref().as_slice(), bytes("bcda3dd5052bbf09684bc24470143c1e94816b1da130c124fbe7605a514bbf6b").as_slice());
    assert_eq!(transaction.version(), TxVersion::V6);
    assert!(transaction.orchard_bundle().is_none() && transaction.sapling_bundle().is_none());
    let values = check_v6_coinbase(&transaction, 4_410_000, 1_800_000_000).unwrap();
    assert_eq!((values.transparent, values.ironwood_balance), (12_500_000, -125_000_000));
    let hashes = PostNu5SignatureHash::new(transaction, vec![]).unwrap();
    assert_eq!(verify_post_nu63_crypto(&hashes), Ok(()));
    // Actual public body admission cannot import this acquisition as a
    // checkpoint: the only owned parent remains authentic height-zero genesis.
    let mut parent = state(); let before = owned_state(&parent);
    let body = post_nu5_structural_body(&[&raw], 4_410_000, [0; 32]);
    assert!(parent.apply_block(&body).is_err());
    assert_eq!(owned_state(&parent), before);
}

fn reauthenticate_ironwood_plaintext(action: &orchard::Action<orchard::primitives::redpallas::Signature<orchard::primitives::redpallas::SpendAuth>>, field: u8) -> orchard::note::TransmittedNoteCiphertext {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag, aead::AeadInPlace};
    use orchard::{keys::OutgoingViewingKey, note_encryption::IronwoodDomain};
    use zcash_note_encryption::{Domain, EphemeralKeyBytes, OutPlaintextBytes};
    let nonce = Nonce::from_slice(&[0; 12]);
    let epk = EphemeralKeyBytes(action.encrypted_note().epk_bytes);
    let ock = IronwoodDomain::derive_ock(&OutgoingViewingKey::from([0; 32]), action.cv_net(), &action.cmx().to_bytes(), &epk);
    let mut outgoing: [u8; 64] = action.encrypted_note().out_ciphertext[..64].try_into().unwrap();
    ChaCha20Poly1305::new_from_slice(ock.as_ref()).unwrap().decrypt_in_place_detached(nonce, &[], &mut outgoing, Tag::from_slice(&action.encrypted_note().out_ciphertext[64..])).unwrap();
    let op = OutPlaintextBytes(outgoing);
    let pk_d = IronwoodDomain::extract_pk_d(&op).unwrap();
    let esk = IronwoodDomain::extract_esk(&op).unwrap();
    let key = IronwoodDomain::kdf(IronwoodDomain::ka_agree_enc(&esk, &pk_d), &epk);
    let mut note: [u8; 564] = action.encrypted_note().enc_ciphertext[..564].try_into().unwrap();
    ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap().decrypt_in_place_detached(nonce, &[], &mut note, Tag::from_slice(&action.encrypted_note().enc_ciphertext[564..])).unwrap();
    assert_eq!(note[0], 3);
    match field {
        0 => note[0] = 2,
        1 => note[1] ^= 1,
        2 => note[12] ^= 1,
        3 => note[20] ^= 1,
        4 => outgoing[..32].fill(0),
        5 => outgoing[32..].fill(0xff),
        6 => note[52..].fill(0xff),
        _ => unreachable!(),
    }
    let mut ciphertext = action.encrypted_note().clone();
    ciphertext.enc_ciphertext[..564].copy_from_slice(&note);
    let tag = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap().encrypt_in_place_detached(nonce, &[], &mut ciphertext.enc_ciphertext[..564]).unwrap();
    ciphertext.enc_ciphertext[564..].copy_from_slice(&tag);
    ciphertext.out_ciphertext[..64].copy_from_slice(&outgoing);
    let tag = ChaCha20Poly1305::new_from_slice(ock.as_ref()).unwrap().encrypt_in_place_detached(nonce, &[], &mut ciphertext.out_ciphertext[..64]).unwrap();
    ciphertext.out_ciphertext[64..].copy_from_slice(&tag);
    ciphertext
}

#[test]
fn nu63_every_ironwood_coinbase_output_requires_lead03_zip2005_fields_and_both_tags() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    let bundle = fixture.ironwood_coinbase.ironwood_bundle().unwrap();
    for (index, original) in bundle.actions().iter().enumerate() {
        let expected = recover_ironwood_coinbase_output(original, NU63_HEIGHT).unwrap();
        assert!([5, 7].contains(&expected));
        for height in [NU63_HEIGHT, 4_465_025] { assert_eq!(recover_ironwood_coinbase_output(original, height), Ok(expected)); }
        for height in [NU63_HEIGHT - 1, 4_465_026, u32::MAX] { assert_eq!(recover_ironwood_coinbase_output(original, height), Err(CoinbaseRecoveryError::UnsupportedEra)); }
        let domain = orchard::note_encryption::OrchardDomain::for_action(original);
        assert!(zcash_note_encryption::try_output_recovery_with_ovk(&domain, &orchard::keys::OutgoingViewingKey::from([0; 32]), original, original.cv_net(), &original.encrypted_note().out_ciphertext).is_none());
        for field in 0..10 {
            let ciphertext = if field < 6 { reauthenticate_ironwood_plaintext(original, field) } else {
                let mut ciphertext = original.encrypted_note().clone();
                match field { 6 => ciphertext.enc_ciphertext[563] ^= 1, 7 => ciphertext.enc_ciphertext[579] ^= 1,
                    8 => ciphertext.out_ciphertext[0] ^= 1, 9 => ciphertext.out_ciphertext[79] ^= 1, _ => unreachable!() }
                ciphertext
            };
            let changed = changed_bundle(bundle, None, |position, action| { if position == index { replace_action(action, None, Some(ciphertext.clone())); } });
            let tx = with_nu63_bundles(&fixture.ironwood_coinbase, None, Some(changed));
            let parent = nu63_funded_parent(); let before = owned_state(&parent);
            assert!(matches!(stage_nu6_transactions(&parent, &[tx], NU63_HEIGHT), Err(SproutLedgerError::IronwoodCoinbaseRecovery { index: actual, error: CoinbaseRecoveryError::IronwoodOutputRecovery }) if actual == index), "field{field}");
            assert_eq!(owned_state(&parent), before);
        }
        let mut memo = original.clone(); replace_action(&mut memo, None, Some(reauthenticate_ironwood_plaintext(original, 6)));
        assert_eq!(recover_ironwood_coinbase_output(&memo, NU63_HEIGHT), Ok(expected));
    }
}

#[test]
fn nu63_coinbase_balance_uses_signed_pool_delta_not_recovered_note_sum() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    let bundle = fixture.ironwood_coinbase.ironwood_bundle().unwrap();
    let parent = nu63_funded_parent(); let before = owned_state(&parent);
    for balance in [0_i64, 12] {
        let changed = bundle.clone().try_map_value_balance(|_| zcash_protocol::value::ZatBalance::from_i64(balance)).unwrap();
        let tx = with_nu63_bundles(&fixture.ironwood_coinbase, None, Some(changed));
        // Both actual output ciphertexts still recover their original 5/7.
        assert!(check_v6_coinbase(&tx, NU63_HEIGHT, 1_800_000_000).is_ok());
        assert!(matches!(stage_nu6_transactions(&parent, &[tx], NU63_HEIGHT), Err(SproutLedgerError::PostNu63(PostNu63CryptoError::InvalidSpendAuth { pool: orchard::ValuePool::Ironwood, index: 0 }))));
        assert_eq!(owned_state(&parent), before);
    }
    let spend_enabled = orchard::Bundle::try_from_parts(bundle.actions().clone(), orchard::bundle::Flags::ENABLED, *bundle.value_balance(), *bundle.anchor(), bundle.authorization().clone(), bundle.bundle_version()).unwrap();
    let tx = with_nu63_bundles(&fixture.ironwood_coinbase, None, Some(spend_enabled));
    assert!(matches!(stage_nu6_transactions(&parent, &[tx], NU63_HEIGHT), Err(SproutLedgerError::InvalidCoinbase)));
    assert_eq!(owned_state(&parent), before);
}

fn nu63_leaf(height: u32, sapling_root: [u8; 32], orchard_root: [u8; 32], ironwood_root: [u8; 32], sapling_tx: u64, orchard_tx: u64, ironwood_tx: u64) -> HistoryLeafV3 {
    HistoryLeafV3 { v2: post_nu5_leaf(height, sapling_root, orchard_root, sapling_tx, orchard_tx), start_ironwood_root: ironwood_root, end_ironwood_root: ironwood_root, ironwood_tx }
}

#[test]
fn nu63_activation_binds_owned_last_nu62_full_auth_then_one_v3_leaf_without_asset_reset() {
    use zcash_history::{V3, Version};
    let fixture = &*NU63_LEDGER_FIXTURES;
    let mut parent = nu63_funded_parent();
    let prior = ChainHistoryV2::new(post_nu5_leaf(NU63_HEIGHT - 2, parent.shielded_roots[1], parent.shielded_roots[2], 0, 0)).unwrap();
    parent.history_root = Some(prior.root()); parent.chain_history_v2 = Some(prior);
    let reward = encoded(&nu62_coinbase(NU63_HEIGHT - 1, TxVersion::V5, NU63_HEIGHT - 1));
    let raw = post_nu5_structural_body(&[&reward], NU63_HEIGHT - 1, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&raw, NU63_HEIGHT - 1).unwrap(); let auth = body.auth_data_root(); let commitment = body.header().final_sapling_root;
    let delta = parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT - 1, 1_800_000_000).unwrap();
    let last = post_nu5_leaf(NU63_HEIGHT - 1, delta.sapling_root, delta.orchard_root, 0, 0);
    let history = parent.stage_post_nu5_history(&commitment, &auth, last.clone()).unwrap();
    parent.commit(delta); parent.history_root = Some(history.root()); parent.chain_history_v2 = Some(history);
    let cb = encoded(&fixture.ironwood_coinbase);
    let raw = post_nu5_structural_body(&[&cb], NU63_HEIGHT, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&raw, NU63_HEIGHT).unwrap();
    let auth = body.auth_data_root(); let commitment = body.header().final_sapling_root;
    let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT, 1_800_000_000).unwrap();
    let first = nu63_leaf(NU63_HEIGHT, delta.sapling_root, delta.orchard_root, delta.ironwood_root, 0, 0, 1);
    let new = parent.stage_nu63_history(&commitment, &auth, first.clone()).unwrap();
    assert_eq!((new.consensus_branch_id(), new.last_height(), new.leaf_count()), (0x37a5_165b, NU63_HEIGHT, 1));
    assert_eq!(new.root(), V3::hash(&first));
    assert_eq!(owned_state(&parent), before);
    for scenario in 0..7 {
        let mut bad = nu63_funded_parent();
        let mut previous = last.clone();
        if scenario == 0 { previous.v1.consensus_branch_id = u32::from(BranchId::Nu6_1); }
        if scenario == 1 { previous.v1.start_height -= 1; previous.v1.end_height -= 1; }
        let history = ChainHistoryV2::new(previous).unwrap(); bad.history_root = Some(history.root()); bad.chain_history_v2 = Some(history);
        let mut actual_auth = auth;
        let mut actual_commitment = block_commitment(bad.history_root().unwrap(), auth);
        if scenario == 2 { bad.chain_history_v2 = None; }
        if scenario == 3 { bad.history_root = Some([0; 32]); }
        if scenario == 4 { actual_auth[0] ^= 1; }
        if scenario == 5 { actual_commitment[0] ^= 1; }
        if scenario == 6 { bad.chain_history_v3 = Some(ChainHistoryV3::new(first.clone()).unwrap()); }
        let snapshot = owned_state(&bad);
        let expected = match scenario { 0 | 6 => SproutLedgerError::History(HistoryError::BranchMismatch), 1 => SproutLedgerError::History(HistoryError::NonconsecutiveHeight),
            2 | 3 => SproutLedgerError::WrongHistoryRoot, _ => SproutLedgerError::Body(BodyError::BlockCommitmentMismatch) };
        assert_eq!(bad.stage_nu63_history(&actual_commitment, &actual_auth, first.clone()).unwrap_err(), expected);
        assert_eq!(owned_state(&bad), snapshot);
    }
    let bundle = fixture.ironwood_coinbase.ironwood_bundle().unwrap();
    let mut auth_mutations = Vec::new();
    for field in 0..bundle.actions().len() + 3 {
        let changed = if field < bundle.actions().len() {
            let mut index = 0;
            bundle.clone().map_authorization(&mut (), |_, _, signature| { let mut bytes = <[u8; 64]>::from(&signature); if index == field { bytes[63] ^= 1; } index += 1; bytes.into() }, |_, authorization| authorization)
        } else if field == bundle.actions().len() + 2 {
            changed_bundle(bundle, Some(parent.shielded_roots[2]), |_, _| {})
        } else {
            let mut proof = bundle.authorization().proof().as_ref().to_vec(); let mut binding = <[u8; 64]>::from(bundle.authorization().binding_signature());
            if field == bundle.actions().len() { proof[0] ^= 1; } else { binding[63] ^= 1; }
            orchard::Bundle::try_from_parts(bundle.actions().clone(), *bundle.flags(), *bundle.value_balance(), *bundle.anchor(), orchard::bundle::Authorized::from_parts(orchard::Proof::new(proof), binding.into()), bundle.bundle_version()).unwrap()
        };
        auth_mutations.push(encoded(&with_nu63_bundles(&fixture.ironwood_coinbase, None, Some(changed))));
    }
    for changed in auth_mutations {
        let raw = post_nu5_structural_body(&[&changed], NU63_HEIGHT, parent.history_root().unwrap());
        let changed_auth = PostNu5Block::parse(&raw, NU63_HEIGHT).unwrap().auth_data_root();
        assert_ne!(changed_auth, auth);
        assert_eq!(parent.stage_nu63_history(&commitment, &changed_auth, first.clone()).unwrap_err(), SproutLedgerError::Body(BodyError::BlockCommitmentMismatch));
        assert_eq!(owned_state(&parent), before);
    }
    parent.commit(delta); parent.history_root = Some(new.root()); parent.chain_history_v2 = None; parent.chain_history_v3 = Some(new);
    assert_eq!(parent.orchard_tree, before.orchard_tree); assert_eq!(parent.orchard_anchors, before.orchard_anchors); assert_eq!(parent.nullifiers[2], before.nullifiers[2]);
    assert_eq!((parent.ironwood_tree_size(), parent.nullifier_count(ShieldedPool::Ironwood)), (2, 2));
    let reward = encoded(&nu63_coinbase(NU63_HEIGHT + 1, TxVersion::V4, NU63_HEIGHT + 1));
    let raw = post_nu5_structural_body(&[&reward], NU63_HEIGHT + 1, parent.history_root().unwrap()); let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 1).unwrap();
    let auth = body.auth_data_root(); let commitment = body.header().final_sapling_root; let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT + 1, 1_800_000_000).unwrap();
    let second = nu63_leaf(NU63_HEIGHT + 1, delta.sapling_root, delta.orchard_root, delta.ironwood_root, 0, 0, 0);
    let new = parent.stage_nu63_history(&commitment, &auth, second.clone()).unwrap();
    assert_eq!(new.root(), V3::hash(&V3::combine(&first, &second))); assert_eq!(new.leaf_count(), 2);
    assert_eq!((delta.ironwood_tree.tree_size(), delta.ironwood_nullifiers.len(), delta.ironwood), (2, 0, 12));
    assert_eq!(owned_state(&parent), before);
    for (height, expected) in [(NU63_HEIGHT + 3, SproutLedgerError::History(HistoryError::NonconsecutiveHeight)), (4_465_026, SproutLedgerError::UnsupportedEra)] {
        let leaf = nu63_leaf(height, delta.sapling_root, delta.orchard_root, delta.ironwood_root, 0, 0, 0);
        assert_eq!(parent.stage_nu63_history(&commitment, &auth, leaf).unwrap_err(), expected);
        assert_eq!(owned_state(&parent), before);
    }
}

#[test]
fn nu63_signed_coinbase_conservation_and_aggregate_max_are_separate_atomic_checks() {
    let height = NU63_HEIGHT;
    // Isolated signed accounting oracle: +3 Sapling and +4 Ironwood reduce the
    // miner's current claim. No ciphertext/proof validity is mocked by this test.
    let mut parent = isolated_deferred_parent(13); parent.shielded_balances[1] = 3; parent.shielded_balances[3] = 4; parent.issued_supply += 7;
    let before = owned_state(&parent);
    let values = CoinbaseValues { claimed: 137_500_007, transparent: 137_500_007, sapling_balance: 3, orchard_balance: 0, ironwood_balance: 4, retained: 137_500_007, sigops: 0 };
    let mut delta = BlockDelta::new(&parent); delta.transparent = 137_500_007; delta.retained = 137_500_007; delta.sapling = -3; delta.ironwood = -4; delta.deferred = 18_750_000;
    let delta = parent.finish_delta(delta, values, height).unwrap();
    assert_eq!((delta.sapling, delta.ironwood, delta.issued, delta.deferred), (0, 0, 156_250_020, 18_750_013)); assert_eq!(owned_state(&parent), before);
    for error in 0..8 {
        let mut bad = isolated_deferred_parent(13);
        if error < 6 {
            if error == 0 { bad.transparent_balance = MAX_MONEY - 1; }
            else if error < 5 { bad.shielded_balances[error - 1] = MAX_MONEY - 1; }
            else { bad.deferred_balance = MAX_MONEY - 1; }
            bad.issued_supply = MAX_MONEY - 1;
        } else { bad.shielded_balances[3] = 1; bad.issued_supply += 1; }
        let snapshot = owned_state(&bad);
        if error < 6 {
            assert!(matches!(stage_nu6_transactions(&bad, &[nu63_coinbase(height, TxVersion::V4, height)], height), Err(SproutLedgerError::ValueOutOfRange)));
        } else {
            let reward = check_coinbase(&nu63_coinbase(height, TxVersion::V4, height), height, 1_800_000_000).unwrap();
            let mut delta = BlockDelta::new(&bad); delta.transparent = 137_500_000; delta.retained = 137_500_000; delta.deferred = 18_750_000; delta.ironwood = if error == 6 { -2 } else { 1 };
            assert!(matches!(bad.finish_delta(delta, reward, height), Err(SproutLedgerError::ValueOutOfRange)));
        }
        assert_eq!(owned_state(&bad), snapshot);
    }
}

#[test]
fn nu63_finite_funding_schedule_claims_actual_fees_and_burns_without_repeat_disbursement() {
    for height in [NU63_HEIGHT, NU63_HEIGHT + 1, 4_199_999, 4_200_000, 4_339_999, 4_340_000, 4_465_025] {
        assert_eq!(subsidy(height), Ok(156_250_000)); assert_eq!(deferred_subsidy(height), 18_750_000); assert_eq!(deferred_withdrawal(height), 0);
        for version in [TxVersion::V4, TxVersion::V5, TxVersion::V6] {
            let parent = isolated_deferred_parent(13); let before = owned_state(&parent);
            let reward = nu63_coinbase(height, version, height);
            assert_eq!(reward.transparent_bundle().unwrap().vout.len(), 2);
            let delta = stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height).unwrap();
            assert_eq!((delta.transparent, delta.deferred, delta.issued), (137_500_000, 18_750_013, 156_250_013));
            for field in 0..4 {
                let mut transparent = reward.transparent_bundle().unwrap().clone();
                match field { 0 => { transparent.vout.remove(1); }, 1 => transparent.vout[1] = output(12_500_000, &[0x51]),
                    2 => transparent.vout[1] = output(12_499_999, &bytes(NU6_FPF_SCRIPT)), 3 => transparent.vout[0] = output(125_000_001, &[0x51]), _ => unreachable!() }
                let tx = if version == TxVersion::V6 { TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap() }
                    else { TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_3, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap() };
                let expected = if field == 3 { SproutLedgerError::CoinbaseRewardExceeded } else { SproutLedgerError::MissingFundingStream { index: 0 } };
                assert!(matches!(stage_nu6_transactions(&parent, &[tx], height), Err(actual) if actual == expected)); assert_eq!(owned_state(&parent), before);
            }
        }
    }
    let mut parent = isolated_deferred_parent(13); let key = ([0xa7; 32], 0); fund(&mut parent, key, 10, &[0x51], 0, false);
    let tx = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, 0.into(), spend(&[(key, &[], u32::MAX)], vec![output(7, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
    let reward = nu63_reward_with_fee(NU63_HEIGHT, 3); let mut transparent = reward.transparent_bundle().unwrap().clone(); transparent.vout[0] = output(125_000_003, &[0x6a]);
    let reward = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, NU63_HEIGHT.into(), Some(transparent), None, None, None).freeze().unwrap();
    let before = owned_state(&parent); let delta = stage_nu6_transactions(&parent, &[reward, tx], NU63_HEIGHT).unwrap();
    assert_eq!((delta.fees, delta.transparent, delta.retained, delta.deferred, delta.issued), (3, 137_500_010, 12_500_007, 18_750_013, 156_250_023)); assert_eq!(owned_state(&parent), before);
    assert_eq!(subsidy(4_465_026), Err(SproutLedgerError::UnsupportedEra));
}

#[test]
fn nu63_actual_old_key_signatures_never_enable_fixed_or_original_proof_fallback() {
    let hashes = PostNu5SignatureHash::new(NU63_LEDGER_FIXTURES.old_key_coinbase.clone(), vec![]).unwrap();
    let bundle = hashes.transaction().ironwood_bundle().unwrap();
    for action in bundle.actions().iter() { assert_eq!(action.rk().verify(&hashes.shielded(), action.authorization()), Ok(())); }
    assert_eq!(bundle.binding_validating_key().verify(&hashes.shielded(), bundle.authorization().binding_signature()), Ok(()));
    assert_eq!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::Proof { pool: orchard::ValuePool::Ironwood, error: crate::orchard_original::PostNu63OrchardError::InvalidProof }));
}

#[test]
fn nu63_raw_v5_restricted_spend_requires_every_proof_signature_and_binding_without_projection_shortcut() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    let raw = RawV5::parse_exact(&fixture.restricted_v5).unwrap();
    let bundle = raw.orchard().copied().unwrap();
    let mut mutations = vec![(bundle.proof().as_ptr() as usize - fixture.restricted_v5.as_ptr() as usize, RawV5Error::InvalidOrchardProof),
        (bundle.binding_signature().as_ptr() as usize - fixture.restricted_v5.as_ptr() as usize + 63, RawV5Error::InvalidOrchardBindingSignature)];
    for index in 0..bundle.action_count() { mutations.push((bundle.spend_auth_signatures().as_ptr() as usize - fixture.restricted_v5.as_ptr() as usize + index * 64 + 63, RawV5Error::InvalidOrchardSpendAuth { index })); }
    for (offset, expected) in mutations {
        let mut changed = fixture.restricted_v5.clone(); changed[offset] ^= 1;
        let parent = nu63_funded_parent(); let before = owned_state(&parent);
        assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V6(Box::new(nu63_coinbase(NU63_HEIGHT, TxVersion::V6, NU63_HEIGHT))), original_v5(&changed)], NU63_HEIGHT, 1_800_000_000), Err(SproutLedgerError::Orchard(error)) if error == expected));
        assert_eq!(owned_state(&parent), before);
        let retry = parent.stage_post_nu5_block(vec![PostNu5Transaction::V6(Box::new(nu63_coinbase(NU63_HEIGHT, TxVersion::V6, NU63_HEIGHT))), original_v5(&fixture.restricted_v5)], NU63_HEIGHT, 1_800_000_000).unwrap();
        assert_eq!((retry.orchard, retry.orchard_tree.tree_size()), (3, 4));
    }
}

#[test]
fn nu63_v6_coinbase_proof_every_disabled_spendauth_binding_and_capacity_stay_required() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    let bundle = fixture.ironwood_coinbase.ironwood_bundle().unwrap();
    for field in 0..bundle.actions().len() + 2 {
        let changed = if field < bundle.actions().len() {
            let mut index = 0;
            bundle.clone().map_authorization(&mut (), |_, _, signature| { let mut bytes = <[u8; 64]>::from(&signature); if index == field { bytes[63] ^= 1; } index += 1; bytes.into() }, |_, authorization| authorization)
        } else {
            let mut proof = bundle.authorization().proof().as_ref().to_vec(); let mut binding = <[u8; 64]>::from(bundle.authorization().binding_signature());
            if field == bundle.actions().len() { binding[63] ^= 1; } else { proof[0] ^= 1; }
            orchard::Bundle::try_from_parts(bundle.actions().clone(), *bundle.flags(), *bundle.value_balance(), *bundle.anchor(), orchard::bundle::Authorized::from_parts(orchard::Proof::new(proof), binding.into()), bundle.bundle_version()).unwrap()
        };
        let tx = with_nu63_bundles(&fixture.ironwood_coinbase, None, Some(changed));
        let parent = nu63_funded_parent(); let before = owned_state(&parent);
        let expected = if field < bundle.actions().len() { PostNu63CryptoError::InvalidSpendAuth { pool: orchard::ValuePool::Ironwood, index: field } }
            else if field == bundle.actions().len() { PostNu63CryptoError::InvalidBindingSignature { pool: orchard::ValuePool::Ironwood } }
            else { PostNu63CryptoError::Proof { pool: orchard::ValuePool::Ironwood, error: crate::orchard_original::PostNu63OrchardError::InvalidProof } };
        assert!(matches!(stage_nu6_transactions(&parent, &[tx], NU63_HEIGHT), Err(SproutLedgerError::PostNu63(error)) if error == expected)); assert_eq!(owned_state(&parent), before);
    }
    let mut parent = nu63_funded_parent(); let leaf = MerkleHashOrchard::from_cmx(bundle.actions().first().cmx());
    parent.ironwood_tree = Frontier::from_parts(((1_u64 << 32) - 2).into(), leaf, vec![leaf; 31]).unwrap(); parent.shielded_roots[3] = parent.ironwood_tree.root().to_bytes();
    let before = owned_state(&parent);
    assert!(matches!(stage_nu6_transactions(&parent, std::slice::from_ref(&fixture.ironwood_coinbase), NU63_HEIGHT), Err(SproutLedgerError::IronwoodTreeFull))); assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu63_mixed_v6_resolves_both_ordered_actual_prevouts_scripts_maturity_and_fees() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    let height = NU63_HEIGHT + 1;
    for index in 0..2 {
        for field in 0..3 {
            let mut parent = nu63_mixed_parent(); let key = ([0xe1 + index as u8; 32], index as u32);
            let coin = parent.utxos.get_mut(&key).unwrap();
            if field == 0 { coin.output = output(u64::from(coin.output.value()) + 1, &coin.output.script_pubkey().0.0); parent.transparent_balance += 1; parent.utxo_balance += 1; parent.issued_supply += 1; }
            if field == 1 { let value = u64::from(coin.output.value()); let mut script = coin.output.script_pubkey().0.0.clone(); script[2] ^= 1; coin.output = output(value, &script); }
            if field == 2 { coin.is_coinbase = true; coin.created_height = height - 99; }
            let before = owned_state(&parent);
            let expected = if field == 2 { SproutLedgerError::ImmatureCoinbase } else { SproutLedgerError::InvalidTransparentScript };
            assert!(matches!(stage_nu6_transactions(&parent, &[nu63_reward_with_fee(height, 5), fixture.mixed.clone()], height), Err(error) if error == expected)); assert_eq!(owned_state(&parent), before);
        }
    }
    let mut parent = nu63_mixed_parent(); let coin = parent.utxos.get_mut(&([0xe1; 32], 0)).unwrap(); coin.is_coinbase = true; coin.created_height = height - 100;
    let before = owned_state(&parent);
    assert!(matches!(stage_nu6_transactions(&parent, &[nu63_reward_with_fee(height, 5), fixture.mixed.clone()], height), Err(SproutLedgerError::UnshieldedCoinbaseSpend))); assert_eq!(owned_state(&parent), before);
    // The shielded ALL message binds the original amount/script order as well as
    // both pool effects; swapping equal cardinality cannot hide a wrong prevout.
    let (_, mut previous) = nu63_transparent_template(&[([0xe1; 32], 0), ([0xe2; 32], 1)]); previous.swap(0, 1);
    let hashes = PostNu5SignatureHash::new(fixture.mixed.clone(), previous).unwrap();
    assert!(matches!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::InvalidSpendAuth { pool: orchard::ValuePool::Orchard, .. })));
}

#[test]
fn nu63_v4_and_raw_v5_keep_actual_zip243_zip244_ecdsa_and_old_signature_rejection() {
    let height = NU63_HEIGHT;
    for p2sh in [false, true] {
        for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
            let (v4tx, v4prev) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu6_3, p2sh, hash_type);
            let keys = [([0xf5; 32], 3), ([0xf6; 32], 7)];
            let (v5raw, v5prev) = independently_signed_v5_for_branch(&keys, BranchId::Nu6_3, p2sh, hash_type);
            let mut parent = isolated_deferred_parent(13);
            fund(&mut parent, ([0xa1; 32], 3), u64::from(v4prev.value()), &v4prev.script_pubkey().0.0, 0, false);
            for (key, prevout) in keys.into_iter().zip(&v5prev) { fund(&mut parent, key, u64::from(prevout.value()), &prevout.script_pubkey().0.0, 0, false); }
            let before = owned_state(&parent);
            let delta = parent.stage_post_nu5_block(vec![PostNu5Transaction::V6(Box::new(nu63_reward_with_fee(height, 7))), PostNu5Transaction::V4(Box::new(v4tx)), original_v5(&v5raw)], height, 1_800_000_000).unwrap();
            assert_eq!((delta.fees, delta.deferred, delta.issued), (7, 18_750_013, 156_550_020)); assert_eq!(owned_state(&parent), before);
            let (old, _) = independently_signed_transparent_for_branch(TxVersion::V4, BranchId::Nu6_2, p2sh, hash_type);
            assert!(matches!(stage_nu6_transactions(&parent, &[nu63_coinbase(height, TxVersion::V4, height), v4(&old, BranchId::Nu6_3, 0)], height), Err(SproutLedgerError::InvalidTransparentScript)));
            let (mut old, _) = independently_signed_v5_for_branch(&keys, BranchId::Nu6_2, p2sh, hash_type); old[8..12].copy_from_slice(&0x37a5_165bu32.to_le_bytes());
            assert!(matches!(parent.stage_post_nu5_block(vec![PostNu5Transaction::V6(Box::new(nu63_coinbase(height, TxVersion::V6, height))), original_v5(&old)], height, 1_800_000_000), Err(SproutLedgerError::InvalidTransparentScript))); assert_eq!(owned_state(&parent), before);
        }
    }
}

#[test]
fn nu63_v6_finality_expiry_order_scripts_resources_and_cutoff_never_publish_partial_delta() {
    let height = NU63_HEIGHT;
    let key = ([0xa8; 32], 0);
    for field in 0..7 {
        let mut parent = isolated_deferred_parent(13); fund(&mut parent, key, 10, &[0x51], 0, false);
        let before = owned_state(&parent);
        let template = spend(&[(key, &[], if field == 2 { 0 } else { u32::MAX })], vec![output(if field == 5 { 11 } else { 10 }, &[0x51])], if field == 2 { height } else { 0 });
        let mut transparent = template.transparent_bundle().unwrap().clone();
        if field == 3 { transparent.vin.push(transparent.vin[0].clone()); }
        if field == 4 { transparent.vin[0] = TxIn::from_parts(OutPoint::new([0xa9; 32], 0), Script::default(), u32::MAX); }
        if field == 6 { transparent.vout[0] = output(10, &vec![0xac; 20_001]); }
        let tx = TransactionData::<Authorized>::from_parts_v6(if field == 0 { BranchId::Nu6_2 } else { BranchId::Nu6_3 }, template.lock_time(), (if field == 1 { height - 1 } else { 0 }).into(), Some(transparent), None, None, None).freeze().unwrap();
        let expected = [SproutLedgerError::UnsupportedTransaction, SproutLedgerError::ExpiredTransaction, SproutLedgerError::NonfinalTransaction, SproutLedgerError::DuplicateTransparentInput, SproutLedgerError::MissingTransparentInput, SproutLedgerError::NegativeFee, SproutLedgerError::TooManySigops][field];
        assert!(matches!(stage_nu6_transactions(&parent, &[nu63_coinbase(height, TxVersion::V6, height), tx], height), Err(error) if error == expected)); assert_eq!(owned_state(&parent), before);
    }
    let parent = isolated_deferred_parent(13); let before = owned_state(&parent);
    for version in [TxVersion::V4, TxVersion::V5, TxVersion::V6] {
        for expiry in [0, height - 1, height + 1] {
            assert!(matches!(stage_nu6_transactions(&parent, &[nu63_coinbase(height, version, expiry)], height), Err(SproutLedgerError::InvalidCoinbase))); assert_eq!(owned_state(&parent), before);
        }
        assert!(matches!(stage_nu6_transactions(&parent, &[nu63_coinbase(4_465_026, version, 4_465_026)], 4_465_026), Err(SproutLedgerError::UnsupportedEra)));
    }
    let first = spend(&[(key, &[], u32::MAX)], vec![output(9, &[0x51])], 0).transparent_bundle().unwrap().clone();
    let first = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, 0.into(), Some(first), None, None, None).freeze().unwrap();
    let first_id: [u8; 32] = first.txid().into();
    let second = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, 0.into(), spend(&[((first_id, 0), &[], u32::MAX)], vec![output(8, &[0x51])], 0).transparent_bundle().cloned(), None, None, None).freeze().unwrap();
    let mut parent = isolated_deferred_parent(13); fund(&mut parent, key, 10, &[0x51], 0, false); let before = owned_state(&parent);
    assert!(matches!(stage_nu6_transactions(&parent, &[nu63_reward_with_fee(height, 2), second.clone(), first.clone()], height), Err(SproutLedgerError::MissingTransparentInput)));
    assert!(matches!(stage_nu6_transactions(&parent, &[nu63_reward_with_fee(height, 3), first.clone(), second.clone(), second.clone()], height), Err(SproutLedgerError::MissingTransparentInput))); assert_eq!(owned_state(&parent), before);
    let delta = stage_nu6_transactions(&parent, &[nu63_reward_with_fee(height, 2), first, second], height).unwrap(); assert_eq!(delta.fees, 2);
}

#[test]
fn nu63_v4_and_v6_inherited_sapling_spends_outputs_and_zip215_groth_remain_genuine_checks() {
    let source = recorded_sapling(); let bundle = source.sapling_bundle().unwrap();
    for version in [TxVersion::V4, TxVersion::V6] {
        for field in 0..4 {
            let mut parent = isolated_sapling_parent(); parent.deferred_balance = 13; parent.issued_supply += 13;
            let changed = if field == 3 {
                let mut spends = bundle.shielded_spends().to_vec(); let spend = &spends[0]; let mut proof = *spend.zkproof(); proof[0] ^= 0x20;
                spends[0] = sapling_crypto::bundle::SpendDescription::from_parts(spend.cv().clone(), *spend.anchor(), *spend.nullifier(), *spend.rk(), proof, *spend.spend_auth_sig());
                sapling_crypto::Bundle::from_parts(spends, bundle.shielded_outputs().to_vec(), *bundle.value_balance(), *bundle.authorization())
            } else { Some(bundle.clone()) };
            if field == 0 { parent.sapling_anchors.remove(&bundle.shielded_spends()[0].anchor().to_bytes()); }
            if field == 1 { parent.nullifiers[1].insert(bundle.shielded_spends()[0].nullifier().0); }
            if field == 2 { let leaf = SaplingNode::from_cmu(bundle.shielded_outputs()[0].cmu()); parent.sapling_tree = Frontier::from_parts(((1_u64 << 32) - 2).into(), leaf, vec![leaf; 31]).unwrap(); parent.shielded_roots[1] = parent.sapling_tree.root().to_bytes(); }
            let tx = if version == TxVersion::V6 { TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, 0.into(), None, changed, None, None).freeze().unwrap() }
                else { TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_3, 0, 0.into(), None, None, changed, None).freeze().unwrap() };
            let expected = [SproutLedgerError::UnknownSaplingAnchor, SproutLedgerError::SpentSaplingNullifier, SproutLedgerError::SaplingTreeFull, SproutLedgerError::Sapling(SaplingCryptoError::InvalidSpendProof { index: 0 })][field];
            let before = owned_state(&parent);
            assert!(matches!(stage_nu6_transactions(&parent, &[nu63_coinbase(NU63_HEIGHT, TxVersion::V6, NU63_HEIGHT), tx], NU63_HEIGHT), Err(error) if error == expected)); assert_eq!(owned_state(&parent), before);
        }
    }
    let source = Transaction::read(bytes(sprout_groth_fixture::TRANSACTION_HEX).as_slice(), BranchId::Nu6_3).unwrap();
    assert_eq!(check_transaction(&v4(&source, BranchId::Nu6_3, 0), NU63_HEIGHT, 1_800_000_000).map(|_| ()), Err(SproutLedgerError::SproutDepositDisabled));
    let mut sprout = source.sprout_bundle().unwrap().clone(); let mut raw = Vec::new(); sprout.joinsplits[0].write(&mut raw).unwrap(); raw[..16].fill(0);
    sprout.joinsplits[0] = JsDescription::read(raw.as_slice(), true).unwrap(); sprout.joinsplit_pubkey = [0; 32]; sprout.joinsplit_sig = [0; 64]; sprout.joinsplit_sig[0] = 1;
    let mut parent = isolated_deferred_parent(13); parent.sprout_anchors.insert(*sprout.joinsplits[0].anchor(), Frontier::empty()); let before = owned_state(&parent);
    let tx = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Nu6_3, 0, 0.into(), None, Some(sprout), None, None).freeze().unwrap();
    assert!(matches!(stage_nu6_transactions(&parent, &[nu63_coinbase(NU63_HEIGHT, TxVersion::V6, NU63_HEIGHT), tx], NU63_HEIGHT), Err(SproutLedgerError::JoinSplit(LegacyJoinSplitError::SproutGrothProof { index: 0, error: crate::sprout_groth16::GrothError::InvalidProof })))); assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu63_history_counts_actual_transactions_not_actions_and_preserves_all_retry_rights() {
    let fixture = &*NU63_LEDGER_FIXTURES;
    let mut parent = nu63_mixed_parent();
    let prior = ChainHistoryV3::new(nu63_leaf(NU63_HEIGHT, parent.shielded_roots[1], parent.shielded_roots[2], parent.shielded_roots[3], 0, 1, 1)).unwrap();
    parent.history_root = Some(prior.root()); parent.chain_history_v3 = Some(prior);
    let reward = encoded(&nu63_reward_with_fee(NU63_HEIGHT + 1, 5)); let mixed = encoded(&fixture.mixed);
    let raw = post_nu5_structural_body(&[&reward, &mixed, &fixture.restricted_v5], NU63_HEIGHT + 1, parent.history_root().unwrap());
    let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 1).unwrap();
    let orchard_tx = body.transactions().iter().filter(|tx| has_orchard(tx)).count() as u64;
    let ironwood_tx = body.transactions().iter().filter(|tx| matches!(tx, PostNu5Transaction::V6(tx) if tx.ironwood_bundle().is_some())).count() as u64;
    let sapling_tx = body.transactions().iter().filter(|tx| tx.sapling_bundle().is_some()).count() as u64;
    assert_eq!((sapling_tx, orchard_tx, ironwood_tx), (1, 2, 1));
    let auth = body.auth_data_root(); let commitment = body.header().final_sapling_root; let before = owned_state(&parent);
    let delta = parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT + 1, 1_800_000_000).unwrap();
    let leaf = nu63_leaf(NU63_HEIGHT + 1, delta.sapling_root, delta.orchard_root, delta.ironwood_root, sapling_tx, orchard_tx, ironwood_tx);
    for field in 0..4 {
        let mut wrong = leaf.clone();
        if field == 0 { wrong.v2.v1.start_height += 1; wrong.v2.v1.end_height += 1; }
        if field == 1 { wrong.v2.orchard_tx = u64::MAX; }
        if field == 2 { wrong.ironwood_tx = u64::MAX; }
        if field == 3 { wrong.end_ironwood_root = parent.shielded_roots[3]; }
        let result = parent.stage_nu63_history(&commitment, &auth, wrong);
        assert!(result.is_err());
        assert_eq!(owned_state(&parent), before);
    }
    let history = parent.stage_nu63_history(&commitment, &auth, leaf).unwrap(); assert_eq!(history.leaf_count(), 2);
    assert_eq!((delta.orchard_tree.tree_size(), delta.ironwood_tree.tree_size(), delta.sapling_tree.tree_size()), (6, 4, 1)); assert_eq!(owned_state(&parent), before);
    parent.commit(delta); parent.history_root = Some(history.root()); parent.chain_history_v3 = Some(history);
    assert!(parent.utxo(&[0xe1; 32], 0).is_none() && parent.utxo(&[0xe2; 32], 1).is_none());
}

#[test]
fn nu63_entire_finite_331026_height_credit_schedule_is_bounded_arithmetic_not_archive() {
    let mut parent = isolated_deferred_parent(13);
    let values = check_coinbase(&nu63_coinbase(NU63_HEIGHT, TxVersion::V4, NU63_HEIGHT), NU63_HEIGHT, 1_800_000_000).unwrap();
    for height in NU63_HEIGHT..4_465_026 {
        let mut delta = BlockDelta::new(&parent); delta.transparent = 137_500_000; delta.retained = 137_500_000; delta.deferred = 18_750_000;
        let delta = parent.finish_delta(delta, values, height).unwrap(); parent.commit(delta);
    }
    assert_eq!((parent.transparent_balance(), parent.deferred_balance(), parent.issued_supply()), (45_516_075_000_000, 6_206_737_500_013, 51_722_812_500_013));
    let before = owned_state(&parent);
    assert!(matches!(stage_nu6_transactions(&parent, &[nu63_coinbase(4_465_026, TxVersion::V6, 4_465_026)], 4_465_026), Err(SproutLedgerError::UnsupportedEra))); assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu63_v6_two_megabyte_transaction_boundary_and_block_sigops_are_not_waived() {
    let height = NU63_HEIGHT;
    let reward = nu63_coinbase(height, TxVersion::V6, height);
    let make = |padding: usize| {
        let mut transparent = reward.transparent_bundle().unwrap().clone(); transparent.vout[0] = output(125_000_000, &vec![0x00; padding]);
        TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap()
    };
    let padding = 2_000_000 - encoded(&make(70_000)).len() + 70_000;
    let parent = isolated_deferred_parent(13); let before = owned_state(&parent);
    assert_eq!(encoded(&make(padding)).len(), 2_000_000);
    assert!(stage_nu6_transactions(&parent, &[make(padding)], height).is_ok());
    assert!(matches!(stage_nu6_transactions(&parent, &[make(padding + 1)], height), Err(SproutLedgerError::TransactionTooLarge))); assert_eq!(owned_state(&parent), before);
    let mut transparent = reward.transparent_bundle().unwrap().clone(); transparent.vout[0] = output(125_000_000, &vec![0xac; 20_001]);
    let tx = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, height.into(), Some(transparent), None, None, None).freeze().unwrap();
    assert!(matches!(stage_nu6_transactions(&parent, &[tx], height), Err(SproutLedgerError::TooManySigops))); assert_eq!(owned_state(&parent), before);
}

#[test]
fn nu63_genuine_shield_only_v6_requires_exact_coinbase_maturity_and_every_prevout_in_all() {
    let height = NU63_HEIGHT + 1;
    let fixture = &*NU63_LEDGER_FIXTURES;
    for created in [height - 99, height - 100] {
        let mut parent = nu63_funded_parent();
        fund(&mut parent, ([0xe4; 32], 0), 3, &[0x51], created, true);
        fund(&mut parent, ([0xe5; 32], 1), 4, &[0x61, 0x51], 0, false);
        let before = owned_state(&parent);
        let result = stage_nu6_transactions(&parent, &[nu63_coinbase(height, TxVersion::V6, height), fixture.shield_only.clone()], height);
        if created == height - 100 {
            let delta = result.unwrap(); assert_eq!((delta.fees, delta.ironwood, delta.ironwood_tree.tree_size()), (0, 7, 2));
            assert_eq!(owned_state(&parent), before); parent.commit(delta); assert!(parent.utxo(&[0xe4; 32], 0).is_none() && parent.utxo(&[0xe5; 32], 1).is_none());
        } else { assert!(matches!(result, Err(SproutLedgerError::ImmatureCoinbase))); assert_eq!(owned_state(&parent), before); }
    }
    for index in 0..2 {
        let mut previous = vec![output(3, &[0x51]), output(4, &[0x61, 0x51])]; previous[index] = output(u64::from(previous[index].value()) + 1, &previous[index].script_pubkey().0.0);
        let hashes = PostNu5SignatureHash::new(fixture.shield_only.clone(), previous).unwrap();
        assert!(matches!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::InvalidSpendAuth { pool: orchard::ValuePool::Ironwood, index: 0 })));
    }
}

fn nu63_signed_sapling_coinbase(version: TxVersion, height: u32, output_description: sapling_crypto::bundle::OutputDescription<[u8; 192]>) -> Transaction {
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x76; 32]);
    let reward = nu63_coinbase(height, version, height); let mut transparent = reward.transparent_bundle().unwrap().clone(); transparent.vout[0] = output(124_999_995, &[0x51]);
    let balance = zcash_protocol::value::ZatBalance::from_i64(-5).unwrap();
    let make = |binding| {
        let sapling = sapling_crypto::Bundle::from_parts(vec![], vec![output_description.clone()], balance, sapling_crypto::bundle::Authorized { binding_sig: binding });
        if version == TxVersion::V6 { TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, height.into(), Some(transparent.clone()), sapling, None, None).freeze().unwrap() }
        else { TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_3, 0, height.into(), Some(transparent.clone()), None, sapling, None).freeze().unwrap() }
    };
    let transaction = make([0; 64].into());
    let digest = if version == TxVersion::V4 { SaplingSignatureHash::new(&transaction).unwrap().shielded() }
        else { PostNu5SignatureHash::new(transaction, vec![]).unwrap().shielded() };
    let key = redjubjub::SigningKey::<redjubjub::Binding>::try_from((-jubjub::Fr::from(19)).to_bytes()).unwrap();
    make(key.sign(&mut rng, &digest))
}

#[test]
fn nu63_genuine_sapling_coinbases_in_v4_v5_v6_require_current_binding_output_proof_and_recovery() {
    let original = NU63_LEDGER_FIXTURES.mixed.sapling_bundle().unwrap().shielded_outputs()[0].clone();
    for version in [TxVersion::V4, TxVersion::V5, TxVersion::V6] {
        for height in [NU63_HEIGHT, 4_465_025] {
            let reward = nu63_signed_sapling_coinbase(version, height, original.clone());
            let parent = isolated_deferred_parent(13); let before = owned_state(&parent);
            let delta = stage_nu6_transactions(&parent, std::slice::from_ref(&reward), height).unwrap();
            assert_eq!((delta.transparent, delta.sapling, delta.deferred, delta.issued, delta.sapling_tree.tree_size()), (137_499_995, 5, 18_750_013, 156_250_013, 1)); assert_eq!(owned_state(&parent), before);
            for field in 0..4 {
                let mut enc = *original.enc_ciphertext(); let mut out = *original.out_ciphertext(); let mut proof = *original.zkproof();
                if field == 0 { enc[579] ^= 1; }
                if field == 1 { out[79] ^= 1; }
                if field == 2 { proof[0] ^= 0x20; }
                let description = sapling_crypto::bundle::OutputDescription::from_parts(original.cv().clone(), *original.cmu(), original.ephemeral_key().clone(), enc, out, proof);
                let tx = if field < 3 { nu63_signed_sapling_coinbase(version, height, description) } else {
                    let bundle = reward.sapling_bundle().unwrap(); let mut binding = <[u8; 64]>::from(bundle.authorization().binding_sig); binding[63] ^= 1;
                    let sapling = sapling_crypto::Bundle::from_parts(vec![], bundle.shielded_outputs().to_vec(), *bundle.value_balance(), sapling_crypto::bundle::Authorized { binding_sig: binding.into() });
                    if version == TxVersion::V6 { TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, height.into(), reward.transparent_bundle().cloned(), sapling, None, None).freeze().unwrap() }
                    else { TransactionData::<Authorized>::from_parts(version, BranchId::Nu6_3, 0, height.into(), reward.transparent_bundle().cloned(), None, sapling, None).freeze().unwrap() }
                };
                let expected = [SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::NoteAuthentication }, SproutLedgerError::CoinbaseRecovery { index: 0, error: CoinbaseRecoveryError::OutgoingAuthentication },
                    SproutLedgerError::Sapling(SaplingCryptoError::InvalidOutputProof { index: 0 }), SproutLedgerError::Sapling(SaplingCryptoError::InvalidBindingSignature)][field];
                assert!(matches!(stage_nu6_transactions(&parent, &[tx], height), Err(error) if error == expected)); assert_eq!(owned_state(&parent), before);
            }
        }
    }
}

#[cfg(not(target_os = "zkvm"))]
mod isolated_source_note {
    use super::*;
    use crate::source_note::{SourceFundingLocator, SourceNoteError, SourceNoteSelection, TrackedNoteState};

    // Test-private monetary admission ONLY: altered headers have invalid PoW,
    // authenticated tip stays genesis, and no public occurrence is constructed.
    fn admit(parent: &mut SproutTestnetLedger, tracker: &mut TrackedNoteState, transactions: &[&[u8]], height: u32) {
        let raw = post_nu5_structural_body(transactions, height, [0; 32]);
        let body = PostNu5Block::parse(&raw, height).unwrap();
        let staged = tracker.stage(parent, body.transactions(), height).unwrap();
        if let Some(candidate) = &staged {
            let locators = [candidate.funding, candidate.consumption]
                .map(|locator| locator.filter(|locator| locator.block_height == height));
            let ranges = crate::source_note::transaction_ranges(&raw, &body, locators).unwrap();
            for (locator, range) in locators.into_iter().zip(ranges) {
                assert_eq!(locator.is_some(), range.is_some());
                if let (Some(locator), Some(range)) = (locator, range) {
                    assert_eq!(&raw[range], transactions[locator.transaction_index as usize]);
                }
            }
        }
        let delta = parent.stage_post_nu5_block(body.into_transactions(), height, 1_800_000_000).unwrap();
        parent.commit(delta);
        if let Some(staged) = staged {
            staged.check_ledger(parent).unwrap();
            *tracker = staged;
        }
        tracker.check_ledger(parent).unwrap();
        assert_eq!(parent.tip().height(), 0);
    }

    fn first_note(pool: ShieldedPool) -> SourceNoteSelection {
        use orchard::keys::{FullViewingKey, OutgoingViewingKey, SpendingKey};
        let fixture = &*NU63_LEDGER_FIXTURES;
        let (transaction, height) = match pool {
            ShieldedPool::Orchard => (Transaction::read(fixture.orchard_funding.as_slice(), BranchId::Nu6_2).unwrap(), NU63_HEIGHT - 1),
            ShieldedPool::Ironwood => (fixture.ironwood_coinbase.clone(), NU63_HEIGHT),
            _ => unreachable!(),
        };
        let bundle = if pool == ShieldedPool::Orchard { transaction.orchard_bundle().unwrap() }
            else { transaction.ironwood_bundle().unwrap() };
        assert_eq!(bundle.actions().len(), 2);
        let (note, _, _) = bundle.recover_output_with_ovk(0, &OutgoingViewingKey::from([0; 32])).unwrap();
        let fvk = FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap());
        SourceNoteSelection {
            pool, commitment: bundle.actions().first().cmx().to_bytes(), nullifier: note.nullifier(&fvk).to_bytes(),
            funding: SourceFundingLocator {
                block_height: height, transaction_index: 0, action_index: 0,
                effect_id: transaction.txid().into(),
                auth_digest: transaction.auth_commitment().as_bytes().try_into().unwrap(),
            },
        }
    }

    fn mixed_consumed_note() -> SourceNoteSelection {
        use orchard::keys::{FullViewingKey, OutgoingViewingKey, SpendingKey};
        let fixture = &*NU63_LEDGER_FIXTURES;
        let fvk = FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap());
        let funding = fixture.ironwood_coinbase.ironwood_bundle().unwrap();
        let (index, note) = funding.actions().iter().enumerate().find_map(|(index, _)| {
            let (note, _, _) = funding.recover_output_with_ovk(index, &OutgoingViewingKey::from([0; 32])).unwrap();
            fixture.mixed.ironwood_bundle().unwrap().actions().iter()
                .any(|action| action.nullifier().to_bytes() == note.nullifier(&fvk).to_bytes())
                .then_some((index, note))
        }).unwrap();
        SourceNoteSelection {
            commitment: funding.actions()[index].cmx().to_bytes(), nullifier: note.nullifier(&fvk).to_bytes(),
            funding: SourceFundingLocator { action_index: u32::try_from(index).unwrap(), ..first_note(ShieldedPool::Ironwood).funding },
            ..first_note(ShieldedPool::Ironwood)
        }
    }

    #[test]
    fn isolated_origin_joint_exact_funding_packet_links_distinct_input_and_output_actions() {
        // Actual monetary transitions with genuine crypto, but an isolated
        // genesis tip: no connected history or immutable replay evidence.
        let fixture = &*NU63_LEDGER_FIXTURES;
        let origin_selection = mixed_consumed_note();
        let mut origin = TrackedNoteState::new(origin_selection).unwrap();
        let mut parent = nu63_funded_parent();
        let cb = encoded(&fixture.ironwood_coinbase);
        admit(&mut parent, &mut origin, &[&cb], NU63_HEIGHT);
        let (_, prevouts) = nu63_transparent_template(&[([0xe1; 32], 0), ([0xe2; 32], 1)]);
        for (key, prevout) in [([0xe1; 32], 0), ([0xe2; 32], 1)].into_iter().zip(prevouts) {
            fund(&mut parent, key, u64::from(prevout.value()), &prevout.script_pubkey().0.0, 0, false);
        }
        let bundle = fixture.mixed.ironwood_bundle().unwrap();
        let input_index = bundle.actions().iter()
            .position(|action| action.nullifier().to_bytes() == origin_selection.nullifier).unwrap();
        let output_index = 1 - input_index;
        // The mechanical tracker accepts an explicit NF; private note-to-NF
        // derivation belongs to native_relation, not this isolated path test.
        let joint_selection = SourceNoteSelection {
            pool: ShieldedPool::Ironwood, commitment: bundle.actions()[output_index].cmx().to_bytes(),
            nullifier: [0; 32],
            funding: SourceFundingLocator {
                block_height: NU63_HEIGHT + 1, transaction_index: 1, action_index: u32::try_from(output_index).unwrap(),
                effect_id: fixture.mixed.txid().into(), auth_digest: fixture.mixed.auth_commitment().as_bytes().try_into().unwrap(),
            },
        };
        let joint = TrackedNoteState::new(joint_selection).unwrap();
        let reward = encoded(&nu63_reward_with_fee(NU63_HEIGHT + 1, 5));
        let mixed = encoded(&fixture.mixed);
        let raw = post_nu5_structural_body(&[&reward, &mixed], NU63_HEIGHT + 1, [0; 32]);
        let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 1).unwrap();
        let origin = origin.stage(&parent, body.transactions(), NU63_HEIGHT + 1).unwrap().unwrap();
        let joint = joint.stage(&parent, body.transactions(), NU63_HEIGHT + 1).unwrap().unwrap();
        let consumed = origin.consumption.unwrap();
        assert_ne!(consumed.action_index, joint.funding.unwrap().action_index);
        crate::source_note::check_origin_joint_link(&origin, &joint).unwrap();
        let [Some(input_packet), Some(output_packet)] = crate::source_note::transaction_ranges(
            &raw, &body, [origin.consumption, joint.funding],
        ).unwrap() else { panic!("actual shared F packet missing"); };
        assert_eq!(input_packet, output_packet);
        assert_eq!(&raw[input_packet], mixed.as_slice());
        for field in 0..4 {
            let mut wrong = origin.clone();
            let locator = wrong.consumption.as_mut().unwrap();
            match field {
                0 => locator.block_height += 1,
                1 => locator.transaction_index += 1,
                2 => locator.effect_id[0] ^= 1,
                _ => locator.auth_digest[0] ^= 1,
            }
            assert_eq!(crate::source_note::check_origin_joint_link(&wrong, &joint), Err(SourceNoteError::FundingMismatch));
        }
        let mut absent = origin.clone();
        absent.consumption = None;
        assert_eq!(crate::source_note::check_origin_joint_link(&absent, &joint), Err(SourceNoteError::FundingMismatch));
        let delta = parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT + 1, 1_800_000_000).unwrap();
        parent.commit(delta);
        origin.checked_path(&parent).unwrap();
        joint.checked_path(&parent).unwrap();
        assert_eq!(parent.tip().height(), 0);
    }

    type WitnessSnapshot = Option<(u64, u64, [u8; 32], [MerkleHashOrchard; 32])>;

    fn snapshot(tracker: &TrackedNoteState) -> (WitnessSnapshot, Option<SourceFundingLocator>, Option<SourceFundingLocator>) {
        (tracker.witness.as_ref().map(|witness| {
            let path: orchard::tree::MerklePath = witness.path().unwrap().into();
            (u64::from(witness.witnessed_position()), u64::from(witness.tip_position()) + 1, witness.root().to_bytes(), path.auth_path())
        }), tracker.funding, tracker.consumption)
    }

    fn check_path(tracker: &TrackedNoteState, parent: &SproutTestnetLedger, selection: SourceNoteSelection, position: u32, count: u64) {
        let path = tracker.checked_path(parent).unwrap();
        let commitment = orchard::note::ExtractedNoteCommitment::from_bytes(&selection.commitment).unwrap();
        assert_eq!(path.position(), position);
        assert_eq!(path.root(commitment).to_bytes(), parent.shielded_root(selection.pool));
        let witness = tracker.witness.as_ref().unwrap();
        assert_eq!(u64::from(witness.tip_position()) + 1, count);
        assert_eq!(parent.orchard_family_frontier(selection.pool).unwrap().tree_size(), count);
    }

    #[test]
    fn isolated_source_note_genuine_coinbase_first_leaf_all_later_actions_and_actual_pair_consumption() {
        let fixture = &*NU63_LEDGER_FIXTURES;
        let orchard_selection = first_note(ShieldedPool::Orchard);
        let ironwood_selection = first_note(ShieldedPool::Ironwood);
        let mut orchard = TrackedNoteState::new(orchard_selection).unwrap();
        let mut ironwood = TrackedNoteState::new(ironwood_selection).unwrap();
        let mut parent = isolated_deferred_parent(13);
        admit(&mut parent, &mut orchard, &[&fixture.orchard_funding], NU63_HEIGHT - 1);
        check_path(&orchard, &parent, orchard_selection, 0, 2);
        assert!(orchard.consumption.is_none());
        // The other pool remains untouched, even while a future Ironwood query
        // is enrolled before its activation/funding occurrence.
        ironwood.check_ledger(&parent).unwrap();
        let cb = encoded(&fixture.ironwood_coinbase);
        let raw = post_nu5_structural_body(&[&cb], NU63_HEIGHT, [0; 32]);
        let parsed = PostNu5Block::parse(&raw, NU63_HEIGHT).unwrap();
        assert!(orchard.stage(&parent, parsed.transactions(), NU63_HEIGHT).unwrap().is_none());
        admit(&mut parent, &mut ironwood, &[&cb], NU63_HEIGHT);
        check_path(&orchard, &parent, orchard_selection, 0, 2);
        check_path(&ironwood, &parent, ironwood_selection, 0, 2);
        let empty = encoded(&nu63_coinbase(NU63_HEIGHT + 1, TxVersion::V4, NU63_HEIGHT + 1));
        let empty_raw = post_nu5_structural_body(&[&empty], NU63_HEIGHT + 1, [0; 32]);
        let empty_body = PostNu5Block::parse(&empty_raw, NU63_HEIGHT + 1).unwrap();
        assert!(ironwood.stage(&parent, empty_body.transactions(), NU63_HEIGHT + 1).unwrap().is_none());
        let (_, prevouts) = nu63_transparent_template(&[([0xe1; 32], 0), ([0xe2; 32], 1)]);
        for (key, prevout) in [([0xe1; 32], 0), ([0xe2; 32], 1)].into_iter().zip(prevouts) {
            fund(&mut parent, key, u64::from(prevout.value()), &prevout.script_pubkey().0.0, 0, false);
        }
        let mixed = encoded(&fixture.mixed);
        let reward = encoded(&nu63_reward_with_fee(NU63_HEIGHT + 1, 5));
        let raw = post_nu5_structural_body(&[&reward, &mixed], NU63_HEIGHT + 1, [0; 32]);
        let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 1).unwrap();
        let next_orchard = orchard.stage(&parent, body.transactions(), NU63_HEIGHT + 1).unwrap().unwrap();
        let next_ironwood = ironwood.stage(&parent, body.transactions(), NU63_HEIGHT + 1).unwrap().unwrap();
        let delta = parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT + 1, 1_800_000_000).unwrap();
        parent.commit(delta);
        orchard = next_orchard;
        ironwood = next_ironwood;
        let reward = encoded(&nu63_coinbase(NU63_HEIGHT + 2, TxVersion::V4, NU63_HEIGHT + 2));
        let restricted = encoded(&fixture.restricted_ironwood);
        assert!(!fixture.restricted_ironwood.ironwood_bundle().unwrap().flags().outputs_enabled());
        assert!(!RawV5::parse_exact(&fixture.restricted_v5).unwrap().orchard().unwrap().flags().outputs_enabled());
        let raw = post_nu5_structural_body(&[&reward, &fixture.restricted_v5, &restricted], NU63_HEIGHT + 2, [0; 32]);
        let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 2).unwrap();
        let next_orchard = orchard.stage(&parent, body.transactions(), NU63_HEIGHT + 2).unwrap().unwrap();
        let next_ironwood = ironwood.stage(&parent, body.transactions(), NU63_HEIGHT + 2).unwrap().unwrap();
        let delta = parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT + 2, 1_800_000_000).unwrap();
        parent.commit(delta);
        orchard = next_orchard;
        ironwood = next_ironwood;
        for (tracker, selection) in [(&orchard, orchard_selection), (&ironwood, ironwood_selection)] {
            check_path(tracker, &parent, selection, 0, 6);
            let (transaction, bundle, index, height) = if fixture.mixed.orchard_bundle().filter(|_| selection.pool == ShieldedPool::Orchard)
                .or_else(|| fixture.mixed.ironwood_bundle().filter(|_| selection.pool == ShieldedPool::Ironwood)).unwrap()
                .actions().iter().any(|action| action.nullifier().to_bytes() == selection.nullifier)
            {
                let bundle = if selection.pool == ShieldedPool::Orchard { fixture.mixed.orchard_bundle().unwrap() }
                    else { fixture.mixed.ironwood_bundle().unwrap() };
                (&fixture.mixed, bundle, 1, NU63_HEIGHT + 1)
            } else if selection.pool == ShieldedPool::Orchard {
                // Independent typed decoder is used only as a test oracle; the
                // production stage above consumed original restricted V5 bytes.
                let restricted = Transaction::read(fixture.restricted_v5.as_slice(), BranchId::Nu6_3).unwrap();
                let bundle = restricted.orchard_bundle().unwrap();
                let action = bundle.actions().iter().position(|action| action.nullifier().to_bytes() == selection.nullifier).unwrap();
                assert_eq!(tracker.consumption, Some(SourceFundingLocator {
                    block_height: NU63_HEIGHT + 2, transaction_index: 1, action_index: u32::try_from(action).unwrap(),
                    effect_id: restricted.txid().into(), auth_digest: restricted.auth_commitment().as_bytes().try_into().unwrap(),
                }));
                continue;
            } else { (&fixture.restricted_ironwood, fixture.restricted_ironwood.ironwood_bundle().unwrap(), 2, NU63_HEIGHT + 2) };
            let action = bundle.actions().iter().position(|action| action.nullifier().to_bytes() == selection.nullifier).unwrap();
            assert_eq!(tracker.consumption, Some(SourceFundingLocator {
                block_height: height, transaction_index: index, action_index: u32::try_from(action).unwrap(),
                effect_id: transaction.txid().into(), auth_digest: transaction.auth_commitment().as_bytes().try_into().unwrap(),
            }));
        }
        assert_eq!(parent.tip().height(), 0);
    }

    #[test]
    fn isolated_source_note_nonzero_parent_position_and_coinbase_transaction_action_order() {
        let fixture = &*NU63_LEDGER_FIXTURES;
        let mut parent = nu63_mixed_parent();
        let commitment = fixture.mixed.ironwood_bundle().unwrap().actions().first().cmx().to_bytes();
        let selection = SourceNoteSelection {
            pool: ShieldedPool::Ironwood, commitment, nullifier: [0; 32],
            funding: SourceFundingLocator {
                block_height: NU63_HEIGHT + 1, transaction_index: 2, action_index: 0,
                effect_id: fixture.mixed.txid().into(), auth_digest: fixture.mixed.auth_commitment().as_bytes().try_into().unwrap(),
            },
        };
        let mut tracker = TrackedNoteState::new(selection).unwrap();
        let reward = encoded(&nu63_reward_with_fee(NU63_HEIGHT + 1, 5));
        let restricted = encoded(&fixture.restricted_ironwood);
        let mixed = encoded(&fixture.mixed);
        admit(&mut parent, &mut tracker, &[&reward, &restricted, &mixed], NU63_HEIGHT + 1);
        // 2 actual prior coinbase leaves, 2 outputs-disabled transaction leaves,
        // then this exact first mixed action: action index0 is global position4.
        check_path(&tracker, &parent, selection, 4, 6);
        assert_eq!(tracker.funding, Some(selection.funding));
        assert!(tracker.consumption.is_none());
    }

    #[test]
    fn isolated_source_note_exact_locator_both_ids_commitment_and_pre_funding_nf_fail_closed() {
        let fixture = &*NU63_LEDGER_FIXTURES;
        let parent = isolated_deferred_parent(13);
        let cb = encoded(&fixture.ironwood_coinbase);
        let raw = post_nu5_structural_body(&[&cb], NU63_HEIGHT, [0; 32]);
        let body = PostNu5Block::parse(&raw, NU63_HEIGHT).unwrap();
        let original = first_note(ShieldedPool::Ironwood);
        let mut cases = Vec::new();
        let mut wrong = original;
        wrong.funding.effect_id[0] ^= 1;
        cases.push((wrong, SourceNoteError::FundingMismatch));
        let mut wrong = original;
        wrong.funding.auth_digest[0] ^= 1;
        cases.push((wrong, SourceNoteError::FundingMismatch));
        let mut wrong = original;
        wrong.funding.transaction_index = 1;
        cases.push((wrong, SourceNoteError::FundingMismatch));
        let mut wrong = original;
        wrong.funding.action_index = 2;
        cases.push((wrong, SourceNoteError::FundingMismatch));
        let mut wrong = original;
        wrong.funding.action_index = 1; // same transaction, wrong actual leaf
        cases.push((wrong, SourceNoteError::FundingMismatch));
        let mut wrong = original;
        wrong.commitment = [0; 32];
        cases.push((wrong, SourceNoteError::FundingMismatch));
        let mut wrong = original;
        wrong.nullifier = fixture.ironwood_coinbase.ironwood_bundle().unwrap().actions().first().nullifier().to_bytes();
        cases.push((wrong, SourceNoteError::NullifierBeforeFunding));
        for (selection, expected) in cases {
            let tracker = TrackedNoteState::new(selection).unwrap();
            let before = snapshot(&tracker);
            assert!(matches!(tracker.stage(&parent, body.transactions(), NU63_HEIGHT), Err(error) if error == expected));
            assert_eq!(snapshot(&tracker), before);
        }
        // An equal commitment at another action cannot rescue a wrong exact leaf.
        let changed = changed_bundle(fixture.ironwood_coinbase.ironwood_bundle().unwrap(), None, |index, action| {
            if index == 1 {
                *action = orchard::Action::from_parts(*action.nullifier(), action.rk().clone(),
                    *fixture.ironwood_coinbase.ironwood_bundle().unwrap().actions().first().cmx(),
                    action.encrypted_note().clone(), action.cv_net().clone(), action.authorization().clone()).unwrap();
            }
        });
        let changed = with_nu63_bundles(&fixture.ironwood_coinbase, None, Some(changed));
        let changed = PostNu5Transaction::V6(Box::new(changed));
        let wrong = SourceNoteSelection {
            commitment: fixture.ironwood_coinbase.ironwood_bundle().unwrap().actions()[1].cmx().to_bytes(),
            funding: SourceFundingLocator { action_index: 1, effect_id: changed.effect_id(), auth_digest: changed.auth_digest().unwrap(), ..original.funding },
            ..original
        };
        assert!(matches!(TrackedNoteState::new(wrong).unwrap().stage(&parent, std::slice::from_ref(&changed), NU63_HEIGHT), Err(SourceNoteError::FundingMismatch)));
        // An earlier actual NF in the same block is not accepted as an
        // apparently unspent later funding occurrence, even at a different cmx.
        let mixed = encoded(&fixture.mixed);
        let restricted = encoded(&fixture.restricted_ironwood);
        let reward = encoded(&nu63_reward_with_fee(NU63_HEIGHT + 1, 5));
        let raw = post_nu5_structural_body(&[&reward, &mixed, &restricted], NU63_HEIGHT + 1, [0; 32]);
        let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 1).unwrap();
        let wrong = SourceNoteSelection {
            commitment: fixture.restricted_ironwood.ironwood_bundle().unwrap().actions().first().cmx().to_bytes(),
            nullifier: mixed_consumed_note().nullifier,
            funding: SourceFundingLocator {
                block_height: NU63_HEIGHT + 1, transaction_index: 2, action_index: 0,
                effect_id: fixture.restricted_ironwood.txid().into(),
                auth_digest: fixture.restricted_ironwood.auth_commitment().as_bytes().try_into().unwrap(),
            },
            ..original
        };
        assert!(matches!(TrackedNoteState::new(wrong).unwrap().stage(&nu63_mixed_parent(), body.transactions(), NU63_HEIGHT + 1), Err(SourceNoteError::NullifierBeforeFunding)));
        let raw = post_nu5_structural_body(&[&cb], NU63_HEIGHT, [0; 32]);
        let body = PostNu5Block::parse(&raw, NU63_HEIGHT).unwrap();
        let tracker = TrackedNoteState::new(original).unwrap();
        let mut wrong_pool = isolated_deferred_parent(13);
        wrong_pool.nullifiers[2].insert(original.nullifier);
        assert!(tracker.stage(&wrong_pool, body.transactions(), NU63_HEIGHT).is_ok());
        wrong_pool.nullifiers[3].insert(original.nullifier);
        assert!(matches!(tracker.stage(&wrong_pool, body.transactions(), NU63_HEIGHT), Err(SourceNoteError::NullifierBeforeFunding)));
    }

    #[test]
    fn isolated_source_note_late_crypto_history_root_count_and_nf_failure_never_publish_staged_state() {
        let fixture = &*NU63_LEDGER_FIXTURES;
        let selection = mixed_consumed_note();
        let mut tracker = TrackedNoteState::new(selection).unwrap();
        let mut parent = nu63_funded_parent();
        let cb = encoded(&fixture.ironwood_coinbase);
        admit(&mut parent, &mut tracker, &[&cb], NU63_HEIGHT);
        let (_, prevouts) = nu63_transparent_template(&[([0xe1; 32], 0), ([0xe2; 32], 1)]);
        for (key, prevout) in [([0xe1; 32], 0), ([0xe2; 32], 1)].into_iter().zip(prevouts) {
            fund(&mut parent, key, u64::from(prevout.value()), &prevout.script_pubkey().0.0, 0, false);
        }
        let before_ledger = owned_state(&parent);
        let before_tracker = snapshot(&tracker);
        let bundle = fixture.mixed.ironwood_bundle().unwrap();
        let changed = bundle.clone().map_authorization(&mut (), |_, _, signature| {
            let mut bytes = <[u8; 64]>::from(&signature);
            bytes[63] ^= 1;
            bytes.into()
        }, |_, authorization| authorization);
        let bad = with_nu63_bundles(&fixture.mixed, fixture.mixed.orchard_bundle().cloned(), Some(changed));
        let bad = encoded(&bad);
        let reward = encoded(&nu63_reward_with_fee(NU63_HEIGHT + 1, 5));
        let raw = post_nu5_structural_body(&[&reward, &bad], NU63_HEIGHT + 1, [0; 32]);
        let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 1).unwrap();
        let candidate = tracker.stage(&parent, body.transactions(), NU63_HEIGHT + 1).unwrap().unwrap();
        assert_ne!(snapshot(&candidate), before_tracker);
        let [Some(bad_range), None] = crate::source_note::transaction_ranges(&raw, &body, [candidate.consumption, None]).unwrap()
            else { panic!("candidate original transaction span missing"); };
        assert_eq!(&raw[bad_range], bad.as_slice());
        assert!(matches!(parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT + 1, 1_800_000_000), Err(SproutLedgerError::PostNu63(_))));
        assert_eq!(owned_state(&parent), before_ledger);
        assert_eq!(snapshot(&tracker), before_tracker);
        // Same effects with changed actual authorization stay distinct; no
        // C/R/refund inference is attached to either unsealed consumer pair.
        let mixed = encoded(&fixture.mixed);
        let raw = post_nu5_structural_body(&[&reward, &mixed], NU63_HEIGHT + 1, [0; 32]);
        let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 1).unwrap();
        let good_candidate = tracker.stage(&parent, body.transactions(), NU63_HEIGHT + 1).unwrap().unwrap();
        let [Some(good_range), None] = crate::source_note::transaction_ranges(&raw, &body, [good_candidate.consumption, None]).unwrap()
            else { panic!("original transaction span missing"); };
        assert_eq!(&raw[good_range], mixed.as_slice());
        assert_ne!(mixed, bad);
        let good = good_candidate.consumption.unwrap();
        let bad = candidate.consumption.unwrap();
        assert_eq!(good.effect_id, bad.effect_id);
        assert_ne!(good.auth_digest, bad.auth_digest);
        for field in 0..2 {
            let mut proof = bundle.authorization().proof().as_ref().to_vec();
            let mut binding = <[u8; 64]>::from(bundle.authorization().binding_signature());
            if field == 0 { proof[0] ^= 1; } else { binding[63] ^= 1; }
            let changed = orchard::Bundle::try_from_parts(bundle.actions().clone(), *bundle.flags(), *bundle.value_balance(),
                *bundle.anchor(), orchard::bundle::Authorized::from_parts(orchard::Proof::new(proof), binding.into()), bundle.bundle_version()).unwrap();
            let changed = encoded(&with_nu63_bundles(&fixture.mixed, fixture.mixed.orchard_bundle().cloned(), Some(changed)));
            let raw = post_nu5_structural_body(&[&reward, &changed], NU63_HEIGHT + 1, [0; 32]);
            let body = PostNu5Block::parse(&raw, NU63_HEIGHT + 1).unwrap();
            let staged = tracker.stage(&parent, body.transactions(), NU63_HEIGHT + 1).unwrap().unwrap();
            assert!(staged.consumption.is_some());
            assert!(matches!(parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT + 1, 1_800_000_000), Err(SproutLedgerError::PostNu63(_))));
            assert_eq!(owned_state(&parent), before_ledger);
            assert_eq!(snapshot(&tracker), before_tracker);
        }
        let source = fixture.mixed.sapling_bundle().unwrap();
        let mut outputs = source.shielded_outputs().to_vec();
        let output = &outputs[0];
        let mut proof = *output.zkproof();
        proof[0] ^= 0x20;
        outputs[0] = sapling_crypto::bundle::OutputDescription::from_parts(output.cv().clone(), *output.cmu(),
            output.ephemeral_key().clone(), *output.enc_ciphertext(), *output.out_ciphertext(), proof);
        let sapling = sapling_crypto::Bundle::from_parts(vec![], outputs, *source.value_balance(), *source.authorization());
        let changed = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 0, 0.into(),
            fixture.mixed.transparent_bundle().cloned(), sapling, fixture.mixed.orchard_bundle().cloned(),
            fixture.mixed.ironwood_bundle().cloned()).freeze().unwrap();
        let changed = encoded(&changed);
        let bad_raw = post_nu5_structural_body(&[&reward, &changed], NU63_HEIGHT + 1, [0; 32]);
        let bad_body = PostNu5Block::parse(&bad_raw, NU63_HEIGHT + 1).unwrap();
        let staged = tracker.stage(&parent, bad_body.transactions(), NU63_HEIGHT + 1).unwrap().unwrap();
        assert!(staged.consumption.is_some());
        assert!(matches!(parent.stage_post_nu5_block(bad_body.into_transactions(), NU63_HEIGHT + 1, 1_800_000_000), Err(SproutLedgerError::Sapling(_))));
        assert_eq!(owned_state(&parent), before_ledger);
        assert_eq!(snapshot(&tracker), before_tracker);
        let mut wrong_anchor = nu63_mixed_parent();
        let bundle = fixture.mixed.ironwood_bundle().unwrap();
        wrong_anchor.ironwood_anchors.remove(&bundle.anchor().to_bytes());
        let before = owned_state(&wrong_anchor);
        assert!(matches!(stage_nu6_transactions(&wrong_anchor, &[nu63_reward_with_fee(NU63_HEIGHT + 1, 5), fixture.mixed.clone()], NU63_HEIGHT + 1), Err(SproutLedgerError::UnknownIronwoodAnchor)));
        assert_eq!(owned_state(&wrong_anchor), before);
        assert_eq!(snapshot(&tracker), before_tracker);
        for pool in [ShieldedPool::Orchard, ShieldedPool::Ironwood] {
            let mut bad = nu63_mixed_parent();
            let bundle = if pool == ShieldedPool::Orchard { fixture.mixed.orchard_bundle().unwrap() } else { bundle };
            bad.nullifiers[pool.index()].insert(bundle.actions().first().nullifier().to_bytes());
            let before = owned_state(&bad);
            let staged = tracker.stage(&bad, body.transactions(), NU63_HEIGHT + 1);
            assert!(stage_nu6_transactions(&bad, &[nu63_reward_with_fee(NU63_HEIGHT + 1, 5), fixture.mixed.clone()], NU63_HEIGHT + 1).is_err());
            drop(staged);
            assert_eq!(owned_state(&bad), before);
            assert_eq!(snapshot(&tracker), before_tracker);
        }
        // A complete malformed later frame cannot expose the previously funded
        // witness either; parsing is authority, not a callback success shortcut.
        let mut truncated = raw.clone();
        truncated.pop();
        assert!(PostNu5Block::parse(&truncated, NU63_HEIGHT + 1).is_err());
        assert_eq!(snapshot(&tracker), before_tracker);
        let delta = parent.stage_post_nu5_block(body.into_transactions(), NU63_HEIGHT + 1, 1_800_000_000).unwrap();
        let leaf = nu63_leaf(NU63_HEIGHT + 1, delta.sapling_root, delta.orchard_root, delta.ironwood_root, 1, 1, 1);
        assert!(parent.stage_nu63_history(&[0; 32], &[0; 32], leaf).is_err());
        drop(delta); // Full-history failure leaves the candidate unpublished.
        assert_eq!(owned_state(&parent), before_ledger);
        assert_eq!(snapshot(&tracker), before_tracker);
        let mut bad_root = tracker.clone();
        bad_root.witness.as_mut().unwrap().append(MerkleHashOrchard::from_bytes(&[0; 32]).unwrap()).unwrap();
        assert_eq!(bad_root.check_ledger(&parent), Err(SourceNoteError::InvalidWitness));
        let mut delta = BlockDelta::new(&parent);
        delta.ironwood_tree.append(MerkleHashOrchard::from_bytes(&[0; 32]).unwrap());
        // Root-equal PushAnchor intentionally keeps the ACTUAL parent count.
        delta.ironwood_root = parent.shielded_root(ShieldedPool::Ironwood);
        parent.commit(delta);
        assert_eq!(parent.ironwood_tree_size(), 2);
        tracker.check_ledger(&parent).unwrap();
        assert_eq!(bad_root.check_ledger(&parent), Err(SourceNoteError::InvalidWitness));
        // Independently make the root match while the persisted frontier count
        // still differs. Root-only checking would incorrectly accept this.
        parent.shielded_roots[3] = bad_root.witness.as_ref().unwrap().root().to_bytes();
        assert_eq!(bad_root.check_ledger(&parent), Err(SourceNoteError::InvalidWitness));
        parent.shielded_roots[3] = before_ledger.roots[3];
        parent.nullifiers[3].insert(selection.nullifier);
        assert_eq!(tracker.check_ledger(&parent), Err(SourceNoteError::InvalidWitness));
        parent.nullifiers[3].remove(&selection.nullifier);
        let mut wrong_leaf = tracker.clone();
        let witness = wrong_leaf.witness.as_ref().unwrap();
        let mut tree = incrementalmerkletree::frontier::CommitmentTree::<MerkleHashOrchard, 32>::empty();
        for _ in 0..=u64::from(witness.witnessed_position()) {
            tree.append(MerkleHashOrchard::from_bytes(&[0; 32]).unwrap()).unwrap();
        }
        wrong_leaf.witness = incrementalmerkletree::witness::IncrementalWitness::from_parts(
            tree, witness.filled().clone(), witness.cursor().clone(),
        );
        let root = wrong_leaf.witness.as_ref().unwrap().root().to_bytes();
        parent.shielded_roots[3] = root;
        // Make an actual same-count frontier match the corrupted witness root;
        // only the selected cmx-to-path equation should reject this fixture.
        let mut frontier = incrementalmerkletree::frontier::Frontier::<MerkleHashOrchard, 32>::empty();
        let funding = fixture.ironwood_coinbase.ironwood_bundle().unwrap();
        for (index, action) in funding.actions().iter().enumerate() {
            let node = if index <= selection.funding.action_index as usize {
                MerkleHashOrchard::from_bytes(&[0; 32]).unwrap()
            } else { MerkleHashOrchard::from_cmx(action.cmx()) };
            assert!(frontier.append(node));
        }
        parent.ironwood_tree = frontier;
        wrong_leaf.check_ledger(&parent).unwrap();
        assert!(matches!(wrong_leaf.checked_path(&parent), Err(SourceNoteError::InvalidWitness)));
    }
}
