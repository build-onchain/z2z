//! Local compiled-ELF fixture process. Funded steps receive exact durable acknowledgements.
use ziquid_protocol::market::{
    Acknowledgement, Decision, Domain, Transition, ACKNOWLEDGEMENT_LEN, DECISION_LEN,
};
use ziquid_solana_harness::wire::{
    digest, FENCE, FILLED_ID, FIRST_LEG_INTENT, HOLD_ID, INSTRUCTIONS_SYSVAR, JOURNAL, RESULT,
    UNUSED_ID,
};
use ziquid_solana_harness::{domain_bytes, token_program, BaseAmounts, Fixture};
use ziquid_solana_interface::{CompactEnvelope, Envelope};
use litesvm::types::TransactionMetadata;
use solana_clock::Clock;
use solana_ed25519_program::new_ed25519_instruction_with_signature;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::io::{self, Read, Write};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}
fn emit(out: &mut impl Write, key: &str, value: impl std::fmt::Display) -> io::Result<()> {
    writeln!(out, "{key}={value}")
}
fn error() -> io::Error {
    io::Error::other("local compiled target fixture refused exact protocol input or execution")
}
fn proposed(fixture: &Fixture, target: &Instruction) -> io::Result<(Decision, Vec<[u8; 32]>)> {
    let tag = *target.data.first().ok_or_else(error)?;
    let transition = Transition::try_from(tag).map_err(|_| error())?;
    let domain = Domain::decode(&domain_bytes(fixture.mint, 1)).map_err(|_| error())?;
    let compact =
        CompactEnvelope::decode(target.data.get(1..65).ok_or_else(error)?).map_err(|_| error())?;
    let (subject, portion, prior) = match tag {
        2 => (fixture.epoch_key(), None, 0),
        4 => (
            fixture.hold_key(),
            None,
            fixture.version(fixture.hold_key(), 181),
        ),
        6 | 7 | 9 => (
            fixture.epoch_key(),
            None,
            fixture.version(fixture.epoch_key(), 49),
        ),
        8 => {
            let key = target.accounts.get(4).ok_or_else(error)?.pubkey;
            (
                fixture.hold_key(),
                Some(key),
                fixture.version(fixture.hold_key(), 181),
            )
        }
        10..=12 => (
            fixture.filled_key(),
            Some(fixture.filled_key()),
            fixture.version(fixture.filled_key(), 153),
        ),
        _ => return Err(error()),
    };
    let keys: Vec<_> = target
        .accounts
        .iter()
        .skip(usize::from(tag == 2 || tag == 8))
        .map(|account| account.pubkey.to_bytes())
        .collect();
    let envelope = Envelope {
        intent: compact.intent,
        predecessor: compact.predecessor,
        generation: fixture.pair_generation().checked_add(1).ok_or_else(error)?,
        prior,
    };
    let decision = ziquid_solana_interface::decision(
        domain,
        subject.to_bytes(),
        portion.map(|key| key.to_bytes()),
        transition,
        envelope,
        &target.data[65..],
        &keys,
    )
    .map_err(|_| error())?;
    Ok((decision, keys))
}
fn decision_hex(decision: &Decision) -> io::Result<String> {
    let mut bytes = [0; DECISION_LEN];
    decision.encode_into(&mut bytes).map_err(|_| error())?;
    Ok(hex(&bytes))
}
fn observation(
    out: &mut impl Write,
    fixture: &Fixture,
    meta: &TransactionMetadata,
) -> io::Result<()> {
    let signature: [u8; 64] = meta.signature.into();
    emit(out, "environment", "LocalFixture")?;
    emit(out, "transaction", hex(&signature))?;
    emit(out, "transaction_id", hex(&digest(&signature)))?;
    emit(out, "slot", fixture.svm.get_sysvar::<Clock>().slot)?;
    emit(out, "compute_units", meta.compute_units_consumed)?;
    emit(out, "packet_bytes", fixture.last_packet_bytes)?;
    emit(out, "pair_head", hex(&fixture.pair_head()))?;
    emit(out, "generation", fixture.pair_generation())?;
    emit(
        out,
        "epoch_version",
        fixture.version(fixture.epoch_key(), 49),
    )?;
    emit(
        out,
        "hold_version",
        fixture.version(fixture.hold_key(), 181),
    )?;
    for (name, key) in [
        ("filled_version", fixture.filled_key()),
        ("unused_version", fixture.unused_key()),
    ] {
        if fixture.svm.get_account(&key).is_some() {
            emit(out, name, fixture.version(key, 153))?;
        }
    }
    emit(out, "seller_balance", fixture.amount(fixture.seller_token))?;
    emit(out, "buyer_balance", fixture.amount(fixture.buyer_token))?;
    emit(out, "escrow_balance", fixture.amount(fixture.escrow_key()))
}
fn run() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    let mut frame = [0; 104];
    input.read_exact(&mut frame)?;
    if &frame[..8] != b"KERBFX01" {
        return Err(error());
    }
    let mut secrets = [[0; 32]; 3];
    for (index, secret) in secrets.iter_mut().enumerate() {
        secret.copy_from_slice(&frame[8 + index * 32..40 + index * 32]);
    }
    let keys = secrets.map(Keypair::new_from_array);
    frame.fill(0);
    secrets.fill([0; 32]);
    let mut fixture = Fixture::with_authorizers(keys, BaseAmounts::DRIVER_FIXTURE);
    fixture.initialized();
    fixture.open();
    fixture.lock();
    let prepare = fixture.prepare_instruction();
    let (prepared, _) = proposed(&fixture, prepare.last().ok_or_else(error)?)?;
    let bootstrap_signatures: Vec<_> = prepare
        .iter()
        .take(3)
        .map(|instruction| hex(&instruction.data[48..112]))
        .collect();
    let prepared_meta = fixture.send(&prepare, false).map_err(|_| error())?;
    emit(&mut out, "schema", "kerb-solana-local-v1")?;
    emit(&mut out, "domain", hex(&domain_bytes(fixture.mint, 1)))?;
    for (index, public) in fixture.roster.iter().enumerate() {
        emit(&mut out, &format!("roster{index}"), hex(public))?;
    }
    for (name, key) in [
        ("admin", fixture.admin.pubkey()),
        ("pair", fixture.pair),
        ("epoch", fixture.epoch_key()),
        ("hold", fixture.hold_key()),
        ("filled", fixture.filled_key()),
        ("unused", fixture.unused_key()),
        ("escrow", fixture.escrow_key()),
        ("mint", fixture.mint),
        ("seller_token", fixture.seller_token),
        ("buyer_token", fixture.buyer_token),
        ("seller_owner", fixture.seller.pubkey()),
        ("buyer_owner", fixture.buyer.pubkey()),
        ("token_program", token_program()),
        ("instructions_sysvar", INSTRUCTIONS_SYSVAR),
    ] {
        emit(&mut out, name, hex(key.as_ref()))?;
    }
    for (name, id) in [
        ("hold_business", HOLD_ID),
        ("filled_business", FILLED_ID),
        ("unused_business", UNUSED_ID),
        ("result", RESULT),
        ("journal", JOURNAL),
        ("fence", FENCE),
        ("first_leg_intent", FIRST_LEG_INTENT),
    ] {
        emit(&mut out, name, hex(&id))?;
    }
    emit(&mut out, "maximum_base", fixture.amounts.maximum)?;
    emit(&mut out, "filled_base", fixture.amounts.filled)?;
    emit(&mut out, "unused_base", fixture.amounts.unused)?;
    emit(&mut out, "expected_chunks", 2)?;
    emit(&mut out, "prepared_decision", decision_hex(&prepared)?)?;
    for (index, signature) in bootstrap_signatures.iter().enumerate() {
        emit(&mut out, &format!("prepared_ack{index}"), signature)?;
    }
    observation(&mut out, &fixture, &prepared_meta)?;
    emit(&mut out, "end", "header")?;
    out.flush()?;
    fixture.require_external_policy_signatures();
    for step in [
        "commit",
        "chunk_filled",
        "chunk_unused",
        "activate",
        "prepare_fill",
        "release",
    ] {
        let proposed_instructions = match step {
            "commit" => fixture.commit_instruction(),
            "chunk_filled" => fixture.allocation_instruction(true),
            "chunk_unused" => fixture.allocation_instruction(false),
            "activate" => fixture.activate_instruction(),
            "prepare_fill" => fixture.prepare_fill_instruction(),
            "release" => fixture.release_instruction(),
            _ => return Err(error()),
        };
        if proposed_instructions.len() != 1 {
            return Err(error());
        }
        let target = proposed_instructions.into_iter().next().ok_or_else(error)?;
        let (decision, keys) = proposed(&fixture, &target)?;
        emit(&mut out, "step", step)?;
        emit(&mut out, "decision", decision_hex(&decision)?)?;
        emit(&mut out, "payload", hex(&target.data[65..]))?;
        let account_bytes: Vec<_> = keys.iter().flat_map(|key| key.iter().copied()).collect();
        emit(&mut out, "accounts", hex(&account_bytes))?;
        emit(&mut out, "end", "plan")?;
        out.flush()?;
        let mut acknowledgements = [0; 3 * ACKNOWLEDGEMENT_LEN];
        input.read_exact(&mut acknowledgements)?;
        let message = decision.signing_bytes().map_err(|_| error())?;
        let mut seen = [false; 3];
        let mut instructions = Vec::with_capacity(4);
        for bytes in acknowledgements.as_chunks::<ACKNOWLEDGEMENT_LEN>().0 {
            let ack = Acknowledgement::decode(bytes).map_err(|_| error())?;
            let index = fixture
                .roster
                .iter()
                .position(|key| key == &ack.signer)
                .ok_or_else(error)?;
            if seen[index] || ack.decision != decision {
                return Err(error());
            }
            seen[index] = true;
            instructions.push(new_ed25519_instruction_with_signature(
                &message,
                &ack.signature,
                &ack.signer,
            ));
        }
        if seen != [true; 3] {
            return Err(error());
        }
        instructions.push(target);
        let meta = fixture.send(&instructions, false).map_err(|_| error())?;
        emit(&mut out, "step", step)?;
        emit(&mut out, "decision", decision_hex(&decision)?)?;
        observation(&mut out, &fixture, &meta)?;
        emit(&mut out, "end", "receipt")?;
        out.flush()?;
    }
    emit(&mut out, "max_packet_bytes", fixture.max_packet_bytes)?;
    emit(&mut out, "end", "scenario")?;
    out.flush()
}
fn main() {
    if run().is_err() {
        eprintln!("local compiled target fixture stopped; no funded step bypass or ambiguous success receipt");
        std::process::exit(1);
    }
}
