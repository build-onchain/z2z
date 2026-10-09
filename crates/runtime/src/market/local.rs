use super::{
    Error, Result,
    config::{self, LocalConfig},
    coordinator::{self, Coordinator},
    facts,
    fixture::{self, FixtureNative},
    native::{self, NativePolicy},
    process::ReplicaProcess,
    target::{Section, TargetProcess},
};
use ed25519_dalek::{Signer, SigningKey};
use crate::market::ledger::*;
use ziquid_protocol::market::*;
use ziquid_solana_interface as interface;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

struct LocalActors<'a> {
    source: &'a SigningKey,
    inventory: &'a SigningKey,
    observer: &'a SigningKey,
    claimant: &'a SigningKey,
}

pub async fn local_safety_scenario(config: LocalConfig, executable: &Path) -> Result<Value> {
    config::version(config.schema_version)?;
    if config.environment != "LocalFixture" {
        return Err(Error::Configuration);
    }
    let native_input = config::read::<NativePolicy>(&config.native_policy)?.context()?;
    if native_input.environment != ObservationEnvironment::LocalFixture {
        return Err(Error::Configuration);
    }
    let source = facts::key()?;
    let inventory = facts::key()?;
    let observer = facts::key()?;
    let claimant = facts::key()?;
    let keys = [facts::key()?, facts::key()?, facts::key()?];
    let mut target =
        TargetProcess::launch(&config.solana_binary, &config.solana_elf, &keys).await?;
    let header = target.section("header").await?;
    let domain = validate_header(&header, &keys)?;
    let recipient = native_input
        .outputs
        .iter()
        .find(|out| out.kind == ziquid_zcash::custody::NativeOutputKind::Recipient)
        .ok_or(Error::Configuration)?
        .recipient;
    let change = native_input
        .outputs
        .iter()
        .find(|out| out.kind == ziquid_zcash::custody::NativeOutputKind::Change)
        .ok_or(Error::Configuration)?
        .recipient;
    let fvk = native_input
        .inputs
        .first()
        .ok_or(Error::Configuration)?
        .trusted_fvk
        .clone();
    let payout = FixtureNative::payout(domain, fvk.clone(), recipient, change)?;
    let change_note = payout.change_note.ok_or(Error::Input)?;
    let change_commitment =
        orchard::note::ExtractedNoteCommitment::from(change_note.commitment()).to_bytes();
    let checked_payout = ziquid_zcash::custody::inspect_pczt(&payout.bytes, &payout.context.expected())?;
    let checked_change = checked_payout
        .outputs()
        .iter()
        .find(|output| output.note_commitment() == &change_commitment)
        .ok_or(Error::Input)?;
    let change_occurrence = SourceOccurrence {
        network: domain.source_network,
        pool: domain.source_pool,
        txid: *checked_payout.txid(),
        action_index: checked_change.action_index(),
    };
    let refund = FixtureNative::refund(domain, fvk, change_note, change_occurrence, change)?;
    let policy = PairPolicy {
        domain,
        environment: ObservationEnvironment::LocalFixture,
        source_policy: [40; 32],
        history_anchor: [41; 32],
        minimum_confirmations: 10,
        receiver: change.to_raw_address_bytes(),
        inventory_scope: domain.pair,
        sponsor_scope: [42; 32],
        source_producer: source.verifying_key().to_bytes(),
        inventory_producer: inventory.verifying_key().to_bytes(),
        target_observer: observer.verifying_key().to_bytes(),
        target_admin: header.id("admin")?,
        roster: keys.each_ref().map(|key| key.verifying_key().to_bytes()),
    };
    let files = LocalFiles::new()?;
    let paths = config
        .replicas
        .iter()
        .enumerate()
        .map(|(index, database)| files.replica(index, database, &policy))
        .collect::<Result<Vec<_>>>()?;
    let ledger = Ledger::connect(&config.database.config()?).await?;
    let result = async {
        ledger.migrate().await?;
        ledger.enroll_pair(&policy).await?;
        let fence = ledger.claim_writer(domain.pair, 0).await?;
        let mut replicas = Vec::with_capacity(3);
        for (path, key) in paths.iter().zip(&keys) {
            replicas.push(ReplicaProcess::launch(executable, path, key, &policy).await?);
        }
        let coordinator = Coordinator {
            ledger: ledger.clone(),
            policy: policy.clone(),
            replicas,
        };
        let mut flow = Flow {
            coordinator,
            generation: fence.generation,
            next: 1,
        };
        let inner = run_flow(
            &mut flow,
            &config,
            executable,
            (&paths, &keys),
            (&mut target, &header),
            LocalActors {
                source: &source,
                inventory: &inventory,
                observer: &observer,
                claimant: &claimant,
            },
            (&payout, &refund),
        )
        .await;
        let shutdown = flow.coordinator.shutdown().await;
        flow.coordinator.ledger.close().await;
        let mut report = inner?;
        shutdown?;
        report["replica_process_ids"] = json!(
            flow.coordinator
                .replicas
                .iter()
                .map(ReplicaProcess::id)
                .collect::<Vec<_>>()
        );
        Ok(report)
    }
    .await;
    ledger.close().await;
    result
}

struct Flow {
    coordinator: Coordinator,
    generation: u64,
    next: u64,
}
impl Flow {
    async fn operation(
        &mut self,
        entity: Id,
        portion: Id,
        transition: Transition,
        command: &LedgerCommand,
    ) -> Result<Operation> {
        let mut intent = [0; 32];
        intent[..8].copy_from_slice(b"KERBFXID");
        intent[8..16].copy_from_slice(&self.next.to_le_bytes());
        self.next = self.next.checked_add(1).ok_or(Error::Input)?;
        coordinator::operation(
            &self.coordinator.policy,
            self.generation,
            (entity, portion),
            intent,
            self.coordinator
                .ledger
                .entity_version(self.coordinator.policy.domain.pair, entity, portion)
                .await?,
            transition,
            command,
        )
    }
    async fn apply(
        &mut self,
        entity: Id,
        portion: Id,
        transition: Transition,
        command: LedgerCommand,
    ) -> Result<JournalDecision> {
        let operation = self
            .operation(entity, portion, transition, &command)
            .await?;
        self.coordinator.apply(operation, command).await
    }
    async fn authorize(
        &mut self,
        hold: Id,
        portion: Id,
        plan: &Section,
    ) -> Result<(Decision, Vec<Acknowledgement>)> {
        let decision = plan.decision("decision")?;
        let command = LedgerCommand::AuthorizeTarget(TargetAuthorization {
            hold,
            portion,
            decision,
            payload: plan.bytes("payload")?,
            accounts: plan.ids("accounts")?,
        });
        let operation = self
            .operation(hold, portion, Transition::PrepareFill, &command)
            .await?;
        let stored = self
            .coordinator
            .ledger
            .prepare_decision(operation, command)
            .await?;
        let acks = self.coordinator.acknowledge(&stored).await?;
        self.coordinator
            .ledger
            .commit_decision(&stored, &acks)
            .await?;
        let target_acks = acks
            .into_iter()
            .map(|ack| ack.target.ok_or(Error::TargetReceipt))
            .collect::<Result<Vec<_>>>()?;
        verify_unanimous(&decision, &target_acks, &self.coordinator.policy.roster)
            .map_err(|_| Error::TargetReceipt)?;
        Ok((decision, target_acks))
    }
}

async fn run_flow(
    flow: &mut Flow,
    config: &LocalConfig,
    executable: &Path,
    (paths, keys): (&[PathBuf], &[SigningKey; 3]),
    (target, header): (&mut TargetProcess, &Section),
    actors: LocalActors<'_>,
    (payout, refund): (&FixtureNative, &FixtureNative),
) -> Result<Value> {
    let LocalActors {
        source,
        inventory,
        observer,
        claimant,
    } = actors;
    let policy = flow.coordinator.policy.clone();
    let pair = policy.domain.pair;
    let hold = header.id("hold_business")?;
    let filled = header.id("filled_business")?;
    let unused = header.id("unused_business")?;
    let credit = [50; 32];
    let command = facts::funding(
        &policy,
        (source, inventory),
        claimant,
        &payout.context.inputs[0],
        credit,
    )?;
    let mut operation = flow
        .operation(credit, [0; 32], Transition::IssueCredit, &command)
        .await?;
    operation.intent = credit;
    operation.effects = command.operation_effects(&operation)?;
    flow.coordinator.apply(operation, command).await?;
    for input in [&payout.context.inputs[1], &refund.context.inputs[1]] {
        let inventory = facts::inventory(
            &policy,
            inventory,
            input,
            InventoryOrigin::Sponsor,
            policy.sponsor_scope,
        )?;
        flow.apply(
            input.inventory_note,
            [0; 32],
            Transition::ReserveInputs,
            LedgerCommand::RegisterSponsor { inventory },
        )
        .await?;
    }
    let prepared = facts::target(header, header.decision("prepared_decision")?, observer)?;
    let mut binding = TargetHoldBinding {
        domain: policy.domain,
        hold_business: header.id("hold_business")?,
        maximum_base: 7,
        expected_chunks: 2,
        refund_token: header.id("seller_token")?,
        epoch_version: header.number("epoch_version")?,
        evidence: TargetHoldEvidence::Prepared { prepare: prepared },
        signature: [0; 64],
    };
    binding.signature = observer.sign(&binding.signing_bytes()?).to_bytes();
    let mut command = LedgerCommand::PrepareHold {
        credit,
        amount: 34,
        refund_receiver: policy.receiver,
        target: binding,
        authorization: [0; 64],
    };
    let mut operation = flow
        .operation(hold, [0; 32], Transition::PrepareHold, &command)
        .await?;
    operation.intent = hold;
    operation.effects = command.operation_effects(&operation)?;
    if let LedgerCommand::PrepareHold { authorization, .. } = &mut command {
        *authorization = claimant
            .sign(
                &operation
                    .signing_bytes(SignatureRole::Application)
                    .map_err(|_| Error::Input)?,
            )
            .to_bytes();
    }
    let pending = flow
        .coordinator
        .ledger
        .prepare_decision(operation, command)
        .await?;
    let acks = flow.coordinator.acknowledge(&pending).await?;
    if flow
        .coordinator
        .ledger
        .commit_decision(&pending, &acks[..2])
        .await
        != Err(LedgerError::MissingUnanimity)
    {
        return Err(Error::Input);
    }
    flow.coordinator.ledger.close().await;
    flow.coordinator.replicas[1].kill().await?;
    flow.coordinator.replicas[1] =
        ReplicaProcess::launch(executable, &paths[1], &keys[1], &policy).await?;
    flow.coordinator.ledger = Ledger::connect(&config.database.config()?).await?;
    if flow.coordinator.reconcile().await? != RecoveryState::PendingRetained
        || flow.coordinator.ledger.pending_decision(pair).await? != Some(pending.clone())
    {
        return Err(Error::Input);
    }
    let held = flow.coordinator.ledger.snapshot(pair).await?;
    if held.available_credit != 0 || held.prepared != 34 {
        return Err(Error::Input);
    }
    flow.coordinator
        .ledger
        .commit_decision(&pending, &acks)
        .await?;
    let native_recipient = payout
        .context
        .outputs
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Recipient)
        .ok_or(Error::Input)?
        .recipient
        .to_raw_address_bytes();
    let allocation = allocation(header, &policy, native_recipient)?;
    let mut target_balances = None;
    for step in [
        "commit",
        "chunk_filled",
        "chunk_unused",
        "activate",
        "prepare_fill",
        "release",
    ] {
        let plan = target.section("plan").await?;
        if plan.text("step")? != step {
            return Err(Error::TargetReceipt);
        }
        let portion = match step {
            "chunk_filled" | "prepare_fill" | "release" => filled,
            "chunk_unused" => unused,
            _ => [0; 32],
        };
        let (decision, acks) = flow.authorize(hold, portion, &plan).await?;
        target.approve(&decision, &acks, &policy.roster).await?;
        let receipt = target.section("receipt").await?;
        if receipt.text("step")? != step || receipt.decision("decision")? != decision {
            return Err(Error::TargetReceipt);
        }
        let target_facts = facts::target(&receipt, decision, observer)?;
        observe_step(flow, step, &allocation, target_facts, filled).await?;
        if step == "commit" {
            flow.apply(
                hold,
                [0; 32],
                Transition::RecordAllocation,
                LedgerCommand::PrepareAllocation(allocation.clone()),
            )
            .await?;
        }
        if step == "chunk_filled" {
            let state = flow.coordinator.ledger.snapshot(pair).await?;
            if state.encumbered != 34
                || state.seller_outstanding != 0
                || state.buyer_unused_outstanding != 0
            {
                return Err(Error::Input);
            }
            let command = LedgerCommand::PrepareFirstLeg {
                hold,
                portion: filled,
            };
            let operation = flow
                .operation(hold, filled, Transition::PrepareFill, &command)
                .await?;
            if flow
                .coordinator
                .ledger
                .prepare_decision(operation, command)
                .await
                != Err(LedgerError::IncompleteAllocation)
            {
                return Err(Error::Input);
            }
        }
        if step == "release" {
            let balances = (
                receipt.number("buyer_balance")?,
                receipt.number("escrow_balance")?,
            );
            if balances != (5, 2) {
                return Err(Error::TargetReceipt);
            }
            target_balances = Some(balances);
        }
    }
    let target_end = target.section("scenario").await?;
    if target_end.number("max_packet_bytes")? > 1232 {
        return Err(Error::TargetReceipt);
    }
    target.finish().await?;
    let (buyer, escrow) = target_balances.ok_or(Error::TargetReceipt)?;
    let mut report = native_flow(
        flow,
        config,
        (payout, refund),
        hold,
        filled,
        unused,
        inventory,
    )
    .await?;
    report["spl_buyer_balance"] = json!(buyer);
    report["spl_escrow_balance"] = json!(escrow);
    report["max_packet_bytes"] = json!(target_end.number("max_packet_bytes")?);
    Ok(report)
}

fn allocation(
    header: &Section,
    policy: &PairPolicy,
    native_recipient: [u8; 43],
) -> Result<AllocationPlan> {
    let pair = header.id("pair")?;
    let epoch = header.id("epoch")?;
    let hold = header.id("hold")?;
    let filled = header.id("filled")?;
    let unused = header.id("unused")?;
    let make_payload = |business: Id, offset: u64, amount: u64, kind: u8| {
        let mut payload = business.to_vec();
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(kind);
        payload.extend_from_slice(&header.id("result")?);
        Ok::<_, Error>(payload)
    };
    let accounts = |portion, recipient| {
        vec![
            pair,
            epoch,
            hold,
            portion,
            recipient,
            policy.domain.mint,
            policy.domain.token_program,
            [0; 32],
            interface::INSTRUCTIONS_SYSVAR_ID,
        ]
    };
    let first = interface::effect_digest(
        Transition::RecordAllocation,
        &make_payload(header.id("filled_business")?, 0, 5, 1)?,
        &accounts(filled, header.id("buyer_token")?),
    );
    let second = interface::effect_digest(
        Transition::RecordAllocation,
        &make_payload(header.id("unused_business")?, 5, 2, 2)?,
        &accounts(unused, header.id("seller_token")?),
    );
    Ok(AllocationPlan {
        hold: header.id("hold_business")?,
        allocation: header.id("result")?,
        chunks: vec![first, second],
        portions: vec![
            PortionSpec {
                portion: header.id("filled_business")?,
                offset: 0,
                amount: 25,
                kind: AllocationKind::SellerLiability,
                native_recipient,
                spl_recipient: header.id("buyer_token")?,
                target_base_offset: 0,
                target_base_amount: 5,
                fill_fence: header.id("fence")?,
            },
            PortionSpec {
                portion: header.id("unused_business")?,
                offset: 25,
                amount: 9,
                kind: AllocationKind::BuyerUnused,
                native_recipient: policy.receiver,
                spl_recipient: header.id("seller_token")?,
                target_base_offset: 5,
                target_base_amount: 2,
                fill_fence: [0; 32],
            },
        ],
    })
}

async fn observe_step(
    flow: &mut Flow,
    step: &str,
    allocation: &AllocationPlan,
    target: SignedTargetFacts,
    filled: Id,
) -> Result<()> {
    let hold = allocation.hold;
    let (entity, portion, transition, command) = match step {
        "commit" => (
            target.facts.decision.operation.entity,
            [0; 32],
            target.facts.decision.operation.transition,
            LedgerCommand::ObserveEpoch { target },
        ),
        "chunk_filled" | "chunk_unused" => {
            let index = u32::from(step == "chunk_unused");
            (
                hold,
                [0; 32],
                Transition::RecordAllocation,
                LedgerCommand::RecordAllocationChunk {
                    hold,
                    allocation: allocation.allocation,
                    index,
                    digest: allocation.chunks[index as usize],
                    target,
                },
            )
        }
        "activate" => (
            target.facts.decision.operation.entity,
            [0; 32],
            Transition::ActivateAllocation,
            LedgerCommand::ActivateAllocation { target },
        ),
        "prepare_fill" => (
            target
                .facts
                .decision
                .operation
                .id()
                .map_err(|_| Error::TargetReceipt)?,
            [0; 32],
            Transition::ObserveNative,
            LedgerCommand::ObserveTarget(target),
        ),
        "release" => (
            hold,
            filled,
            Transition::ReleaseSpl,
            LedgerCommand::ObserveSplRelease {
                hold,
                portion: filled,
                recipient: allocation.portions[0].spl_recipient,
                target_base_amount: 5,
                target,
            },
        ),
        _ => return Err(Error::TargetReceipt),
    };
    flow.apply(entity, portion, transition, command).await?;
    Ok(())
}

fn validate_header(header: &Section, keys: &[SigningKey; 3]) -> Result<Domain> {
    if header.text("schema")? != "kerb-solana-local-v1"
        || header.text("environment")? != "LocalFixture"
        || header.number("maximum_base")? != 7
        || header.number("filled_base")? != 5
        || header.number("unused_base")? != 2
        || header.number("expected_chunks")? != 2
    {
        return Err(Error::TargetReceipt);
    }
    let domain = header.domain("domain")?;
    if domain.deployment != [0x44; 32]
        || domain.solana_genesis != [0x47; 32]
        || domain.solana_program != [0x4b; 32]
        || domain.pair != [0x50; 32]
        || domain.epoch != 1
        || domain.mint != header.id("mint")?
        || domain.token_program != header.id("token_program")?
    {
        return Err(Error::TargetReceipt);
    }
    let roster = keys.each_ref().map(|key| key.verifying_key().to_bytes());
    for (i, key) in roster.iter().enumerate() {
        if *key != header.id(&format!("roster{i}"))? {
            return Err(Error::TargetReceipt);
        }
    }
    let pair = interface::pair_address(&domain, &header.id("admin")?);
    let epoch = interface::epoch_address(&domain, &pair);
    let hold = interface::hold_address(&domain, &epoch, &header.id("hold_business")?);
    if pair != header.id("pair")?
        || epoch != header.id("epoch")?
        || hold != header.id("hold")?
        || interface::escrow_address(&domain, &hold) != header.id("escrow")?
        || interface::portion_address(&domain, &hold, &header.id("filled_business")?)
            != header.id("filled")?
        || interface::portion_address(&domain, &hold, &header.id("unused_business")?)
            != header.id("unused")?
        || header.id("instructions_sysvar")? != interface::INSTRUCTIONS_SYSVAR_ID
    {
        return Err(Error::TargetReceipt);
    }
    let decision = header.decision("prepared_decision")?;
    let acks = roster
        .iter()
        .enumerate()
        .map(|(i, key)| {
            Ok(Acknowledgement {
                signer: *key,
                signature: header.array(&format!("prepared_ack{i}"))?,
                decision,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    verify_unanimous(&decision, &acks, &roster).map_err(|_| Error::TargetReceipt)?;
    if decision.operation.domain != domain
        || decision.operation.entity != hold
        || decision.operation.transition != Transition::PrepareSeller
    {
        return Err(Error::TargetReceipt);
    }
    Ok(domain)
}

async fn native_flow(
    flow: &mut Flow,
    config: &LocalConfig,
    (payout, refund): (&FixtureNative, &FixtureNative),
    hold: Id,
    filled: Id,
    unused: Id,
    observer: &SigningKey,
) -> Result<Value> {
    let pair = flow.coordinator.policy.domain.pair;
    let checked = ziquid_zcash::custody::inspect_pczt(&payout.bytes, &payout.context.expected())?;
    let plan = native_plan(
        (hold, filled),
        NativeIntentKind::SellerPayout,
        &flow.coordinator.policy,
        &checked,
        fixture::USER_NOTE,
        fixture::FIRST_SPONSOR_NOTE,
        Some(&refund.context.inputs[0]),
    )?;
    let operation = flow
        .operation(
            hold,
            filled,
            Transition::PrepareNative,
            &LedgerCommand::PrepareNative(plan.clone()),
        )
        .await?;
    flow.coordinator
        .prepare_native(operation, plan.clone(), &checked)
        .await?;
    let payout_intent = operation.intent;
    flow.apply(
        payout_intent,
        [0; 32],
        Transition::ObserveNative,
        LedgerCommand::NativeUnknown {
            intent: payout_intent,
            transaction: plan.transaction,
        },
    )
    .await?;
    flow.coordinator.ledger.close().await;
    flow.coordinator.ledger = Ledger::connect(&config.database.config()?).await?;
    if flow.coordinator.reconcile().await? != RecoveryState::Current {
        return Err(Error::Input);
    }
    let unknown = flow.coordinator.ledger.intent(pair, payout_intent).await?;
    let before = flow.coordinator.ledger.snapshot(pair).await?;
    if unknown.state != IntentStatus::Unknown
        || before.locked_inventory != 34
        || before.seller_outstanding != 25
        || before.buyer_unused_outstanding != 9
        || before.final_payout != 0
        || before.final_refund != 0
        || flow
            .coordinator
            .ledger
            .native_plan(pair, payout_intent)
            .await?
            != plan
    {
        return Err(Error::Input);
    }
    // Synthetic fixture observation is explicit authority testimony, not a
    // native signature, mined transaction or evidence of real payment.
    let facts = facts::observe_native(&flow.coordinator.policy, observer, payout_intent, &plan)?;
    flow.apply(
        payout_intent,
        [0; 32],
        Transition::ObserveNative,
        LedgerCommand::ObserveNative(facts),
    )
    .await?;
    let changed = flow.coordinator.ledger.snapshot(pair).await?;
    if changed.available_credit != 0
        || changed.usable_inventory != 9
        || changed.locked_inventory != 0
        || changed.final_payout != 25
        || changed.buyer_unused_outstanding != 9
    {
        return Err(Error::Input);
    }
    let checked_refund = ziquid_zcash::custody::inspect_pczt(&refund.bytes, &refund.context.expected())?;
    let refund_plan = native_plan(
        (hold, unused),
        NativeIntentKind::BuyerRefund,
        &flow.coordinator.policy,
        &checked_refund,
        fixture::CHANGE_NOTE,
        fixture::SECOND_SPONSOR_NOTE,
        None,
    )?;
    let refund_operation = flow
        .operation(
            hold,
            unused,
            Transition::PrepareNative,
            &LedgerCommand::PrepareNative(refund_plan.clone()),
        )
        .await?;
    flow.coordinator
        .prepare_native(refund_operation, refund_plan.clone(), &checked_refund)
        .await?;
    flow.apply(
        refund_operation.intent,
        [0; 32],
        Transition::ObserveNative,
        LedgerCommand::NativeUnknown {
            intent: refund_operation.intent,
            transaction: refund_plan.transaction,
        },
    )
    .await?;
    let snapshot = flow.coordinator.ledger.snapshot(pair).await?;
    if snapshot.available_credit != 0
        || snapshot.locked_inventory != 9
        || snapshot.usable_inventory != 0
        || snapshot.final_payout != 25
        || snapshot.final_refund != 0
        || snapshot.buyer_unused_outstanding != 9
    {
        return Err(Error::Input);
    }
    Ok(
        json!({ "environment": "LocalFixture", "simulated_operator_independence": true,
        "prepared_debit": u64::try_from(before.seller_outstanding + before.buyer_unused_outstanding).map_err(|_| Error::Input)?,
        "seller_liability": plan.amount, "unused_refund": refund_plan.amount, "partial_activation": "held",
        "unknown_restart": "held", "unused_refund_without_spl": "inspected-and-prepared",
        "native": "two-unsigned-intents-durable", "native_fee_each": checked.fee(),
        "user_inputs": payout.context.inputs[0].value,
        "sponsor_fee_capital": payout.context.inputs[1].value + refund.context.inputs[1].value,
        "native_recipient": plan.amount, "native_change": plan.change[0].value,
        "refund_recipient": refund_plan.amount, "journal_ack_count_each": flow.coordinator.replicas.len(),
        "local_observed_payout": u64::try_from(snapshot.final_payout).map_err(|_| Error::Input)?,
        "refund_status": "prepared-unknown", "real_native_payout": false, "real_native_refund": false,
        "native_signed": false, "native_broadcast": false, "private_enabled": false,
        "journal_head": native::hex(&snapshot.head), "target_head": native::hex(&snapshot.target_head),
        "locked_user_inventory": u64::try_from(snapshot.locked_inventory).map_err(|_| Error::Input)?,
        "pczt_digest": native::hex(checked.exact_pczt_digest()), "refund_pczt_digest": native::hex(checked_refund.exact_pczt_digest()),
        "source_history_verified": false, "native_consensus_verified": false }),
    )
}

fn native_plan(
    (hold, portion): (Id, Id),
    kind: NativeIntentKind,
    policy: &PairPolicy,
    checked: &ziquid_zcash::custody::UnsignedNativeInspection<'_>,
    user_input: Id,
    fee_input: Id,
    change_input: Option<&ziquid_zcash::custody::ReservedNativeInput>,
) -> Result<NativePlan> {
    let recipient = checked
        .expected_outputs()
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Recipient)
        .ok_or(Error::Input)?;
    let change = change_input
        .map(|input| ChangeOutput {
            note: input.inventory_note,
            receiver: policy.receiver,
            value: input.value,
            action_index: input.source_occurrence.action_index,
            note_commitment: input.note_commitment,
            nullifier: input.nullifier,
        })
        .into_iter()
        .collect();
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Input)?;
    Ok(NativePlan {
        hold,
        portion,
        kind,
        recipient: recipient.recipient.to_raw_address_bytes(),
        amount: recipient.value,
        inventory_scope: policy.inventory_scope,
        inputs: vec![user_input],
        fee_inputs: vec![fee_input],
        change,
        fee: checked.fee(),
        nonce,
        pczt_digest: *checked.exact_pczt_digest(),
        sighash: *checked.shielded_sighash(),
        transaction: *checked.txid(),
    })
}

struct LocalFiles {
    path: PathBuf,
}
impl LocalFiles {
    fn new() -> Result<Self> {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).map_err(|_| Error::Input)?;
        let path = std::env::temp_dir().join(format!(
            "z2z-runtime-local-{}-{}",
            std::process::id(),
            native::hex(&nonce)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).map_err(|_| Error::Input)?;
        Ok(Self { path })
    }
    fn replica(
        &self,
        index: usize,
        database: &config::Database,
        policy: &PairPolicy,
    ) -> Result<PathBuf> {
        let path = self.path.join(format!("replica{index}.json"));
        let value = json!({ "schema_version": 1, "database": database,
            "policy": policy.canonical_bytes()?, "expected_signer": policy.roster[index] });
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| Error::Input)?;
        file.write_all(&serde_json::to_vec(&value).map_err(|_| Error::Input)?)
            .map_err(|_| Error::Input)?;
        Ok(path)
    }
}
impl Drop for LocalFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replica_file_contains_only_uri_reference_schema_and_enrolled_policy() {
        use std::os::unix::fs::PermissionsExt;
        let database = config::Database {
            uri_env: "Z2Z_LOCAL_FIXTURE_URI_REFERENCE".into(),
            schema: "z2z_fixture_replica".into(),
            max_connections: 4,
        };
        let domain = config::read::<NativePolicy>(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/market/policy.json")
        ).unwrap().context().unwrap().domain;
        let keys = [facts::key().unwrap(), facts::key().unwrap(), facts::key().unwrap()];
        let policy = PairPolicy {
            domain,
            environment: ObservationEnvironment::LocalFixture,
            source_policy: [20; 32], history_anchor: [21; 32], minimum_confirmations: 10,
            receiver: [22; 43], inventory_scope: domain.pair, sponsor_scope: [24; 32],
            source_producer: keys[0].verifying_key().to_bytes(),
            inventory_producer: keys[1].verifying_key().to_bytes(),
            target_observer: keys[2].verifying_key().to_bytes(),
            target_admin: [25; 32],
            roster: keys.each_ref().map(|key| key.verifying_key().to_bytes()),
        };
        let files = LocalFiles::new().unwrap();
        let path = files.replica(0, &database, &policy).unwrap();
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["database"], json!({
            "uri_env": "Z2Z_LOCAL_FIXTURE_URI_REFERENCE",
            "schema": "z2z_fixture_replica",
            "max_connections": 4,
        }));
        let parsed: config::ReplicaConfig = config::read(&path).unwrap();
        assert_eq!(config::policy(&parsed.policy).unwrap(), policy);
        assert_eq!(parsed.expected_signer, policy.roster[0]);
        assert_eq!(fs::metadata(&files.path).unwrap().permissions().mode() & 0o077, 0);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o177, 0);
        assert!(files.replica(0, &database, &policy).is_err(), "existing child config must not be replaced");
    }
}
