#![cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod support;
use ed25519_dalek::Signer;
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use ziquid_solana_interface as target;
use support::*;

// A real target signature may escape after a crash; durable held credit must not.
#[tokio::test]
async fn target_authorization_persists_before_export_and_unknown_releases_never_free_credit() {
    let f = Fixture::new("presign").await;
    let (_, hold) = f.held().await;
    let domain = f.policy.domain;
    let pair = target::pair_address(&domain, &f.policy.target_admin);
    let epoch = target::epoch_address(&domain, &pair);
    let payload = [64; 32].to_vec();
    let accounts = vec![pair, epoch, target::INSTRUCTIONS_SYSVAR_ID];
    let predecessor = f.ledger.snapshot(domain.pair).await.unwrap().target_head;
    let target_decision = target::decision(
        domain,
        epoch,
        None,
        Transition::CommitEpoch,
        target::Envelope {
            intent: [62; 32],
            generation: 2,
            prior: 3,
            predecessor,
        },
        &payload,
        &accounts,
    )
    .unwrap();
    let command = LedgerCommand::AuthorizeTarget(TargetAuthorization {
        hold,
        portion: [0; 32],
        decision: target_decision,
        payload,
        accounts,
    });
    let operation = f.operation(
        hold,
        [0; 32],
        [63; 32],
        1,
        Transition::PrepareFill,
        &command,
    );
    let decision = f.ledger.prepare_decision(operation, command).await.unwrap();
    let acknowledgements = f.acknowledge(&decision).await;
    for acknowledgement in &acknowledgements {
        assert_eq!(acknowledgement.target.unwrap().decision, target_decision);
    }
    f.ledger.close().await;
    let recovered = Ledger::connect(&f.db.config).await.unwrap();
    assert_eq!(
        f.reconcile(&recovered).await,
        RecoveryState::PendingRetained
    );
    assert_eq!(
        recovered.pending_decision(domain.pair).await.unwrap(),
        Some(decision.clone())
    );
    recovered
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    let snapshot = recovered.snapshot(domain.pair).await.unwrap();
    assert_eq!((snapshot.available_credit, snapshot.prepared), (0, 34));
    assert_eq!(
        snapshot.target_head, predecessor,
        "signature export is not a chain observation"
    );
    let command = LedgerCommand::AuthorizeTarget(TargetAuthorization {
        hold,
        portion: [0; 32],
        decision: target_decision,
        payload: [64; 32].to_vec(),
        accounts: vec![pair, epoch, target::INSTRUCTIONS_SYSVAR_ID],
    });
    let operation = f.operation(
        hold,
        [0; 32],
        [66; 32],
        2,
        Transition::PrepareFill,
        &command,
    );
    assert_eq!(
        recovered.prepare_decision(operation, command).await,
        Err(LedgerError::CompetingIntent)
    );
    let facts = TargetFacts {
        decision: target_decision,
        observation: ChainObservation {
            environment: f.policy.environment,
            operation: target_decision.operation.id().unwrap(),
            transaction: [67; 32],
            slot: 200,
            commitment: ChainCommitment::Finalized,
            effects: target_decision.operation.effects,
        },
    };
    let command = LedgerCommand::ObserveEpoch {
        target: SignedTargetFacts {
            signature: f
                .target_key
                .sign(&facts.signing_bytes().unwrap())
                .to_bytes(),
            facts,
        },
    };
    let operation = f.operation(
        target_decision.operation.entity,
        [0; 32],
        [68; 32],
        0,
        Transition::CommitEpoch,
        &command,
    );
    let observed = recovered
        .prepare_decision(operation, command)
        .await
        .unwrap();
    let acknowledgements = f.acknowledge(&observed).await;
    assert!(
        acknowledgements.iter().all(|ack| ack.target.is_none()),
        "observation cannot re-export target signing authority"
    );
    recovered
        .commit_decision(&observed, &acknowledgements)
        .await
        .unwrap();
    assert_eq!(
        recovered.snapshot(domain.pair).await.unwrap().target_head,
        target_decision.next_head
    );
    recovered.close().await;
    f.remove().await;
}

// Fresh signed observations may not synthesize authorization after the effect.
#[tokio::test]
async fn unjournaled_target_observation_rejects_even_with_enrolled_observer() {
    let f = Fixture::new("unauthorizedtarget").await;
    let (_, hold) = f.held().await;
    let target = f
        .target(
            (hold, [0; 32]),
            Transition::CommitEpoch,
            [61; 32],
            1,
            0,
            [62; 32],
        )
        .await;
    let epoch = target.facts.decision.operation.entity;
    let command = LedgerCommand::ObserveEpoch { target };
    let operation = f.operation(
        epoch,
        [0; 32],
        [63; 32],
        1,
        Transition::CommitEpoch,
        &command,
    );
    assert_eq!(
        f.ledger.prepare_decision(operation, command).await,
        Err(LedgerError::InvalidEvidence)
    );
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .prepared,
        34
    );
    f.remove().await;
}

#[tokio::test]
async fn target_generation_advances_independently_of_private_writer_generation() {
    let f = Fixture::new("targetgeneration").await;
    let (_, hold) = f.held().await;
    let head = f
        .ledger
        .snapshot(f.policy.domain.pair)
        .await
        .unwrap()
        .target_head;
    let mut auth = f.authorization(
        (hold, [0; 32]),
        Transition::CommitEpoch,
        3,
        [62; 32],
        [64; 32].to_vec(),
        head,
    );
    auth.decision.operation.generation = 2;
    auth.decision = Decision::new(auth.decision.operation, head).unwrap();
    let command = LedgerCommand::AuthorizeTarget(auth);
    let op = f.operation(
        hold,
        [0; 32],
        [63; 32],
        1,
        Transition::PrepareFill,
        &command,
    );
    let decision = f.ledger.prepare_decision(op, command).await.unwrap();
    let acks = f.acknowledge(&decision).await;
    f.ledger.commit_decision(&decision, &acks).await.unwrap();
    assert_eq!(decision.operation.generation, 1);
    assert_eq!(decision.target.unwrap().operation.generation, 2);
    f.remove().await;
}
