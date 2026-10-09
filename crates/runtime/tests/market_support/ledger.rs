#![allow(dead_code)]
use ed25519_dalek::{Signer, SigningKey};
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use rand_core::OsRng;
use sqlx::{Connection, PgConnection};
use ziquid_runtime::database::{self, DatabaseConfig};
pub struct TestDatabase {
    pub config: DatabaseConfig,
}
impl TestDatabase {
    // Name allocation is pure. Only Ledger/Replica::migrate creates a schema.
    pub async fn create(label: &str) -> Self {
        assert_eq!(std::env::var("Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES").as_deref(), Ok("yes"),
            "PostgreSQL tests require explicit isolated-schema authorization");
        assert!(std::env::var_os("Z2Z_TEST_DATABASE_URL").is_some(),
            "PostgreSQL tests require private URI configuration; never silently skip");
        let prefix = std::env::var("Z2Z_TEST_PG_SCHEMA_PREFIX")
            .expect("PostgreSQL tests require an authorized schema prefix");
        let policy = DatabaseConfig { uri_env: "Z2Z_TEST_DATABASE_URL".into(), schema: prefix.clone(), max_connections: 8 };
        policy.validate().expect("invalid authorized PostgreSQL test schema prefix");
        assert!(prefix.len() <= 30, "PostgreSQL test schema prefix must be at most 30 bytes");
        assert!(!label.is_empty() && label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).expect("cannot allocate isolated PostgreSQL test name");
        let nonce = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let schema = format!("{prefix}_{}_{nonce}", &label[..label.len().min(6)]);
        let config = DatabaseConfig { schema, ..policy };
        config.validate().expect("invalid isolated PostgreSQL test schema name");
        Self { config }
    }
    pub async fn connection(&self) -> PgConnection {
        database::test_connection(&self.config).await.expect("authorized PostgreSQL test connection failed")
    }
    pub async fn fork(&self, label: &str) -> Self {
        let clone = Self::create(label).await;
        let ledger = Ledger::connect(&clone.config).await.unwrap();
        ledger.migrate().await.unwrap();
        ledger.close().await;
        let mut connection = self.connection().await;
        let mut tx = connection.begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ").await.unwrap();
        // A coherent old writer snapshot is copied into a separately initialized
        // schema. Schema OIDs/identity/catalog/history are NEVER cloned.
        for table in [
            "ledger_pairs", "replica_pairs", "ledger_versions", "ledger_target_versions",
            "ledger_journal", "ledger_commits", "ledger_credits", "ledger_holds",
            "ledger_allocations", "ledger_allocation_chunks", "ledger_portions",
            "ledger_intent_records", "ledger_intent_states", "ledger_nonce_tombstones",
            "ledger_change_reservations", "ledger_physical_claims", "ledger_inventory",
            "ledger_consumptions", "ledger_native_observations", "ledger_target_authorizations",
            "ledger_target_observations", "ledger_epoch_terminal", "replica_journal", "replica_intents",
        ] {
            sqlx::raw_sql(&format!("INSERT INTO {}.{table} SELECT * FROM {}.{table}", clone.config.schema, self.config.schema))
                .execute(&mut *tx).await.unwrap();
        }
        tx.commit().await.unwrap();
        connection.close().await.unwrap();
        clone
    }
    pub async fn remove(self) {
        database::test_drop_schema(&self.config).await.expect("authorized PostgreSQL test schema cleanup failed");
    }
}

pub fn domain() -> Domain {
    Domain {
        schema_version: 1,
        deployment: [1; 32],
        solana_genesis: [2; 32],
        solana_program: [3; 32],
        mint: [4; 32],
        token_program: LEGACY_TOKEN_PROGRAM,
        source_network: SOURCE_NETWORK_TESTNET,
        source_pool: SOURCE_POOL_IRONWOOD,
        source_branch: SOURCE_BRANCH_NU6_3,
        source_tx_version: SOURCE_TRANSACTION_VERSION,
        source_genesis: [5; 32],
        receiver_policy: [6; 32],
        pair: [7; 32],
        epoch: 1,
        rules_hash: [8; 32],
        roster_version: 1,
        signature_scheme: 1,
    }
}

pub struct Fixture {
    pub db: TestDatabase,
    pub ledger: Ledger,
    pub policy: PairPolicy,
    pub fence: WriterFence,
    pub keys: [SigningKey; 3],
    pub source_key: SigningKey,
    pub inventory_key: SigningKey,
    pub target_key: SigningKey,
    pub claimant: SigningKey,
    pub replica_dbs: [TestDatabase; 3],
    pub replicas: [Replica; 3],
}
impl Fixture {
    pub async fn new(label: &str) -> Self {
        let db = TestDatabase::create(label).await;
        let ledger = Ledger::connect(&db.config).await.unwrap();
        ledger.migrate().await.unwrap();
        let keys = std::array::from_fn(|_| SigningKey::generate(&mut OsRng));
        let source_key = SigningKey::generate(&mut OsRng);
        let inventory_key = SigningKey::generate(&mut OsRng);
        let target_key = SigningKey::generate(&mut OsRng);
        let claimant = SigningKey::generate(&mut OsRng);
        let policy = PairPolicy {
            domain: domain(),
            environment: ObservationEnvironment::LocalFixture,
            source_policy: [20; 32],
            history_anchor: [21; 32],
            minimum_confirmations: 10,
            receiver: [22; 43],
            inventory_scope: domain().pair,
            sponsor_scope: [24; 32],
            source_producer: source_key.verifying_key().to_bytes(),
            inventory_producer: inventory_key.verifying_key().to_bytes(),
            target_observer: target_key.verifying_key().to_bytes(),
            target_admin: [25; 32],
            roster: keys.each_ref().map(|k| k.verifying_key().to_bytes()),
        };
        ledger.enroll_pair(&policy).await.unwrap();
        let fence = ledger.claim_writer(policy.domain.pair, 0).await.unwrap();
        let replica_dbs = [
            TestDatabase::create("replica").await,
            TestDatabase::create("replica").await,
            TestDatabase::create("replica").await,
        ];
        let replicas = [
            Replica::connect(&replica_dbs[0].config)
                .await
                .unwrap(),
            Replica::connect(&replica_dbs[1].config)
                .await
                .unwrap(),
            Replica::connect(&replica_dbs[2].config)
                .await
                .unwrap(),
        ];
        for replica in &replicas {
            replica.migrate().await.unwrap();
            replica.enroll_pair(&policy).await.unwrap();
        }
        Self {
            db,
            ledger,
            policy,
            fence,
            keys,
            source_key,
            inventory_key,
            target_key,
            claimant,
            replica_dbs,
            replicas,
        }
    }
    pub fn operation(
        &self,
        entity: Id,
        portion: Id,
        intent: Id,
        prior_version: u64,
        transition: Transition,
        command: &LedgerCommand,
    ) -> Operation {
        let mut operation = Operation {
            domain: self.policy.domain,
            entity,
            portion,
            intent,
            generation: self.fence.generation,
            prior_version,
            transition,
            effects: [0; 32],
        };
        operation.effects = command.operation_effects(&operation).unwrap();
        operation
    }
    pub async fn acknowledge(&self, decision: &JournalDecision) -> Vec<JournalAcknowledgement> {
        let mut acknowledgements = Vec::new();
        for (replica, key) in self.replicas.iter().zip(&self.keys) {
            acknowledgements.push(replica.acknowledge(decision, key).await.unwrap());
        }
        acknowledgements
    }
    pub async fn apply(
        &self,
        mut operation: Operation,
        mut command: LedgerCommand,
    ) -> JournalDecision {
        operation.prior_version = self
            .ledger
            .entity_version(operation.domain.pair, operation.entity, operation.portion)
            .await
            .unwrap();
        if let LedgerCommand::AuthorizeTarget(auth) = &mut command {
            auth.decision.operation.generation = self
                .ledger
                .snapshot(operation.domain.pair)
                .await
                .unwrap()
                .target_generation
                .checked_add(1)
                .unwrap();
            auth.decision =
                Decision::new(auth.decision.operation, auth.decision.predecessor).unwrap();
        }
        operation.effects = command.operation_effects(&operation).unwrap();
        let decision = self
            .ledger
            .prepare_decision(operation, command)
            .await
            .unwrap();
        let acknowledgements = self.acknowledge(&decision).await;
        self.ledger
            .commit_decision(&decision, &acknowledgements)
            .await
            .unwrap();
        decision
    }
    pub fn funding(&self, amount: u64, tag: u8) -> LedgerCommand {
        let occurrence = SourceOccurrence {
            network: self.policy.domain.source_network,
            pool: self.policy.domain.source_pool,
            txid: [tag; 32],
            action_index: 0,
        };
        let credit_intent = [tag.wrapping_add(1); 32];
        let note = [tag.wrapping_add(2); 32];
        let source = SourceFacts {
            domain: self.policy.domain,
            provenance: ObservationEnvironment::LocalFixture,
            occurrence,
            receiver: self.policy.receiver,
            value: amount,
            block: [30; 32],
            height: 100,
            confirmations: 12,
            history_anchor: self.policy.history_anchor,
            policy: self.policy.source_policy,
            effect: SourceEffect::Deposit {
                claimant: self.claimant.verifying_key().to_bytes(),
                credit_intent,
            },
        };
        let mut claim = FundingClaim {
            domain: self.policy.domain,
            occurrence,
            claimant: self.claimant.verifying_key().to_bytes(),
            receiver: self.policy.receiver,
            value: amount,
            block_policy: self.policy.source_policy,
            inventory_note: note,
            evidence_digest: source.digest().unwrap(),
            credit_intent,
            authorization: [0; 64],
        };
        claim.authorization = self
            .claimant
            .sign(&claim.signing_bytes().unwrap())
            .to_bytes();
        let inventory = InventoryFacts {
            domain: self.policy.domain,
            provenance: ObservationEnvironment::LocalFixture,
            note,
            occurrence,
            note_commitment: [tag.wrapping_add(3); 32],
            nullifier: [tag.wrapping_add(4); 32],
            receiver: self.policy.receiver,
            value: amount,
            scope: self.policy.inventory_scope,
            control: self.policy.inventory_producer,
            origin: InventoryOrigin::Deposit,
            condition: InventoryCondition::Spendable,
            history_anchor: self.policy.history_anchor,
        };
        LedgerCommand::IssueCredit {
            claim,
            source: SignedSourceFacts {
                signature: self
                    .source_key
                    .sign(&source.signing_bytes().unwrap())
                    .to_bytes(),
                facts: source,
            },
            inventory: SignedInventoryFacts {
                signature: self
                    .inventory_key
                    .sign(&inventory.signing_bytes().unwrap())
                    .to_bytes(),
                facts: inventory,
            },
        }
    }
    pub async fn issue(&self, amount: u64, tag: u8) -> Id {
        let command = self.funding(amount, tag);
        let LedgerCommand::IssueCredit { claim, .. } = &command else {
            unreachable!()
        };
        let credit = claim.credit_intent;
        let op = self.operation(
            credit,
            [0; 32],
            credit,
            0,
            Transition::IssueCredit,
            &command,
        );
        self.apply(op, command).await;
        credit
    }
    pub fn target_binding(&self, hold: Id) -> TargetHoldBinding {
        use ziquid_solana_interface as target;
        let domain = self.policy.domain;
        let pair = target::pair_address(&domain, &self.policy.target_admin);
        let epoch = target::epoch_address(&domain, &pair);
        let target_hold = target::hold_address(&domain, &epoch, &hold);
        let accounts = [pair, epoch, target_hold, target::INSTRUCTIONS_SYSVAR_ID];
        let decision = target::decision(
            domain,
            target_hold,
            None,
            Transition::PrepareSeller,
            target::Envelope {
                intent: [26; 32],
                generation: 1,
                prior: 1,
                predecessor: [0; 32],
            },
            &[],
            &accounts,
        )
        .unwrap();
        let facts = TargetFacts {
            decision,
            observation: ChainObservation {
                environment: self.policy.environment,
                operation: decision.operation.id().unwrap(),
                transaction: [27; 32],
                slot: 100,
                commitment: ChainCommitment::Finalized,
                effects: decision.operation.effects,
            },
        };
        let prepared = SignedTargetFacts {
            signature: self
                .target_key
                .sign(&facts.signing_bytes().unwrap())
                .to_bytes(),
            facts,
        };
        let mut binding = TargetHoldBinding {
            domain,
            hold_business: hold,
            maximum_base: 7,
            expected_chunks: 2,
            refund_token: [28; 32],
            epoch_version: 3,
            evidence: TargetHoldEvidence::Prepared { prepare: prepared },
            signature: [0; 64],
        };
        binding.signature = self
            .target_key
            .sign(&binding.signing_bytes().unwrap())
            .to_bytes();
        binding
    }
    pub fn prepare(&self, credit: Id, hold: Id, amount: u64) -> (Operation, LedgerCommand) {
        let mut command = LedgerCommand::PrepareHold {
            credit,
            amount,
            refund_receiver: [40; 43],
            target: self.target_binding(hold),
            authorization: [0; 64],
        };
        let op = self.operation(hold, [0; 32], hold, 0, Transition::PrepareHold, &command);
        if let LedgerCommand::PrepareHold { authorization, .. } = &mut command {
            *authorization = self
                .claimant
                .sign(&op.signing_bytes(SignatureRole::Application).unwrap())
                .to_bytes();
        }
        (op, command)
    }
    pub async fn held(&self) -> (Id, Id) {
        let credit = self.issue(34, 50).await;
        let hold = [60; 32];
        let (op, command) = self.prepare(credit, hold, 34);
        self.apply(op, command).await;
        (credit, hold)
    }
    pub async fn target(
        &self,
        scope: (Id, Id),
        transition: Transition,
        effects: Id,
        generation: u64,
        prior_version: u64,
        intent: Id,
    ) -> SignedTargetFacts {
        let (entity, portion) = scope;
        let snapshot = self.ledger.snapshot(self.policy.domain.pair).await.unwrap();
        let operation = Operation {
            domain: self.policy.domain,
            entity,
            portion,
            intent,
            generation,
            prior_version,
            transition,
            effects,
        };
        let decision = Decision::new(operation, snapshot.target_head).unwrap();
        let facts = TargetFacts {
            decision,
            observation: ChainObservation {
                environment: ObservationEnvironment::LocalFixture,
                operation: operation.id().unwrap(),
                transaction: [90; 32],
                slot: snapshot.sequence + 100,
                commitment: ChainCommitment::Finalized,
                effects,
            },
        };
        SignedTargetFacts {
            signature: self
                .target_key
                .sign(&facts.signing_bytes().unwrap())
                .to_bytes(),
            facts,
        }
    }
    pub fn authorization(
        &self,
        scope: (Id, Id),
        transition: Transition,
        prior: u64,
        intent: Id,
        payload: Vec<u8>,
        predecessor: Id,
    ) -> TargetAuthorization {
        let (hold, portion) = scope;
        use ziquid_solana_interface as t;
        let d = self.policy.domain;
        let pair = t::pair_address(&d, &self.policy.target_admin);
        let epoch = t::epoch_address(&d, &pair);
        let h = t::hold_address(&d, &epoch, &hold);
        let p = t::portion_address(&d, &h, &portion);
        let (entity, part, accounts) = match transition {
            Transition::CommitEpoch | Transition::AbortEpoch | Transition::ActivateAllocation => {
                (epoch, None, vec![pair, epoch, t::INSTRUCTIONS_SYSVAR_ID])
            }
            Transition::RecordAllocation => (
                h,
                Some(p),
                vec![
                    pair,
                    epoch,
                    h,
                    p,
                    if portion == [65; 32] {
                        [67; 32]
                    } else {
                        [28; 32]
                    },
                    d.mint,
                    d.token_program,
                    [0; 32],
                    t::INSTRUCTIONS_SYSVAR_ID,
                ],
            ),
            Transition::PrepareFill | Transition::CancelFill => (
                p,
                Some(p),
                vec![pair, epoch, h, p, t::INSTRUCTIONS_SYSVAR_ID],
            ),
            Transition::ReleaseSpl => (
                p,
                Some(p),
                vec![
                    pair,
                    epoch,
                    h,
                    p,
                    t::escrow_address(&d, &h),
                    d.mint,
                    [67; 32],
                    d.token_program,
                    t::INSTRUCTIONS_SYSVAR_ID,
                ],
            ),
            _ => panic!("unsupported fixture transition"),
        };
        TargetAuthorization {
            hold,
            portion,
            decision: t::decision(
                d,
                entity,
                part,
                transition,
                t::Envelope {
                    intent,
                    generation: 1,
                    prior,
                    predecessor,
                },
                &payload,
                &accounts,
            )
            .unwrap(),
            payload,
            accounts,
        }
    }
    pub fn observed(&self, decision: Decision) -> SignedTargetFacts {
        let facts = TargetFacts {
            decision,
            observation: ChainObservation {
                environment: self.policy.environment,
                operation: decision.operation.id().unwrap(),
                transaction: decision.operation.id().unwrap(),
                slot: 200,
                commitment: ChainCommitment::Finalized,
                effects: decision.operation.effects,
            },
        };
        SignedTargetFacts {
            signature: self
                .target_key
                .sign(&facts.signing_bytes().unwrap())
                .to_bytes(),
            facts,
        }
    }
    pub async fn authorize(
        &self,
        scope: (Id, Id),
        transition: Transition,
        prior: u64,
        intent: Id,
        payload: Vec<u8>,
        private_intent: Id,
    ) -> SignedTargetFacts {
        let (hold, portion) = scope;
        let snapshot = self.ledger.snapshot(self.policy.domain.pair).await.unwrap();
        let mut auth = self.authorization(
            (hold, portion),
            transition,
            prior,
            intent,
            payload,
            snapshot.target_head,
        );
        auth.decision.operation.generation = snapshot.target_generation.checked_add(1).unwrap();
        auth.decision = Decision::new(auth.decision.operation, snapshot.target_head).unwrap();
        let version = self
            .ledger
            .entity_version(self.policy.domain.pair, hold, portion)
            .await
            .unwrap();
        let command = LedgerCommand::AuthorizeTarget(auth.clone());
        let op = self.operation(
            hold,
            portion,
            private_intent,
            version,
            Transition::PrepareFill,
            &command,
        );
        self.apply(op, command).await;
        self.observed(auth.decision)
    }
    pub async fn accepted(&self, hold: Id) {
        let target = self
            .authorize(
                (hold, [0; 32]),
                Transition::CommitEpoch,
                3,
                [62; 32],
                [64; 32].to_vec(),
                [63; 32],
            )
            .await;
        let epoch = target.facts.decision.operation.entity;
        let command = LedgerCommand::ObserveEpoch { target };
        let version = self
            .ledger
            .entity_version(self.policy.domain.pair, epoch, [0; 32])
            .await
            .unwrap();
        let op = self.operation(
            epoch,
            [0; 32],
            [61; 32],
            version,
            Transition::CommitEpoch,
            &command,
        );
        self.apply(op, command).await;
    }
    pub async fn allocated(&self, hold: Id) -> AllocationPlan {
        self.accepted(hold).await;
        let mut plan = AllocationPlan {
            hold,
            allocation: [64; 32],
            portions: vec![
                PortionSpec {
                    portion: [65; 32],
                    offset: 0,
                    amount: 25,
                    kind: AllocationKind::SellerLiability,
                    native_recipient: [66; 43],
                    spl_recipient: [67; 32],
                    target_base_offset: 0,
                    target_base_amount: 5,
                    fill_fence: [72; 32],
                },
                PortionSpec {
                    portion: [68; 32],
                    offset: 25,
                    amount: 9,
                    kind: AllocationKind::BuyerUnused,
                    native_recipient: [40; 43],
                    spl_recipient: [28; 32],
                    target_base_offset: 5,
                    target_base_amount: 2,
                    fill_fence: [0; 32],
                },
            ],
            chunks: vec![],
        };
        for p in &plan.portions {
            let mut payload = p.portion.to_vec();
            payload.extend_from_slice(&p.target_base_offset.to_le_bytes());
            payload.extend_from_slice(&p.target_base_amount.to_le_bytes());
            payload.push(p.kind as u8);
            payload.extend_from_slice(&plan.allocation);
            let auth = self.authorization(
                (hold, p.portion),
                Transition::RecordAllocation,
                2,
                [70; 32],
                payload,
                [0; 32],
            );
            plan.chunks.push(auth.decision.operation.effects);
        }
        let command = LedgerCommand::PrepareAllocation(plan.clone());
        let version = self
            .ledger
            .hold(self.policy.domain.pair, hold)
            .await
            .unwrap()
            .version;
        let op = self.operation(
            hold,
            [0; 32],
            [69; 32],
            version,
            Transition::RecordAllocation,
            &command,
        );
        self.apply(op, command).await;
        plan
    }
    pub async fn chunk(&self, plan: &AllocationPlan, index: u32, _version: u64) {
        let p = plan.portions[index as usize];
        let mut payload = p.portion.to_vec();
        payload.extend_from_slice(&p.target_base_offset.to_le_bytes());
        payload.extend_from_slice(&p.target_base_amount.to_le_bytes());
        payload.push(p.kind as u8);
        payload.extend_from_slice(&plan.allocation);
        let target = self
            .authorize(
                (plan.hold, p.portion),
                Transition::RecordAllocation,
                2 + u64::from(index),
                [80 + index as u8; 32],
                payload,
                [84 + index as u8; 32],
            )
            .await;
        let command = LedgerCommand::RecordAllocationChunk {
            hold: plan.hold,
            allocation: plan.allocation,
            index,
            digest: plan.chunks[index as usize],
            target,
        };
        let version = self
            .ledger
            .hold(self.policy.domain.pair, plan.hold)
            .await
            .unwrap()
            .version;
        let op = self.operation(
            plan.hold,
            [0; 32],
            [82 + index as u8; 32],
            version,
            Transition::RecordAllocation,
            &command,
        );
        self.apply(op, command).await;
    }
    pub async fn activate(&self, plan: &AllocationPlan, _version: u64) {
        let mut payload = plan.allocation.to_vec();
        payload.extend_from_slice(&[73; 32]);
        let target = self
            .authorize(
                (plan.hold, [0; 32]),
                Transition::ActivateAllocation,
                6,
                [85; 32],
                payload,
                [86; 32],
            )
            .await;
        let epoch = target.facts.decision.operation.entity;
        let command = LedgerCommand::ActivateAllocation { target };
        let version = self
            .ledger
            .entity_version(self.policy.domain.pair, epoch, [0; 32])
            .await
            .unwrap();
        let op = self.operation(
            epoch,
            [0; 32],
            [87; 32],
            version,
            Transition::ActivateAllocation,
            &command,
        );
        self.apply(op, command).await;
    }
    pub async fn active(&self) -> (Id, Id, AllocationPlan) {
        let (credit, hold) = self.held().await;
        let plan = self.allocated(hold).await;
        self.chunk(&plan, 0, 3).await;
        self.chunk(&plan, 1, 4).await;
        self.activate(&plan, 5).await;
        (credit, hold, plan)
    }
    pub async fn refund(
        &self,
        hold: Id,
        portion: Id,
        note: Id,
        tag: u8,
    ) -> (Operation, LedgerCommand) {
        let command = LedgerCommand::PrepareNative(NativePlan {
            hold,
            portion,
            kind: NativeIntentKind::BuyerRefund,
            recipient: [40; 43],
            amount: 9,
            inventory_scope: self.policy.inventory_scope,
            inputs: vec![note],
            fee_inputs: vec![],
            change: vec![ChangeOutput {
                note: [tag + 1; 32],
                action_index: 1,
                note_commitment: [tag + 6; 32],
                nullifier: [tag + 7; 32],
                receiver: self.policy.receiver,
                value: 25,
            }],
            fee: 0,
            nonce: [tag + 2; 32],
            pczt_digest: [tag + 3; 32],
            sighash: [tag + 4; 32],
            transaction: [tag + 5; 32],
        });
        let version = self
            .ledger
            .entity_version(self.policy.domain.pair, hold, portion)
            .await
            .unwrap();
        let op = self.operation(
            hold,
            portion,
            [tag; 32],
            version,
            Transition::PrepareNative,
            &command,
        );
        (op, command)
    }
    pub async fn reconcile(&self, ledger: &Ledger) -> RecoveryState {
        let challenge = ledger
            .begin_reconciliation(self.policy.domain.pair)
            .await
            .unwrap();
        let mut retained = Vec::new();
        for (replica, key) in self.replicas.iter().zip(&self.keys) {
            retained.push(replica.retained_head(&challenge, key).await.unwrap());
        }
        ledger.reconcile_heads(&challenge, &retained).await.unwrap()
    }
    pub async fn remove(self) {
        self.ledger.close().await;
        for replica in &self.replicas {
            replica.close().await;
        }
        self.db.remove().await;
        for db in self.replica_dbs {
            db.remove().await;
        }
    }
}
