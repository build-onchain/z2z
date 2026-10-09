# Kerb independent safety cores — implementation design

Status: written spec approved in this conversation; implementation plan approved for subagent-driven execution. User authorized progressing with independent safety cores while retaining the full strict-private native Solana↔Ironwood end goal. No complete funded protocol or privacy solution is claimed. This spec is not deployment/signing/funding authorization.

## 1. Intent, decisions and full objective

Build real reusable safety modules for every reachable independent part of Kerb, rather than an empty project frame or a plaintext simulator mislabeled MPC. The current conversation retains strict matcher content/accepted-identity noninference, allows auction/output redesign, and subsequently approves independent safety-core implementation first after output-level incompatibility analysis.

Full objective remains all core/major Kerb modules: source acquisition and claimant/inventory credit checks; canonical authorization/units; holds/epoch/entitlement accounting; actual FAA/MPC matching; Solana escrow/fences; native threshold custody/payment effects/recovery; coordinator/clients and actual integration. Strict-private auction feasibility is unresolved, not waived or silently replaced with the historical public-Solana auction.

This implementation increment delivers protocol/safety rules, persistent journals/inventory reservations, local compiled Solana escrow/transitions, native custody effect-checking and a runnable reconciliation runtime. It does not substitute these for the full objective. Actual acquisition, FAA/Arcis/Cerberus, FROST transaction authoring/signing and the strict-private mechanism remain explicitly separate requirements where this increment cannot exercise them.

User-facing/private funded enablement stays absent until an achievable approved mechanism and all relevant release gates exist. No fake scanner, MPC backend, signer or verified-funding constructor is permitted.

Sources: [current authority](../../../00-CANONICAL.md#0-current-documentation-authority), [Oct1 accounting/custody candidate](2026-10-01-kerb-production-demo-design.md), [review](2026-10-01-kerb-design-review.md), [strict-privacy feasibility record](../../../reviews/2026-10-02-strict-privacy-feasibility.md).

## 2. Smallest fitting software shape

One Kerb Rust host workspace and an independently built Solana target workspace. No empty future packages. Browser/client work follows real operations rather than a placeholder UI. Postgres retains the candidate's persistence choice; SQLite is not substituted for its concurrency/transaction requirements. Docker may host local disposable Postgres for integration verification, with no deployment or credentials publication.

| Module/package | Consumes → produces | Authority/build fence |
|---|---|---|
| `crates/protocol` / `kerb-protocol` | Explicit deployment/pair/epoch/rules/roster context; bounded amounts and records → canonical signing bytes, checked economic arithmetic, exact typed transition decisions | Target-safe Rust. No I/O, spend keys, generic verified flag, source-history proof or auction success claim. |
| `crates/ledger` / `kerb-ledger` | Authenticated application decisions and observed source/native/target facts under explicit policy → durable credits, holds, liabilities, inventory locks, intent history and reconciliation states | Postgres host module. Scanner/history/claimant evidence producer remains separate; database alone does not establish chain truth or solvency. |
| `crates/custody` / `kerb-custody` | Native PCZT + pinned network/pool/recipient/change/fee/expiry policy + exact durable intent → independently computed effects/sighash and rejection/approval-for-signing decision | Maintained upstream native parsing/sighash, not custom note/FROST crypto. No automatic signing, keys, proof generation, broadcast or claim that a signature is payout. |
| `crates/runtime` / `kerb-runtime` | Ledger decisions, acknowledgement protocol and exact stored operations → runnable coordinator/replica/inspection/reconciliation operations | Host. Real persistence/validation behavior; no placeholder source/MPC/native network adapters. |
| `contracts/solana` | Canonical domain plus actual signer/native-precompile authorization and real legacy-SPL state → checked escrow, epoch/portion fences and atomic transfers | Independent target build; target-safe protocol only. No host SQL/node/prover dependencies or private on-chain secrets. |

Dependency direction: protocol has no sibling dependencies; ledger and custody depend on protocol, not runtime; runtime composes them. Solana uses only target-safe protocol/chain dependencies. Arcis compiler target will be separate when a viable matching contract exists. Zoss stays externally owned and concurrently edited; inspect real exported APIs before importing common encoding/acquisition/client operations. Its receipt-specific context/auth must not become a Kerb monetary domain. Do not edit sibling code or duplicate its scanner/RPC integration.

## 3. Canonical records and authorization

Versioned fixed integer/domain encoding is explicit, deterministic and independent of Rust enum/struct memory layout. Raw amounts are `u64`; products and sums use checked `u128` with checked transfer conversion. Zero/invalid lot sizes, overflow, mixed pair/network/token-program contexts and unrecognized versions fail before mutation.

`Domain` binds exact schema, Solana genesis/program, synthetic mint and legacy token program, Zcash network/NU6.3 branch/Ironwood pool/receiver policy, pair, epoch, rules hash and roster version. Pair scopes never share credit/control keys/inventory. Testnet versus mainnet and ordinary Ed25519 versus Arcis SHA3-512 versus native spend roles cannot alias.

`EntityVersion` and `OperationId` bind deployment/pair/epoch/stable entity/portion/intent identifier, monotonic generation, prior version and transition. IDs and terminal markers survive rotation and ordinary account cleanup; no ABA or per-hold generation collision. Encoding includes lengths/tags and rejects noncanonical/trailing data. Avoid allocating when fixed arrays suffice.

Protocol records include FundingClaim, AdmissionHold, EpochDecision, AllocationPartition, FillIntent, NativeIntentKind::{SellerPayout,BuyerRefund,SponsorFee}, acknowledgement predecessor/next-head/effects and chain-operation identity. Signed records bind exact bytes, not a client-supplied opaque digest. These are authorization/data records, not fabricated consensus/history/MPC facts.

Auction is not implemented from the failing Oct1 contract as an approved private mechanism. Checked notional, allocation-limit/conservation verification and intent predicates are independent safety behavior, not a renamed auction.

## 4. Credits, holds, liabilities and inventory

A source funding credit is unique by `(network,pool,txid,action_index)` and claimant-bound credit intent, with block eligibility separate from stable occurrence. Exact source receiver/value, claimant authorization, canonical history policy and controlled unallocated spendable inventory must agree. Changed blocks/re-inclusion/restart/copied memo never issue a second credit. Unclaimed/gapped/reorged/unknown observations remain quarantined. Change is backing existing liabilities, never a new deposit credit.

The ledger consumes validated observations from an explicit producer contract; it does not contain a permissive RPC-success→credit method. This increment implements verification/dedup/authorization against concrete structured evidence and owns resulting state. Real source adapter is a later integration criterion; fixture observations must be labeled local inputs, not validated chain evidence.

Buyer credit partitions disjointly into available, prepared, epoch-encumbered, seller-payout-outstanding, buyer-unused-outstanding, final-payout and final-refund. Seller quantities have corresponding prepared/encumbered/filled/final-unused/released/returned partitions. Each portion can have one competing live disposition; distinct portions can progress independently.

Prepare holds full maximum buyer debit/seller quantity. Delay, expiry, zero fill reservations, missing message, restart or unknown commit does not free it. Exclusion/abort requires a canonical irreversible disposition; finalized allocation requires complete authenticated chunks plus unanimous same allocation and fully activated journal before unused refund or first-leg release. No MPI/MPC authenticity is inferred merely because a caller supplies a result digest.

Physical inventory is separate: controlled spendable notes, exclusively locked inputs, provisional recipient effects, provisional change and confirmed usable change. Canonical input consumption replaces input backing with exact attributed recipient/change once; neither original input+change nor pending recipient+available credit is counted twice. Pending recipient backs only its own liability. Fee sponsor inventory is isolated. Impairment stops new activation/sends; it preserves outstanding claims rather than paying first claimants or inventing restitution.

## 5. Persistent fencing and acknowledgement protocol

One active fenced writer per pair uses serializable transactions, generation/version CAS and unique business intents. A journal entry binds predecessor head/hash, writer generation, exact entity/portion prior/next versions and immutable effects. Retries must match stored bytes exactly; same ID/different decision is conflict, not an update.

Three acknowledgement replicas persist the exact decision before emitting their ordinary Ed25519 business acknowledgement. Replicas each have an independently retained store/key capability; local verification uses three isolated stores/processes with generated test-only keys and explicitly labels control independence simulated. Every policy transition requiring unanimity verifies all three distinct enrolled keys and the same decision. Missing acknowledgement, stale writer, mismatched predecessor or equivocation halts. 2-of-3 native spend signatures are separate and do not supply business consensus.

Non-rollback protection compares externally retained replica heads/intent tombstones and actual canonical transitions. A restored old coordinator database cannot resume while acknowledgement stores retain newer heads; restore of all copies with no independently retained anchor is unverifiable and must halt, not claim rollback detection. Cryptographic hashes inside one rolled-back database alone are insufficient. Signer nonce consumed/tombstoned before handoff; ambiguous or potentially live signed operations remain locked.

Atomic DB+chain commit is not claimed. Prepared intent → submitted/unknown → exact chain observation → apply/reconcile is explicit. Lost response never turns into failed/no-effect automatically. Finalized incompatible histories become Disputed; timeout never proves absence.

## 6. Real local Solana safety program

First target is exact synthetic legacy SPL mint with disclosed mint/freeze authorities in a local compiled-program environment. No real network funds, deployments or keys are required for local fixture transactions. Contract state is public; this surface is not offered as a strict-private collateral solution.

Implement actual program-owned config/epoch/hold/fill/portion accounts and PDA-controlled escrow. Pin genesis/program/pair/mint/token/context and verify account owner/discriminator/PDA/bump, signer/writable constraints, canonical recipient and exact token program. Initialize under named authority; refuse reinitialization/alias/substitution. Only enrolled domain authorizers can sign joint business decisions; use real native Ed25519 precompile instructions plus exact instruction-sysvar offsets/key/message checks when authorizers are not transaction signers. No generic callback/CPI target.

Instructions cover initialize pair/epoch, lock and prepare seller collateral, commit/abort immutable epoch decisions, record authenticated-authority allocation and activation fences, prepare/release/cancel exact fills, return excluded/final-unused collateral and inspect reconciliation state. A recorded allocation is trusted authority testimony, not validated MPC computation. Dedicated validation verifies amounts, partitions and prior versions; caller-provided signatures cannot change immutable recipients or unencumber accepted portions by timeout.

`release_spl` and `cancel_fill` consume the same monotonic fill disposition. Release requires matching activated allocation, exact first-leg preparation fence and authorized recipient/amount. Cancel requires approved cancel decision and unreleased state; only one can commit. Filled native entitlement return additionally requires custody journal evidence—Solana alone cannot prove no Ironwood spend.

Real `transfer_checked` CPI occurs before marking the portion paid; any unexpected CPI failure rolls back balances/state. Frozen/unavailable token transfer preserves entitlement and reports actionable error; no successful payout from a no-op. No arbitrary admin sweep, fund confiscation or account closure resetting consumption. Local tests exercise mutate-before-CPI failure and verify full rollback.

## 7. Custody effect checks and native intents

Use compatible maintained native Ironwood/v6 PCZT libraries, pinned by actual dependency compilation, to inspect the transaction—not fabricated effects constructed from a coordinator hash. Independently recompute correct shielded sighash and validate exact pool/network, every recipient/nonzero output/change, amount/fees, expiry and authorized input inventory. Unsupported branch, hidden/missing metadata or incomplete proof/auth state needed for the signing role fails closed.

SellerPayout requires active seller liability and exact finalized SPLReleased recipient/atoms. BuyerRefund instead requires a disjoint final-unused/excluded/fenced-aborted/safely-cancelled portion, immutable refund destination and no competing same-portion live intent; it does not require SPL delivery. SponsorFee consumes only its own isolated operator authority/inventory.

Before any native signing handoff, persist exact intent/effects/transaction identity, nonce history and input locks with unanimous decision heads. Approval-for-signing is not a native signature, broadcast or mined payment. Threshold key setup, RedPallas/rerandomized FROST signing/proving, conformant derivation/recovery and actual recipients remain explicit later native integration obligations. Never add a software master-key bypass or dummy signer to finish this increment.

## 8. Runtime and exercised acceptance

Provide runnable CLI processes for acknowledgement replica and coordinator/storage inspection, replay/recovery and exact operation reconciliation. Configuration has mandatory explicit pair/deployment/roster/store/finality policies; no production-safe invented default values or secret dumps. Operator diagnostics contain IDs/state/reasons, not private keys, full notes/PCZT/witnesses/certificates or order↔funding maps. Secrets remain owner-provisioned; no requesting tokens/keys in chat.

Independent checks must exercise real behavior:

- Canonical rejection vectors and checked quantity/notional boundaries, wrong network/pair/scheme/domain and ID collision.
- Actual Postgres concurrency/restart: prepared/accepted max debit cannot be reused; allocation M34→seller25+unused9; partial FINAL never releases9; separate portions progress without double disposal.
- Source occurrence/re-inclusion/change dedup and inventory input→recipient/change exclusive replacement using explicit observed-fact inputs; real source acquisition remains separately labeled.
- Real separately launched acknowledgement stores/processes: missing/equivocating/stale acknowledgements halt; retained newer heads reject restored old coordinator journal; all-head loss halts.
- Native PCZT inspection/sighash and typed refund/payout predicate rejection, including refund without SPL when legally unused; no signature-output stand-in.
- Independent SBF build plus compiled local legacy-SPL transactions: owner/PDA/signature/recipient/replay substitution, issuer freeze failure/rollback, exclusion/abort/activation boundaries and cancel-versus-release mutual exclusion.
- Runnable coordinator scenario: prepare→commit observation→activation→release observation→native intent; local fixtures explicitly not MPC/history/finality proof. Unknown outcomes/restart preserve holds. No real signing/broadcast.
- Independent code/security review and fix confirmed important findings. Tests and local smoke are recorded separately from real devnet/Ironwood evidence and privacy gates.

## 9. Threat and release boundaries

| Risk | Required safety behavior/evidence |
|---|---|
| Malicious client/observation/authority context | Canonical bytes, claimant/pair/receiver/occurrence/inventory checks; unsupported or incomplete facts reject. |
| Double credit/business payment | Unique source issuance/portion intents, transactional locks, no change credit; non-rollback retained heads and live intents. |
| Split-brain/stale writer/partial result | Fencing/CAS/unanimity, complete activated result, canonical observed state; uncertainty holds/halt. |
| Signer policy bypass/nonce reset | Independent real PCZT effects, typed predicates, persisted history; corrupt spend threshold remains theft risk. |
| Account/token/CPI substitution | Exact owners/mints/PDAs/recipients/native authorization; real compiled failure leaves balances/state unchanged. |
| Public and own-result leakage | Unresolved strict-private mechanism; no funded-private enablement or privacy claim from these safety checks. |
| Missing independent operators/external action | Local independence labelled simulated; exact deployment/signing/funding permissions and real rosters remain requirements. |

Safety-core completion requires every behavior in this increment exercised with actual artifacts and documented build/run commands. It does not complete the user’s all-core goal. No core Zoss or Kerb GD gates are fabricated from local verification. Original funded obligations must keep usable evidence/rules/private witness/recovery support until actual terminal; no message/library upgrade erases them.

## 10. Approval and subsequent handoff

User reviews this written spec before the detailed implementation plan. Plan must enumerate actual APIs/files and testable behavior for each independent slice, preserve all full-objective outstanding requirements and identify dependency/action prerequisites. User then reviews the plan and selects execution method. Only after those approvals may product code/dependencies be added.

No Git initialization, worktree, commit or push is assumed: the inspected workspace is not a Git repository and none is authorized. Do not overwrite concurrent user changes. This document changes no historical financial authority and is not a copied blocker register.
