# Kerb Independent Safety Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development or executing-plans according to the user's execution selection. Steps use checkbox tracking. No commits/pushes, deployment, real-key signing, broadcasts or funds without exact permission.

**Goal:** Implement and exercise all independent safety-core behavior in the approved spec; keep the full strict-private native Solana↔Ironwood objective active, including its unresolved mechanism.

**Architecture:** Target-safe Rust protocol below a real Postgres ledger/replica journals and native PCZT custody inspection; runtime composes processes. Independent Solana escrow performs real legacy-SPL transfers and monotonic transition fences, loaded as compiled ELF locally. No fake scanner/MPC/signer or private-release claim.

**Tech Stack:** Rust1.98.1 host; ordinary Ed25519/SHA256; SQLx0.8.6/Tokio/Postgres16.15 Unix socket; maintained PCZT0.9.3/Ironwood cohort; solana-program3.0/spl-token-interface2.0; LiteSVM0.10/precompiles; cargo-build-sbf4.4/platform1.57/SBFv0. Actual resolved locks/compiled execution establish compatibility. SQLx0.9 was rejected after observed Cargo conflict between its digest0.11/crypto-common0.2-stable requirement and native primitives0.30.1's exact0.2-rc pin; no native cryptographic dependency was patched.

**Spec:** [approved written specification](../specs/2026-10-02-kerb-safety-core-design.md), approved in this conversation. This plan is approved for subagent-driven execution; no external chain actions are authorized.

## Global constraints

- Entire core objective remains; strict privacy retained. Auction/FAA/MPC and private funded enablement unresolved, not replaced with historical auction or no-trade system.
- Raw u64 amounts; checked u128 products/sums; no floats, signed narrowing, shared-pair inventory or receipt-funded credit.
- Wallet/Solana/business ordinary Ed25519, Arcis SHA3-512 and native FROST roles remain distinct. No custom crypto or fake backend.
- Prepared/accepted full buyer debit and seller quantity held through delay/expiry/restart/unknown result. Exact allocation activation and disjoint portions govern return.
- SERIALIZABLE DB transactions, one fenced writer, CAS/unique intents and three distinct durable unanimous business acknowledgements. This is not BFT or native spend quorum.
- Exact native intents/effects/input locks/nonce history durable before signing handoff. Unknown effects held; all retained heads missing halts.
- Independent target-safe Solana build; real SPL CPI/native precompile/instruction sysvar; no Rust processor substituted for ELF.
- Local generated noncustodial fixture signatures only; never request/print keys. VM finality/control independence explicitly LocalFixture/simulated; no automatic network mutation.
- Zoss is externally owned/concurrently edited: inspect actual compatible exports before reuse, do not edit or duplicate shared scanner/client work; receipt-specific domains never money domains.

## Review focus

1. Full u64 values exceed SQL BIGINT: persist canonical integer NUMERIC, test max-u64 and reject negative/overflow values.
2. Partial FINAL or lost response must not free unused debit or release first leg; immutable-operation replay required.
3. Restored coordinator/retained newer replicas detect rollback; all heads lost halts rather than inventing monotonicity.
4. Actual CPI failure, prefunded/aliased accounts and cancel-vs-late-release preserve exact token/contract state.
5. PCZT output metadata may be missing/inconsistent; verify against native effects, not opaque hash or strings; network is explicit policy context.

## Ownership, files and interfaces

Parent owns root Cargo.toml/Cargo.lock/.gitignore and shared interface changes. Create packages alongside their first exercised behavior, not empty inventory.

- `crates/protocol`: Cargo.toml; src/{lib,domain,records,policy}.rs; tests/contracts.rs.
- `crates/ledger`: Cargo.toml; migrations/0001_safety.sql; src/{lib,credit,journal,inventory,replica}.rs; tests/{postgres,replicas}.rs.
- `crates/custody`: Cargo.toml; src/{lib,pczt}.rs; tests/pczt_effects.rs.
- `crates/runtime`: Cargo.toml; src/{lib,main,coordinator}.rs; tests/{local_flow,solana_safety}.rs.
- `contracts/solana`: independent Cargo.toml/Cargo.lock; program/Cargo.toml; program/src/{lib,state,instruction,authorization}.rs.

Dependency direction: protocol has no sibling I/O; ledger/custody depend on protocol; runtime composes; Solana only target-safe protocol. No browser scaffold, SDK, generic event bus or proof engine.

Shared signatures; parent approves changes:

- `Id=[u8;32]`; explicit `Domain` deployment/genesis/program/pair/mint/token/source-network/pool/branch/receiver-policy/epoch/rules/roster/version. Canonical LE tagged encoding into caller buffer; host wrapper returns bytes, target no avoidable allocation.
- `Operation {domain,entity,portion,intent,generation,prior_version,transition,effects}`; `id()`, `digest()`, `signing_bytes()` bind all fields. `Decision {operation,predecessor,next_head}`; `Acknowledgement {signer,signature,decision}`; host `verify_unanimous(decision,acks,roster:&[[u8;32];3])`.
- `Units {base_atoms_per_lot,quote_atoms_per_lot_tick}`; `notional(lots:u64,ticks:u64,units:Units)->Result<u64,ProtocolError>`; `AllocationPartition::validate(max_debit:u64)` checks exact sum and unique portions.
- `NativeIntentKind::{SellerPayout,BuyerRefund,SponsorFee}`; explicit legal `Disposition` states. Typed evidence checks, never generic verified boolean.
- `FundingClaim` holds domain/occurrence/claimant/receiver/value/block-policy/inventory-note/evidence-digest/auth. Data/evidence only; validated producer/policy required, local fixture is not source proof.
- `ChainObservation {environment:LocalFixture|Network,operation,transaction,slot,commitment,effects}`; no fixture→network-finality constructor.
- Async `Ledger::connect(DatabaseConfig)`, `migrate`, operations below return stored state or typed conflict/halt. All state mutations bind exact operation/generation/prior-version.
- `Replica::acknowledge(decision:&Decision,signer:&SigningKey)` persists exact predecessor/decision before signature export. Signer caller-owned.
- `inspect_pczt(bytes:&[u8],expected:&NativeSpendPolicy)->Result<CheckedNativeEffects,CustodyError>` computes real native effects/sighash. Private checked fields/accessors; not signing/payment.

### Task 1: Canonical protocol and checked safety rules

**Files:** root workspace and protocol files above.
**Consumes:** approved domain/units/typed transition contract.
**Produces:** shared records/codecs, checked arithmetic/policy, target-safe default and host ordinary Ed25519 verification.

- [x] Write first behavior tests: independently constructed canonical domain bytes; entity/portion/prior-version/role mutations alter authorization; same generation/different entity distinct ID; zero units and overflow reject;34=25+9 valid but overlapping/over34 allocation fails; legal unused BuyerRefund without SPL versus SellerPayout requiring exact SPL evidence.
- [x] Minimal manifest/test setup, run `cargo test -p kerb-protocol --all-features --test contracts` and observe missing/incorrect behavior. Setup alone not deliverable.
- [x] Implement bounded canonical codec/records/checked rules using maintained SHA256/strict Ed25519. Distinct algorithm/role preimages; no Arcis/FROST substitute or invented auction.
- [x] Parent runs focused test, independent-vector scenario and `cargo check -p kerb-protocol --no-default-features`; observe exact outputs. Fifteen contracts passed; independent smoke observed partition and authorization rejection. Native target backend additionally exercised by actual compiled ELF key/R/S cases; target review remains separate.

### Task 2: Real Postgres credit, holds and physical inventory

**Files:** ledger lib/credit/inventory/migration/tests/postgres.rs.
**Consumes:** Task1 domain/claim/operation/partition.
**Produces:** async credit/hold/inventory APIs and immutable ledger commands, including shared target-only `ObserveEpoch { target }` and `ActivateAllocation { target }` with epoch-PDA CAS; no obsolete per-hold observation/activation aliases.

- [x] Provisioned NEW user-owned PostgreSQL **16.15** extraction and separate coordinator/replica databases with peer-only socket and durable settings. Actual server version is16.15; a temporary directory name containing16 does not establish another version.
- [x] Pinned SQLx **=0.8.6** postgres/runtime-tokio/migrate; SERIALIZABLE transactions, canonical decimal NUMERIC u64 storage and exact-length byte domains; no signed narrowing or patched native crypto dependencies.
- [x] Real DB RED/GREEN exercised conflicting prepares against34, occurrence/reinclusion uniqueness, claimant/receiver/pair rejection, physical input/change conservation and max-u64 roundtrip.
- [x] Implemented constraints/unique issuance/CAS/fence, exclusive reservations and immutable retries; whole DB serialization/deadlock retries never repeat signing/send effects. Seven migrations0001–0007 retain safety, target authorization/state/lifecycle, native conflicts, shared terminal epochs and shared allocation results.
- [x] Parent exercised concurrent transactions/restart, held34 through uncertainty/partial evidence, complete25/9 activation, disjoint unused refund and impairment. Final45 ledger cases passed (artifact275); fixture testimony is not source/MPC proof.

### Task 3: Unanimous durable replicas and rollback fences

**Files:** ledger journal/replica/tests/replicas.rs; runtime replica CLI with real behavior.
**Consumes:** Task1 Decision/Acknowledgement; Task2 separate persisted databases.
**Produces:** `prepare_decision`, `Replica::acknowledge`, `commit_decision`, `reconcile_heads`, intent/nonce tombstone operations.

- [x] Real RED/GREEN covers distinct exact3/3 acknowledgements, duplicate/stale/wrong predecessor/equivocation rejection, immutable effects and pre-export nonce/intent persistence.
- [x] Append-only decisions/heads/tombstones, writer generation and exact resumed bytes implemented; three local fixture signers/stores simulate, not establish, independent control.
- [x] Three real replica processes with isolated databases use bounded canonical framing and replay economic validation/reservation before persisting and exporting signatures.
- [x] Parent exercised lost acknowledgements/crash/restart, stale coordinator restore, exact mixed-head recovery and missing-head halt without releasing potentially live effects/input locks or resetting history.

### Task 4: Compiled Solana escrow and monotonic transition fences

**Files:** independent contracts/solana/program modules; runtime/tests/solana_safety.rs.
**Consumes:** target-safe protocol and exact three-authorizer decisions plus actual legacy-SPL accounts.
**Produces:** `Instruction::{InitializePair,OpenEpoch,LockSeller,PrepareSeller,CommitEpoch,AbortEpoch,RecordAllocation,ActivateAllocation,PrepareFill,ReleaseSpl,CancelFill,ReturnUnused}` and builders/decoded state shared with runtime. RecordAllocation is trusted authority testimony, not a verified MPC output.

- [x] Compiled-program cases cover initialized SPL accounts, authorization/domain/account rejection, persistent accepted holds, partial activation, mutually exclusive cancel/release and business replay with fresh blockhash.
- [x] Exact program-owned layouts/markers/PDA bounds and strict account types implemented; actual legacy transfer_checked uses escrow PDA, with paid marker after successful transfer and unchanged balances on rejection.
- [x] Three distinct enrolled keys authorize exact messages through actual Ed25519 precompiles and instruction sysvar; canonical self-contained layout enforced, with offset/order/duplicate/substitution rejection and no precompile CPI.
- [x] Independent pinned Solana3.0/spl-token-interface2.0 target and LiteSVM0.10 harness built using cargo-build-sbf4.4/platform1.57/SBFv0; target Clippy/format checks passed.
- [x] Parent loaded exact ELF with bundled actual SPL Token ELF, not a processor callback. Independent SBF plus18 target ELF/interface tests passed (artifact280), including frozen-account CPI rollback. Final ELF hash and actual CLI observations recorded below; VM success is not network finality/privacy.

### Task 5: Native PCZT effect/sighash gate and typed intents

**Files:** custody manifest/lib/pczt/tests/pczt_effects.rs.
**Consumes:** real native PCZT bytes, Task1 typed intent/policy, Task2/3 live liability/fences.
**Produces:** `inspect_pczt` checked effects/sighash, `authorize_native_intent(intent,liability,effects,acks)` approval-for-signing only.

- [x] Pin pczt0.9.3 (`std,signer`; dev `zcp-builder`), primitives0.30.1/protocol0.10.5/orchard0.15.5/encryption0.4.2 after actual compiler resolution. Parse/resolve fields; reject non-v6/wrong group/branch or nonempty other pools. `Verifier::with_ironwood` exposes parsed metadata but does NOT automatically verify it: call `verify_cross_address_restriction`, every action `verify_cv_net`, spend `verify_nullifier(Some(expected_fvk))/verify_rk(Some(expected_fvk))`, and output `verify_note_commitment`.
- [x] Real unsigned fixture: attributed public test-vector FVK (no spending keys), two local V3 notes with upstream coherent tree/witnesses, two nonzero outputs, seeded RNG, real `Builder::build_for_pczt`→`Creator::build_from_parts`. No IoFinalizer (can sign dummy spends), prover, signing methods or TransactionExtractor (creates binding signatures). Exact2/2 local shape avoids dummy-spend keys; retain builder action mapping, not insertion order. Wrong input/receiver/value/change/fee/expiry, redaction, extra output and ciphertext tamper reject.
- [x] Reconstruct every nonzero output's native Note and use `IronwoodDomain::for_pczt_action` plus upstream `try_output_recovery_with_pkd_esk` to verify ciphertext/receiver/value, including change. Match exact reserved nonzero input nullifier/note/value/FVK set and complete output multiset; compute actual fee from all values/value balance. Real source occurrence is mapped from independent inventory facts, not a shielded outpoint field or proprietary assertion. Explicit network/genesis context cannot be inferred from branch/receiver bytes alone.
- [x] Consume checked PCZT through `into_effects` and independently compute TxIdDigester/to_txid/v6_signature_hash; compare a fixture reference with `Signer::new/shielded_sighash` without any signatures. Bind exact input PCZT byte digest separately: v6 txid/sighash excludes anchor and doesn't hash all metadata. UnsignedEffectsChecked is not fully proved/broadcast-ready; accept legitimate deferred-anchor unsigned state for inspection, fail closed on missing policy-required metadata. No source-spendability/network/consensus assurance.
- [x] Typed SellerPayout active-liability/SPLFinal, disjoint BuyerRefund without SPL prerequisite and isolated SponsorFee checks implemented; inspected effects/intents/nonce tombstones persist before any later native handoff. Runtime additionally binds each inspected input value and user/sponsor scope before reservation or acknowledgement export.
- [x] Parent runs real PCZT parse/metadata/sighash scenario and custody rejection checks. Ten behavior tests passed after a reproduced disabled-spend/output-flag consistency defect was fixed; independent scoped review passed. Actual CLI inspected restricted synthetic native bytes and rejected substitutions. No FROST/native payout/consensus pass from inspection.

### Task 6: Runnable coordinator and exact observation reconciliation

**Files:** runtime lib/main/coordinator/tests/local_flow.rs; necessary native Solana observation client only when concrete operation justifies reuse.
**Consumes:** Tasks1–5 actual APIs; exact canonical local execution/network facts with explicit environment and policy.
**Produces:** CLI `migrate`, `replica`, `inspect-pczt`, `inspect-ledger`, `reconcile`, `local-safety-scenario`; commands require explicit config paths and cannot sign/send/deploy by default.

- [x] Real DB34→unanimous epoch decision→canonical fixture commit→quote25/9→complete authenticated chunks→global activation exercised; partial evidence retains backing, actual SPL release enables typed PCZT inspection only, not native send.
- [x] Persistent prepared/stored identity→Unknown/observed→apply implemented; lost/mismatched response or deadline never implies absence, and restart retains identical operation/context/body/backing.
- [x] Actual separately launched replica stores/processes, compiled ELF and custody inspection integrated; fixture producers are not real scanner/MPC/native signer or private funded operation.
- [x] Parent launched current non-test CLI and independently inspected SQL/balances/heads; crash/restart/reconciliation and configuration/environment rejection exercised. Diagnostics disclose states/reasons without secrets or native note/PCZT/witness dumps.

### Task 7: Whole safety-increment evidence and full-goal accounting

**Files:** affected existing docs/README and behavior commands beside implementation; no copied readiness register.

- [x] Parent final host suite passed81 tests (artifact278); host/target lint, format, SBF18 and no-default checks passed. Separately exercised actual PostgreSQL16.15 stop/start in the same owned data directory using `examples/postgres_restart.rs`: exact Unknown intent/reservations/tombstones and three retained heads survived; signed PendingRetained reconciliation committed the same stored decision. Earlier pool-reopen checks alone did not satisfy this gate.
- [x] Fresh independent reviews covered authorization, conservation, input/change exclusivity, rollback boundaries, custody metadata and target privilege/replay/CPI. Confirmed findings were reproduced and fixed; scoped native/runtime/epoch clearances and final four-P1 re-review returned findings=[] (confidence0.97), bounded to this increment.
- [x] Existing behavior/commands/docs updated from observed evidence, retaining public runnable native fixtures and historical source prerequisites. Parent owns cleanup evidence; no Git actions or copied external readiness register.
- [ ] Physical-note substitution cutover is verified (99 tests, lint/format, actual identity-preserving PostgreSQL stop/start and separate CLI/SQL); acceptance remains open for newly reported finalized-overlap, sponsor impairment and cancelled refund-before-SPL-return defects. These are separate consumer paths, not a physical-identity or privacy waiver. Broader full-goal prerequisites remain outstanding.

## Local persistence setup and evidence limits

Historical provisioning prerequisite (before implementation): Docker diagnostic failed at missing Desktop socket; no postgres/initdb/psql was then on PATH. Configured apt indexes supplied PostgreSQL16.15-0ubuntu0.24.04.1; libicu74 was installed and libllvm17t64 required extraction. Parent subsequently provisioned and exercised actual PostgreSQL16.15; the original user-owned, no-system-service procedure remains:

1. New owned temp/cache directory0700; apt download postgresql16/client16/libllvm17t64; dpkg-deb extract, ldd missing deps only.
2. `initdb -D OWNED/data -L EXTRACTED/usr/share/postgresql/16 --locale=C --encoding=UTF8 --auth-local=peer --auth-host=reject`.
3. `pg_ctl -D OWNED/data -l OWNED/postgres.log -o "-k OWNED/socket -p55432 -c listen_addresses='' -c unix_socket_permissions=0700" -w start`; distinct databases coordinator/ack0/ack1/ack2.
4. Use PgConnectOptions.socket/port/username(currentOS user)/database; no token/password output. Explicit pool limit/timeout; close all pools before clean pg_ctl stop. Keep fsync on. Remove only own disposable directory after proof/stop.

Local source/target/storage fixtures demonstrate safety behavior, not source-history validity, actual distributed Cerberus, independent operator custody, network finalized decisions or strict-private protocol viability. Future external chain actions need explicit summary/simulation/signing approval and owner-provisioned capabilities.

## Execution result — 2026-10-02

The approved **independent safety increment**, not the full goal or a funded/private release, has observed execution evidence: final host81PASS (artifact278); independent SBF and18 ELF/interfacePASS plus target Clippy/format and no-default protocolPASS (artifact280); host all-targets/all-features Clippy-D warnings and formatPASS. Final exercised ELF SHA256: `ea9c2fd385dc8b50c6343f69d984f65c1b3cfc0e4163e4064e01cf1776205154`. Dependencies remain SQLx **=0.8.6** and actual PostgreSQL **16.15**.

Current non-test CLI exited0. Independent SQL retained22 journals/22 commits,2 nonce tombstones and1 terminal epoch; credit34/available0 and all three matching retained heads atsequence22. Actual local SPL buyer5/escrow2 corresponds to base7=5+2, separately from quote34=25+9. Native refund9 remains unsigned/Unknown with backing locked; native payment, real signing, native consensus, strict-private enablement and independent governance remain false.

Cleanup after final proof: the disposable PostgreSQL service had zero active verification clients, `pg_ctl -m fast -w stop` exited0, and the supervised process exited0. Only owned temporary server extraction/data and smoke configuration/native-fixture directories were removed. Public synthetic fixtures remain under `crates/runtime/tests/fixtures`; source and compiled artifacts remain in the workspace. No Git repository, commit, push or external transaction action was performed.

Shared `ObserveEpoch { target }` consumes the one canonical target CommitEpoch/AbortEpoch event at the epoch PDA and atomically classifies all bound Prepared/Locked holds; closed admission and same-row CAS alias regressions were reproduced and fixed. Shared `ActivateAllocation { target }` consumes the target receipt at global epoch CAS: every accepted hold's canonical result, complete chunks and conserved quote/base partitions are validated before signatures, then activated once globally. Seven migrations retain these boundaries, including0006 terminal epoch and0007 shared per-hold allocation results. Authenticated finalized known-input subset conflicts dispute without unlocking remaining backing. Runtime checks actual inspected per-input value **and** retained user/sponsor scope before reservation/export (RED274, focused GREEN105); ledger RED269→45-case GREEN275 and final scoped four-P1 review findings=[] establish the latest bounded fixes.

Historical source prerequisites and full-goal nonapproval remain unchanged: real source acquisition/claimant history/witness producers, FAA/private auction/MPC, native proving/FROST signing/recipient settlement, strict privacy and independently controlled operators require direct evidence and separate release approval. No network mutation, real-key signing, payment, deployment, push or full-goal completion is authorized or established. The local safety audit includes actual clean PostgreSQL server stop/start proof; no power-loss/crash recovery or broader prerequisite is waived.

### Actual PostgreSQL server restart correction

The original completion claim conflated pool reopen with server restart. The gate was reopened and an owned PostgreSQL16.15 cluster was provisioned with peer Unix sockets/no TCP and `fsync`, `synchronous_commit`, `full_page_writes` enabled. `cargo run -p kerb-ledger --example postgres_restart` retained a committed Unknown refund plus a coordinator-pending exact journal decision acknowledged in all three replica stores, then closed all pools/connections.

Negative control: sending `POSTGRES_RESTARTED` without restarting the server exited101 at the independent postmaster identity check. Actual proof: zero active harness clients, `pg_ctl -m fast -w stop`, then start the **same** data directory; postmaster PID247290→254752 and startup identity changed. Harness exited0 with `POSTGRES_RESTART_PROOF_PASSED`: input34 stayed locked; Unknown intent1, nonce tombstone1 and future-change reservation1 were unchanged; exact coordinator/replica rows and pending bytes matched. Fresh signed heads reconciled PendingRetained, the same stored decision committed sequence13→14, subsequent Current reconciliation and exact replay were idempotent. All four fixture databases were removed. Workspace all-target/all-feature Clippy-D warnings and format checks passed with the retained example; independent scoped acceptance/quality review returned findings=[] (confidence0.98).

This covers clean server stop/start persistence, not forced-crash/power-loss recovery or distributed operator independence. The manual example is deliberately outside the parallel default test suite so it cannot restart another test's server.

### Future-change inventory admission correction

`IssueCredit` and `RegisterSponsor` previously admitted a note ID already retained in `ledger_change_reservations`, allowing external inventory to collide with later native change materialization. Both authentic registration regressions failed before the fix (0/2, artifact301). Shared `validate_inventory_admission` now checks both materialized inventory and future-change reservations in the same pair-scoped transaction before admission/ACK; all three replicas independently run that validator. Authority/context and source-occurrence dedup precedence are retained, and identical stored retries remain idempotent.

Both new regressions passed, including canonical forged admission refusal by every replica, unchanged credit/heads on rejection, and exact native observation creating change25 plus refund9 conserving34 with no new credit or duplicate materialization. The full native-conflict suite passed7/7; current workspace passed83 tests with all-target/all-feature Clippy-D warnings and format checks (artifact310). Scoped review returned findings=[] (confidence0.96). A separate current CLI/SQL smoke exited0 with matching three sequence22 heads, credit34/available0, native change9 materialized then locked for Unknown refund, SPL5/escrow2 and no signing/broadcast/private enablement. No ObserveNative upsert, PK suppression, schema or authorization change was introduced.

### Authenticated physical inventory identity correction

Actual RED artifact315 showed distinct genuine equal-value/same-role notes B could adopt inventory labels A and receive native ACKs. Inventory testimony now signs structured source occurrence, commitment and nullifier; retained projections bind those exact fields. Custody's actual note verification exports checked input identity, and the coordinator compares every field plus value/role before preparation. Derived change binds real transaction/action index, reconstructed/ciphertext-checked commitment and nullifier derived with the owning viewing key; duplicate receiver/value outputs keep separate concrete indexes rather than arbitrary policy role ordering.

Append-only physical claims reserve source-network/pool/genesis-scoped occurrence, commitment and nullifier globally before ACK, independent of label, value, pair or scope. Deposit/sponsor admission and future change share that namespace. Inventory projections reference the exact immutable claim; consumption/dispute never releases it. V2 roles and 02 inventory/native/journal frames reject legacy unbound metadata. Migration0008 fails transactionally on nonempty legacy enrollment/history—no zero identities, caller-policy backfill or rewritten signed journals. Fresh re-enrollment is for synthetic stores only; existing operational data requires a separate authenticated migration.

Current physical cutover verification: full workspace99 tests passed twice (artifacts327/335); all-target/all-feature Clippy-D warnings and format passed. Genuine equal-value input and confirmed-change substitutions rejected before reservation/ACK, with correct-note positive continuation, owning-second-FVK and duplicate-output regressions. Scoped physical review returned findings=[] (confidence0.95). Separate actual CLI/SQL verified all four inventory identities match physical claims and change occurrence matches its parent transaction; native refund9 remained Unknown/locked. Migrated restart example passed actual same-data stop/start (postmaster276502→311361) with exact identity rows/claims/pending bytes preserved, fresh signed PendingRetained recovery and idempotent commit. This remains local authenticated testimony, not source-history/proving/signing/payment proof.




### Approved-increment acceptance audit

| Specification §8 requirement | Exercised implementation and evidence |
|---|---|
| Canonical domains, roles, checked units and identity collisions | `crates/protocol/tests/contracts.rs`: 15 cases; valid hold-ID/epoch-PDA alias in `crates/ledger/tests/epochs.rs`. Final host artifact278. |
| Real database concurrency, full held debit, complete allocation and disjoint liabilities | `postgres.rs`, `policy.rs`, `epochs.rs`, `lifecycle.rs`: concurrent reservation, full-u64 bounds, partial-result retention, global multi-hold commit/activation, cancellation and separate SPL/native return. Actual PostgreSQL, no skipped cases. |
| Source occurrence/change dedup and exclusive input→recipient/change replacement | `postgres.rs` and `native_conflicts.rs`: claimant/producer/history policy rejection, reinclusion/copied memo, no change credit, provisional change, exclusive future change IDs, sticky finalized/disputed history and finalized subset conflicts. Source observations are signed fixture testimony, not actual acquisition. |
| Separate retained acknowledgement processes and recovery | `replicas.rs`, runtime `local_flow.rs` and `process_liveness.rs` cover lost ACK/pool reopen, restored coordinator and retained-head fences. Separately, `examples/postgres_restart.rs` exercised actual PostgreSQL server stop/start, exact Unknown reservations/tombstones and all three retained pending heads, followed by signed reconciliation and idempotent commit. Control independence is simulated. |
| Real native effects/sighash and typed payout/refund gate | Custody `pczt_effects.rs` (10), runtime `native_binding.rs`, `native_diagnostics.rs` and `input_binding_tests.rs`: native metadata/ciphertext/multisets, exact byte identity, sponsor/user per-input value/scope, legal refund without SPL, no signing/proving/broadcast. |
| Independent compiled target, genuine token CPI and irreversible fences | Final SBF artifact280, 16 compiled-ELF plus two interface cases: actual legacy-SPL balances, account/recipient/precompile/key/R/S/offset/replay rejection, freeze-induced full rollback, abort/exclusion and cancel-versus-release. ELF hash recorded above. |
| Actual coordinator prepare→commit→activation→release→native intent and Unknown/restart | Runtime `solana_safety.rs` plus separately invoked current CLI: base7→5+2; quote34→25+9; SQL22 journals/22 commits/two tombstones/one epoch terminal, credit available0 and three matching retained heads. Native refund9 remains Unknown/locked. |
| Independent review and confirmed important corrections | Protocol/custody/target reviews; native, runtime and epoch scoped corrections; final four-P1 fix-wave review correct with findings=[] and confidence0.97. Actual RED/GREEN regressions retained; final host81 and target18 cases, lint/format/no-default checks all passed. |

Reproduction prerequisites and retained public native fixtures are documented in `docs/README.md`. No fake source/MPC/FROST/backend, network finality, independent operator or strict-private approval follows from this audit.

## Execution handoff

Recommend **subagent-driven** with parent-owned shared interface/manifests and max four workers: after protocol settles, ledger, target and custody are independent; runtime waits for real interfaces. Workers skip build/lint/tests/formatters mid-flight; parent runs test-first/verification checkpoints and final checks once edits settle. Fresh reviewers reject specific unsafe behavior. Native execution is also available if user selects it.

The user approved this independent increment and subagent-driven execution before implementation; the execution handoff above is historical workflow guidance, not a pending approval request. No commits/pushes/worktrees or external chain actions were authorized. Full objective is not redefined as this increment; its separate prerequisites remain open.
