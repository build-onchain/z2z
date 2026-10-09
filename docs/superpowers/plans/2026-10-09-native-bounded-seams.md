# Native Bounded Seams Implementation Plan

> Execution decision: owner selected B/B in this conversation: derive and implement journal and native ETH interfaces from existing docs. No further design approval loop; no deploy, signing, submission, funds, operational migration or SQL execution permission follows.

**Goal:** finish the native quote custody/journal and native ETH obligation implementations, then integrate their real callers. This is not completion of the entire product.
**Architecture:** runtime reuses the existing database/custody modules; EVM reuses NativeFinancialCodec, Allocation and the internally constructed vendored SP1 verifier. No new certificate encoding, no accepting mock, no always-reverting placeholder.
**Spec:** `docs/modules/destination-settlement.md`, approved native allocation/retry rules, roadmap R4/R5, and the implementation decisions below.

## Exact ETH interface

Constructor `(bytes32 financialProgram, bytes32 originProgram, bytes32 sourceAcceptanceProgram, bytes32 sourcePolicyId, uint16 schemaVersion, uint8 sourceNetwork)` pins nonzero program/policy identities, schema1/testnet1, actual nonzero uint64 chain ID, internally constructs the vendored SP1 verifier and pins its runtime hash. No verifier injection, admin, upgrade or expiry-based withdrawal. `deployment()` returns the NativeFinancialCodec deployment digest using actual post-construction addresses/runtime hashes and fixed program/policy pins; it is checked with the complete Statement before every mutator.

`fundAndArm(bytes rawStatement, bytes rawBoundary, bytes armProof, bytes originProof, bytes acceptanceProof) external payable` strictly decodes existing Statement and SourceBoundary; checks exact deployment/program/policy/source identities, `msg.sender == statement.payer`, `msg.value == statement.d`, and no existing statement or stable J-tag reservation. It constructs expected Arm/Origin/SourceAcceptance journal bytes itself. All three real SP1 proofs (exact356 bytes each) must verify under their fixed respective programs and identical supplied source boundary before any obligation/tag/liability is recorded. Never accepts a supplied journal or caller-selected verifier/program. Context ID is SHA256 of the full canonical statement. Reserve the stable tag permanently across context/quote changes in this deployment; arm, backing and reservation are atomic.

`resolve(bytes rawStatement, bytes rawBoundary, uint8 outcome, uint64 cnet, bytes financialProof, bytes acceptanceProof) external` requires that exact armed context and permanent tag binding; verifies exact Resolve and SourceAcceptance journals under immutable pins at the identical supplied boundary. Outcome1 requires `0<cnet<=A`; outcome2 requires `cnet==0`. Unknown/Other/excess cannot be encoded into an accepted result. Reuse Allocation.split(D,A,cnet), set the obligation consumed/decrement totalLiability, send nonzero U and S shares to the fixed beneficiaries, and emit success only after both sends return successfully. Reentrancy guard covers all mutators; a failure rolls back every state update and both transfers. No source-height versus EVM-clock comparison or post-expiry forfeiture. `obligations(context)` and `contextForTag(tag)` expose fixed backing/state; forced ETH is not liability and has no sweep path.

These methods implement actual execution logic conditioned on genuine proofs. Nonzero constructor identities and correct framing do not qualify the programs, source finality, origin independence or proof availability. Missing genuine composed proofs blocks positive qualification, not source implementation. No mock/seeded state may masquerade as a funded positive test. Source financial producers and genuine proof-driven transfer/retry tests remain required under the full goal.

## Exact Store interface

`NativeTradeStore::connect(DatabaseConfig)`, `migrate()`, `list_owner(owner_scope)` reuse database::connect/migrate/ensure_ready and a separate native_trade schema identity. Cargo auto-discovers tests; no explicit [[test]] is needed for discovery. Existing postgres-tests gating stays. No SQL execution without separately authorized private URI/schema scope.

Implement usable quote persistence, not only empty schema: `save_quote(location, &AuthenticatedQuote, Option<TradeCursor>) -> DurableQuote`, `restore_quote(location, &QuoteSelection, TradeCursor) -> DurableQuote`, `claim_writer(&QuoteSelection, TradeCursor) -> QuoteSnapshot`, `stop_quote(&QuoteSelection, TradeCursor) -> QuoteSnapshot`. Reuse capsule save/load; encrypted publication/authenticated readback precedes DB commit; matching DB readback precedes DurableQuote escape. Scope keys `(owner_scope, session_id, quote_id, local_role)`; stored selection immutable. Initial cursor version1/generation1; existing operations use exact CAS, checked positive SQL bigint counters. Writer takeover increments generation and version. Same-content retry does not advance phase; changed terms at same identity reject. Phase transitions Proposal->UserAcceptance->Agreed bind unchanged q/proposal and predecessor acceptance hashes. Stopped quotes never restart. Stop is local quote negotiation cancellation, never onchain refund or unlock of an armed obligation.

Add real digest-only operation fences in this same schema: `prepare_operation(&QuoteSelection, TradeCursor, OperationBinding)`, `release_operation(..., op_id, capsule_digest)`, `mark_submitted(..., op_id, tx_hash)`, `mark_unknown(..., op_id)`, `operation(..., op_id)`. OperationBinding uses explicit context/deployment/stable-J-tag/op ID/payload digest/action; each is an immutable caller-local pin, not proof validation. Prepare requires Agreed and not stopped; atomic reservation prevents conflicting operations using the same owner/deployment/tag/action. Release requires an authenticated existing encrypted capsule binding (not a raw unchecked digest); implement a capsule-bearing API if needed to enforce this. States Prepared->Released->Submitted or Unknown; Unknown never returns to Prepared or frees the reservation. Exact retry preserves the same binding/bytes. No generic Complete/refund/unlock method based on a boolean. SQL stores fixed identities, digests, states and counters only; executable bytes remain guarded/encrypted locally.

## Threat model and verification

| Risk | Required control / check |
|---|---|
| Wrong chain/program/policy/beneficiary or caller-supplied journal | Decode full context, independently pin deployment, construct expected journals and invoke real verifier; negative mutation tests |
| Forged proof / unsupported outcome | Strict proof length and canonical journal construction; real pairing rejection preserves balance/liability/tag |
| Same note under new quote or duplicate resolve | Permanent tag->context plus armed/consumed state; no reuse after terminal |
| Reentrancy/second receiver failure | Shared guard; checks-effects-interactions; whole EVM transaction rollback; positive proof-driven failure tests remain unqualified until genuine certificates exist |
| Lost response, concurrent/stale writer or crash | Scoped lock/CAS, authenticated durable capsule before release, immutable binding, Unknown reservation retained and restart readback |

## Tasks and ownership

1. Store implementer: runtime native_trade subtree, its migration and tests, lib export and native_trade database SchemaSpec integration only. Write behavioral tests first; no build/lint/tests/SQL mid-flight. Do not alter native_quote semantics.
2. ETH implementer: NativeEthObligation.sol, its tests, NativeFinancialCodec/test vectors only if genuine byte-parity bug is established. Constructor test expectations migrate to the explicit origin pin. No Rust or runtime changes. Write tests first; no build/lint/tests mid-flight.
3. Parent integration: compile and run once after handoff; affected Rust test/check and SQL compile-only, Forge offline actual tests plus in-process smoke, then one scoped review and fix concrete findings. Update evidence docs with separate counts. Preserve the F/J/C/R, complete lifecycle, companion/frontend and full-product requirements; no task is dropped by this decomposition.

## Execution checkpoint — 2026-10-09

- ETH source implements the frozen interface; full offline Foundry67/9suites and independent actual-verifier rejection smoke are exercised. Positive financial lifecycle remains unqualified without genuine composed certificates.
- Protocol/chain/CLI call integration is exercised: protocol82all-target, chains118all-target, native CLI8process and Rust→Solidity3call smoke; protocol/chains Clippy passed. No signing/submission or SQL ran.
- Store implementation is landed: SQL-off library10/integration4 and actual fresh-process encrypted quote/operation restart passed; seven new PostgreSQL cases compile only, **NOT RUN**. Selection AAD2 binds challenges/slots; Unknown retains hash/payload/reservation. Scoped review's exact shared application-registration defect is fixed and rereviewed; no remaining concrete findings.
- Grounded Statement→F/J/C/R source checks are landed and exercised by genuine localF/R/C plus mismatches; proofs Clippy passed. Missing canonical private commitment/beneficiary/grant openings and composed financial guest/finality remain full-goal prerequisites, not invented authorities. Source/ETH scoped review found no actionable findings.
- Quote challenge/sequence/version/private-buffer corrections and actual receiving dispatch are landed: quote6/dispatch4/codec1/DKG1 passed. There is no ordinary run-node owner quote-control bridge or complete economic quote schema. Full companion/frontend acceptance is not completed.
- Target observation is landed: client11/CLI4 localHTTP checks and complete chains129/11suites passed with full hash/code/deployment pins; no Completed/refund/source release conversion. Native inspection/public-call/source-ETH source reviews found no actionable findings; runtime SQL-feature Clippy passed without SQL execution.

Remaining scope retains the full lifecycle, both-role independent recovery, companion/four-screen integration and all R1–R10 acceptance. These module checkpoints do not mark the product done.

## Commit instruction — owner 2026-10-09

After current verification/fixes, commit all intended source/tests/docs; do not push. Existing target/node_modules/Foundry outputs remain ignored. Two tracked heavyweight legacy recovery executables are now removed from the index via exact ignores, **not deleted from disk**; both hashes match their preservation manifest. Existing history still contains their blobs; no destructive history rewrite is authorized or performed. Preserve ELFs/setup/custody/journals and all old rights.

## Scoped review corrections — exercised and closed

Native terminal ACK requests intentionally omit a response; bounded exact `(PeerId,InboundRequestId)` exemptions now consume only the resulting `ResponseOmission`, preserving the selected quote without an ACK loop. Genuine untracked failure still tears down. Shared codec requires actual EOF under the pinned handler's half-close semantics. Actual TCP/Noise/yamux two-swarm full signed quote/retry/omission regression and suffix/second-frame rejection passed; quote/dispatch/actual DKG CLI regression34 and node unit41 passed; SQL-feature runtime Clippy passed. Scoped rereview found no new actionable defect. There is still no ordinary run-node owner quote bridge or complete economic schema.

Shared database acquisition now admits exact `native_trade` application alongside prior identities; exact registry regression1, custody10 and PostgreSQL compile-only passed. Alias/case/version-suffix admission remains rejected; catalog/manifest/migration/TLS controls are unchanged. Scoped Store rereview closed the sole finding. SQL lifecycle remains NOT RUN.

Final current-source runtime all-target verification passed312checks/43suites,0failed,2ignored after all concrete corrections; SQL-feature Clippy passed. All owned source/tests/docs are ready for the explicitly authorized local checkpoint commit. Financial producer/companion requirements remain open as recorded above; this is not product completion or push/release approval.
