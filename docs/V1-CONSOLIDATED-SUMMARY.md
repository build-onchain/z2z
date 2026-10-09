# Z2Z V1 Documentation Consolidation Summary

**Updated:** 2026-10-06  
**Purpose:** Navigate the current V1 scope and corrected planning boundaries. This is not a second task tree, readiness register, exercised-evidence checkpoint or completion report.

## 1. Active Document Owners

| Question | Authoritative owner |
|---|---|
| Implementation instructions and action boundaries | [Z2Z-V1 implementation prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md) |
| Release requirements and retained V2 scope | [V1 delivery matrix](V1-DELIVERY-MATRIX.md), [PRODUCT](PRODUCT.md) |
| Detailed tasks and dependency edges | [V1 micro-implementation plan](V1-MICRO-IMPLEMENTATION-PLAN.md), under the existing [roadmap](Z2Z-V1-ROADMAP.md) |
| Pending design choices | [V1 architecture decisions](V1-ARCHITECTURE-DECISIONS.md), [storage decision](V1-P2P-STORAGE-DECISION.md), [testnet selection](V1-TESTNET-SELECTION.md) |
| Candidate network/coordination contract | [V1 P2P spec](V1-P2P-PROTOCOL-SPEC.md) |
| Measurement contract, not hardware promises | [Proving qualification](PROVING-COST-SOLUTIONS.md), [resource targets](V1-RESOURCE-TARGETS.md) |
| Enablement/readiness and observed results | [BLOCKERS](BLOCKERS.md) and [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md), respectively |
| Module ownership, recovery and SQL restrictions | [ARCHITECTURE](ARCHITECTURE.md), [MODULES](MODULES.md), [SERVER-INDEPENDENCE](SERVER-INDEPENDENCE.md), [SQL-VERIFICATION](SQL-VERIFICATION.md) |

The microplan catalogues Phase 0–5 tasks and covers the existing roadmap's final security/documentation review; phase numbers are scope buckets, not a strict execution sequence. Task estimates are not proving timings, and documentation corrections do **not** complete Phase 0. This summary reports no implementation run, benchmark, testnet transaction or recovery drill. Existing primitive evidence stays in the checkpoint; target-hardware/full-V1 execution is not established here.

## 2. First Passing Journey (samechain) — Not Passing Evidence

- Owner-local long-running `z2z-node` in this repository, P2P discovery and native CLI create/discover/list/fill/cancel/withdraw/status/sync/recover. No mandatory hosted backend/shared company database or sibling frontend takeover.
- Base Sepolia samechain by **engineering default** (not owner approval), with real Native and one fixed-supply 6-decimal vanilla ERC20. Local Anvil is not public-testnet acceptance, and deployment requires its own permission. Releasing this journey does not complete the project (§4).
- Independently checked backed orders, both owners online for every **new** fill and fresh consent over one exact bilateral packet. Genuine local role proofs and exact authority verification/consumption/output append/transfers must be atomic.
- **Full and supported partial fills, correct proceeds/disjoint remainder, eligible cancel and actual withdrawal are required**, not V2 deferrals. Each settled portion succeeds independently; cancel cannot undo paid fills or restore spent predecessors.
- Durable intents, backing reservations, certificate-release exposure, exact authorized/signed bytes and pending/`Unknown` reconciliation across crash/restart/stale backup.
- Full company-off recovery: encrypted clean restore + retained usable artifacts → independent authenticated complete history/current eligibility → local witness and genuine proof → owner sign → independent submit → actual assets and correct residual rights, including valid retry. Observation/decryption alone is not recovery.

Pre-funding recovery/artifact qualification and proving qualification block irreversible deposits. Specifically authorized deployment precedes funded lifecycle acceptance. Missing scope/privacy/storage/resource/action prerequisites block affected work, not every independent nonfinancial task; no all-Phase-0-complete claim or blanket stop is inferred.

## 3. Corrected Construction Boundaries

### Storage

Keep three stores separate: bounded volatile **public discovery hints**, **public durable journals** and **owner-private encrypted files**.

- **Durable design target (owner, 2026-10-06):** each owner's own PostgreSQL, keyed by lane. It holds digests and identities only.
- **Executable bytes:** certificate, signed-tx and preimage bytes live only in an owner-local encrypted immutable release capsule. Required order on every sink: capsule durable → `Released` CAS → export.
- **Backup:** verified offline independent-media backup before deposit and before each new release capability.
- **Prohibited:** local SQL execution and SQLite substitution.
- **Preserved:** existing stores, legacy funding journals/sidecars and funded artifacts.

Details are in the [storage decision](V1-P2P-STORAGE-DECISION.md).

### Discovery and privacy

Public-field gossip is strictly a **non-secret generated test construction**, blocked for private-market release pending every field/metadata inference and concrete backing/ownership/current-spentness review. Signatures, known roots, seen commitments and aggregate vault balances do not prove an advertised order's backing. Unverified hints are not a reduced V1 release criterion. Transport encryption, decentralization and short local retention do not close strict GD2 or erase peer archives/chain history.

### Public assembly and authorization exposure

Both recipients first prepare/check/back up their own outputs locally. Current [reviewed Fill2](superpowers/specs/2026-10-06-independent-owner-fill-design.md) uses [actual protocol hashes](../crates/protocol/src/samechain/fill.rs) and [OwnerWitness/reviewer](../crates/proofs/src/samechain.rs): agree public B/E, exchange only permitted public descriptors and ordered opaque A/B policy leaves, compute C/freeze identical packet; each witness retains only own authenticated policy/openings and independent own_salt. `review-fill --packet FILE --execution FILE --role a|b --witness-stdin` requires independently selected canonical E frame2. No whole Terms/common blind/counterparty witness exchange; quantities are shared with the counterparty, not GD2-secret. Guest mode0 is byte0 + one OwnerWitness frame2; non-fill/note/tree/schema/outer journal remain1. New ELF/program requires authorized new immutable authority and genuine all-mode target/recovery qualification; original fill1 artifacts remain under original identities, no migration/reinterpretation. [Checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) owns current native/CPU/correspondence and completed source-review evidence; independent source/setup/program qualification, durable backup/session integration, wrapping/funded/privacy remain unqualified. Note recovery ciphertext descriptors are not proving witnesses; private policies/salts/keys/openings/witnesses never leave owners, even encrypted.

Permissionless certificate release exposes an authorization that another holder can combine and submit. Retain exposure/fences until chain-enforced packet expiry or finalized shared-capability consumption/invalidation, with actual pending/`Unknown` reconciliation. ACK refusal, timeout, peer disconnect and local deletion are not revocation or unlock; transaction broadcast is not the first exposure boundary. Expiry does not release backing or erase an earlier included effect by itself.

### Proving and resources

Existing SP1 `prove-owner` is the first candidate to benchmark on the owner's i5-11400H / 16GB machine, not a guaranteed feasible choice or hardware minimum. Target-hardware whole-prover peak/time/storage and all-mode genuine wrapping/exact admission remain unqualified; component sizes, CPU journals and historical capped OOM are not substitutes.

Targets stay TBD until measured. Alternatives require measured constraints/resources and the same ownership/consent/conservation/uniqueness/recovery/privacy/verifier qualification. No no-proof release, observation-only recovery, remote-witness fallback, unmeasured performance saving or silent hardware/scope downgrade is authorized. Changed verifier/program requires a new separately authorized immutable authority and preservation of old funded lifetimes.

## 4. Whole Project: Active Parallel Lanes, and V2

**Active, required for project completion, not V2.** Each lane is reported separately in [BLOCKERS](BLOCKERS.md) §4.2:

- **L-HEVM:** spot first, then isolated position-claim research toward the full Core use cases.
- **L-SOL:** owner-ZK on Devnet.
- **L-NEAR:** native NEAR first, NEP-141 later.
- **L-ZEC:** native ZEC with complete P/Q/history/net/excess/uniqueness/privacy/recovery, under native S1–S7/M1–M5. Wrapped ZEC is no substitute.
- **Cross-chain fills:** all pairs, token/collateral legs first. HTLC CX-1 is not atomic or private; CX-2 is in research.

**V2:** standing maker (one opening signature, offline multi-fill), GUI and hardware wallets, mainnet, Intents/1Click, LP/agents/ZSA. Strict GD2 remains Blocked.

## 5. Remaining Prerequisites and Permissions

Use existing task IDs/owners rather than duplicating status here: P0.04 durable public-journal/private-file/release integration; P0.05 disclosure and advertised backing relation; P0.06 public packet assembly/exposure/expiry/outcome contract; P0.07 actual networking version/codecs/bounds/reachability; P1.23 genuine all-mode owner-local qualification; P4.05 pre-funding restore; exact testnet/assets/finality/deployment pins and separately authorized actions.

Zero paid infrastructure means no paid VPS/prover or witness upload, not zero gas/hardware/storage. SQL verification awaits private URI and isolated approved scope; no local SQL execution. No deployment (including Anvil), production-secret use, signing/submission, funds, migration/reset, Git setup/commit/push or mainnet authorization follows from these documents. Only observed, scope-qualified checkpoint evidence and the sole readiness register can establish closure.
