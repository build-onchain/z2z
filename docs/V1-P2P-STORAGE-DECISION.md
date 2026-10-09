# V1 P2P Node Storage Strategy

**Updated:** 2026-10-06  
**Purpose:** P0.04 storage boundary and the owner-selected durable design target. Read the [active V1 prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md), [microplan](V1-MICRO-IMPLEMENTATION-PLAN.md) and the [durability research](research/2026-10-06-phase0-durability-recovery.md).

## 1. Three Separate Storage Responsibilities

| Responsibility | Existing boundary / candidate | Authority and lifetime |
|---|---|---|
| **Public discovery hints** | Candidate bounded volatile cache of permitted advertisements, peer/query data and nonauthoritative fill/cancel notices. | Rebuildable and incomplete; not backing proof, owned capacity, a reservation or a financial outcome. Cache loss can discard hints, never pending rights. Public-field gossip is a non-secret generated test construction until disclosure/backing review permits its use; see [P2P spec](V1-P2P-PROTOCOL-SPEC.md). |
| **Public durable journals** | Existing native inventory and market/replica journals use PostgreSQL. The samechain lifecycle needs a new reviewed `samechain` application schema keyed by lane (X.07). It retains operation IDs, reservations, **digests and identities** of authorized bytes, submission identities and pending/`Unknown` observations. It never stores executable certificate or signed-transaction bytes (X.REL-DIGEST). | Durability prevents duplicate local authorization; chain consumption and actual asset effects determine financial outcomes. Active SQL remains PostgreSQL-only. No local SQL execution or substitute backend is authorized. |
| **Owner-private encrypted files** | Existing `runtime::custody` retains immutable encrypted native P/Q preparation; owner recovery capabilities, note openings and proof witnesses remain local. | Separate from SQL and discovery. Existing P/Q custody is not an implemented full samechain recovery bundle or durable node lifecycle. Retain actual secret capabilities plus usable artifacts; public hashes/ciphertexts cannot replace missing secrets. |

The PostgreSQL rule applies to **active SQL**, not all storage. It does not move encrypted private custody into SQL, authorize SQLite, or require a company database. A bounded public cache may need no database.

## 2. Current Source and Operational Constraints

- Runtime already separates PostgreSQL inventory/market persistence from encrypted actor-local custody. See [MODULES](MODULES.md), [ARCHITECTURE](ARCHITECTURE.md) and the [native checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) for source/evidence ownership.
- Existing PostgreSQL compiler evidence is not executed SQL lifecycle/concurrency/restart evidence. SQL-dependent verification remains **NOT RUN** pending the user's private URI and an authorized isolated scope.
- [SQL-VERIFICATION](SQL-VERIFICATION.md) prohibits local PostgreSQL execution, Docker/Testcontainers/embedded alternatives and SQLite fallback. URI delivery alone does not authorize schema reset, production migration or server restart. Credentials stay outside repo/chat/argv/log.
- Database operators must not receive keys, FVK, note openings, recovery capabilities, private order-policy openings or proving witnesses. Storing encrypted witness payloads in a shared journal is not an approved private-custody design.
- Preserve existing PostgreSQL stores, legacy SQLite funding journals and sidecars, encrypted files, original migration bytes and funded/signed artifact identities. A retained legacy journal is not an active SQLite option or permission to rerun it. No implicit conversion, blanket cleanup or decommission follows.

## 3. Durable Financial State Cannot Be a Cache

Before a proof/consent/authorized call can escape the owner process, the approved design must durably retain its exact identity and bytes, backing reservation, release state and recovery generation. Record transaction signing/submission intent before send. An exported certificate can authorize permissionless execution before the designated submitter broadcasts; an ACK or negotiation timeout cannot revoke it.

Restart and stale-backup restore must reconcile exact released bytes against current chain consumption and the selected finality/expiry policy. `Submitted/Unknown` stays nonterminal while an effect is ambiguous. Neither lost gossip nor elapsed negotiation time releases a reservation, resets capacity or resurrects a predecessor note.

Supported full/partial fills, proceeds and disjoint remainder are V1 requirements. Each settled portion succeeds independently; only an eligible residual can stay open/cancel/withdraw. Backups must preserve all owned proceeds/remainder openings and pending operations. Full company-off cold restore → history → witness → genuine local proof → owner sign → independent submit → actual assets remains required.

## 4. P0.04 Construction Prerequisites

Choose and review a complete owner-local durability path, rather than assigning a database by node label:

1. Identify rebuildable public hints versus non-discardable operation/reservation/release records and private recovery generations.
2. Define atomic publication, crash barriers, exclusive writer behavior, identity/tombstones and reconciliation across public journals and private files. Failure between backup, consent, certificate release and send must not lose or duplicate rights.
3. Determine which node responsibilities need SQL, whether existing PostgreSQL journals fit them, and how independent owners operate without mandatory company storage or paid services. A database-free discovery cache does not establish a database-free trading lifecycle.
4. Specify the samechain encrypted backup inventory and authenticated restore behavior separately from existing native P/Q custody; preserve old funded deployments and prover kits.
5. Obtain an approved private PostgreSQL URI and isolated execution scope for SQL-dependent checks; operational migration/reset remains separately authorized.

An alternative durable backend requires an explicit reviewed decision and any applicable superseding approval; there is no optional SQLite path or automatic PostgreSQL-per-node mandate. Permitted nonfinancial work can proceed independently, but affected durability/restart/recovery implementation cannot assume this decision is closed.

**2026-10-06 owner decisions (supersede the earlier "backend undecided" note).**

Durable design target: each owner's own self-operated PostgreSQL, on the owner node by default. This is a design choice only. It grants no install, service, run, schema, migration or SQL-execution permission.

**Release capsule and X.REL-DIGEST.** Certificate and signed-transaction bytes are public in syntax but executable authority. A database administrator or host root could read them before the client sees COMMIT, so the following rules apply:

- The exact bytes, and any cross-chain preimage, live only in an owner-local immutable encrypted **release capsule**.
- PostgreSQL holds only their digests and identities.
- Order on every sink (stdout, file, peer, relay, RPC, DB): capsule durable → `Released` CAS committed → export.
- A lost COMMIT acknowledgment freezes the exact bytes until reread. It never unlocks or changes them.

**Private snapshots.** The generated-key immutable private snapshot spec and plan are approved in writing; implementation is not started. A verified offline backup on independent failure-domain media is required before the first deposit and before each new release capability. Default backup key: one random 32-byte owner key on offline media.

Packet order: public descriptors → freeze packet/witness → encrypted backup and read-back → consent → local proof → verify → `Released` CAS → export.

**What can be built before SQL runs.** The capsule, snapshot, release gate, schema file and pure state machines can be implemented and compiled now. Executing them against PostgreSQL waits for the private test URI and an isolated-schema scope.

## 5. Status Ownership

[V1 architecture decisions](V1-ARCHITECTURE-DECISIONS.md) owns the pending choice; [BLOCKERS](BLOCKERS.md) owns readiness and [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md) owns exercised evidence. This document supplies P0.04's boundary and missing construction prerequisites, not a second status register, database installation guide or execution approval.
