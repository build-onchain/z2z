# Phase 0 durability and recovery research — P0.04, P0.10, durability of P0.09/P0.11, multichain lanes

**Date:** 2026-10-06. **Author role:** domain planner PlanDurabilityMultichain (configured PLAN model), integrating the frozen PlanDurabilityRecovery handoff and the PlanTestnetProverPolicy addendum as an independent judge. **Nature:** research and proposed mechanisms only. No product source, SQL, build, test, signing, deployment, or funds action was taken. The only live calls were public, read-only, documentation-grade (one NEAR testnet `EXPERIMENTAL_genesis_config` RPC read, recorded in §8).

Status vocabulary (from ConfiguredPlanCoordinator): SOLVED-TECH, PROPOSED-MECHANISM, RESEARCH-OPEN, OWNER-DECISION, ACTION-HELD, EXTERNAL-INPUT. Lane namespaces were answered by the owner (MQ8): the existing 122 IDs = EVM/Base, `L-HEVM.*`, `L-SOL.*`, `L-NEAR.*`, `X.*` for shared seams, and L-ZEC reusing the native plan tasks. [BLOCKERS](../BLOCKERS.md) remains the sole readiness register. [NATIVE-IMPLEMENTATION-STATUS](../NATIVE-IMPLEMENTATION-STATUS.md) remains the sole exercised-evidence register. Nothing here is closure evidence.

## 1. Binding owner answers used (do not re-ask)

- Durability design target: each owner self-operates PostgreSQL. This selects a design only. It grants no permission to install, run, or alter a service, schema, migration, or SQL execution. [SQL-VERIFICATION](../SQL-VERIFICATION.md) holds stay in force.
- Every written spec and every implementation plan is reviewed before code.
- The generated-key immutable complete-operation snapshot spec and plan are approved as a planning priority. Production keys, scanners, and held `check-appended-note-recovery` stay unauthorized.
- A verified backup on offline/independent failure-domain media is required before the first deposit and before each new release capability. Same-machine fsync covers crash/restart only, not disk loss.
- Output sequence: erase-on-drop memory outputs → public unauthorizing descriptors → freeze the complete packet/witness → encrypted backup publish + read-back → consent. No standalone pre-assembly output capsule.
- Disclosure goes to the bilateral counterparty only. Reachability is direct plus an optional independent relay. Network checks are generated-loopback only.
- NEAR and Solana lanes are ACTIVE in parallel with EVM, not deferred to V2. "Hyperliquid and Base for testnet" is answered: HyperEVM 998 spot first, then HyperCore positions via isolated position claims (investigation). The token is a fixed-supply vanilla 6-decimal token, constructor-only. Proof latency ≤15 min is provisional, not a guarantee.

## 2. Source facts this report relies on

| Fact | Source |
|---|---|
| `ActorStore` states are Reserved/FundingPrepared/SubmissionUnknown/Armed/Cancelled. Only Reserved can cancel. It stores digests and optional tx hash, never exact tx bodies or witnesses. | `crates/runtime/src/store.rs:7-10,108-132,392,451-512` |
| Schema identity marker `_z2z_schema_identity` holds application/version/OID/owner/manifest/catalog/migration digests. Generic inspection accepts only `market`/`inventory`. | `crates/runtime/src/database.rs:281-300` |
| Session forces VerifyFull TLS, `synchronous_commit=on`, and disables statement logging. Migration is one READ COMMITTED transaction creating an absent schema. | `database.rs:153-155,350-385` |
| Installed SQLx `=0.8.6`. Commit returns only after server commit, so a lost reply leaves the outcome ambiguous. | `crates/runtime/Cargo.toml:21`; registry `sqlx-core-0.8.6/src/transaction.rs:115-128` (handoff) |
| Native custody publisher: descriptor-relative NOFOLLOW, 0700/0600 single-link files, dot-staging, flock, NOREPLACE install, file+dir fsync. | `crates/runtime/src/custody.rs` (handoff ranges 98-188, 225-302, 312-539) |
| Approved snapshot spec: one immutable file holds one complete existing `OwnedOwnerInput` witness. Domain `ziquid.samechain.backup.v1`. The selection binds Deployment/token/code/policy/op/role/digest/E/history/ELF/kit. | `docs/superpowers/specs/2026-10-06-samechain-private-snapshot-design.md:9-52` |
| EVM `fill` is permissionless. `block.timestamp > packet.expiry` reverts, so equality still executes. cancel/exit consumes the same input NF. | `contracts/evm/src/SamechainAuthority.sol:181` (+handoff 127-275) |
| `PublicHistory` is bounded (2048 blocks/4096 notes/8192 NF/16 MiB) and trusts the provider's initial boundary and log completeness. Blocks expose hash/number/parent only, with no timestamp or finality. | `crates/chains/src/samechain/history.rs`, `inspection.rs` (handoff) |
| The Solana workspace is the Kerb public legacy-SPL escrow with three business ACKs. It is not a samechain owner-ZK authority. | `contracts/solana/README.md:3`; `program/src/state.rs:5-22` |
| The NEAR workspace is an empty slot with no contract, verifier, or account. | `contracts/near/README.md:1-7` |
| `prove-owner` returns the complete certificate JSON with no release hook (Coverage peer finding). | `owner_worker::prove` (peer-reported :658-715, not reopened here) |

Consequence: none of the three lanes has an owner-ZK samechain authority on Solana or NEAR yet. Their durability lanes can be specified now, but their codecs, pins, and terminal predicates depend on lane contracts that do not exist. The EVM snapshot approval does not approve Solana/NEAR codecs (see §5).

## 3. Core mechanism (shared seam, all lanes)

### X.REL-DIGEST — this resolves the remote/local PG admin first-escape risk

Problem. Certificate and raw signed-tx bytes are public in syntax but executable authority. Once any byte leaves the owner's process, a third party can execute it permissionlessly. An administrator of the PG server (or a root on the same host) can read a row before the client sees COMMIT. Storing the executable bytes in PG would therefore release authority while the journal still reads "Authorized/not released". This holds for local PG too, because the PG superuser/OS root boundary is not the owner process boundary.

Mechanism (PROPOSED-MECHANISM). PostgreSQL never stores executable authority bytes. The rules:
1. The exact executable bytes (the certificate and the raw signed transaction per lane) are written only into an owner-local immutable encrypted release capsule. The capsule reuses the custody publisher, but it is a second distinct physical domain proposed as `ziquid.samechain.release.v1` (codec reviewed separately, §4). It is also copied to the independent failure-domain backup before the new release capability is first used.
2. PG stores only `op_id`, lane, the canonical packet digest, the certificate digest (SHA-256 of exact bytes), the signed-tx digest/lane tx identity, required NF/lane-consumption identities, the signed expiry/lifetime bound, the capsule digest, and the backup generation digest.
3. A DB admin can therefore observe intent metadata but cannot execute anything. Metadata exposure (amount, scope, timing) remains, and DQ1 below decides which operator may see it.
4. Release order: capsule durable → PG CAS `Authorized→Released` committed and acknowledged → only then export (stdout/file/peer/relay/RPC). If acknowledgment is lost, the state freezes until an exact reread. The bytes never change.

Why not encrypt bytes in PG: that is still an approved-custody change ([storage decision §2](../V1-P2P-STORAGE-DECISION.md)) and gives no benefit over the capsule. A remote PG makes this mandatory. With local PG it is still required, because OS-root/DB-superuser ≠ owner process boundary.

### X.LIFE — common lifecycle (per op, per lane)

`Prepared → Frozen → BackedUp → Consented → Proved → Authorized → Released → {SignIntent → Signed → Submitted} → Unknown → Observed → Final{Completed(with rights) | Expired-proven-unexecuted | Consumed-by-competitor | Reverted-attempt}`

- `Frozen`/`BackedUp` follow the approved output sequence. A crash before `Consented` may abandon negotiation. Nothing has escaped yet.
- `Released` is entered before the first byte leaves. Neither ACK, peer abort, timeout, tx-not-found, nor an unfinalized competing cancel can leave `Released`.
- Terminal rule (addendum, adopted): for every outstanding exported packet on a reserved input, resolve only at an agreed canonical finalized point F where either (a) `F.timestamp > E` strictly for each still-relevant signed expiry E, or (b) a finalized consumption of a required input NF exists. Then reconcile the complete effects and rights through F. Discovered prior execution yields Completed-with-rights, never Expired. Missing history keeps Unknown. A reverted wallet tx closes that attempt only, not the permissionless certificate.
- Restore never moves state forward. A stale backup authenticates bytes, not freshness. Writer generation, heads, tombstones, and capacity are never reset from a file.

### X.JOURNAL — PG samechain schema (PROPOSED-MECHANISM)

A new application identity `samechain`, version 1. It needs a reviewed change to `database.rs:295`'s inspector allow-list. A guessed adoption is not acceptable. It reuses the transport, session, identity-marker, row-lock, and CAS patterns. It does not reuse `ActorStore` states or market credit semantics. Tables: `ops` (op_id PK, lane, scope, state, packet/cert/tx digests, expiry, capsule/backup digests, writer generation, version), `reservations` (input NF/lane-consumption-id UNIQUE among non-terminal, op_id), `send_attempts` (op_id, lane, attempt_no, lane-tx-identity UNIQUE, lifetime bound, state), `observations` (op_id, finalized point hash/number/timestamp, evidence digest), and `tombstones`. All writes run as short READ COMMITTED transactions with `SELECT … FOR UPDATE` on the op row plus a version CAS. No transaction stays open across proving, user, or network waits ([PG explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html)). Exclusive writer: a `writers` row with a monotonic generation, CAS-claimed on start. A same-filesystem flock is not a cloned-machine fence (§3 crash rules).

### X.SNAP — private immutable snapshot (approved, EVM-first)

This is unchanged from the approved spec. Additions needed for the lifecycle, each reviewed as a separate spec:
- An immutable signed-witness snapshot (new file, never overwrite the zero-consent file).
- The release capsule above.
- A recovery catalogue index (encrypted, immutable, appended per generation) that lists capsule/snapshot digests per op. Restore compares it against the journal and the chain, and a missing suffix freezes new authorizations.
- The offline kit manifest (ELF/VK/setup identities). It references pinned artifacts and never regenerates under a guessed identity.

### Crash cuts (all lanes)

| Cut | Outcome |
|---|---|
| Before snapshot read-back | Abandon negotiation; no authority escaped. |
| Snapshot durable, consent not given | Retain; resume or abandon. Never re-key the same op with different bytes. |
| Capsule durable, PG not Released | On restart PG says Authorized and the capsule exists. Treat as possibly released (conservative): move to Released by CAS before any action. Never delete. |
| PG Released, export failed | Stays Released. |
| SignIntent recorded, raw signed bytes not durable | Bytes never left: discard the signature, re-sign the same intent, record it first. |
| Signed bytes durable, submit result lost | Unknown. Only the lane-specific mutually exclusive replacement is allowed (§4, DQ3). |
| Finalized consumption seen | Reconcile rights and publish the recovery package before the terminal CAS plus tombstone. |

## 4. Per-lane durability specifics

Lane facts in this section come from the primary docs listed in §8. Latest owner scope:

- **L-HEVM:** HyperEVM spot and perps positions.
- **L-SOL:** a new owner-ZK lane on Devnet. The existing 3-ACK Kerb escrow is retained as a separate artifact, untouched.
- **L-NEAR:** owner-ZK on testnet first, with Intents in the backlog.
- **Cross-chain fills** are active (§4a).
- **Deployments** are immutable on every lane.
- **Release:** the first lane to pass may be released. The other lanes and cross-chain fills remain active obligations, so the whole project stays incomplete until they pass.

The SOL and NEAR lane contracts are not in the repo yet.

| Concern | EVM/Base (existing IDs) | L-HEVM (HyperEVM) | L-SOL (owner-ZK Devnet) | L-NEAR (owner-ZK testnet) |
|---|---|---|---|---|
| Exact executable bytes in capsule | Certificate + RLP signed tx | Same as EVM | Certificate + serialized signed tx (message + signatures) | Certificate + Borsh `SignedTransaction` |
| Replay/uniqueness fence | Sender nonce; same-nonce replacement is mutually exclusive | Same as EVM; finalized tag availability unconfirmed (Prover verifying) | Recent blockhash. A tx is invalid once the finalized block height exceeds `lastValidBlockHeight` (about 151 blocks). Durable nonce removes the lifetime. | Access-key nonce must be in `(current+1 .. height·10^6)`. Block hash validity is `transaction_validity_period` = 86400 blocks on testnet (observed). |
| Bounded Unknown | Until the nonce is consumed (unbounded if stuck) | Same | Bounded: about 151 blocks after the blockhash (recommended) | Bounded by 86400 blocks, or earlier by the nonce being superseded |
| Proof tx never executes | Finalized block whose sender nonce > n without our hash | Same | Finalized height > `lastValidBlockHeight` with no signature in status | Finalized key nonce ≥ ours without our hash, or the validity window passed |
| Effect atomicity | One reverting tx (source) | Same (EVM) | One tx, atomic across instructions/CPI | NOT atomic: the receipt DAG means cross-contract `ft_transfer` can fail after NF consumption (DQ6) |
| Finality evidence stored | Finalized block hash/number/timestamp | Pending Prover confirmation | Finalized slot, blockhash, block time | Final block hash/height, plus `wait_until=Final` status for the whole receipt DAG |
| Signer key custody | Owner wallet key | Same | Fee payer + owner; nonce authority if durable nonce is used | Full-access vs FunctionCall access key (DQ5) |
| Snapshot codec | Approved `ziquid.samechain.backup.v1` | Reuse only if its Deployment/codec is byte-identical (otherwise new reviewed lane id) | New `Deployment`-equivalent with program id/PDA/mint/token-program pins; separate reviewed codec | New with account id/code hash/NEP-141 contract pins; separate reviewed codec |

Interfaces (PROPOSED-MECHANISM). Each lane is a private interface in `runtime` under the existing module ownership. No sixth crate is needed:

```rust
// runtime::samechain::lane (proposed; one impl per approved lane)
pub(crate) trait LaneSubmission {
    type SignedTx;            // exact lane bytes; lives only in the release capsule
    fn tx_identity(tx: &Self::SignedTx) -> LaneTxId;            // EVM hash, Solana first sig, NEAR tx hash
    fn lifetime(tx: &Self::SignedTx) -> LaneLifetime;           // Nonce(n) | LastValidHeight(h) | NearWindow{nonce, block_hash}
    fn excludes(a: &Self::SignedTx, b: &Self::SignedTx) -> bool; // replacement is mutually exclusive
}
pub(crate) trait LaneFinality {
    async fn finalized_point(&self) -> Result<FinalPoint, LaneError>;          // hash, height, timestamp
    async fn outcome(&self, id: &LaneTxId, at: &FinalPoint) -> Result<Outcome, LaneError>; // Executed{effects}|ProvenNotExecutable|Unknown
}
```

`ponytail:` this is a trait with one implementation per approved lane, and today exactly one exists (EVM). Do not add the trait until a second lane's contract is approved. Until then, EVM stays concrete and the table above is the spec the second implementation must satisfy.

Shared publisher: the custody publisher has genuinely two-plus users (native P/Q, the EVM snapshot, and the release capsule), so it is extracted once as the approved spec states. Lane codecs do not share a publisher abstraction beyond that seam.

### 4a. X.XCHAIN: two-lane hashlock fill (PROPOSED-MECHANISM)

Cross-chain fills are not atomic. The hashlock gives safety only when the timeouts are staggered and the participant watching each lane stays live. Each lane needs a new reviewed lock/claim/refund entrypoint inside its immutable authority. No current contract provides one.

Roles:

- **Initiator I** holds the secret preimage `s`, with `h = SHA-256(s)`.
- **Responder R** locks second.

Timeouts: `T_I` on I's lock lane and `T_R` on R's lock lane must satisfy `T_I ≥ T_R + fin(R lane) + fin(I lane) + claim_inclusion_margin`. Each lane's `fin` is the finalized-point delay under that lane's `LaneFinality`. The margin is a per-lane parameter the owner calibrates; it is not a guess.

Journal states for one owner. These extend X.LIFE, and each state is recorded before the step it guards.

| State | Durable precondition before entering | Release meaning |
|---|---|---|
| `XPrepared` | Op row exists, with both lanes, both lock specs, `h`, `T_I` and `T_R`. I only: `s` is in an immutable snapshot that has been read back from independent media. | Nothing has escaped. |
| `LockOwnReleased` | Own lock tx bytes are in the release capsule, and PG CAS has committed. | Own funds are committed until claim or refund. |
| `LockOwnFinal` | The own lock is observed at a finalized point. | |
| `CounterLockFinal` | The counterparty lock is verified at a finalized point: amount, asset, recipient, `h`, and the timeout satisfies the inequality. | Without this, I never reveals and R never claims. |
| `PreimageReleased` (I) | `s` and the claim tx bytes are in the capsule, PG CAS has committed, and the time is before `T_R − fin(R lane) − margin`. | The reveal releases authority. Once `s` is published, R can claim I's lock. |
| `PreimageLearned` (R) | `s` was extracted from a finalized claim on R's lane, and it has been written to the capsule and PG digest before R builds its claim. | |
| `ClaimReleased` / `ClaimFinal` | Claim tx bytes are in the capsule before they are sent. | |
| `RefundEligible` | A finalized point exists with timestamp > own T. For R, this additionally requires that no finalized claim exposing `s` exists on R's lane. | The refund right exists only after the timeout is final. |
| `RefundReleased` / `RefundFinal` | Refund tx bytes are in the capsule before they are sent. | |
| `XUnknown` | Any ambiguous send. | Nonterminal. The counterparty-side watch continues. |

Rules:

- Recovery must never lose `s`. It lives in the snapshot before the lock and in the capsule before the reveal. Restore re-derives `PreimageLearned` from the chain, never from peer messages.
- No state may skip the counterparty-finality check. Peer ACKs, the relay, and timeouts never move a state.
- After `PreimageReleased`, I must watch I's own lane until R claims or `T_I` passes. After `PreimageLearned`, R must claim before `T_I`. A missed watch window is a liveness loss of funds, not a protocol failure. The node must surface it as an alarm.
- Privacy: the same `h` links both lanes publicly. This does not close GD2.
- **L-HEVM perps:** a position is not an escrowable asset. Only collateral or spot tokens can be hashlocked. Opening or closing a position is a separate post-claim action that carries its own liability (XQ1).

Unknown and asymmetric finality, per lane: a claim stuck in `XUnknown` on a fast-finality lane while the other lane's timeout approaches is the primary risk. The timeout inequality above is the only defense. There is no implied atomicity.

## 5. Old-identity preservation on restore

- Restore keys by `(lane, deployment pin, packet digest, op_id)` from the independently supplied selection, never from ciphertext.
- Existing funded or old artifacts, native custody v1/v2/v3, legacy SQLite funding journals, and market/inventory PG schemas are preserved byte-for-byte. Restore never migrates or rewrites them.
- A Solana/NEAR snapshot can never be decoded by the EVM codec. Each needs a distinct domain string and its own `Deployment`-equivalent frame. The EVM approval is not lane approval.
- Cloned-device rollback: no cryptographic antirollback. An old clone's released authority stays protected by NF/expiry and finalized reconciliation. Retiring a clone is an operational procedure (writer generation CAS on PG plus owner retirement of the old machine). It is a written runbook, not a code claim.

## 6. Assigned P0 rows

| ID | Acceptance | Current source evidence | Contradiction | Status | Proposed resolution & interfaces | Future verification | Remaining owner/permission |
|---|---|---|---|---|---|---|---|
| **P0.04** storage (EVM/Base) | One approved path for intents/reservations/Unknown, PG-only, no company DB, legacy retained, test URI scope distinct from migration | Storage decision records owner-selected per-owner PostgreSQL; Wave B EVM `samechain` schema/inspector/journal source exists; SQL tests NOT RUN | Earlier "undecided"/missing-schema source descriptions are superseded; the EVM release journal does not implement full reservations or lane-keyed X.JOURNAL | Design selected; full lifecycle PROPOSED-MECHANISM; SQL ACTION-HELD | Per-owner PG X.JOURNAL + X.REL-DIGEST + capsule; preserve legacy identities and separate action approval | Approved-URI SQL suite: identity adoption, concurrent CAS/reservation uniqueness, commit-ack loss, restart, writer generation, every crash cut in §3 | SQL execution needs explicit URI env, test role, schema prefix and schema-change approval; design selection grants none |
| **L-HEVM.STORE / L-SOL.STORE / L-NEAR.STORE** | Same as P0.04 per lane | §4 | No lane contract for SOL/NEAR | PROPOSED-MECHANISM (lane scope answered: MQ1–MQ3, Z2) | Same schema, `lane` column, lane-specific `send_attempts.lifetime` | Same SQL suite per lane | Lane contract specs; DQ3–DQ6 are engineering defaults |
| **P0.10** recovery/private-use | Before-funding bundle covers keys/openings/consents/pending intents/artifacts; generated-key checks distinct from production; held command not implied | `samechain::backup` implemented; generated-key library + clean-process restore focused evidence in [native status](../NATIVE-IMPLEMENTATION-STATUS.md), no post-snapshot broad green | Complete-witness snapshot ordering is P3.03a → P3.04 → P3.03b → P3.05; no standalone output capsule | Private snapshot exercised; full offline recovery/release integration PROPOSED-MECHANISM | Preserve v1; qualify the implemented capsule/consumer guard with genuine certificates and approved SQL; catalogue, kit and cloned-writer policies still need specs; independent-media verification before deposit and each new release capability | Independent-media read-back, genuine VM/wrapped restore and stale-catalogue freezes remain unexercised; snapshots never resolve Released/Unknown | Offline 32-byte backup key is the engineering default; production-secret use ACTION-HELD; offline-media drill needs its own approval |
| **L-SOL.RECOVERY / L-NEAR.RECOVERY** | Lane snapshot + restore | None | EVM approval ≠ lane codec | RESEARCH-OPEN | Distinct domains `ziquid.samechain.{sol,near}.backup.v1`; lane `Deployment` frames after contract design | Same as P0.10 per lane | MQ2/MQ3 contract approval; separate written spec+plan review |
| **P0.09** durability portion | Prepared/Authorized/Released/Submitted/Unknown/observed/final defined; release-before-export; no timeout unlock; locks until finalized expiry/consumption | Authority expiry equality remains executable; rev 3 capsule/journal/consumer guard source implemented, with focused negative checks and both scoped source reviews passing | Source cutover is implemented; SQL behavior NOT RUN and genuine wrapped capsule/export positives BLOCKED, not full lifecycle qualification | Full lifecycle PROPOSED-MECHANISM; implemented release-guard slice | X.LIFE + terminal rule; every export sink remains fenced; finalized point/timestamp acquisition requires a reviewed seam | Late permissionless execution after abort; `ts == E`; finalized `> E` with prior execution; reorg retains fences; SQL execution held | Per-lane finality/source qualification and action-specific permissions remain required |
| **L-*.FINALITY** | Lane-specific "proven not executable" predicate | §4 table | NEAR receipts async | PROPOSED-MECHANISM (SOL/EVM), RESEARCH-OPEN (NEAR atomicity) | §4 predicates via `LaneFinality` | Controlled VM/LiteSVM/near-sandbox fixtures only | DQ6; HyperEVM finalized tag unconfirmed (Prover) |
| **P0.11** durability/action portion | Each action packet: chain/signer/recipients/asset/amount/fee/simulation; credentials out of chat/repo/argv | `SQL-VERIFICATION §2` env-only URI | — | OWNER-DECISION | Separate packets: (1) SQL test scope, (2) PG service on owner host (no install by agent), (3) offline-media backup drill, (4) cold restore drill, (5) per-lane sign/send preview including lane lifetime (nonce / lastValidBlockHeight / NEAR window), (6) any replacement/fee-bump | Packet reviewed before each action | All actions held until each packet is approved individually |
| **X.REL-DIGEST** | No executable bytes reach any non-owner store before Released | Rev 3 capsule, digest-only EVM journal and consumer guard implemented; focused negative checks and both scoped source reviews passed | SQL behavior NOT RUN; genuine capsule/committed-export positives BLOCKED | Implemented source slice, not full acceptance | §3 and the scoped release spec; full signed-tx/preimage/lane lifecycle remains outside Wave B | Behavioral crash cuts and committed-export ordering remain SQL-held; negative evidence is not a valid-certificate roundtrip | SQL test scope and genuine wrapped certificate remain prerequisites |
| **X.XCHAIN** | Two-lane fill without loss of `s` or refund rights | None. No lane has a hashlock entrypoint | Owner-ZK authorities have no HTLC path | PROPOSED-MECHANISM (journal), RESEARCH-OPEN (lane contract HTLC inside owner-ZK, perps liability) | §4a states plus the timeout inequality | Controlled VM, LiteSVM and near-sandbox, two-lane: crash at every state; late claim; R misses the window; `XUnknown` near T | XQ1; lane contract specs |

### 6a. What can start now vs what is held

**Unblocked source work.** Each item still needs its written spec and plan reviewed before code.

- The approved EVM snapshot module and the custody-seam extraction.
- The release capsule codec.
- The release gate around every export sink (start at `prove-owner` stdout).
- The `samechain` schema migration file and the `database.rs` allow-list change. These are compile-only and not executed.
- The X.LIFE state machine as pure Rust with in-memory test doubles at the journal trait boundary.
- The lane finality predicates against controlled fixtures.
- The §4a state machine as pure code.

**Held** (ACTION-HELD or EXTERNAL-INPUT):

- Any SQL execution. This needs the private test URI and an isolated schema-scope packet.
- The PG service on the owner's host.
- Offline-media and cold-restore drills.
- Production secrets.
- All deploy, sign, send, and fund actions on every lane.
- Lane contract code for SOL, NEAR, and HTLC until their specs are reviewed.

## 7. New material questions (sent to ConfiguredPlanCoordinator; not duplicating MQ1–MQ9)

1. **DQ1 PG placement.** DEFAULT (canonical): PG runs on the owner node. X.REL-DIGEST already removes the executable-escape risk, so what remains is metadata visible to the PG operator. Alternatives the owner can choose instead:
   - (B) A separate owner-controlled host over VerifyFull TLS.
   - (C) A managed third-party PG. This leaks metadata and adds an availability dependency.
2. **DQ2 backup key custody.** DEFAULT (canonical): one independent random 32-byte key on offline media. The owner may override with one of these alternatives:
   - (B) Per-lane keys.
   - (C) A passphrase KDF. This is a new construction and carries brute-force risk.
   - (D) A key derived from the wallet seed. This couples the backup to wallet compromise.
3. **DQ3 Unknown replacement.** ADOPTED (A) by the coordinator, PROPOSED-MECHANISM. Only mutually exclusive replacements are allowed, and each is recorded first:
   - EVM: same nonce.
   - NEAR: same key nonce.
   - Solana: only after the finalized height exceeds every prior `lastValidBlockHeight`.
4. **DQ4 Solana lifetime.** ADOPTED (A): use a recent blockhash, with no durable nonce.
5. **DQ5 NEAR signer.** PROPOSED, not adopted. The canonical default is the owner full-access key, used only under explicit signing approval. The FunctionCall-key minimum-privilege scope is decided in the lane spec.
6. **DQ6 NEAR async payout.** Owner answer Z2: native NEAR comes first, and native-transfer failures must still reconcile. For later NEP-141 payouts, a claimable credit is PROPOSED and not adopted. The NF is never unconsumed. The journal tracks the payout to `Final`.
7. **XQ1 HyperEVM perps in cross-chain fills.** ANSWERED (Z3): token/collateral legs go first. Position-claim trading is active research.

## 8. Primary sources (retrieved 2026-10-06)

- PostgreSQL 18 docs: [WAL config](https://www.postgresql.org/docs/18/runtime-config-wal.html), [WAL reliability](https://www.postgresql.org/docs/18/wal-reliability.html), [explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html), [isolation](https://www.postgresql.org/docs/18/transaction-iso.html), [pg_dump](https://www.postgresql.org/docs/18/backup-dump.html). Read by the predecessor handoff; claims as recorded there.
- Linux man-pages 6.19: [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html), [rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html), [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html) (handoff).
- Solana: [Confirmation & Expiration](https://solana.com/developers/cookbook/transactions/confirmation): 151-blockhash max processing age, recent-blockhash expiry. [Durable nonces](https://solana.com/developers/cookbook/transactions/durable-nonces) (2024-06-29): nonce advance as the first instruction, removes mortality, nonce authority. [getLatestBlockhash](https://solana.com/docs/rpc/http/getlatestblockhash): `lastValidBlockHeight`.
- NEAR: [Anatomy of a Transaction](https://docs.near.org/protocol/transactions/transaction-anatomy.md): nonce range `(current+1 .. height·10^6)`, block hash limits validity, single receiver. [Lifecycle](https://docs.near.org/protocol/transactions/transaction-execution.md): receipts, `wait_until` levels, a tx can succeed while a later receipt fails.
- NEAR testnet RPC `EXPERIMENTAL_genesis_config` at `rpc.testnet.near.org`: `transaction_validity_period = 86400`. This is a single-provider observation, not a pin.
- Not verified here (Prover lane owns): HyperEVM finalized tag/historical state, Solana/NEAR alt_bn128 cost.
