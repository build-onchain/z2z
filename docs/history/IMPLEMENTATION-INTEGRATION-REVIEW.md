# Z2Z implementation integration — source review and acceptance map

**2026-10-03.** User requests merging all Kerb/Ziquid implementations then completing full Z2Z. This review is current-source discovery, not code migration, financial acceptance or final overview. Source roots: existing `ziquid-dex` and sibling `kerb`. Code implementation remains unchanged during discovery; active goal remains full project, not import/build-only.

## 1. Controlling instructions

- Latest user choice: **PostgreSQL for all SQL; NO local SQL tests**. [SQL-VERIFICATION](../SQL-VERIFICATION.md) owns URI-provisioned verification hold and safe config. Old SQLite journals/sidecars stay untouched; no automatic data migration/reset/deletion.
- Ziquid is base; Z2Z product name, no blanket namespace/wire/crypto rename. Existing signed records/proof artifacts/PDA seeds must retain their bytes and identity.
- Native source/user keys/private witnesses and encrypted recovery files are not SQL accounting records; do not upload them to remote PostgreSQL because engine changes.
- Git repo is absent. No Git initialization, commits/pushes/worktree creation, no signing/network transactions/deploy/funds/mainnet/publication permissions follow from implementation intent.
- Current new architecture needs concrete integration spec/plan review before new architectural code. Prior native execution plan applies to its unchanged approved workstream, not newly invented privacy/custody changes.

## 2. Live baseline evidence in this investigation

| Operation | Observed result | Limit |
|---|---|---|
| Cargo metadata on both workspaces | Rust/cargo1.98.1; Ziquid five host crates, Kerb four host crates; independent targets. | Metadata only, not build/target operation. |
| `cargo test --offline --locked --workspace --all-targets --release` in Ziquid | **FAILED**: `temporary_sprout_ledger_guest.rs` imports optional `sp1_primitives` and cfg-gated execution/QualificationResult without manifest `required-features`. | Existing/concurrent source retained; no deletion or re-run to confirm. Fix must feature-gate correctly, not enable heavy prover by default. |
| `cargo run --offline --locked --release -p ziquid-runtime --bin ziquid -- allocation 6000000 30000000 2000000` | `user_wei=10000000 solver_wei=20000000`. | Actual arithmetic CLI, no funds. |
| Ziquid non-SQL baseline `cargo test --offline --locked --release -p ziquid-protocol -p ziquid-zcash -p ziquid-proofs -p ziquid-chains --lib --tests`, jobs1 | **146 passed,15 suites**. | Selected host primitives only; no full workspace default-example pass, SP1 wrapping or source network/escrow acceptance. |
| Kerb non-SQL baseline `cargo test --offline --locked -p kerb-protocol -p kerb-custody --all-features --lib --tests`, jobs1 | **27 passed,4 suites**. | Existing source pure protocol/inspection, not merged code, matcher, source history/payment or SQL. |
| Ziquid non-SQL custody/allocation baseline `cargo test --offline --locked --release -p ziquid-runtime --test custody --test allocation`, jobs1 | **12 passed,2 suites**,29.14s test time. | Existing encrypted custody and arithmetic paths; no PostgreSQL or merged runtime verification. |
| Kerb Solana baseline `KERB_SBF_ELF=…/kerb/target/kerb-sbf/kerb_solana.so cargo test --offline --locked --manifest-path contracts/solana/Cargo.toml -p kerb-solana-harness --test compiled_elf -p kerb-solana-interface -- --test-threads=1`, jobs1 | **16 passed,1 suite**,9.87s test time. | Existing compiled-ELF harness; this command's result does not establish a separate interface unit-suite run, merged target build or owner-proof settlement. |
| Existing Kerb runtime `--help` | Executed migrate/replica/inspect-ledger/inspect-pczt/reconcile/local-safety-scenario CLI surface. | Help, not complete execution or signing. |
| Earlier Kerb local SQL baseline | Started before user prohibition, **canceled immediately on instruction**. | No passing evidence accepted; no local SQL actions afterward. |
| Resource check |20GiB disk free; host15GiB RAM,4.1GiB available and swap full at observation. | No repeat of known OOM or big artifact download. Proof resource qualification pending. |

Do not aggregate these separate-source results into a complete merged-suite result; code is not merged. SQL, destination-built target and new product features remain unverified.

## 3. Real implementations to integrate, not replace with stubs

| Current source | Actual capability | Proposed home and separation |
|---|---|---|
| Ziquid protocol |474-byte big-endian native-EVM context, bounded zatoshis, full U256 allocation. | Preserve root exports/wire in `crates/protocol`; does not become market Domain325. |
| Kerb protocol | no_std market domains/records/policies, little-endian typed signatures, holds/partitions/native dispositions. | Namespaced `protocol::market`, host/target feature isolation; ordinary Ed25519 not legacy Sprout signature verifier. |
| Ziquid zcash | Real local P/Q authoring, Q proving/sign/extraction, sender recovery, v6 authorization parser, limited Zoss raw acquisition. | Preserve owner/source flow; caller independent arm/release and full source facts still missing. |
| Kerb custody | PCZT effect/sighash/input/output/ciphertext checks against enrolled physical facts/FVK. | `zcash::custody`, explicit designated custody capability, not permission to give U FVK to solver or prove arbitrary hostile facts. |
| Ziquid runtime custody | Immutable encrypted actor-local P/Q/witness preparation save/restore. | Keep `runtime::custody` file/key policy; not SQL engine or Kerb effect inspector. |
| Kerb ledger/replicas | PostgreSQL durable credit/hold/epoch/portion/input/change/journal/3-ACK and target-authority records. | `runtime::market::ledger`, preserve8 migrations/bytes; custody liability, not proof-controlled note/native escrow. |
| Ziquid ActorStore | SQLite immutable scoped reservations/funding intents/Unknown fencing, total-capacity accounting. | Async PostgreSQL ActorStore with explicit scope/row locks/U256 bytes; old files untouched and not fallback. |
| Kerb runtime | CLI/coordinator/replicas/PCZT physical binding/target process orchestration plus LocalFixture safety scenario. | `runtime::market`; single CLI branch, all self-spawn/tests/config path callers migrated, no shadow legacy binary. |
| Kerb Solana interface/program/harness | Canonical effects/envelopes/PDA, public SPL escrow using3 ordinary authorized business signatures; real localVM fixture. | Whole group in existing independent Solana build; keep authority class legacy, not owner-ZK program. |
| Ziquid proofs/guests | Genuine prep/sender/early-history/Sprout/legacy checks,5 independent SP1 method workspaces, real base verifier. | Preserve exact source includes/pins and artifact identities; full financial composition still to implement. |
| Ziquid chains/EVM/SDK | Chains empty; EVM allocation/general base verifier; SDK export-empty. | Existing roles, explicit new implementation and route qualification; no readiness from tree. |

Host production current graph: runtime→protocol/zcash/proofs, proofs→protocol, zcash→upstream+external Zoss, chains empty. Proofs→zcash is dev-only. Intended target/source/proof responsibilities stay acyclic; runtime composes actual clients, not vice versa.

## 4. Noncosmetic identities and complete caller migration

Preserve native `ZIQUID_DEX_STATEMENT\0`474BE; market `KERBDM01`325LE, role `KERB_*` signing bytes, V2 journal/wire physical-record identities, Solana `KERBSFX1`/account tags and PDA seeds (`pair`,`epoch`,`hold`,`escrow`,`portion`). Preserve migration checksums and exact source fixtures. Code/package path changes do not justify signature/domain rename or reinterpret financial facts.

Required caller categories: every Rust `use crate` relocation, manifests/dev/path deps, guest `#[path]`/`include_bytes`, program/interface/harness refs, CLI current_exe self-spawn, `CARGO_BIN_EXE`, test helper includes, SQL migration source root, fixture config/ELF paths, examples/docs commands. LSP native ActorStore references inspected:38 references include store implementation/tests and inventory example. Follow LSP references for actual exported relocations, never assume textual match equals caller completeness.

Known feature trap: current protocol uses std+default primitive-types and context `encode()->Vec`. New no_std market consumer must not pull std/U256/SQL/source/prover into SBF. Proposed feature isolation: native default preserves old API; market/host features explicit, no_std base and no-default crypto deps. Independent target consumer uses market-only. Fallback additional target-safe crate only if justified actual dependency constraints, not a forwarding façade.

## 5. PostgreSQL cutover hazards

- SQLx0.8.6/Tokio is existing source pattern, no second ORM/backend abstraction. Current Kerb connects Unix socket only and omits TLS feature; it is not ready for user remote URI.
- Use private URI env/file parsing and redacted errors/Debug. Remote TLS/server authentication required according provider; no implicit local fallback or password in subprocess argv/checked-in JSON.
- ActorStore native wei stays BYTEA32/full U256 with Rust checked aggregation; market u64 `NUMERIC(20,0)` cannot replace it.
- Scope lock must exist before competing inserts: actor/asset/deployment scoped parent row + transactional lock, not just locking existing reservation rows. Total capacity counts Reserved/Prepared/Unknown/Armed; only unfunded Reserved cancel releases. Exact retry/immutable context/operation/tx binding remains.
- Separate owned schemas/migration histories: SQLx uses unqualified `_sqlx_migrations`; two unrelated version1 migration sets in same search_path collide. Keep existing market8 files/checksums and separate native inventory schema/history. No arbitrary user search_path or schema adoption.
- Remote durability/ACL/server settings are new trust boundary; SQLite private-path/WAL evidence does not transfer. SQLx commit alone not proof provider fsync/backups/permissions correct.
- Existing tests require socket+CREATE/DROP DATABASE/template copies/restart; must migrate to **explicitly approved URI and isolated scope**, not run blindly against user's DB. SQL test suites marked pending/explicit opt-in; missing URI is not green skipped-test evidence.
- Operational SQLite import needs explicit read-only export/exclusive writer/fence/row-value-state identity reconciliation approval. Empty fresh Postgres must not be called equivalent to old outstanding funding state.

## 6. Full-scope remaining work and real dependencies

Native full all-era genesis validity/acquisition/source acceptance; private preparation/semantic commitments and actual wrapped proof; independent net classifier for every hostile T; actual source excess return; hidden stable one-note uniqueness; actual immutable DEX escrow/client; full manual durable execution/reconciliation. These remain entire-native acceptance, not reduced to happy path.

P2P full private admission/matching: strict own-result-inclusive noninference remains structural FAIL for current useful bilateral/auction construction without substitute capital. This is not an unwritten MPC call. No output waiver/collusion exclusion/nontrading replacement selected. Full implementation needs compatible reviewed mechanism/security contract.

Samechain: new genuine owner/backing/conservation proofs, per-owner common exact-fill semantics, recipient-prepared checked/recoverable outputs, partial successors/capacity/shared cancel across F1/F2, retained authenticated roots/global consumed tags, actual atomic asset transfer/manual drill. It is not current Kerb Solana signatures relabeled ZK.

Crosschain/reverse/Hyperliquid A: exact asset/domain/control/authority/recovery/finality/privacy construction per route; no backward arrow magically gives native ZEC SpendAuth. HyperCore B external spot: exact network/account/market/action encoding, explicit per-action user consent, cancel/partial/Unknown/reservation reconciliation, no broad agent key assumed spot-only.

Retain public LP/provider/agent/ZSA/SDK/UI deferred scope exactly as docs, not silently removed or claimed as implemented. Native manual consumer remains core, not deferred UI. ZSA activation, real target support, qualified issuer/provider/legal/domain decisions cannot be fabricated in code.

## 7. Conditions that cannot be solved by a code-copy operation

1. Concealed hostile-T owners/debits/openings need an actual independently obtainable relation/witness/authority construction. Raw bytes/S IVK/full zkVM do not supply those facts.
2. Returning S-owned received ZEC needs actual source-authorized capability and data/lifetime, not target collateral or Q on old U input.
3. Strict private matching needs compatible useful economics/adversary definition; user already retained strict privacy, so do not ask to secretly weaken it as implementation detail.
4. SQL tests await user URI; runtime proving needs actual local resources/setup assurance; real source notes/history and target actions need separate specific authorization.

All reachable migration/pure/native work remains in scope after plan review. These prerequisites block their dependent completion; they do not authorize fake verifiers, arbitrary negative facts, safe-pending-as-complete or a partial overview labeled final.
