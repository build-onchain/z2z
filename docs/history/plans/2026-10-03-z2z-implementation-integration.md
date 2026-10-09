# Z2Z Implementation Integration Plan

> **Archived V1 supersession — 2026-10-05:** retained dated plan, not the active execution guide. Follow the [Z2Z-V1 implementation prompt](../../Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md); historical requirements, approval boundaries and unchecked tasks remain provenance, not completion evidence.

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge every existing Kerb implementation and caller into the Ziquid base, replace native SQLite persistence with PostgreSQL, and preserve the full Z2Z completion obligations without claiming a code merge solves unresolved protocol constructions.

**Architecture:** Keep five native roles and one `ziquid` application CLI. Import market rules under protocol, effect inspection under zcash, and market ledger/coordinator under runtime; retain an independent Solana target workspace. Share PostgreSQL connection policy, not balances, financial authority or private witness custody.

**Tech Stack:** Rust/Cargo, existing Zcash cohort, SQLx0.8.6/Tokio, PostgreSQL, existing SP1 guests, Solidity EVM primitives and Solana/LiteSVM target.

**Spec:** [Approved integration design](../../superpowers/specs/2026-10-03-z2z-implementation-integration-design.md). Owner selected **Duyệt thiết kế** and subsequently explicitly requested autonomous full implementation with no further routine decision waits. Execute subagent-driven with one integration owner. SQL hold and action restrictions remain unchanged.

## Global Constraints

- PostgreSQL is the only active SQL backend. **No local SQL tests**. SQL integration/migration/restart checks await the owner URI and authorized isolated scope; [SQL-VERIFICATION](../../SQL-VERIFICATION.md) owns that hold.
- Never request/print/commit credentials. URI environment-variable name may be config; URI itself is not argv, diagnostic output or generated child JSON. TLS requires server identity validation; no local/socket fallback.
- Preserve original sibling sources, operational PostgreSQL stores, SQLite journal/WAL/SHM, encrypted custody files and funded proof/program identities. No blanket target cleanup or automatic operational-data conversion.
- Preserve canonical signed/domain/PDA/process/migration bytes. Package/module names change, not `KERB*` byte constants. No compatibility crates, forwarding exports or active `../kerb` inputs remain.
- Exact cohort: Orchard0.15.5, PCZT0.9.3, primitives0.30.1, protocol0.10.5, note-encryption0.4.2. Business Ed25519 acceptance is not historical Zcash acceptance.
- Current native root API defaults remain `native`; target consumers select only `market` with defaults disabled. No runtime/SQL/wallet/prover dependencies in SBF.
- No signing/broadcast/deployment/funding/mainnet/key acquisition/Git initialization/commit/push authorized. Local synthetic fixtures are not live money or source finality.
- Do not run SQL through Cargo defaults, doctests, build scripts or live query macros. SQL targets use `postgres-tests` plus `required-features`; compile-only is allowed, execution is not.
- Do not repeatedly rebuild during delegated edits. Agents finish coherent slices without build/test/lint/formatters; integration owner runs one staged verification pass after all dependent edits. Existing known baseline failure is not rerun merely to confirm it.

## Review Focus

1. Empty-scope concurrent reservations: two processes cannot each spend the same total capacity; Task4 SQL concurrency cases.
2. Pooled temporary tables/missing schema: no accounting or migration fallback into temporary/public relations; Task3 URI-backed cases.
3. Unsupported URI parameters: SQLx parser tracing cannot leak decoded credentials before error sanitization; Task3 pure logging case.
4. Self-spawn after CLI relocation: replica receives `market replica` and stdout contains frames only; Task5 pure argv checks and Task7 actual SQL-backed handshake.
5. Unknown submission after restart: no cancellation, resurrection, changed tx hash or reclaimed capacity; Task4 SQL cases and Task7 process-restart scenario.

## File ownership and dependency order

| Slice | Destination | Source and responsibility |
|---|---|---|
| Task1 | `crates/protocol/src/market/{mod,domain,policy,records}.rs`; protocol Cargo/lib/tests | Kerb protocol4 files, market rules/host signatures; preserve existing native amount/context/allocation. |
| Task2 | `crates/zcash/src/custody/{mod,pczt,projection}.rs`; zcash Cargo/lib/tests | Kerb effect inspector3 files; no signer or financial verifier. |
| Task3 | `crates/runtime/src/database.rs`; `src/market/ledger/{mod,codec,wire,store,replica,target}.rs`; `migrations/market/` | Shared private connection policy plus complete Kerb ledger6 files/eight migrations. |
| Task4 | `crates/runtime/src/store.rs`; `migrations/inventory/0001_inventory.sql`; runtime inventory example/tests | Actual PostgreSQL ActorStore replacement, not market credit conversion. |
| Task5 | `crates/runtime/src/market/{mod,config,coordinator,native,process,target,local,facts,fixture,input_binding_tests}.rs`; main/lib/tests | Complete Kerb runtime/callers, single CLI, process/config adaptation. |
| Task6 | `contracts/solana/{Cargo.toml,Cargo.lock,interface,program,harness}` | Whole existing Kerb target implementation and tests; new destination ELF. |
| Task7 | Existing READMEs/status/SQL verification and consumer test targets | Integrated non-SQL proof first; URI-backed end-to-end only after authorization. |

Task1 is shared prerequisite. Task2 and Task6 are independent after Task1. Task3 requires Task6's pure interface source (not target build); Task4 requires Task3 database contract. Task5 integrates Tasks2–4 and target interface. Max4 agents. Parent owns root/runtime manifests, lock resolution, CLI root and final verification; implementation agents own disjoint modules and submit exact manifest requirements. No concurrent shared-file edits.

Full source inventory is [IMPLEMENTATION-INTEGRATION-REVIEW](../../history/IMPLEMENTATION-INTEGRATION-REVIEW.md); the source trees are authoritative for complete file counts. Preserve source license notices. Migrate all original tests/examples alongside code, including cases not runnable before URI; do not omit failed or inconvenient cases.

## Task1: Target-safe market rules without native API changes

**Files:** root `Cargo.toml`; `crates/protocol/Cargo.toml`, `src/lib.rs`, new `src/market/{mod,domain,policy,records}.rs`, `tests/market_contracts.rs` from Kerb `tests/contracts.rs`; `crates/proofs/Cargo.toml` for example feature gate.

**Interfaces:** existing root native exports unchanged; imported source exports live at `ziquid_protocol::market::*`. Features `native` (default), `market`, `market-host` (implies market). Source `host` cfg becomes `market-host`. `Id`, `Domain`, records, borrowed policy evidence and verification function signatures otherwise unchanged.

- [ ] Read actual LSP references for exported symbols and enumerate independent guest protocol consumers before moving exports.
- [ ] Relocate all four protocol files, rewrite crate-relative imports to the market namespace, retain exact bytes and crypto predicates. Move source contract tests with imports changed only where required; retain consumer-visible cases, remove only incidental/source-text tests if found.
- [ ] Gate native modules/primitive-types/std separately from market/curve dependencies. Shared SHA2 defaults off, native explicitly restores std. Preserve Solana syscall cfg and root unexpected-cfg declaration.
- [ ] Add `[[example]]` with `name="temporary_sprout_ledger_guest"` and `required-features=["sp1-execute"]`; do not change example behavior or enable heavy defaults.
- [ ] Integration owner verifies after edits: `cargo test --offline --locked --release -p ziquid-protocol --features market-host`, then `cargo check --offline --locked -p ziquid-protocol --no-default-features --features market`. Expect unchanged native vectors and migrated market cases pass; independent target build remains Task6 evidence.

## Task2: Preserve PCZT effect inspection in the source role

**Files:** `crates/zcash/Cargo.toml`, `src/lib.rs`, new `src/custody/{mod,pczt,projection}.rs`, `tests/custody_pczt_effects.rs` copied from Kerb `tests/pczt_effects.rs`.

**Interfaces:** `ziquid_zcash::custody::{inspect_pczt,ExpectedNativeEffects,ExpectedNativeOutput,ReservedNativeInput,UnsignedNativeInspection,...}` retain source signatures/borrowed lifetimes. Existing P/Q authoring API and runtime encrypted custody are unrelated and unchanged.

- [ ] Move the complete inspector and its exact dependency features using existing cohort; rewrite imports to `super`/market namespaces, not root reexports.
- [ ] Preserve all effect-mutation rejection cases: input/occurrence/commitment/nullifier, output ciphertext/receiver/value, fee/sighash and exact PCZT bytes. Neither checked metadata nor synthetic proof fields become source-validity claims.
- [ ] Integration owner runs `cargo test --offline --locked --release -p ziquid-zcash --test custody_pczt_effects` and existing zcash lib/tests in final host pass. Expect actual inspection and original rejection semantics, no network or real signing.

## Task3: PostgreSQL connection policy and market ledger relocation

**Files:** runtime manifest/lib, `src/database.rs`, entire `src/market/ledger/`, `migrations/market/0001_safety.sql` through original eighth migration (preserve original filenames/bytes), test/support relocation below.

**Interfaces:** `database::DatabaseConfig` serializes only `uri_env: String`, `schema: String`, `max_connections: u32`; optional provider TLS configuration is represented by paths/nonsecret policy, never credential text. `DatabaseConfig::validate(&self) -> Result<(), DatabaseError>` is pure. Crate-private `connect(&DatabaseConfig) -> Result<PgPool, DatabaseError>` is async and obtains secrets privately. Errors are fixed redacted categories. `Ledger::connect(&DatabaseConfig)` and `Replica::connect(&DatabaseConfig)` keep async source shape; replace source transport struct entirely. Ledger/replica data/method/signature formats remain unchanged.

- [ ] Add pure tests `database_configuration` for invalid schema identifiers and synthetic URI decoding/unknown key/duplicate alias/insecure TLS policy; capture tracing and assert synthetic URI/value never appear. Check occurs before SQLx parsing. No DB connection in this test target.
- [ ] Implement schema identifier rule: ASCII lowercase letter first, then lowercase letters/digits/underscore, max63 bytes; reject reserved `pg_` prefix and `public`. Parse URI query parameters without logging, allow only deliberately supported SQLx parameters, reject schema/session/role override and unknown decoded keys before SQLx sees them. Require verified TLS for remote URI.
- [ ] Implement private pool configuration with pinned `<app>,pg_temp` search_path and implicit catalog precedence; validate scope identity/ownership, set session synchronous_commit on, sanitize connection/query errors. `connect` establishes transport and validates any existing app schema but never creates/adopts/migrates it. A missing schema permits construction solely so explicit `migrate` can initialize it; every operational method first requires valid completed schema identity.
- [ ] Move full ledger implementation; use qualified operational relations and validated identifier construction, not arbitrary SQL interpolation. Preserve serializable transactions, pair locks, existing bounded pre-signature SQL retries and durable ACK-before-export ordering.
- [ ] Explicit `migrate` acquires schema initialization lock, creates only authorized absent schema or validates recognized existing schema, refuses foreign/partial objects, and executes original migrations under the pinned namespace. Temporary relation/type collisions must reject before unqualified SQLx history/migration access. Runtime migration path becomes `migrations/market`; distribution must include these bytes as existing source pattern requires.
- [ ] Move ledger tests as `market_postgres_{epochs,lifecycle,native_conflicts,policy,postgres,replicas,target}.rs`; migrate common helpers to `tests/market_support/ledger.rs`. Inspect mixed files and keep genuinely pure cases outside SQL-only targets. Gate all SQL targets explicitly; no skipped-green path if deliberately invoked without authorization/configuration.
- [ ] Replace source test CREATE/DROP DATABASE/template helpers with uniquely named authorized schemas. No public-schema assumptions; cleanup limited to created schema. Preserve logically independent writer/replica histories, without claiming independent operators from one DB.
- [ ] Compile with `cargo test --offline --locked --release -p ziquid-runtime --features postgres-tests --no-run`; do not execute. URI-backed cases cover concurrent initialization, foreign/partial rejection without mutation, migration checksum preservation, temp relation/type shadowing, missing app relation, pool reuse and existing ledger invariants. Record all as NOT RUN until authorized URI.

## Task4: Actual PostgreSQL native inventory cutover

**Files:** `src/store.rs`, new `migrations/inventory/0001_inventory.sql`; replace `tests/store.rs` with feature-gated `tests/postgres_inventory.rs`; update `examples/inventory.rs`, runtime manifest, public exports and every LSP caller.

**Interfaces:** `InventoryScope { actor: [u8;32], asset: [u8;32], deployment: [u8;32] }`; `ActorStore::connect(DatabaseConfig, InventoryScope) -> Result<Self,StoreError>` async; `migrate(&self) -> Result<(),StoreError>` async. Existing reservation/funding enums and returned record fields remain. `reserve(&mut self, order_id, context_digest, amount:NativeAmount, available:NativeAmount)`, `cancel(&mut self,order_id)`, `prepare_funding(&mut self,order_id,operation_id,unsigned_payload_digest)`, `mark_submission_unknown(&mut self,operation_id,transaction_hash)`, `mark_armed(&mut self,operation_id,observed_context_digest)` become async with original Result types. Read methods `reservation(&self,order_id)` and `funding(&self,operation_id)` also become async, original option results retained. All IDs/digests are `[u8;32]`.

- [ ] Preserve original money/state regression cases when moving tests. Drop obsolete SQLite/path ACL tests only for removed SQL backend; keep runtime encrypted-file custody ACL tests unchanged.
- [ ] Implement separate inventory schema/history with explicit actor/asset/deployment key, parent scope row, reservations and operation uniqueness per scope. BYTEA32 amounts stay full U256 BE; constrain lengths/nonzero/state-nullability in SQL and checked decode in Rust.
- [ ] Use READ COMMITTED transactions for native scope operations with parent scope row acquired/locked before any aggregate/read/update; after waiting for the lock, issue subsequent statements with fresh snapshots. Parent insertion uniqueness serializes empty-scope initialization. Scope identity cannot be changed by an operation. Do not reuse market SERIALIZABLE retry behavior blindly across externally visible native actions.
- [ ] Preserve immutable retries including Cancelled, total active-capacity aggregation/overflow, prepared fence before export, unknown tx binding, no Armed downgrade, context-bound arming and Reserved-only cancellation. No terminal-release method added.
- [ ] Update actual inventory example to explicit private config/scope and async calls; no implicit fresh-store replacement for old funded inventory. Remove rusqlite dependency/backend and obsolete store filesystem helpers after every caller migrates; old journal files remain untouched.
- [ ] Compile SQL tests only. Required later URI assertions: with cap10 two concurrent reserve7 attempts yield exactly one durable reservation and one insufficient-capacity outcome; active states keep capacity after reconnect; same IDs in distinct scopes cannot read/mutate each other; reserve U256::MAX succeeds within exact cap, another1 overflows/rejects without mutation; replay never resurrects Cancelled; wrong context/hash/payload/operation leaves prior state unchanged.

## Task5: One CLI and complete runtime/caller cutover

**Files:** `src/main.rs`, `src/lib.rs`, entire `src/market/` source runtime group, runtime manifest, migrated tests/support/fixtures and examples.

**Interfaces:** `ziquid allocation A D C` retains output/status. Six commands under `ziquid market`: `migrate`, `replica`, `inspect-ledger`, `inspect-pczt`, `reconcile`, `local-safety-scenario`, with exact arguments in spec §4. Source market Error/Result remain namespaced, not merged with native custody errors. Child argv `market replica --config PATH --local-fixture-key-stdin`; stdout binary framing unchanged.

- [ ] Move entire runtime implementation, replacing all crate-root anchors with correct market-local modules; coordinator uses relocated actual inspector/ledger/interface, never mock or sibling import.
- [ ] Migrate config from raw socket fields to Task3 config; preserve private file checks and immutable policy/domain checks. Child config contains URI environment reference/schema, never resolved URI; child inherits only intended credential environment and no diagnostic echo.
- [ ] Adopt names once: `Z2Z_TEST_NATIVE_DIR`, `Z2Z_TEST_SOLANA_BIN`, `Z2Z_SBF_ELF`, `Z2Z_RUNTIME_BIN`, `Z2Z_TEST_DATABASE_URL`. Update every setter/reader, CARGO_BIN_EXE reference, fallback path, fixture include and current_exe invocation. No old aliases. Preserve all KERB-prefixed wire bytes.
- [ ] Copy public synthetic `policy.json`/`unsigned.pczt` to `tests/fixtures/market/` with provenance; never copy private keys, journals or produced proof artifacts. Migrate pure tests to `market_configuration.rs`, `market_native_diagnostics.rs`, `market_native_binding.rs`. Keep native_binding pure despite its ledger type imports.
- [ ] Move SQL tests to `market_postgres_local_flow.rs`, `market_postgres_process_liveness.rs`, `market_postgres_solana_safety.rs`; internal input_binding_tests compiled only under `cfg(all(test,feature="postgres-tests"))`. Shared runtime helper lives at `tests/market_support/runtime.rs`; update all path includes and inventory-binding fixture paths.
- [ ] Move restart example to `examples/market_postgres_restart.rs`, feature-gated; it must not restart a server itself or imply URI grants restart permission. Preserve explicit operator rendezvous with sanitized instructions.
- [ ] Integration owner runs actual allocation CLI (expect10000000/20000000 for6000000/30000000/2000000), actual `market inspect-pczt` on the copied synthetic fixture (effects-checked; signing/proofs/history/broadcast false), help/error cases and pure migrated tests. Replica DB handshake and coordinated safety scenario stay pending Task7 URI execution, not replaced with mock echoes.

## Task6: Destination-built Solana program/interface/harness

**Files:** complete source `contracts/solana` manifests/lock and interface/program/harness sources/tests, paths changed to destination protocol market; existing target README updated only after observed build.

**Interfaces:** packages `ziquid-solana-interface`, `ziquid-solana`, `ziquid-solana-harness`; source `process_instruction`, interface types and harness transport unchanged. Target output `target/z2z-sbf/ziquid_solana.so`; harness still exposes `local-safety-scenario`. Fixture program identity/PDA seeds do not change with file name.

- [ ] Import full group with source edition/profile/dependency pins. All target protocol dependencies use defaults=false/market only. Preserve interface host consumers from Task3 without importing runtime into target.
- [ ] Update `Z2Z_SBF_ELF` fixture lookup, all test imports and program artifact paths; retain independent compiler settings and maintain lockfiles coherently. No original ELF/keypair overwrite or private key reads.
- [ ] Integration owner runs `cargo-build-sbf --manifest-path contracts/solana/program/Cargo.toml --tools-version v1.57 --arch v0 --sbf-out-dir target/z2z-sbf`; actual source-selected toolchain must be available, no fabricated build. Build independent harness against current manifests.
- [ ] Run interface suite separately, then `Z2Z_SBF_ELF=<absolute destination ELF> cargo test --offline --locked --manifest-path contracts/solana/Cargo.toml -p ziquid-solana-harness --test compiled_elf -- --test-threads=1`. Expect preserved authorization/recipient/partial/cancel/CPI rollback cases against new ELF, not source sibling binary. No network deployment or owner-ZK settlement claim.

## Task7: Integrated verification, SQL hold and truthful delivery

**Files:** root/runtime/target README command sections, `docs/NATIVE-IMPLEMENTATION-STATUS.md`, `docs/SQL-VERIFICATION.md`, relevant module/architecture/blocker current implementation descriptions.

- [ ] Integration owner resolves Cargo locks once after shared-file integration; check no active sibling Kerb dependency/input, stale CLI alias or SQLite backend remains. Preserve external Zoss dependency. Verify migration fixture byte identity against source originals; no unrelated cleanup.
- [ ] Run pure host workspace tests/all-targets with PostgreSQL feature disabled and synthetic fixture env configured. Run selected SP1 feature compile separately, respecting existing resource limits; no claim guest proof passed from host compile. Run Task5 real CLI and Task6 target scenarios. Compiler/lint passes are not financial proof.
- [ ] Compile PostgreSQL targets with `--no-run`. Until authorized URI, report SQL NOT RUN, not merged lifecycle complete. Request endpoint through private configuration only when available, plus schema-scope test permission; do not echo URI or provision local substitute.
- [ ] After URI/scope authorization only, execute all migrated SQL suites and actual single-CLI safety scenario with writer+three replica schemas, checked fixture input effects and destination-built target. Reconnect/cold process restart must retain exact unknown/prepared records and replay heads. Do not call process restart a server restart; latter requires separate explicit authorization.
- [ ] Obtain independent review of changed code against approved spec, with particular attention to authority boundaries, amounts, URI leaks, feature graph, caller closure and schema concurrency. Address findings before completion claim.
- [ ] After runtime smoke, update existing docs with exact commands/results and unresolved gates; remove throwaway probes. No final full-product overview yet unless every full-product obligation below has direct evidence.

## Full Z2Z continuation: required work, not invented implementation instructions

Tasks1–7 do not narrow the user objective. They are the executable consolidation subproject. The following dependent subprojects remain required; no honest method signatures/implementation steps can substitute for missing financial/privacy constructions. Each must receive a concrete reviewed construction/spec and runnable acceptance plan before architectural implementation. Existing approved native plan remains applicable where its assumptions are actually satisfied.

| Required deliverable | Current prerequisite to resolve | Acceptance that must eventually run |
|---|---|---|
| All-era native history and acquisition | Complete applicable consensus/era transition relation and source acceptance/finality policy; no SPV/arbitrary checkpoint fallback. | Connected valid history plus rejected invalid transitions, matching host/guest statements and actual composed proof. |
| Native financial classification/uniqueness/recovery | Independently available hostile-T owner/debit/opening evidence; actual S-authorized received-ZEC excess return; composed prep/net/tag relation. | Full, partial, zero and excess consideration; conflicting spends; missing/invalid witness rejected; independent terminal recovery and actual excess transfer, no Q-on-old-input substitute. |
| Native target/client/manual execution | Real accepted financial certificate and immutable target rule/recipient/lifetime binding. | Prefund/arm before P release, atomic one-note consumption and exact transfers, failed transfer retry, cold company-off restore/prove/submit/reconcile. |
| Private P2P admission/matching/partial/cancel | Current GD2 construction fails strict own-result-inclusive privacy; compatible useful economics/security definition remains unresolved, no waiver granted. | Meaningful matching plus adversarial own-result inference checks, no double allocation, preserved cancel/partial rights and chosen actual settlement. |
| Samechain owner-proof assets and confirmed resting maker | Maker signs once at order opening; takers must fill many portions while maker offline within signed limits. Current dual-fresh-consent proofs need new standing input authority/recoverable variable-output construction; preserve old artifact identities. | Maker opens/backs/signs once → offline → multiple independent takers settle partial fills without further maker signature → recover all receipts/conserved remainder → cancel residual/race/replay/company-off exit. Real atomic backed effects and strict privacy required; no secret delegation or database-only standing claim. |
| Reverse/crosschain/Hyperliquid P2P routes | Exact per-direction source authority, asset/history/privacy/recovery construction; cannot invert native settlement arrow. | Both assets delivered/recovered under adversarial interruption with independent owner data/capability. |
| External HyperCore spot | Qualified network/market/action encoding and explicit per-action consent, exact nonce/fee/reconciliation policy. | Partial fills/cancel/Unknown/restart/manual venue path; no broad agent key misrepresented as spot-only, no automatic venue fallback. |
| Runnable software/server and owner-local frontend integration | Define reviewed public backend API/process lifecycle and secure owner-local companion boundary over existing native runtime; no hosted owner keys/witnesses. CLI is manual/ops path, not final product substitute. | Launch actual long-running service and owner-local software; frontend uses real actions/data/status; exercise input/auth/errors/restart/Unknown and actual permitted outcome; company-off CLI preserves same rights. No fixture financial fallback or SQL-local workaround. |
| Other documented workstreams | SDK/UI/bindings/LP/provider/agent/ZSA remain deferred as canonical docs specify; retain activation/asset/legal/provider gates. | Workstream-specific accepted behavior when activated; do not count placeholders or erase roadmap. |
| Final whole-product report | All required work above and SQL/target/company-off/security evidence complete. | Report exercised end-to-end behavior, exact limitations and separate action permissions; never sum isolated tests into a finished exchange. |

**Execution state:** latest user explicitly selected autonomous implementation with no further routine decision waits; subagent-driven source Tasks1–6 are implemented and independently reviewed. Pure host/actual target/guest smoke evidence is recorded in [status](../../NATIVE-IMPLEMENTATION-STATUS.md); PostgreSQL targets compile but SQL lifecycle remains NOT RUN pending private URI/scope. Task7 and all full-product continuation rows remain incomplete where that direct evidence or sound construction is absent. No full-goal completion or external action authorization is inferred.
