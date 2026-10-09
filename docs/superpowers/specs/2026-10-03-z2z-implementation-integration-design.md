# Z2Z implementation integration and full completion design

> **Status — 2026-10-06:** owner-approved design, still not an action grant. Active lanes are native ZEC (L-ZEC, first-class, not V2), L-HEVM, L-SOL, L-NEAR and X.CROSSCHAIN; the whole project stays incomplete until every lane passes.

**Status: owner-approved design, 2026-10-03.** Owner selected **Duyệt thiết kế** after reviewing the written integration proposal. [Implementation plan](../../history/plans/2026-10-03-z2z-implementation-integration.md) now awaits separate owner review and execution-method selection. User requests merging all Kerb and Ziquid implementations into existing Ziquid base, then completing the entire Z2Z product per canonical docs/plans. This is not approval to weaken strict privacy, native financial requirements or server-off independence; not deployment/signing/funding/production-database migration authorization.

**Latest owner requirement:** PostgreSQL is the only active SQL backend. **No local SQL tests**. SQL verification awaits an owner-provided URI via private configuration and authorized isolated scope; [SQL-VERIFICATION](../../SQL-VERIFICATION.md) owns that hold. A URI contains credentials and must not be requested/printed/committed in chat/source/argv/logs. Final overview is delivered after actual completion; an unverified merge is not the final product.

## 1. Full objective and known design limits

The goal includes central P2P market, native RFQ/crosschain settlement, proposed samechain owner-proof execution, owner manual company-off path and the other selected workstreams—not only local safety code. [PRODUCT](../../PRODUCT.md), [ARCHITECTURE](../../ARCHITECTURE.md), [SERVER-INDEPENDENCE](../../SERVER-INDEPENDENCE.md), [MODULES](../../MODULES.md), [BLOCKERS](../../BLOCKERS.md) and [native status](../../NATIVE-IMPLEMENTATION-STATUS.md) define scope/authority. [Source integration review](../../history/IMPLEMENTATION-INTEGRATION-REVIEW.md) maps current code, real baseline and hazards.

The consolidation below is fully specified for existing behavior. Whole-product completion additionally requires constructions **not supplied by the current implementations**:

- Private matching under unchanged strict own-result-inclusive noninference and useful limit-respecting trade. Current candidate GD2 is structurally failing; copying MPC/bookkeeping does not solve it.
- Independently obtainable terminal classification/recovery for every hostile shielded mixed-input T; raw source/S IVK cannot reveal missing ownership/value/debit witnesses.
- Actual independently usable S-authorized source ZEC excess return for C>A; target escrow cannot sign the received source note, Q controls only old U input.
- Real samechain per-owner ownership/conservation/common-fill proof composition and exact target relation; source safety-roster signatures are not that relation.
- Full all-era validating source proof/acquisition/finality policy, local actual wrapped proofs/resources/setup assurance, full financial target/client/manual execution.

These remain explicit full-goal blockers, not reduced acceptance. Independent reachable integration/native work can proceed after review; enablement cannot pretend missing capability exists. Deferred SDK/UI/LP/provider/agent/ZSA stay in the documented scope/roadmap, not silently erased or counted implemented.

## 2. Chosen integration shape

**One codebase, existing five native roles, one application CLI; no duplicate live Kerb package tree or compatibility forwarding crates.** Retain the source sibling unchanged for provenance/verification and operational records, not as an active implementation dependency of merged code. No blanket Kerb→Z2Z text rename: source cryptographic domains and migrations keep identity.

```text
crates/protocol/src/
  allocation.rs amount.rs context.rs       existing native public API
  market/{mod,domain,records,policy}.rs    imported target-safe legacy-market rules
crates/zcash/src/
  ...existing P/Q/witness/source...
  custody/{mod,pczt,projection}.rs         imported effect inspector, not signer
crates/runtime/src/
  custody.rs                             existing encrypted owner-local files
  database.rs                            private PostgreSQL config/connection/schema policy
  store.rs                               native ActorStore PostgreSQL, not market credit
  market/
    mod.rs config.rs coordinator.rs native.rs process.rs target.rs
    local.rs facts.rs fixture.rs input_binding_tests.rs
    ledger/{mod,codec,wire,store,replica,target}.rs
crates/runtime/migrations/
  market/0001..0008                       original bytes/versions preserved
  inventory/0001_*.sql                    native scoped reservations, separate history
contracts/solana/
  Cargo.toml Cargo.lock                   actual independent target workspace
  interface/ program/ harness/            complete original group, current package names
```

Names `ziquid-*`/binary `ziquid` stay while product is Z2Z. Target packages become `ziquid-solana-interface`, `ziquid-solana`, `ziquid-solana-harness`; artifact filenames follow Cargo but **program IDs/PDA/record/signature bytes do not rename**. No source keys or produced ELF/setup/journal copied as ordinary source. Source fixtures `unsigned.pczt`/`policy.json` have documented public synthetic provenance; copy them with attribution, not private operational data.

### Source ownership contracts

| Source | Destination | Contract preserved |
|---|---|---|
| Kerb pure protocol4 files | `ziquid_protocol::market` | Exact Domain325LE/record widths, role-separated ordinary signatures and safety predicates. Native474BE context remains different. |
| Kerb custody3 files | `ziquid_zcash::custody` | `inspect_pczt`/ExpectedNativeEffects/checked identities; no proof/sign/history claim or U-FVK sharing permission. |
| Kerb ledger6 files+8 migrations | `ziquid_runtime::market::ledger` | Actual PostgreSQL journals/replicas/physical inventory/holds/portions; no cast into native facts or owner-proof notes. |
| Kerb runtime library+CLI caller logic | `ziquid_runtime::market`, single `ziquid market …` CLI | Framing/timeout/reconciliation and explicit LocalFixture limitations; current_exe self-spawn correctly prefixes market. |
| Kerb Solana3 packages | existing independent target tree | Public legacy-SPL escrow with3 business ACK signatures, exact effect/account checks, actual target transfers; not private owner-ZK escrow. |
| Native SQLite ActorStore | same native module, async PostgreSQL | Full U256/total-cap/reservation/prepared/Unknown/armed/idempotence behavior, distinct from market credit. |

All source tests/examples/fixture references migrate with their consumer. Maintain original implementation source inventory and reviewed relocation map; no optional source file omitted because it is inconvenient to test. Existing target source README is a historical slot description to update after actual target compilation.

## 3. Protocol feature isolation and dependency graph

`ziquid-protocol` default `native` keeps existing allocation/amount/context root exports unchanged. `native` enables primitive-types/std/alloc only for existing host/guest consumers. `market` enables target-safe market modules and curve dependencies; `market-host` adds actual Ed25519 verification and implies market. `#![cfg_attr(not(feature="native"), no_std)]` or equivalently explicit std feature must satisfy actual SBF compiler without changing native serialization/Vec API. SHA2 must have defaults off at the shared dependency declaration; features enable std only in native host builds. Native modules are cfg-native; no target accidental mandatory primitive-types/std.

Solana program/interface/harness consume `default-features=false, features=["market"]`; host runtime consumes native+market-host. Guest preparation still consumes native-only default, not market-host; no feature-unified host runtime stack in target builds. Module imports referencing source crate root must be migrated to `market`/`custody`/`market::ledger` scopes, not wildcard reexport shims.

`zcash` may depend on pure protocol market (already allowed intended graph); source/proofs/chains never depend on runtime. Runtime composes source/proofs/chains; target interface is shared pure format/PDA responsibility, not database/network. Keep exact common cohort Orchard0.15.5/PCZT0.9.3/primitives0.30.1/protocol0.10.5/note-encryption0.4.2. No crypto upgrade or ordinary Ed25519 substitution into historical Zcash legacy verifier.

## 4. One CLI and process contract

Existing `ziquid allocation A D C` success/error semantics stay. Real market operations become:

```text
ziquid market migrate --config PATH
ziquid market replica --config PATH --local-fixture-key-stdin
ziquid market inspect-ledger --config PATH
ziquid market inspect-pczt --config PATH --pczt PATH
ziquid market reconcile --config PATH --local-fixture-keys-stdin
ziquid market local-safety-scenario --config PATH
```

These are target interfaces to implement, not current commands. Market dispatch uses current-thread Tokio. Replica stdout remains framed binary only, no help/log leakage. Self-spawn uses `["market","replica",…]`; every test/current_exe/env/CARGO_BIN_EXE caller uses the single binary. No `kerb-runtime` shim.

Keep wire magic/frame limits/role signatures (`KERBFX01`, `KERBRD01`, `KERBER01`, `KERBSTOP`, fixed ACK bytes/target line schema) unchanged because they are encoded consumer contracts. Nonsecret test/config env names cleanly cut over to `Z2Z_TEST_*` once; source historical docs keep old names as history. Raw URI never in command line or generated config; config names an environment variable/reference, schema and actor scope only.

## 5. PostgreSQL-only design

### 5.1 Connection, schema identity and secret policy

Reuse SQLx0.8.6/Tokio. `runtime::database` owns URI acquisition and validated schema configuration, PgPool setup, redacted error categories and migration preflight. Callers hold a non-Debug secret connection capability; serialize only environment-variable name/schema/profile metadata to child configs, not DSN. Children inherit explicitly allowed environment for URI; do not log environment/connection options. Existing fixture transport bytes are not changed to carry credentials.

Remote URI parsing must require PostgreSQL scheme and provider-compatible TLS/server validation; enable an actual SQLx TLS backend. Reject query settings that undermine selected schema/role/SSL policy; do not silently disable TLS, accept-invalid or fallback Unix socket/local default. Exact service/TLS root and authorized DB scope will be checked when URI is supplied; no live connection or test occurs now.

Before invoking SQLx's URI parser, parse without logging and validate percent-decoded query keys against an explicit supported-parameter allowlist; reject unknown keys, duplicates/aliases with conflicting values, and forbidden overrides using a fixed redacted error. SQLx0.8.6 `sqlx-postgres/src/options/parse.rs:107` logs unknown key/value pairs during parsing, before a caller can sanitize returned errors. Never pass unknown provider parameters through. After implementation approval, a no-database check must capture tracing output while parsing a synthetic unsupported credential parameter and assert that neither its synthetic value nor the URI appears, and that rejection occurs before SQLx parsing. No real credential is used by this check.

Use separate owned schema families for native inventory and market ledger/each replica: e.g. explicitly configured validated identifiers `z2z_inventory_*`, `z2z_market_*`. Pin each connection to `search_path=<validated application schema>,pg_temp`, with `pg_catalog` omitted so PostgreSQL implicitly searches it first while unqualified CREATE still targets the application schema. Validate schema existence/ownership before migrations; explicitly qualify operational relation access, and reject temporary relation/type collisions before running unchanged unqualified migration SQL, including SQLx `_sqlx_migrations` access. Do not expose pooled connections for arbitrary SQL or allow caller-controlled extra search paths. No loose SQL interpolation except validated identifier quoting from a restricted ASCII identifier validator. Schemas must be app-owned/no unrelated writers; no create/adopt foreign/nonempty schema on connect. Explicit initialization uses transaction/advisory lock and checks identity/migration table before applying migrations. SQLx `_sqlx_migrations` is isolated per schema; source market versions/checksums remain1–8. New native inventory history starts1 only in its own schema. Lookup/CREATE behavior follows [PostgreSQL18 search_path documentation](https://www.postgresql.org/docs/18/runtime-config-client.html#GUC-SEARCH-PATH), retrieved2026-10-03; this is source evidence, not executed SQL verification.

Target tables/views contain IDs/digests/accounting only, never user source FVK/keys/Q/private proof witnesses. A remote database operator sees stored journal metadata; disclose this privilege and keep actor keys/files private. PostgreSQL does not reproduce Linux per-file ACL privacy by itself.

### 5.2 Native ActorStore

Proposed typed shape:

```rust
pub struct InventoryScope { actor: [u8; 32], asset: [u8; 32], deployment: [u8; 32] }
impl ActorStore {
    pub async fn connect(database: DatabaseConfig, scope: InventoryScope) -> Result<Self, StoreError>;
    pub async fn migrate(&self) -> Result<(), StoreError>;
    // reserve/reservation/cancel/prepare_funding/funding/
    // mark_submission_unknown/mark_armed preserve arguments/result semantics;
    // all become async and use shared scope binding.
}
```

Fields supplied by caller are identity bindings, not chain-authenticated facts. `asset` is an exact selected native asset descriptor digest, not symbol; route/runtime must prove scope matches actual deployment before financial operations. Same scope serialized across process connections by stable parent row locked `FOR UPDATE` **before** aggregate/read/new insert. Scope creation transaction/uniqueness prevents empty-scope race. Reservation primary key `(scope,order_id)`, operation uniqueness `(scope,operation_id)`; immutable context/amount/payload/hash bindings. Distinct scopes cannot pool capacity or steal a reservation. Checked summed active amounts are32-byte BE U256; overflow rejects, total cap includes every Reserved/Prepared/Unknown/Armed row. Schema enforces byte lengths/state-nullability/positive amount, not numerical narrowing.

Use explicit SERIALIZABLE transactions or correctly serialized scope lock with documented isolation; follow existing SQLx serialization/deadlock classification. Do not add automatic retry across any signature/network/external effect. Commit prepared intent before return/export. Exact replay returns existing record including Cancelled; never resurrect. Only Reserved→Cancelled releases capacity; Unknown/Armed remain locked, mark_armed caller testimony not source/target verified settlement. No new terminal-release API from this storage refactor.

Durability requires `synchronous_commit=on`, server durability/role/backup assumptions documented and eventual URI validation; never silently alter operator global settings. Connection errors don't expose DSN/query/private records. Original `store.rs` SQLite filesystem helpers/tests become obsolete only after all callers cut over; encrypted-file custody ACL code remains unchanged.

### 5.3 SQL test segregation and operational data

SQL-specific test targets are explicitly opt-in under feature `postgres-tests` and named `postgres_*`/`market_postgres_*` with Cargo `required-features`; never reachable by ordinary default pure test command. They fail a deliberately invoked SQL suite if secure URI/scope authorization is absent, never silently skip green. `--all-features` must not be used to run tests now. Compile-only SQL checks may run with `--no-run`; no build-time live SQL macros or schema prepare before URI.

Split mixed unit/integration tests into pure and SQL suites; no “skipped=pass” reporting. SQL test harness uses approved URI/role and unique schemas (not CREATE/DROP DATABASE or TEMPLATE unless separately granted). Cleanup drops only its own generated schema after explicit test-scope authorization. Server restart test remains pending until restart authorization; reconnect/process restart is not mislabeled server restart.

Pending URI-backed schema regressions must exercise a same-named temporary `_sqlx_migrations`/ledger relation, an absent application relation, and a conflicting application-schema built-in name. Expected behavior: no temporary fallback or redirected accounting; built-ins resolve through `pg_catalog`; unchanged migration CREATE targets only the authorized application schema. These checks remain NOT RUN until URI/scope authorization.

Preserve existing source PostgreSQL DBs, SQLite journal/WAL/SHM and encrypted custody files untouched. Code cutover does not move operational records. Future data cutover requires separately authorized exclusive old writer fence, read-only consistent export/schema identity, externally bound scope, every live/Cancelled row/amount/operation identity, transactional idempotent import and reconciliation evidence. No dual-write fallback; fresh empty PostgreSQL is not declared free capacity equivalent to an old funded store.

## 6. Preservation and baseline repair

No whole-target cleanup: original sender/preparation/Sprout/legacy/ledger ELF/VKeys/public setup/private proving outputs/funding journal remain protected. Source Kerb keypair file is not copied/read. Retain both original lockfiles as provenance, resolve destination root lock additively/coherently and target lock independently; no overwrite existing richer native lock wholesale. Rebuilt artifacts may have new identity, never replace funded pinned identity silently.

Existing `temporary_sprout_ledger_guest` unconditionally imports optional SP1-execute deps. Correct with explicit `[[example]] required-features=["sp1-execute"]` while preserving source file/behavior, no default heavy feature enablement. Verify normal pure host suite and feature-enabled compile separately within resources. Do not rerun known baseline failure merely to rediscover it.

## 7. Full completion dependency graph

| Workstream | Required implementation outcome | Prerequisites / no substitute |
|---|---|---|
| Merge and SQL cutover | All original implementation/callers local to base; single CLI; no_std target; coherent source/host/target tests; PostgreSQL-only actual persistence. | This reviewed design/plan; SQL URI tests pending not waiver. |
| Native source validity | Genesis→all applicable eras→Ironwood complete consensus state/history acquisition and accepted-history relation, recursion/state commitments. | No SPV or arbitrary trusted checkpoint; correct parser/equations not global canonicality. |
| Native financial proofs/recovery | Genuine prep/meaning/tag/ownership/net classifier, all-hostile independently terminal, actual S-authorized excess return. | Missing info/authority construction must be resolved; no fabricated owner labels, indefinite-pending completion or Q excess refund. |
| Native financial target/client | Real composed accepted certificate, immutable arm+one-note reservation, atomic fixed U/S transfers/retry, exact EVM client/wallet P-release. | Actual proofs/program/schema, history/finality, local resources and separate action permissions. |
| P2P market | Actual admission/discovery/feasible private matcher/partial allocations, no-double-use, selected settlement route and company-off rights. | GD2-compatible useful mechanism; no RFQ/public Core substitution under private-market label. |
| Samechain owner-proof execution | Qualified exact assets, real per-owner semantic proof composition/consent, correct recipient outputs, conserved successors/global cancellation/root history, target+manual execution. | Concrete relation/crypto/target qualification and resource evidence; not source business ACKs. |
| Reverse/crosschain/Hyperliquid A | Source/destination control/payout/recovery, exact native/programmable asset qualification and independent witnesses per direction. | Explicit independent source authority, not inverted native arrow or generic proof. |
| HyperCore B | Exact per-action signed spot workflow, token/account/network/nonce/fees, actual partial/cancel/Unknown reconciliation/manual native venue path. | Qualified network/market/account/actions; no broad agent signer asserted spot-only, no perps/automatic fallback. |
| Native manual operator-independent runtime | Cold restore/private data/artifacts, independent state/history, local prove/submit/retry/final transfers with company services absent. | Actual route capabilities and data/prover availability; code hash/root alone insufficient. |
| Deferred product scope | SDK/UI/bindings, LP/provider/agents/ZSA/additional targets tracked under current docs, not falsely completed or deleted. | Workstream activation/eligibility/source consensus/provider/asset choices and specific authorization; not blockers of narrower native completion but remain full-product roadmap. |

## 8. Verification and approval gate

Non-SQL preserved baseline:146 native selected tests and27 Kerb protocol/custody tests passed; native allocation actual output10,000,000/20,000,000. Those are old separate implementations, not merged proof. Default all-target failure and canceled local SQL run are recorded in integration review.

After approved edits: compile/pure tests/lint/target build and actual non-SQL CLI/PCZT/target-VM smoke; SQL suites **compiled only and marked NOT RUN pending URI**; complete end-to-end/financial/company-off/private-market verification still required before full-goal completion. Independent review covers byte/caller/feature/schema/URI/identity and money authority transitions. No permanent mock verifier or prepared scaffold can be delivered as complete.

Owner has approved this integration shape and PostgreSQL policy. The linked implementation plan still needs owner review and execution-method selection before new architectural code. Design approval does not resolve missing financial/private constructions or grant transactions/funds; the full Z2Z goal remains incomplete until direct evidence covers every applicable deliverable.
