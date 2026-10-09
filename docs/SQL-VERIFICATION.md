# PostgreSQL verification — isolated Docker tests exercised

**User instruction, 2026-10-03:** mọi SQL persistence dùng **PostgreSQL**; **không chạy SQL tests tại local**. User sẽ cung cấp URI sau. Yêu cầu này supersede SQLite backend direction và local PostgreSQL testing commands trong tài liệu/plans cũ; historical results giữ ngày/scope, không bị đổi thành kết quả hiện tại.

**Scoped owner approvals, 2026-10-06 (latest):** after “Prepare private test environment; approve isolated tests”, the owner instructed “i just opened Docker and enable postgres container please use it to test instead”. This supersedes the earlier local/Docker endpoint ban **only for the already-running owner-selected container** (`postgres`, parent-observed ID `621cc7e67d78`, published port5432). Existing gated PostgreSQL tests may create/drop only their own isolated test schemas after private connection inputs, verified TLS/server identity, authorized safe prefix and `Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES=yes` are qualified. This does not authorize installation, container/service start/restart/reconfiguration, operational migrations/resets, production secrets, proving, transactions or funds. Strict runtime TLS/URI validation is unchanged; selecting a container does not waive it.

**Subsequent explicit approval, 2026-10-06:** owner selected “Configure TLS and restricted test role”. Test-only TLS and a restricted role were provisioned in that existing container, with a configuration reload and no server/container restart. PostgreSQL18.4 authenticated the restricted role over verified TLS1.3; production `VerifyFull` remains unchanged. Credentials and keys remain outside the repository and are not printed.

## 1. Trạng thái hiện tại

- The selected Docker endpoint is qualified. Actual test processes receive the private URI, authorized `z2z_release_20261006` prefix and schema-change opt-in through their child environment.
- **Final complete runtime run:** `cargo test --locked --offline -p ziquid-runtime --features sp1-local,postgres-tests -- --test-threads=1` passed373 primary tests across42 nonempty suites, with7 ignored subprocess/manual-qualification entries. All eleven PostgreSQL integration targets, release journal7 and release CLI8 passed against the selected restricted role over verified TLS. `cargo clippy --locked --offline -p ziquid-runtime --features sp1-local,postgres-tests --all-targets -- -D warnings` passed. Includes real process restart/reconciliation, migration/adoption rejection, CAS, replica retention, inventory constraints and committed-release-before-key-read. It is not a successful genuine certificate or funded trade.
- Trước khi nhận instruction, đã khởi chạy baseline Kerb sử dụng service PostgreSQL local hiện hữu. Lượt chạy đó **đã bị hủy ngay khi user yêu cầu không test local**, không dùng làm passing evidence.
- No new container, package installation, unrelated local store, operational migration/reset or server restart was performed. Only the explicitly approved TLS/role preparation and owned disposable test schemas were changed; TLS/role artifacts remain in use.
- Compiler, Rust pure tests, crypto/parser tests và target local-VM tests không truy cập SQL có thể chạy riêng. Không dùng `cargo test --workspace --all-features` khi nó tự gọi SQL tests trước khi URI được cấp phép.
- Actual runtime now uses SQLx PostgreSQL for scoped native ActorStore and market/replica journals; active rusqlite/backend/path callers removed, old files preserved. Eight market migrations are byte-identical to source; native inventory has a separate version1 history.
- Earlier release-profile compile-only results remain historical. The current debug-profile runtime SQL tests now have actual execution evidence above.
- **2026-10-06 implementation fixes:** shared schema fingerprint SQL explicitly casts PostgreSQL internal `"char"` catalog fields to text. Contaminated pooled sessions are rejected through SQLx's graceful-close path, avoiding an idle-TLS hard-close acquisition timeout without weakening schema validation. The actual inventory example retained `SubmissionUnknown` after reconnect and refused cancellation. PostgreSQL server restart and genuine proof/funded acceptance remain unexercised.
- **2026-10-09 native trade addition:** `NativeTradeStore` now has a separate digest-only version1 schema and encrypted quote/operation custody with selection AAD2, CAS/takeover and permanent Submitted/Unknown reservations. Seven new `native_trade_postgres` cases compile with `--features postgres-tests --no-run` but were **NOT RUN** under this implementation scope. The earlier373-test result does not include them. SQL-off filesystem restart and pure state checks do not qualify their SQL lifecycle; no new endpoint/schema action permission is inferred.
- Cleanup removed only the two remaining owned disposable schemas from the failed pool-reuse run and the inventory smoke; the owned test-prefix catalog was empty afterward. Subsequent successful tests use their existing guarded cleanup. Active TLS files, restricted role and private credentials remain provisioned; no operational schema was removed.

## 2. Quyền kết nối và bảo vệ credentials

User cung cấp URI qua private environment hoặc file cấu hình ngoài repo; **không paste credentials vào docs/chat/argv/log**, không commit URI, không Debug raw connection options hoặc raw SQLx errors có DSN. Actual test implementation reads `Z2Z_TEST_DATABASE_URL`; production configs hold `uri_env`, `schema`, `max_connections` only. URI parsing validates decoded parameters before constructing SQLx options, requires verified TLS and rejects socket/ambient libpq fallback. Temporary original URI/password buffers are zeroizing; URL/SQLx internal copies are not claimed erased.

The owner has now approved existing isolated-schema tests conditionally; the operator must supply a test-only database/role with the corresponding create/drop rights before use. URI alone grants no production reset/migration or server restart. Current implementation allocates random96-bit names under `Z2Z_TEST_PG_SCHEMA_PREFIX` (at most30bytes: starts lowercase ASCII, then lowercase letters/digits/underscore; neither `public` nor a `pg_` prefix), requires `Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES=yes`, and uses only schemas it initializes. Shared cleanup refuses foreign/partial identity; no CREATE/DROP DATABASE or TEMPLATE copies. Tests deliberately corrupting their own schemas retain explicit created-scope cleanup guards. Server restart is separate from reconnect/process restart.

Không in full host/user/password/db URI trong report. Report chỉ operation, engine/version khi an toàn, schema test ID không nhạy cảm, pass/fail và redacted error class. Remote connection cần TLS/server identity phù hợp provider; không âm thầm dùng disable/accept-invalid TLS. Remote DB operator có thể xem stored records: encrypted file custody/private proof witnesses vẫn actor-local, không tự chuyển lên SQL vì đổi engine.

### Operator: privately supply the existing three inputs

1. The owner has selected an already-running Docker PostgreSQL endpoint for these isolated tests. Qualify that exact endpoint's version, TLS/server identity and test database/role rights through the assigned read-only path; handle connection credentials privately, never paste them here. Do not invent an endpoint, start a service or weaken strict TLS if qualification fails. Any needed TLS/server reconfiguration requires separate authorization.
2. Configure the agent launcher/session's private environment with `Z2Z_TEST_DATABASE_URL` (secret), `Z2Z_TEST_PG_SCHEMA_PREFIX` (an operator-selected safe prefix satisfying the rule above), and `Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES=yes`. Do not write credentials into the repo, chat, command arguments or logs. A `DatabaseConfig` file names `uri_env`; it does not supply the URI to the gated tests by itself.
3. If launching a new agent process from a private Bash terminal, with shell tracing/session recording disabled, enter values through builtins rather than putting the URI in command history:

```bash
read -r -s -p 'Private PostgreSQL test URI: ' Z2Z_TEST_DATABASE_URL; printf '\n'
read -r -p 'Approved isolated schema prefix: ' Z2Z_TEST_PG_SCHEMA_PREFIX
export Z2Z_TEST_DATABASE_URL Z2Z_TEST_PG_SCHEMA_PREFIX
export Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES=yes
```

Launch the agent through its normal launcher **from that same shell**, without echoing the variables. Exports in an unrelated terminal cannot modify an already-running agent's environment. For the existing session, use the harness/launcher's private environment injection mechanism instead; its exact UI/command is deployment-specific and is not guessed here. Report only “configured”, never values. The parent must recheck presence/approval and verified TLS/scope before any test connection. Keep SQL/feature builds serialized after the in-progress default workspace run so they cannot overwrite its shared CLI binary.

## 3. Phạm vi bắt buộc khi có URI

| Group | Scenario cần chạy | State |
|---|---|---|
| Schema adoption/migration | Application/schema identity, concurrent initialization, foreign/partial schema rejection, forward-only migrations/checksums. | Passed existing isolated tests |
| Native inventory PostgreSQL cutover | Exact256-bit amounts, active reservation capacity, concurrent reserve and immutable funding fences. |17 tests passed |
| Native restart/reconciliation | Actual process restart and reconnect retain prepared/unknown records and capacity. | Passed; server restart NOT RUN |
| Legacy market ledger | Funding/history/physical-note uniqueness, sponsor/change and liability/input locks. | Passed existing isolated tests |
| Epoch/allocation/target authority | Canonical epoch commit/abort, activation, immutable intents and partial-result retention. | Passed existing isolated tests |
| Writer/replicas | Advisory/row locks, retained heads, writer generation, replay and process-loss recovery. | Passed existing isolated tests |
| Cross-module lifecycle | Real local CLI/native fixture/ledger/target-program paths; fixture payout is not mined ZEC. | Local fixtures passed; funded trade NOT RUN |
| Failure isolation | Drift, rollback, credential redaction, foreign-schema preservation and contaminated pool replacement. | Passed exercised paths; no claim of every possible failure |

Migrated opt-in targets include `market_postgres_epochs`, `market_postgres_lifecycle`, `market_postgres_native_conflicts`, `market_postgres_policy`, `market_postgres_postgres`, `market_postgres_replicas`, `market_postgres_target`, `market_postgres_local_flow`, `market_postgres_process_liveness`, `market_postgres_solana_safety`, `postgres_inventory` and `samechain_journal_postgres`. Existing dual-feature release-order checks also require `sp1-local,postgres-tests`. SQL internal input-binding/database cases use the same `postgres-tests` gate. `market_native_binding`, `market_configuration`, `market_native_diagnostics` and database URI-policy tests stay pure/default. Existing isolated tests may run only after the approved private inputs and TLS/scope checks are satisfied; until then evidence is compile-only, not skipped-green SQL.

## 4. Existing data is not disposable

Old Ziquid `target/ziquid-inventory-smoke-20261001/actor/inventory.sqlite3` and sidecars are retained funding journals; source Kerb PostgreSQL stores and any pending financial records stay untouched. No blanket target clean, database reset, schema drop or implicit auto-conversion. PostgreSQL code cutover does not authorize data movement or source decommission. A separately reviewed export/import with exclusive writer fence, amounts/state/IDs/payload identity checks and dry-run evidence is required before operational data migration; no dual-write shim.

## 5. Completion/reporting rule

A SQL-dependent operation is not verified because it compiles or passes pure tests. No `Passed` in status/gates, no goal completion for full integrated project before required DB checks on approved URI have actual evidence. The final overview must distinguish compiled/pure/target/SQL/company-off checks, unresolved protocol/privacy capabilities, and action permission gates. This file records the intentional verification hold, not a waiver of SQL correctness.
