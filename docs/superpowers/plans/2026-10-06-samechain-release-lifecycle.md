# Samechain Release Fence Implementation Plan (reviewed rev 3)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Parent owns integration/checks. Fresh scoped rev3 specification review passed after four findings were addressed; Tasks1–3 source and both example migrations are implemented, with both scoped source reviews passing. Focused negative/observer results, compile-only PostgreSQL checks and serialized default-workspace1120checks/93suites/2ignored are recorded in [native status](../../NATIVE-IMPLEMENTATION-STATUS.md). Genuine certificate positives and SQL behavior remain unestablished; checklist requirements are not all complete and broader action holds remain.

**Goal:** Certificate bytes can leave the owner only after (1) an immutable encrypted capsule exists, bound to independent expectations, and (2) a committed `Released` row exists with the same binding.

**Depends on:** the reviewed snapshot-wave custody publisher (done).

**Holds:**
- Generated keys only.
- No SQL connection or execution. Postgres tests compile only.
- No heavy proving, signing, sending, deployment or new dependency.
- No source-text tests.
- No terminal or financial states in this wave.
- A new op_id cannot revive rights to the same inputs, bypass reservations, clear an earlier Released record, or satisfy the unresolved reservation/reconciliation gate; no cross-operation NF uniqueness is supplied by this journal.

### Task 1: Binding and capsule
**Files:** `crates/runtime/src/custody.rs`, new `crates/runtime/src/samechain/release.rs`, `tests/samechain_release.rs`.

Custody changes for the third domain `ziquid.samechain.release.v1` (27 bytes):
- add `RELEASE_DOMAIN` to the `EnvelopeFormat::max_envelope_bytes` allow-list (custody.rs:76);
- raise `MAX_HEADER_LEN` to a 3-way max (55 bytes) and add a release const assert;
- add the domain and the `ziquid.samechain.release.v` family to protected recognition;
- keep native AAD pinned.

Steps:
- [ ] RED tests (spec §Verification, capsule part, plus three-way publisher seam directions).
- [ ] Implement `ReleaseBinding` (canonical encode/decode/digest), `save_release` and `load_release` with independent expectations, journal-digest checks and `verify_owner_certificate` on both save and load.

### Task 2: `samechain` PostgreSQL journal (compile-only)
**Files:** `crates/runtime/migrations/samechain/0001_samechain.sql`, `crates/runtime/src/database.rs` (allow-list identity), new `crates/runtime/src/samechain/journal.rs`, and a `postgres-tests` test file plus its Cargo `[[test]]` entry.

- [ ] Schema with the full binding columns, `octet_length = 32` CHECKs, and no byte-payload column.
- [ ] `authorize` / `commit_release` / `read_release` with the non-constructible `Committed`, binding-mismatch errors and the restart rule.
- [ ] SQL behavior tests written. **NOT RUN.**

### Task 3: Export fences
**Exclusive Task 3 written ownership:** `crates/runtime/src/samechain/owner_worker.rs`, `crates/runtime/src/samechain.rs` (CLI arguments/dispatch only; Tasks 1/2 retain their module lines), affected `crates/runtime/tests/samechain_*cli*.rs`, `crates/runtime/tests/samechain_release_cli.rs`, `crates/runtime/examples/owner_creation_qualification.rs`, and `crates/runtime/examples/owner_worker_smoke.rs`. All affected `prove-owner` callers must cut over; any additionally discovered caller needs explicit parent ownership assignment before editing, not an omitted migration or compatibility shim.

- [ ] RED negative CLI tests under `sp1-local`, varying one intended cause before stdin/key content/prover; separate default-feature command-absence coverage. Use `--backup-key-file`, no DB prerequisite for proving, export-only config/URI failures, and all unrelated fixtures valid (including canonical binding and a canonical encrypted invalid-certificate envelope for MissingUri, never a fake positive). Distinguish parser exit 2 from runtime exit 1 without diagnostic Display pins; exit 1 does not identify every semantic cause. URI-before-binding/capsule precedence is covered by independent source review and the existing typed `DatabaseError` parser test, not permanent source-text assertions. Follow spec verification's calibrated Linux inotify observer: install before the actual child; open/stat baseline is not ACCESS; a real 32-byte read must emit ACCESS; drain control events before asserting no ACCESS after rejection. Unchanged key bytes prove neither no key read nor no DNS/connection; no hooks, telemetry, unsafe code or dependencies are added.
- [ ] `prove-owner` (rev 3). Steps: validate the args, release dir and key file (open only) **before** stdin → binding → worker → verify → read key → `save_release` → print the capsule metadata. **No DB**, no journal/proof bytes.
- [ ] `export-certificate` (rev 3). Steps: validate args/dir/key file/config/uri_env → binding file → `release::capsule_digest` → `authorize` → `commit_release` → `read_release` → read key → `load_release` → print.
- [ ] Task 1 adds the crate-private `custody::encrypted_file_digest`, `custody::trusted_backup_key_file` and `release::capsule_digest`, and tests them.
- [ ] Migrate every existing stdout-proof CLI test and affected caller without deletion. Success expects only `kind:"samechain_owner_capsule"` and canonical public binding/digests/basename, never journal/proof bytes. `owner_creation_qualification.rs` removes prove-side database arguments, config loading and URI forwarding, validates capsule metadata against independently derived expectations, and emits capsule-only qualification output rather than re-publishing a certificate; retained ELF/program checks stay independent of absent stdout certificate fields. `owner_worker_smoke.rs` supplies valid generated 32-byte key-file, private release-dir and op-id fixtures while preserving its original artifact/policy rejection categories.
- [ ] Write the real committed-export/key-read ordering test behind both `sp1-local` and `postgres-tests` using the spec's calibrated observer and real journal API. Compile only: **NOT RUN under the SQL hold**, no fake Committed/product hook, no exercised-ordering claim.

## Execution
- Workers:
  - Task 1 test-first worker.
  - Task 3 negative-CLI test worker (in parallel).
  - Parent RED.
  - Then Task 1 source, Task 2 (after Task 1 types), Task 3 source (after Tasks 1–2).
- After the freeze, the parent runs:
  - focused suites;
  - snapshot and native custody regressions;
  - default and `sp1-local` compile;
  - `--features postgres-tests` and `--features sp1-local,postgres-tests --tests` cargo check (including the committed-export/key-read test; never execute it under the hold);
  - scoped clippy.
- Then two scoped independent reviews: capsule/custody, and journal/fence.
- Evidence is recorded as "fence implemented; Released path unexercised pending SQL scope".

## Not closed
- Exercised committed Released row (needs SQL scope).
- I2 reducer/finality (P2.20) and effect reconciliation (P3.12).
- Signed-tx capsules (P3.11).
- Funded P3.20–P3.22.
- Lanes and cross-chain.
