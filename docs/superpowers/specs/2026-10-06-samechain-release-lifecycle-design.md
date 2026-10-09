# Samechain certificate release fence design (Wave B, reviewed rev 3)

> **Status:** Rev 3, written 2026-10-06 by the configured PLAN model, based on the [durability report](../../research/2026-10-06-phase0-durability-recovery.md) §3 (X.REL-DIGEST, X.JOURNAL) and microplan P3.08 / P2.05-partial. The owner selected private capsule first with PostgreSQL gating export and trusted key-file input. Fresh scoped independent review passed after all four rev 3 findings were addressed, clearing the user's conditional specification gate. Tasks 1–3 source is implemented and both scoped source reviews passed; focused negative evidence is in [native status](../../NATIVE-IMPLEMENTATION-STATUS.md). Genuine certificate positives and SQL behavior remain unexercised; no financial or full-wave acceptance follows. This spec authorizes no SQL execution, heavy proving, signing, sending, deployment or production secrets. Production keys remain held; key files are generated test keys only.
>
> Rev 2 changes, from the review constraints:
> - The capsule binds independently supplied expectations. It never self-selects them.
> - The journal row carries the full immutable binding.
> - The I2/finality reducer moves out of this wave. Nothing here produces a financial `Completed`.
> - No source-text tests are allowed.

## Problem

Before this cutover, `prove-owner` verified a certificate and printed its full journal and proof bytes to stdout. A paired certificate can be executed permissionlessly (`SamechainAuthority.fill`), so printing it already released authority without a durable release record. Wave B separates private capsule-only proving from certificate export, which requires:
1. an immutable encrypted capsule bound to independent expectations, and
2. a committed PostgreSQL `Released` row with the same binding.

## Scope (EVM/Base lane only; lane tagging belongs to X.02)

### 1. Release binding (public, independently derived)

`ReleaseBinding { op_id: [u8;32], deployment: Deployment, operation, role, packet_digest: [u8;32], program_vkey: [u8;32], journal_digest: [u8;32], expiry: u64, required_nfs: Vec<[u8;32]> }`

- `binding_digest` = SHA256(`Z2Z_SAMECHAIN_RELEASE_BINDING\0` ‖ u16BE 1 ‖ canonical fields).
- `prove-owner` builds the binding from values the parent computes **before** the worker runs:
  - deployment and program pins, selected independently;
  - the parent-computed expected journal (`OwnerInput::expected_journal`);
  - the frozen packet's digest/expiry/input NFs.
- Nothing in the binding comes from the child certificate.

### 2. Release capsule

The capsule is a third custody domain, `ziquid.samechain.release.v1`. It needs these `custody.rs` changes:
- add the domain to the `EnvelopeFormat::max_envelope_bytes` allow-list;
- raise `MAX_HEADER_LEN` to a 3-way max (55) and add a const assert for it;
- add the domain and the `ziquid.samechain.release.v` family to protected recognition.

The native header and AAD bytes stay unchanged.

API:
- `save_release(path, key, namespace, binding: &ReleaseBinding, certificate: &OwnerCertificate) -> Result<ReleaseDigest>`
- `load_release(path, key, namespace, expected: &ReleaseBinding, expected_release: ReleaseDigest) -> Result<OwnerCertificate>`

Rules:
- The AEAD context is `binding_digest`. The plaintext is the canonical binding plus the exact certificate journal and the 356-byte proof.
- **Save** requires both:
  - SHA256(certificate.journal) = `binding.journal_digest`;
  - `verify_owner_certificate(certificate, &binding.program_vkey, journal)` passes.
- **Load** authenticates against the caller's expected binding. It then requires the decoded binding to equal the expected binding, re-checks the journal digest, and re-runs `verify_owner_certificate`.
- The capsule never chooses its own statement.
- Capsules are immutable. An identical retry is accepted; different bytes produce a Conflict.

### 3. `samechain` PostgreSQL journal (compile-only now)

New application identity `samechain` v1, with a reviewed `database.rs` inspector allow-list entry. It reuses the `ActorStore` patterns: `lock_scope`, `synchronous_commit on`, READ COMMITTED, row lock, version CAS.

The `ops` row stores the complete public binding:
- op_id PK;
- deployment digest;
- operation, role;
- packet_digest, program_vkey, journal_digest;
- expiry, required NFs;
- binding_digest;
- release_digest (NULL until Released);
- state ∈ {Authorized, Released};
- version, writer_generation.

Every digest column has `CHECK (octet_length(col) = 32)`. There is **no column that can hold certificate, journal or proof bytes**. That is the X.REL-DIGEST guarantee, enforced by the schema and by the API types: the journal API accepts only `[u8;32]`/typed digests and fixed integers, never `Vec<u8>`.

API:
- `authorize(&ReleaseBinding)`
  - Inserts an Authorized row.
  - An identical retry is OK.
  - The same op_id with a different binding gives a Conflict.
  - Binding columns are never updated after insert.
- `commit_release(op_id, expected_version, &ReleaseBinding, ReleaseDigest) -> Committed`
  - Performs the CAS `Authorized → Released`.
  - Requires the stored binding_digest to equal the supplied binding's digest.
  - An identical retry of Released returns the same `Committed`.
- `read_release(op_id, &ReleaseBinding) -> Option<Committed>`
  - On any stored-binding mismatch it returns `BindingMismatch`, never a repair.
- `Committed` has private fields and is constructible only from a row read inside the committing or reading transaction.

Restart rule: if the capsule exists and the row is Authorized, a CAS to Released must happen before any other action. Capsules are never deleted.

The SQL tests are written behind the existing `postgres-tests` feature. They stay **NOT RUN** until the user grants a private URI and test scope. No connection is opened without that grant.

### 4. Proving and export (rev 3 ordering)

**Owner decision:** proving writes only the owner-local encrypted capsule. That is inside the owner boundary, so it is not a release. PostgreSQL gates the first escape, which happens only at export. Proving and proof qualification therefore need no SQL scope. P2.05 reservation visibility is not waived; it stays a separate obligation.

**Key input:** `--backup-key-file PATH`. This is a generated-key file on owner media, and the path is the only key-related value in argv. A crate-private custody helper, `trusted_backup_key_file(path) -> Result<File, CustodyError>`, opens it with these checks:
- descriptor-relative, with NOFOLLOW;
- the parent directory is 0700, owner-owned and trusted;
- the file is a 0600, owner-owned, single-link regular file of exactly 32 bytes;
- the descriptor is CLOEXEC, so the prover worker never inherits it.

The key is read into `Zeroizing<[u8;32]>` only at the step that uses it. Raw key file descriptors are not supported.

`prove-owner --release-dir DIR --backup-key-file PATH --op-id HEX` runs these steps in order:
1. Validate the arguments, the release directory (trusted-private-directory check) and the key file (`trusted_backup_key_file`, open only). All of this happens **before** reading stdin.
2. Prepare the witness and build the binding from independent expectations.
3. Run the worker, then call `verify_owner_certificate`.
4. Read the key, then `save_release`.
5. Print `{kind:"samechain_owner_capsule", op_id, binding:"0x"+hex(ReleaseBinding::encode()), binding_digest, release_digest, capsule:<basename>}`.

It never prints journal or proof bytes, and it makes no database connection.

`export-certificate --release-dir DIR --op-id HEX --binding FILE --database-config FILE --backup-key-file PATH` runs these steps in order:
1. Validate the arguments, the release directory, the key file (open only), the config, and that `uri_env` is present. A missing URI fails with MissingUri before any read.
2. Decode the canonical public binding file.
3. Compute `release_digest` over the exact capsule bytes with the crate-private `release::capsule_digest(path)`, which wraps `custody::encrypted_file_digest(path, FORMAT)`. This is a trusted read; it uses no key and does no decryption.
4. `authorize(binding)`, then `commit_release(binding, version, release_digest)`, then `read_release(binding)`. Anything other than a matching `Committed` is an error, raised before the key is read.
5. Read the key, then `load_release(expected binding, Committed.release_digest())`. This re-checks the file digest, the binding and the certificate, so a capsule swapped after step 3 fails closed.
6. Print the certificate. The shape is the existing export minus `elf_sha256`, which the binding does not carry.

**Crash cuts:**
- The capsule exists and there is no row: nothing has escaped. Export can proceed later.
- Commit succeeded but the export was interrupted: the row stays Released. A retry is idempotent.
- Capsules are never deleted.

**Why committing Released before decryption is safe:**
- Released means "may have escaped". Committing it conservatively before `load_release` can only over-lock: if load then rejects, nothing escapes and the row stays Released.
- A capsule that was swapped or corrupted under the owner's own release directory blocks that op_id with Conflict or BindingMismatch. It is never repaired. A new op_id is not a recovery remedy: it cannot restore rights to the same inputs, bypass existing reservations, clear any prior Released record, or satisfy the unresolved reservation/reconciliation gate. Reproving or exporting those inputs remains subject to that gate; the journal's per-op_id checks do not provide cross-operation NF uniqueness.
- The binding file is owner-supplied, but it cannot be forged into a different statement. `load_release` authenticates the AEAD under the binding digest, and the encrypted binding must equal the expected binding. So only the binding that `prove-owner` actually sealed can export.
- Released is never a financial status. No Completed or unlock exists in this wave.

Existing CLI tests and all `prove-owner` callers are migrated to these paths, not deleted. Task 3 explicitly owns `crates/runtime/examples/owner_creation_qualification.rs` and `crates/runtime/examples/owner_worker_smoke.rs`: qualification is capsule-only with no DB configuration/URI dependency and no certificate/proof output; smoke cases supply valid generated-key/release/op-id fixtures so their existing artifact/policy failure causes remain reachable. Tests assert behavior only.

## Explicitly not in this wave

- The I2 unlock/finality reducer and every terminal state (`Completed`, `ConsumedByCompetitor`, `ExpiredProvenUnexecuted`). They require authenticated finalized acquisition (P2.20) and actual transfer/effect reconciliation (P3.12). Deciding them over caller-supplied flags would let unverified input reach financial status. Wave B knows only Authorized and Released, and a Released lock never unlocks in this wave.
- Signed-tx capsules (P3.11), lane descriptors (X.01/X.02), cross-chain states.

## Verification acceptance (behavior only; no source-text or wiring tests)

**Capsule (generated keys).** Positive roundtrip, retry and conflict are BLOCKED until a genuine wrapped certificate exists; no stubs or `#[ignore]` placeholders stand in for them. Tests cover:
- rejecting a wrong key, wrong namespace, any changed binding field, a wrong journal digest, a wrong program, or a tampered proof;
- journal-consistency rejects;
- rejecting a canonical invalid certificate at save and at load;
- cross-format staging preservation across {native, snapshot, release}.

**Key file helper.** It rejects a missing file, a symlink, mode ≠ 0600, a group- or other-writable parent, a hard link, and length ≠ 32. The descriptor is CLOEXEC, which is checked by an exec'd child that cannot see it.

**Journal.**
- At the type level, the public API cannot accept byte payloads.
- SQL behavior tests are compiled and NOT RUN. They cover: Authorized insert/retry/conflict; CAS version/binding mismatch; Released retry; read mismatch; and inserting a non-32-byte digest failing the CHECK.

**CLI.** Behavior only: parser rejection exits 2 versus runtime rejection exits 1, empty stdout, unread stdin, unchanged release directory/key bytes, and the calibrated content-read observation below. Exit 1 does not distinguish all semantic causes; do not pin diagnostic Display text or add new error strings/hooks to make it do so. Unchanged bytes establish no mutation, not no key read or DNS/connection activity. Process tests run under `sp1-local`; a separate default-feature test asserts both commands are absent. Each negative varies one intended cause, supplies all unrelated arguments and fixtures valid, and checks observable rejection before stdin/key content/prover use:
- `prove-owner` with a missing or invalid release-dir, key-file or op-id; no database argument/config/URI prerequisite;
- `export-certificate` with a missing or invalid binding file, config, or key file;
- `export-certificate` with otherwise valid config and `uri_env` unset (intended `MissingUri`). Supply a canonical binding and a real canonical encrypted invalid-certificate envelope at the expected capsule path, so an absent/malformed capsule cannot mask the cause. This is a rejection fixture, not a genuine certificate or fake positive. URI-before-binding/capsule precedence needs independent source review plus the existing typed `DatabaseError` parser test; generic runtime exit 1 alone cannot establish that precedence. Do not add permanent source-text assertions or product test hooks/telemetry.

`prove-owner` makes no database connection; successful output is only `kind:"samechain_owner_capsule"` and the §4 metadata. Only export requires database configuration. Raw key-fd and stdout-release expectations are removed rather than retained as alternative contracts.

**Key-content observation (Linux, test harness only).** Use the existing pinned `rustix = 1.1.5` dependency with its already enabled `fs` feature (`crates/runtime/Cargo.toml:124–125`), not a new dependency, unsafe test code, product hook, or external binary. Installed primary source under `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustix-1.1.5/` exposes safe `fs::inotify::{init, add_watch, Reader}` (`src/fs/inotify.rs:54–79,105–121,161–176`), with `Event::wd/events` at 134–146. `src/fs/mod.rs:35–36` exposes the module under `linux_raw_dep`; `src/lib.rs:220–223` gates fs on the existing feature. `src/backend/linux_raw/fs/inotify.rs:12–16,29–53,86–119` defines `CLOEXEC`, `NONBLOCK`, separate `ACCESS`/`OPEN`, and watch-loss/overflow flags. The library encapsulates event decoding; the caller supplies `[MaybeUninit<u8>; 512]` as in its safe example (`src/fs/inotify.rs:11–34`), never casts raw event bytes.
- Create the generated owner-private regular key file (0700 parent, 0600 file, 32 bytes) before observation. Install a nonblocking/CLOEXEC watch on that file **before spawning the actual CLI**, including `ACCESS`, `OPEN`, and self-delete/move notifications. Retain the watch/reader through child exit and match the watch descriptor.
- Calibrate each negative's watch: open/stat/close the file without reading content, drain to `AGAIN`/`WOULDBLOCK`, and require no `ACCESS` (an `OPEN` is not a read). Then perform an actual 32-byte `read_exact` into a zeroizing buffer, require `ReadFlags::ACCESS` (`IN_ACCESS`), and drain those control events completely before launching the CLI. For an invalid key-file case, calibrate while the generated file is valid, then change only the tested property (mode/link/path/length), retain the watched inode, and drain fixture-setup events before spawn. An empty stream without this positive control is not evidence.
- After the child exits, drain the same reader to `AGAIN`/`WOULDBLOCK` and require no `ACCESS`. No harness content read may occur in that interval; any post-case byte comparison runs only after collecting the observation. Watch errors, `QUEUE_OVERFLOW`, `IGNORED`, `UNMOUNT`, self-delete/move or inode replacement invalidate the observation, never pass it. For missing-file cases there is no key inode to watch; say so rather than attributing an unread-key observation. For symlink/invalid-file cases watch the existing generated target when one exists.
- This is bounded evidence for ordinary file content reads of the watched inode by the controlled CLI on this Linux filesystem, not general proof against mmap access, other inodes, or lost events. If calibration or watch integrity fails, mark the no-read evidence unavailable; unchanged bytes or source-text assertions cannot replace it.
- The actual PostgreSQL committed-export/key-read ordering case uses the same calibrated observer with real journal behavior, not a fake `Committed` or product hook. Write/compile it behind **both** `sp1-local` and `postgres-tests`; it is **NOT RUN under the SQL hold**. No claim that commit-before-key was behaviorally exercised follows from the SQL-free negatives.

**Compile:** default plus `sp1-local`, plus `--features postgres-tests` and `--features sp1-local,postgres-tests` test compilation (cargo check only).
