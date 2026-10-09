# Optional Node Peer Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Owner approved this plan and implementation on2026-10-06. Preserve the selected parent-orchestrated execution method; parent owns RED/GREEN, process smoke and final checks. Generated transport keys and the bounded loopback scope only.

**Goal:** Explicit opt-in transport-key persistence with stable PeerId across real restarts, preserving the default ephemeral node and every financial custody invariant.

**Architecture:** One integrated slice through existing config, custody filesystem policy and Swarm construction. A small node identity module owns the52-byte plaintext transport format/publication flow; custody exposes only existing secure directory/file admission primitives, not a universal storage interface or financial-envelope API.

**Tech Stack:** Existing Rust/libp2p0.56.0 identity0.2.14, rustix1.1.5, zeroize1.9.0, getrandom0.3.4, tempfile and existing process tests. No new dependencies/features/lock update.

**Spec:** [Owner-approved2026-10-06 peer identity design](../specs/2026-10-06-node-peer-identity-design.md). Network§7 was separately approved as a design only; its implementation is outside this plan.

## Global Constraints

- Owner approved this written plan and implementation on2026-10-06. Proceed with existing-suite failing tests, parent-observed RED, implementation and parent qualification within the generated-transport-only scope below. Approval grants no additional permissions and no git commit/push authorization.
- `peer_identity_file: Option<PathBuf>` / `--peer-identity-file PATH`; absent preserves ephemeral behavior, strict public JSON stays schema1, config/transport-option conflicts remain enforced.
- File exactly52 bytes: `b"Z2Z_PEER_IDENTITY\0"` (18), `u16BE(1)` (2), independently generated transport-only Ed25519 seed (32). Fixed guarded buffers and EOF check; no financial keys/seeds, encrypted-custody envelope, secret serde/Debug or plaintext logs.
- Linux existing external0700 parent, trusted ancestors, no symlinks/`..`/dot-final/build-tree location,0600 regular effective-UID single-link file; descriptor-relative opens, directory publication flock, file flock, NOREPLACE and file+parent fsync. No mkdir/chmod, deletion, overwrite, invalid-stage repair or ephemeral fallback.
- Directory/file lock acquisition uses nonblocking attempts under the same5s monotonic startup deadline,10ms retry; no spawned lock worker. Load/create finishes before Swarm/listen/dial. Every successful initializer reads back and uses the winning final.
- Default feature build must not acquire `sp1-local`; existing encrypted custody behavior/source policy/callers unchanged. Generated keys and loopback TCP only; no SQL, production-secret, proving, financial signing, funds, WAN/LAN/multicast or service change.
- Parent executes checks serially after worker handoffs; implementation worker writes tests first and waits for parent RED before product edits, then hands off all changes for integrated GREEN. Do not independently rerun parent-reported failures.

## Review Focus

- Concurrent publication winner, complete interrupted stage and post-rename fsync failure: no second identity or key deletion; process/unit cases below pin all three.
- Hostile path/file and restrictive umask: fail before any network event without weakening custody's0700/0600 policy; rejection corpus below includes namespace alias and hard links.
- Invalid final versus valid leftover stage, or valid final versus invalid leftover stage: final authority is deterministic, no silent repair/rotation; exact-byte preservation assertions below.
- Default-feature deployment and strict CLI/JSON compatibility: no indirect prover dependency; all original ephemeral/reconnect assertions remain.
- Entropy/lock/durability failure and secret-bearing diagnostics: bounded fail-closed behavior, no listener or unguarded secret copies; private unit failure seams and captured process output below.

---

### Task1: Persistent transport identity, end to end

**Files and ownership:**
- Modify `crates/runtime/src/node/config.rs`: optional path throughout Options/FileConfig/Config and conflicts.
- Create `crates/runtime/src/node/identity.rs`: concrete format, bounded lock/read/publish/readback and node key selection only.
- Modify `crates/runtime/src/custody.rs`: narrow Linux crate-private wrappers over existing directory/open/metadata policy; existing financial paths retain current semantics.
- Modify `crates/runtime/src/node/network.rs`: key injection and accurate startup flags, no transport/reconnect behavior change.
- Modify `crates/runtime/src/node/mod.rs`: Linux identity module, categorical identity errors and CLI description; retain bounded diagnostics.
- Extend `crates/runtime/tests/node_transport_cli.rs` and `crates/runtime/tests/node_reconnect_cli.rs`; unit cases live beside identity/custody code, not a new test framework.
- Update existing `README.md` node usage with opt-in/path/risk/default boundary; update `docs/NATIVE-IMPLEMENTATION-STATUS.md` only with parent-observed outcomes at handoff.

**Exact proposed internal seams (not public APIs):**
- `node::identity::load_or_create(path: &Path) -> node::Result<libp2p::identity::Keypair>`: persistent path only; errors map to static node categories. Network keeps `with_new_identity()` behavior when absent or supplies a newly generated ephemeral key equivalently; persistent branch uses `with_existing_identity(keypair)` only after final readback.
- `custody::trusted_existing_private_directory(path: &Path) -> Result<(std::fs::File, PathBuf), CustodyError>`: ungated by `sp1-local`, Linux-only wrapper over `linux::directory(path, false, false)`. No lock/provisioning; caller performs publication barriers. Existing prover wrapper may delegate here without changing its signature/semantics.
- `custody::trusted_private_file_at(directory: &std::fs::File, name: &std::ffi::OsStr) -> Result<Option<std::fs::File>, CustodyError>`: wrapper over existing `linux::opened`; identity supplies a validated single basename, never an arbitrary relative traversal.
- `custody::validate_private_file(file: &std::fs::File) -> Result<(), CustodyError>`: wrapper over `linux::validate_file`, used after stage creation and readback. Share the predicate, do not copy or weaken it.
- Identity-local helpers: `lock_until(file: &File, exclusive: bool, deadline: Instant) -> node::Result<()>`; `read_frame(file: &File) -> node::Result<Zeroizing<[u8;52]>>`. No exported generic publication/encryption trait. Directory fd lives through final readback; stage write lock is dropped before shared-lock reopening of the renamed inode.
- `node::Error` gains static `IdentityPath`, `IdentityEncoding`, `IdentityLock`, `IdentityIo`, `IdentityDurability` categories with fixed nonblocking diagnostics; never store upstream error/path/secret bytes. `NodeStarted` schema1 emits `persistent_transport`/true only on the successful persistent branch, else original `ephemeral_transport`/false; all financial readiness flags stay false.

- [x] **Step1 — Read exact source seams and write existing-suite failing tests only.** Before changing exported/shared symbol visibility or signatures, use available `xd://lsp` references for affected custody helpers and retain every existing consumer. No broad custody refactor. In `node_transport_cli.rs`, add `persistent_identity_survives_process_restart`: external tempfile parent explicitly0700, new option, first successful process,52-byte0600 final, second process same PeerId and persistent flags. Add strict JSON equivalent/config conflict and omitted-option/no-files assertions. Do not weaken existing `transport_only` assertions; add a persistent-specific expectation. Add concurrent initializers using the existing real-process harness and bounded event/time limits. Parent reads the tests, then runs RED below; current missing option/config support must cause assertion failure, not unrelated infrastructure failure.

- [x] **Step2 — Parent records RED, then releases the same integrated implementation worker.** Run only after plan approval and tests land:
  `cargo test --locked --offline -p ziquid-runtime --test node_transport_cli persistent_identity_survives_process_restart -- --exact --nocapture`
  Expected RED: node rejects the new option and the new success/persistence assertion fails. Missing compiler/cache/binary is a prerequisite failure, not RED. Worker does not run this command.

- [x] **Step3 — Implement the narrow filesystem/key flow and its unit failure corpus.** Reuse the exact seams above. Resolve against startup cwd once; validate the approved external-path requirement against known checkout/build roots before mutation, using descriptor-relative traversal rather than trusting `canonicalize` alone. Identify existing repository/build-location handling before coding it; no new config knob or runtime environment-derived permission bypass. Under the bounded directory lock: valid final wins; otherwise complete valid stage resumes; otherwise absent final+stage generates guarded bytes and creates EXCL0600 stage. Unknown/partial/unsafe final/stage rejects unchanged. Write/sync, NOREPLACE, parent-sync, close stage lock, reopen/validate/readback/sync winner, then consume seed slice `[20..52]` with installed Ed25519 decoder. `EEXIST` uses only the validated winner; other errors stop, never remove an artifact. A valid final ignores leftover stage. Add private unit tests for raw32/raw64/51/53-byte frames, wrong domain/version/EOF, complete-stage resume, partial-stage preservation, final precedence, wrong mode/hardlink/symlink/FIFO/traversal/dot-final/unsafe ancestor/missing parent/build-tree and file metadata changes. Failure seams are private/test-only at the actual entropy/rename/fsync boundary, not production failpoints or mock secure storage; pin entropy failure, NOREPLACE winner, post-rename fsync failure followed by same-key retry and lock deadline. Compare generated secret bytes only inside guarded test state; never include them in assert diagnostics. Financial custody's existing partial-envelope repair is intentionally unchanged.

- [x] **Step4 — Wire config/Swarm/public status and finish real-process acceptance.** Load identity before creating the Swarm/listener or dialing; startup cannot emit `listening` on identity failure. Extend tests for simultaneous startup same final/PeerId, distinct generated files, invalid-final/stage byte preservation, real held-lock timeout, restrictive umask, redacted stdout/stderr and strict JSON. In `node_reconnect_cli.rs` add `persistent_identity_restart_reconnects_expected_peer`: A retains its process/configured expected B PeerId with existing reconnect enabled; stop persisted B, restart it on the same loopback address/file, require A reconnects to identical authenticated B PeerId without consuming more than the existing bounded retry budget. Keep current live-forwarder same-identity outage tests unchanged. Update README usage/risk; no shell/example ever prints the private frame or seed.

- [x] **Step5 — Freeze worker changes; parent runs one serial integrated qualification wave.** Worker hands off source/tests without running checks. Parent commands, each must exit0 with intended tests actually executed:
  - `cargo test --locked --offline -p ziquid-runtime --lib node::identity`
  - `cargo test --locked --offline -p ziquid-runtime --lib custody`
  - `cargo test --locked --offline -p ziquid-runtime --test node_transport_cli --test node_reconnect_cli`
  - Actual two-node/persisted-restart smoke: use the process harness produced above against the real default-feature `z2z-node` binary, external0700 generated-key roots and `/ip4/127.0.0.1/tcp/...`; observe initial Noise/identify/ping, stop B, restart same file/address, observe stable B PeerId and A reconnect, orderly bounded shutdown and immutable final. Do not substitute a parser/unit/mock or an ephemeral restarted B. This named process case may serve as the smoke within the single integrated test invocation; no duplicate run required if its full public-event evidence is captured.
  - `cargo clippy --locked --offline -p ziquid-runtime --lib --bin z2z-node --test node_transport_cli --test node_reconnect_cli -- -D warnings`
  No `--all-features`, SQL feature, prover, new dependency download or workspace-wide rebuild. If another writer owns source, wait for integration rather than run against half-finished edits. Parent does scoped source review of shared custody policy/callsites and secret lifetime, records only observed tests/smoke and remaining limits in native status, then returns acceptance or the concrete defect; no new universal audit or repeated plan loop.

  Observed completion: parent recorded actual missing-flag RED; artifacts3582/3584 show11 identity +10 custody +20 transport +7 reconnect checks (48 total), scoped Clippy and real persisted-peer restart/reconnect smoke. Independent read-only spec/code-quality review reported PASS with no findings. The later broader default-runtime run is additional qualification and is not claimed here.


## Handoff and approval

This one integrated slice is complete only when default ephemeral behavior is preserved, optional generated-key persistence survives concurrent startup and actual process restart, every unsafe/invalid/durability failure is fail-closed without key mutation, shared financial custody remains unchanged and parent-observed default-feature checks pass. P2.02 completion would remain transport-only; no money/recovery/GD2/full-journey closure follows.

**Execution approved:** owner approved this plan and implementation on2026-10-06; no further plan-review or execution-method question is needed. Preserve parent-orchestrated subagents: implementation worker writes the existing-suite RED tests first, parent runs actual RED, then releases product implementation and owns integrated qualification. Authorization is generated transport keys and the specified bounded loopback checks only, not production secrets, financial actions, expanded networking, commit or push.
