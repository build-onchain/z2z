# Samechain Private Snapshot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development; parent integrates and owns all checks.

**Goal:** Publish immutable encrypted complete owner-operation snapshots and restore actual capabilities in a clean generated-owner process.

**Architecture:** Reuse complete existing witness codecs/one owning enum and concrete custody publisher. Independently selected public metadata binds domain-separated AEAD; native P/Q semantics remain in native wrapper. Snapshots do not implement the undecided public journal or resolve Released/Unknown.

**Tech Stack:** Existing Rust runtime/proofs/protocol/chains, XChaCha20Poly1305, SHA256, zeroize, rustix, tempfile; no new dependency.

**Spec:** [samechain private snapshot design](../specs/2026-10-06-samechain-private-snapshot-design.md).

## Global Constraints

- User approved generated-key bundle/restore only; no production-secret/held scanner/SQL/heavy-prover/Anvil/deploy/sign/send/Git or data migration.
- Native envelope `ziquid.u.custody.v3` and retained v1/v2 identities unchanged; snapshot domain `ziquid.samechain.backup.v1` separate.
- Exact canonical selection/framing/context/bounds/protected-prefix precedence are spec30/32; one encoder supplies payload and context.
- Backup interface preserves complete existing witness, zero consent, semantic unsigned review; nonzero consent additionally strict verified, never generated/repaired.
- Independently selected fixed token binds every token asset; metadata pins are descriptors, not authenticity or eligibility.
- Linux descriptor-relative trust/NOFOLLOW/0700/0600/single-link/lock/NO_REPLACE/fsync invariant preserved.
- Capacity incl tag before private append; partial values guarded, diagnostics categorical/redacted.
- One existing owning enum, four existing witness codecs; no parallel owner material type, mutable inventory, public operational journal or export/sign/send state.
- Children skip checks; parent RED before source then integrated GREEN/smoke after all source freezes.

## Review Focus

- Shared/foreign/unknown staging prefixes never erased; tests both native→snapshot and snapshot→native plus existing old-domain behavior.
- Semantically valid foreign-token witness cannot authenticate under contradictory selected token; real valid baseline then token pin/material mismatch.
- Zero-consent prepared backup and invalid nonzero consent differ; neither restore path signs or repairs material.
- Producer exits and restore process has no original witness/regeneration; only encrypted artifacts, independent public selection and unnamed backup-key pipe.
- Private buffer growth, fallback trust or a barrier error must not be mistaken for durable success; native regressions and immutable conflicting publication preserve originals.

### Task 1: Concrete shared encrypted publisher

**Files:** Modify `crates/runtime/src/custody.rs`; custody focused tests where required. No samechain semantic files.

**Interface:** crate-private `EnvelopeFormat { domain: &'static [u8], max_plaintext_bytes: usize }`; protected known-format/version-family recognition is shared fixed policy from spec. `save_encrypted(path: &Path, key: &[u8;32], namespace:[u8;32], context:[u8;32], format: EnvelopeFormat, plaintext: Zeroizing<Vec<u8>>) -> Result<(), CustodyError>`; `load_encrypted(path: &Path, key:&[u8;32], namespace:[u8;32], context:[u8;32], format: EnvelopeFormat) -> Result<Zeroizing<Vec<u8>>, CustodyError>`. Validate capacity contract or use detached AEAD; reject unsafe/incomplete/future data. Native wrappers decode/validate before save and after load; retry constant-time plaintext equality.

- [ ] Write tests exposing missing shared interface and cross-format/shared-prefix preservation; parent run RED.
- [ ] Extract only concrete envelope/publisher parameterization; retain byte-compatible native header/AAD and same path/barrier logic.
- [ ] Freeze source, no child checks. Parent native custody regressions plus snapshot consumers qualify both real callers.

### Task 2: Actual snapshot codec and typed semantic restore

**Files:** Create `crates/runtime/src/samechain/backup.rs`; modify `crates/runtime/src/samechain.rs` owning enum/export only. Focused tests `crates/runtime/tests/samechain_backup.rs`.

**Consumes:** Task1 exact encrypted publisher; existing `OwnedOwnerInput`, borrowed `OwnerInput`, witness encoders/reviewers.

**Produces:** Exact public selection/types/save/load interface in spec; default available owning enum with redacted Debug, feature-gated CLI decode unchanged. Pure snapshot mode decode uses existing guest code mapping, strict witness framing.

- [ ] Write semantic generated all-operation tests against absent interface and freeze; parent RED.
- [ ] Implement canonical selection encode/decode/context/bounds once, one guarded plaintext containing metadata+existing full witness; no secret JSON.
- [ ] Validate independent pins/op/role/action/E/digest/fixed-token, actual unsigned review and optional existing nonzero strict consent.
- [ ] Integrate shared encrypted store; immutable names/retries, no newest/spendable selection or journal.
- [ ] Freeze source; parent tests malicious modes/pins/crypto/path/consent/overlength/canonical exhaustion/foreign stages and full native custody behavior.

### Task 3: Clean-process capability acceptance

**Files:** Existing new snapshot tests and generated test support only; no public production CLI/scanner.

**Interface:** Actual test harness producer/restore child processes using library save/load, key via unnamed private stdin pipe, independent public selection; parent retains encrypted files/public pins only.

- [ ] Producer generates zero-consent creation/fillA/B/cancel/exit/withdrawal complete snapshots and exits; no same-owner secret exchange/publicfiles.
- [ ] Fresh child restores actual stored capabilities (no deterministic fixture regeneration), exact canonical public packet/unsigned message; decrypt output material and use restored generation/proceeds/ordinary return for existing unsigned preparation/review.
- [ ] Verify older files/identical retries remain byte-exact; meaningful wrong-context/key/pins/semantic and filesystem/interruption/concurrency failures preserve original bytes.
- [ ] Parent direct built harness smoke, focused/native custody suites, scoped clippy and default+sp1-local compile; independent source/security review, update existing module/status/docs only after proof.

## Execution ownership and preflight

One integration owner parent. Task1 custody worker and Task2 codec worker disjoint source may run together after fixed spec/interfaces; Task3 consumer worker owns snapshot tests only, consumes fixed interface and begins test-first. Parent no build/lint/test while source wave active. Integration test RED allowed only testfreeze before anyproductionpermit. No Git workspace/commits, user explicitly withheld. No temporary secret scripts retained.

Coverage is immutable private snapshots after complete public packet freezing. Incomplete negotiated outputs, usable complete prover kit/genuine VM restore, financial release barriers/current chain reconciliation and funded recovery remain missing named acceptance; do not silently close them.
