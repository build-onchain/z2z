# Ziquid Native Protocol Implementation Plan

> **Archived V1 supersession — 2026-10-05:** retained dated plan, not the active execution guide. Follow the [Z2Z-V1 implementation prompt](../../Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md); historical requirements, approval boundaries and unchecked tasks remain provenance, not completion evidence.

> **Authority/supersession update — 2026-10-02.** This is the retained native execution-plan record, **not a completion ledger or automatically active instruction to recreate files/dependencies**. Goal/owner-selected full validation, proportional settlement and one-note/deployment uniqueness remain; starting no-code layout, proposed path/API shapes, `zcash_protocol=0.10.6` candidate and then-pending approval language are dated. [Native status](../../NATIVE-IMPLEMENTATION-STATUS.md) owns actual limited implementation/coherent `0.10.5` cohort and exercised evidence; [ARCHITECTURE](../../ARCHITECTURE.md), [MODULES](../../MODULES.md) own current behavior/packaging; [BLOCKERS](../../BLOCKERS.md) owns readiness. [SERVER-INDEPENDENCE](../../SERVER-INDEPENDENCE.md) owns manual rights/data/resource/drill acceptance; [redesign spec](../../superpowers/specs/2026-10-02-z2z-server-independent-architecture-design.md) owns proposed future expanded design, not code/actions permission.
>
> **Execution precedence:** use actual existing primitives/interfaces before any current authorized implementation. Approved `0<=C<=A` floor allocation/dust-to-fixed-S rules are not reopened by “proposed” headings below. Every hostile T independently terminal and actual S-authorized excess source return remain blocking; permanent hidden-witness gaps are not accepted completed Pending. Runtime store/custody library and limited source/proof guest primitives exist; full financial verifier/escrow/manual lifecycle does not. Tasks8/10 must include native standalone company-off cold restore, authentic history/witness reconstruction, usable local proof artifacts/resources, direct exact submission/retry and observed actual effects—not deferred SDK/UI. Proposed samechain recipient-prepared bilateral relation is separate/unimplemented, not native substitution, custody escape or strict-GD2 waiver. Original checkboxes remain untouched because they are not current status; historical commands/results/approvals never grant fresh signing/funding/deployment/Git/viewing permission.

**Retained plan instructions and tasks follow; consult current authorities and active approval before execution.**

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This checkout is not Git-initialized: use file snapshots and a persistent progress ledger, not commit/worktree scripts.

**Goal:** Implement the entire native Ziquid protocol with real Ironwood authoring/app proofs, full validating source-history proofs, proportional native-EVM settlement, durable recovery/reconciliation, hiding and one-note/one-obligation enforcement.

**Architecture:** Five native roles keep the existing acyclic graph; runtime/user-local caller composes wallet/source, app proof and destination clients. A pinned real zero-knowledge application verifier authorizes exact escrow allocation; observations never authorize money. Zoss libraries are supplied independently by the user and integrated at agreed concrete seams.

**Tech Stack:** Rust edition 2024/resolver 3, native upstream Ironwood libraries, actual EVM Solidity/Foundry, actor-isolated SQLite persistence, and a qualified local zero-knowledge proving backend. Initial authoring qualification uses published `zcash_primitives =0.30.1`, `pczt =0.9.3`, `orchard =0.15.5`, `zcash_protocol =0.10.6`, `zcash_note_encryption =0.4.2`; source qualification can reject this cohort, not mix it with same-labelled unreleased Git APIs. Backend qualification starts with SP1 v6.8.1/local Groth16 and actual v6.1.0 base verifier, not network/mock proving. These are implementation candidates requiring executable qualification; installing dependencies/toolchains is separate from network transactions.

**Spec:** [Owner-approved native design](../../superpowers/specs/2026-10-01-native-protocol-implementation-design.md), [implementation brief](../../history/ZIQUID-IMPLEMENTATION-SYSTEM-PROMPT.md), current [MODULES](../../MODULES.md) and functional specs. Owner selected full validating proof, proportional settlement and one real note per obligation in one EVM deployment. Exact proportional/excess/backend/bootstrap contracts below are proposed for plan review, not already-approved economic/trust policies.

## Global Constraints

- Entire native protocol remains the deliverable; first slices cannot be labelled complete settlement.
- SDK/UI/bindings and additional targets are deferred; no new wallet product.
- `protocol` has no I/O; zcash/proofs/chains do not import one another or runtime; callers compose artifacts.
- U retains spend/view keys and locally proves Q; no U FVK/spend key to S. Independent U sender payout never requires S IVK release.
- Full-validity target is mandatory. SPV/operator/quorum/RPC is not a fallback.
- Unknown evidence remains pending; no deadline/admin allocation, beneficiary redirection or latest-version rewrite.
- All attempted allocation/uniqueness consumption and both transfers revert together on failure; original entitlement remains retryable.
- One authenticated real source note may arm only one obligation in the selected EVM deployment across supported versions; uniqueness reservation is atomic with funding and retained after terminal.
- Existing no-Git-init/commit/push constraint stays; no privileged viewers, key signing, broadcasts, deployments or funding without explicit action authorization.
- Actual source/target/network evidence is distinct from generated local fixtures. No synthetic block/node acceptance may close full-source runtime gates.

## Review Focus

1. Mixed-input hidden values unavailable after hostile author disappears: Unknown must not become false payout/full refund; the capability gap remains an explicit full-release prerequisite.
2. Valid early P consumes the input before escrow activation: earlier historical proof must remain admitted and permit correct allocation.
3. Valid effect identity with substituted authorization/ciphertext: selected full body and source state must be verified, not txid-only.
4. Fresh order/commitment or new artifact version: same note tag cannot arm another obligation, and old entitlements remain usable.
5. Partial transfer/reentrancy/crash between actions: no split consumption, double funding or unbacked terminal status.

---

## Exact contracts proposed for approval

### Proportional allocation

Let `A > 0` be quoted net source consideration in zatoshis, `D > 0` exact funded destination amount in wei, and `C` the cryptographically authenticated **net U-funded** consideration under the selected complete-input predicate. Source amounts use bounded checked `u64`; EVM amount uses a full 256-bit integer, never a lossy Rust cast.

For supported `0 <= C <= A`:

```text
user_wei   = floor(D * C / A)
solver_wei = D - user_wei
```

Use full-precision multiply/divide; rounding dust goes to fixed S beneficiary, with loss strictly below one wei relative to the rational allocation. C=0 requires valid same-real-input nonpaying conflict (not silence); C=A requires actual recoverable payment. A partial payment also requires valid accepted-history conflict consuming the agreed real note, complete ownership/output/ciphertext/net accounting, and irreversible source-resolution facts. Both fixed transfers execute atomically; zero transfers skip the call. Neither relayer chooses beneficiaries nor source fees silently change A/D.

**Excess C>A is not silently a gift or automatically supported payout.** Proposed conservative treatment is pending until a separately proved, actually executed return of excess source value reduces net consideration to the approved allocation relation. Existing Q does not refund source funds already paid to S. Independent excess recovery needs a new explicitly authorized source-refund capability before such cases can be claimed supported. Owner can instead define another excess economic contract, but the implementation cannot invent it.

Unsupported mixed/third-party ownership/debit cases remain pending until complete independent witnesses and approved contribution rules exist. Proportional arithmetic does not solve hidden-input witness availability. This is a real protocol limitation and release gate, not an input guard or mock implementation.

### Statement, allocation and proof interfaces

`protocol` owns `StatementContext`, `ValidatedContext`, `SourcePolicyId`, `ProofArtifactId`, `OrderId`, `ConsumptionTag`, `SourceAmount`, `NativeAmount`, `Allocation { user, solver }`, `PendingReason` and versioned plain proof journals. Canonical context has fixed-width little/big-endian choices once agreed with Zoss; EVM fields use canonical ABI encoding. Independent byte/digest vectors freeze each actual choice before consumers implement it. No arbitrary algorithm identifier selects weak verification.

Proposed public entry points:

```rust
StatementContext::validate(&self) -> Result<ValidatedContext, ContextError>
ValidatedContext::encode(&self) -> Vec<u8>
allocate(quoted: SourceAmount, funded: NativeAmount,
         consideration: SourceAmount) -> Result<Allocation, AllocationError>
```

`allocate` is pure arithmetic, **not financial verification**. Its inputs may be untrusted; only actual target verification can authorize escrow settlement. Raw observations and caller-owned journals cannot construct `VerifiedSettlementFact`. Rust types cannot replace Solidity proof enforcement.

Proof artifact roles: preparation certificate, source validity/state extension, payment/classification, and composed settlement. Each has immutable program/VK/policy identity, actual public statement and explicit private witness schema. Full source validity needs authenticated predecessor state, not a hash of a caller snapshot. The exact guest's built image/VK and witness/public-journal formats are outputs of qualification tasks, never invented constants in contracts.

### Bootstrap and chain acceptance

Proposed full-validation baseline: reconstruct/validate testnet history from authenticated genesis semantics, or consume a recursively verified predecessor-state proof anchored at genesis. **No trusted arbitrary state checkpoint**. Every pool/UTXO/anchor/nullifier/upgrade/auth/history transition of accepted blocks must be covered; one-note app scope does not permit skipping unrelated transactions.

Full validity does not establish global canonicality: qualified source policy must pin valid chain selection, competing-history availability/challenge/freshness and source finality. Counts/limits come from actual network/policy approval, not made-up defaults. Funding stays disabled until this policy is concrete and enforced by the verifier. Earlier admissible spending transactions must remain provable. A native Zebra result or header alone is not a proof.

## File and ownership map

| Task | Production paths | Evidence/tests |
|---|---|---|
| 1 | `crates/protocol/src/{lib,context,amount,allocation}.rs`, manifest | `crates/protocol/tests/{context,allocation}.rs` |
| 2 | `crates/zcash/src/{lib,authoring,witness,validation}.rs`, manifest/root lock | `crates/zcash/tests/authoring.rs` |
| 3 | `crates/proofs/src/{lib,preparation,payment}.rs`, actual guest build/artifacts under same crate | `crates/proofs/tests/{preparation,payment}.rs` |
| 4 | `crates/proofs/src/history/`, actual history guest/state proof integration | `crates/proofs/tests/history.rs` |
| 5 | `crates/proofs/src/{composition,consumption,artifacts}.rs` | `crates/proofs/tests/composition.rs` |
| 6 | `contracts/evm/src/{StatementVerifier,NativeEscrow}.sol`, actual pinned backend verifier | `contracts/evm/test/NativeEscrow.t.sol` and real-proof fixtures |
| 7 | `crates/chains/src/{lib,evm}.rs`, manifest | `crates/chains/tests/evm.rs` |
| 8 | `crates/runtime/src/{main,store,driver}.rs`, manifest | native CLI/store behavior tests |
| 9 | selected existing module seams/root dependency pins only | actual Zoss conformance/isolation checks |
| 10 | implementation docs/artifact lifetime/runbooks; fixes in owning modules | actual native end-to-end, adversarial/lifetime/privacy/resource evidence |

Create modules only when real behavior belongs there; no empty future files. Names above assign ownership, not new services/crates. Shared protocol edits have one integration owner. After contracts exist, source authoring and backend/full-history qualification can be investigated independently; EVM/client/runtime consumers wait for actual consistent interfaces, not invented mock outputs.

### Task 1: Validated native statements and proportional arithmetic

**Consumes:** reviewed exact amount/economic/context contract and agreed Zoss encoding vectors. **Produces:** validated context, canonical bytes, checked allocation; no verified financial fact.

- [ ] Write failing allocation tests with independent values: A=3,D=10,C=1 → U=3,S=7; C=2 → U=6,S=4; C=0 → U=0,S=10; C=A → U=D,S=0. Reject A=0/C>A and prove full-width multiplication does not truncate at u128/u256 boundaries.
- [ ] Write context tests rejecting zero/wrong network/pool/branch/deployment/asset/beneficiary/schema/policy/VK bindings and noncanonical/trailing-byte input, using independent exact wire vectors once encoding agreement exists.
- [ ] Run `cargo test -p ziquid-protocol`; observe failure because real API/behavior is missing, not unrelated syntax errors.
- [ ] Implement pure amount/context/allocation modules using checked U256/full-precision arithmetic and a single real canonical encoding; no source truth booleans or generic verifier.
- [ ] Run targeted/full workspace tests and a throwaway native caller over boundary/context/partial cases. Record actual output; no gate closure from arithmetic alone.

### Task 2: Real local Ironwood P/Q and sender witness custody

**Consumes:** Task 1 context plus real upstream note/anchor/witness. **Produces:** unsigned P, final fully authorized/proved Q, private payout witness and exact redacted preparation inputs.

- [ ] Add real upstream behavior checks for one valid owned V3 note, correct pool/branch/expiry, normal padding/every-action completion, source fee/change conservation, and unsigned export with no real P completion material.
- [ ] Qualify the published candidate lockfile/API cohort by compiling actual authoring and sender recovery; do not mix newer Git signatures/dependencies under old package labels.
- [ ] Implement `prepare(context, note, witness, wallet_capability)` in authoring, build for PCZT, locally prove/sign/extract Q, retain P private effects/authorization gate. Preserve sender ciphertext randomness/receiver/value/memo/action-index witnesses before redaction.
- [ ] Exercise missing dummy/action signatures, malformed positive outputs, wrong fee/anchor/branch, redaction leaks and same-effect rebroadcast. New app preparation certificate from Task 3 is required for S's independent no-FVK validation; source proof alone is insufficient.
- [ ] Run actual local generated proof/transaction extraction and inspect only redacted results. Actual real-note/U-offline broadcast waits for specific source action permission; local fixtures do not pass M2 network acceptance.

### Task 3: Qualified backend and app preparation/payment relations

**Consumes:** Tasks 1–2 statements/private witnesses and qualified upstream APIs. **Produces:** real private preparation/payment proofs with identical sender/receiver predicate and actual verifier artifacts.

- [ ] Compile and execute deterministic native reference checks for real note membership/value/nullifier/ownership, complete dummy/input set, every Q self-output ownership/fee and full encryption recoverability. Reject unrelated IVK and omitted paying outputs.
- [ ] Qualify explicit local SP1/Groth16 guest execution/real proving and pinned base EVM verifier. Disable mock/network proving; reject non-ZK intermediates at private interfaces. If this backend cannot execute the real checks, report exact guest/tool/library evidence and qualify another real backend without changing trust/relations.
- [ ] Implement actual preparation relation linking hidden FVK-derived real-note ownership/nullifier to exact P/Q effects and complete zero dummies, plus recoverable U outputs. Prover receives U private data locally; S receives no FVK and verifies the actual certificate.
- [ ] Implement full receiver and independent sender payment relation for the same quoted receiver/amount/ciphertext/input predicate. Required mixed T returns S-owned A with gross A/net zero: reject payout; missing ownership/debit witness is pending, not false nonpayment.
- [ ] Generate real wrapped proofs and verify them natively; mutation of context/ownership/dummy/ciphertext/effect invalidates proof. Record actual cycles/memory/proving and witness scope. Unsupported hostile input witnesses remain a named feasibility blocker, never synthesized from public bytes.

### Task 4: Full validating source state/history proof

**Consumes:** reviewed source/bootstrap/fork policy, authentic genesis/history/state witnesses and Task 3 backend qualification. **Produces:** actual deterministic source-validity/state-transition proofs, effect/auth-body/inclusion facts and earlier spending provenance.

- [ ] Reuse/extract actual maintained validator semantics, not a node RPC acceptance wrapper. Map every semantic/contextual check from the pinned validator to guest constraints/state transitions, including non-Ironwood pools and transparent script validity.
- [ ] Write failing checks for arbitrary checkpoint state, orphan/lower-work competing chain, omitted tx/auth body, root-as-leaf/count manipulation, wrong branch/expiry/anchor/nullifier/state and earlier P/T omission.
- [ ] Implement authenticated predecessor-state bootstrap, connected block validity/PoW/difficulty/time/subsidy/history/auth commitments, complete transactions/UTXO/pool/anchor/nullifier state transitions and selected history policy. Native async/DB/FFI dependencies must be replaced only by equivalent reviewed deterministic validation code, not skipped checks.
- [ ] Prove actual qualified history/state extension and selected full transaction authentication in the guest; composed verification anchors to genesis/predecessor proof. Compare independent native validation over the same source data.
- [ ] Observe altered histories/bodies/checkpoints fail and earlier bound payments remain admitted. If actual full-validator guest/cost cannot be implemented, this task is blocked with concrete evidence; SPV is not a fallback and later escrow cannot claim full settlement.

### Task 5: Composed private financial fact and one-note uniqueness

**Consumes:** preparation/payment/history proofs, agreed exact allocation and deployment-scoped uniqueness. **Produces:** real composed settlement proof/public journal and stable authenticated consumption tag.

- [ ] Define and review a stable secret-bound PRF/nullifier linkage: actual ownership/nullifier derivation secret participates in tag proof; arbitrary chosen salt/key cannot alter same-note identity. Namespace is selected source network/pool and EVM deployment, stable across funded supported versions.
- [ ] Implement actual app proof linkage/composition so S uses reusable preparation certificate for Q recovery without U FVK/nk, and U independently proves payout. Public journals disclose no source locator/receiver/value/path fingerprints beyond approved disclosures.
- [ ] Write/execute new-order/random-commitment/new-version same-note duplication, fabricated tag key, paying P′, earlier P, unavailable witnesses and net-zero mixed-T cases. Both proof routes must agree exact contribution/allocation predicates.
- [ ] Bind full context/history/policy/artifact/allocation/tag to actual verified journal; produce immutable image/VK/version metadata and reproducible artifact generation commands. Never expose a caller constructor as financial verification.
- [ ] Verify real composed proofs and mutation rejection. Cryptographic construction and witness feasibility need independent security review before money acceptance.

### Task 6: Actual EVM verifier and atomic proportional escrow

**Consumes:** Task 5 real backend/verifier/public-journal formats; reviewed proportional/excess rules. **Produces:** actual fixed-beneficiary fund/arm/settle with deployment-wide tag reservation, no timer/cancel and atomic both-beneficiary transfer.

- [ ] Write Foundry checks for exact native funding, unsupported policy/VK/domain rejection, same-note duplicate arming, armed cancellation denial, and actual U/S balances for C=0/partial/exact. Tests of allocation storage may use controlled fixtures but cannot substitute for actual proof integration.
- [ ] Integrate the actual immutable pinned base verifier and exact program/VK/journal parsing. Require preparation proof/tag at fund-and-arm; enforce deployment/chain/code/policy/context and exact value. Persistent tag reservation spans artifact versions; no registry latest/owner reallocation.
- [ ] Implement settle with full verified allocation sum D; both fixed transfers and terminal/consumption revert atomically if either fails. Reentrancy/new-order/replay/beneficiary substitutions fail; no claim deadline.
- [ ] Run in-process EVM execution with **real generated Task 5 proofs**, observe balances/state/receipts; tampered proof/program/journal/body/context fails. No broadcasts/deployment transactions without approval.
- [ ] Verify recipient revert/OOG/reentrancy then same-valid-proof retry, proof after source expiry/new version and no double settlement. Unknown/excess without approved source-return proof cannot allocate.

### Task 7: Real native destination clients and independent arm checks

**Consumes:** Task 6 ABI/bytecode/context/real state. **Produces:** exact unsigned fund/settle calls, independent code/config/amount/beneficiary/finality checks and operation reconciliation.

- [ ] Implement `chains` actual ABI/context encoding and selected local RPC/read capabilities, actor-owned signer boundaries, exact operation/receipt/finality provenance. Source/proof crates remain outside its import graph.
- [ ] Write/execute wrong bytecode/verifier/amount/beneficiary/chain/config and uncertain submission checks; U never releases P from server event/quote-only assertion.
- [ ] Exercise exact operations against actual EVM state; unknown outcome reconciles before retry/re-fund. Local read/VM evidence is not deployed staging; transaction actions require approval.

### Task 8: Durable solver/native driver

**Consumes:** real Tasks 1–7 artifacts/interfaces. **Produces:** actor-private durable journals/reservations/proof jobs/reconciliation and native end-to-end execution commands.

- [ ] Implement a real SQLite store with checked transactional reservations, unique operation/order records, persist-before-export/sign/send and atomic outcome reconciliation; U/S custody stores remain separate with reviewed encryption/access/backups.
- [ ] Write/execute concurrent reservation, crash before/after funding intent/send/receipt, cache loss/restart/reorg, backup restore, released-but-unmined authorization and unknown operation tests. TTL/absence cannot free armed funds.
- [ ] Compose native wallet prepare/check/export, quote/reserve, proof, independent arm verification, authorized P/Q submission requests, settle/retry/reconcile/status. No SDK or duplicate rules in argument handlers. Privileged real signing/broadcast remains an explicit user action.
- [ ] Launch the actual native driver over real backend/source/VM artifacts, observe durable progress/transfer evidence, kill/restart workers and resume without double funding or private logging. Existing CLI test is updated only for actual changed commands, not pinned old wording.

### Task 9: Actual Zoss dependency cutover

**Consumes:** owner-published real common exports/revision and independent vectors. **Produces:** actual common-library reuse without new viewer/receipt conversion or shared private state.

- [ ] Send exact encoding/acquisition/client export requirements and compatibility results to the owner; retain acyclic caller-owned integration.
- [ ] Compile/execute agreed real exports, compare common context/source provenance/error vectors, test isolated private capabilities with two app-owned consumers. Unsupported exports fail closed.
- [ ] Migrate all callers/remove superseded common duplication; raw observations cannot construct financial fact. If owner exports are unavailable, block only these dependent checks and finish independent native tasks.

### Task 10: End-to-end security/lifetime/resource acceptance

**Consumes:** all real native/source/proof/EVM/persistence/shared artifacts. **Produces:** verified protocol evidence, accurate documentation/gate entries and independent code/security review.

- [ ] Execute P/Q/T/earlier/replacement/partial/net-zero and both-beneficiary failure paths through the actual native driver; inspect source allocation, actual destination balances/receipts and durable state. Actual network note/spend runs need action approval and remain separately reported.
- [ ] Execute source/destination halt/reorg, offline U/S witnesses, wrong proof/artifact context, old-order proving/verifying after expiry/version change, fresh-note-tag replay and backup recovery. Never claim expired Q can mine or invent finite recovery.
- [ ] Trace public/private surfaces and measure actual proof size/time/memory/gas/data/storage, setup/artifact provenance and operator linkage. Fix critical/high independent review findings without weakening relation/scope.
- [ ] Update affected implementation docs and DEX BLOCKERS only against exact observed closure; communicate Zoss evidence to its owner. Remove temporary experiments and obsolete callers. List unresolved full-validity/private-witness/excess/net-input cases honestly; no complete protocol claim until every named release criterion is met.

## Self-review and execution handoff

All design responsibilities map to tasks: pure protocol 1; wallet/independent witness 2–3; full validity 4; classification/hiding/uniqueness 3–5; target/client 6–7; durable driver 8; shared integration 9; full acceptance/lifetime 10. Shared interfaces have a single owner; task outputs are consumed by later explicit prerequisites. Unavailable arbitrary-T private openings, excess source-return authority, full-validator guest feasibility and network action evidence are not hidden behind placeholders; they are concrete blocking acceptance conditions that must be solved or reported as incomplete.

Before production changes, review the proposed exact proportional/dust/excess policy, full-validation genesis/bootstrap and chain acceptance contract, backend/setup/privacy qualification and execution method. Recommended execution: delegated bounded module slices with one shared-protocol integration owner and independent review, keeping dependency branches parallel when contracts permit. No Git commit steps apply. Do not interpret plan approval as transaction/funding/deployment permission.
