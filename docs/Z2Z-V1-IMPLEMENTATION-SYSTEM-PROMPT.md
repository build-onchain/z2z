# Z2Z V1 Implementation System Prompt

**Last updated:** 2026-10-06

## Latest owner instruction — active one-route release overrides the baseline below

**Scope approved 2026-10-06:** deliver one protected native-ZEC pair/direction, full quoted trades, both users online for agreement, a selected counterparty/shared link and four screens (Offers/quote, Review, Status, Recovery). Working default is **native shielded ZEC on a qualified Zcash testnet → ETH Base Sepolia**, not an assertion that the source note/network or deployment is ready. U sells ZEC/buys ETH; S buys ZEC/supplies ETH. Both roles retain independent payout/recovery capabilities and backups; source-payment authority follows independently verified target protection. The exact construction/order is pending selection/review; complete Q is conditional on selecting P/Q, not mandatory for a different native mechanism.

Use [roadmap R1–R10](Z2Z-V1-ROADMAP.md#active-approved-release--one-protected-native-zec-route-2026-10-06) as the entire 30-ID next-work checklist, not the samechain catalog. Owner selected **bilateral privacy with explicit disclosure** and **investigate a different native settlement construction**. The [approved matrix](ARCHITECTURE.md#approved-release-decision--2026-10-06) accepts exact bilateral terms/fees/own results, exact public ETH amounts/addresses/code/txs and potential IP/timing/linkage inference; secrets/FVKs/private witnesses remain owner-local. **R1.2 policy-definition DONE; implementation/privacy verification future R3/R10.** Historical strict-GD2 analysis remains, but unchanged own-result noninference is not this release's constraint. R1.3 native financial feasibility and R1.1 selected-contract freeze remain open; direct P/Q witness/excess/composition NO-GO is not general impossibility. Compare alternatives without approving a mechanism/trust change. Retain S1–S7/M1–M5 financial rights, loss prevention, full source validity, private uniqueness and both-role standalone recovery. Handle reachable hostile branches or prove protocol prevention; excess return needs actual authority/evidence unless sound prevention receives explicit retained-rights review. No samechain proof, UI rejection, generic timer or indefinite pending substitutes; no release date.

Reuse existing runtime/transport/PostgreSQL/custody. Required local companion handles wallet, sync, proof jobs, persistence and recovery so ordinary users do not manually administer PostgreSQL or run CLI/prover commands. Agree and exercise the four-screen API with the **user-owned sibling frontend**; never edit/take it over without separate assignment. Real testnet assets, both roles' recovery and independently verified actual transfers are mandatory; no custody/wrapped/transparent-ZEC/payment-directory or mock substitute.

Samechain 122 tasks, other chains/all-pairs, broad market discovery, deliberate user partial orders, standing/offline maker and wider production GUI remain later backlog, not parallel first-release prerequisites. Minimal app/companion is no longer deferred. Preserve old task IDs/evidence, funded code/rights, journals and original recovery artifacts; do not redo implemented primitives. **Everything below is the earlier execution baseline:** scope/order, selected-P/Q and unchanged strict-GD2 release requirements are superseded above; financial/loss-prevention/recovery and owner-local secret invariants remain binding. This limited annotation is not a whole-document-set consistency claim.

**Permission boundary:** current choices authorize policy/docs and alternative investigation only, not mechanism selection, trust change or automatic implementation from historical broad authorization below. Later implementation/review, heavy resources, real-secret/wallet/network actions, SQL changes, deployment (including local-node), signing/submission/funds, outages and release retain explicit approvals. Existing isolated PostgreSQL scope is not new install/reset/migration approval. No mainnet authorization.

## Superseded implementation baseline — retained provenance and reusable contracts

Use this as the active V1 implementation brief, subject to higher-priority instructions, current source and actual action permissions. It specifies acceptance, not resource feasibility, deployment/signing authorization, an audit or completion evidence. Retained V2/full-product obligations are not deleted by this release split.

**Active execution authorization — 2026-10-06:** User explicitly requested “Start building following system prompt and plans to finish entire project completely.” Implement reachable plan slices and run controlled generated-key/local verification; do not wait for routine coding confirmation. Unresolved privacy/backing/storage/prover qualification blocks dependent acceptance, not independent work. This does not authorize local SQL execution, real signing/submission, deployments, money movement, production-secret use, paid services or operational-data migration.

## Mission and Scope

Deliver **`z2z-node` in `ziquid-dex`**: P2P discovery, native CLI trading, samechain settlement with the maker online and fresh consent per fill, genuine owner-local proofs and **complete company-off recovery**.

The **first passing journey** is samechain, which the owner decided. It runs on **Base Sepolia**, an engineering default the owner can override. It uses real Native plus a new fixed-supply 6-decimal constructor-only ERC20. No presentation branding, separate demonstration mode, mock balances/verifiers or scripted success.

The first journey closes only itself. These **active parallel lanes** are required for the whole project:
- native Zcash/ZEC across the whole pipeline (L-ZEC; full P/Q/history/net/excess/uniqueness/recovery, S1–S7/M1–M5 unchanged; wrapped ZEC is never a substitute);
- HyperEVM spot plus HyperCore isolated position claims, under investigation; owner-side Core execution is not the selected design (L-HEVM);
- Solana Devnet owner-ZK (L-SOL);
- NEAR testnet owner-ZK, native NEAR first and then NEP-141 (L-NEAR);
- cross-chain fills across all pairs: HTLC first, not atomic, no privacy claim; proof-verified release is active research (X.CROSSCHAIN).

See the micro-plan [Parallel lanes](V1-MICRO-IMPLEMENTATION-PLAN.md#parallel-lanes-active-obligations-beyond-the-122-id-evmbase-catalog).

V1 includes:
- A long-running owner-local node that composes the existing native modules. It uses libp2p transport/discovery/reconnect (installed), a neutral lane beacon and bilateral sessions (planned), and bounded authenticated messages.
- CLI create/discover/list/fill/cancel/withdraw/status/sync/recover connected to actual node/chain state.
- Backed orders, fresh exact samechain packet consent from both online parties, atomic bilateral transfers, supported partial proceeds/remainder and eligible cancellation.
- Owner-local proving (system TBD after benchmark), genuine wrapped proofs, independent program/setup/verifier qualification and exact target admission.
- Durable intents/reservations/authorized bytes and restart/`Unknown` reconciliation.
- Encrypted cold restore → independent authenticated history → witness → real proof → owner sign → independent submit → actual asset arrival, with company services/bootstrap unavailable.

A mandatory hosted backend/shared order database/frontend bridge is not the V1 delivery surface. Bootstrap peers are discovery only, never money authority, owner provers or mandatory exit authorization. Support replacement peers and independent chain access. GUI is later production work; the user owns the sibling frontend. Do not edit/take over that repository.

**Retained V2/later production:**
- one-opening-signature maker-offline standing multi-fill;
- NEAR Intents/1Click adapter;
- GUI/companion and hardware-wallet modes;
- public LP/agents/ZSA;
- wider device/load/security qualification;
- separately authorized mainnet release.

Native ZEC, the other chains and cross-chain fills are **not** V2; they are the active lanes above. Strict GD2 privacy is an active **blocked** gate with no waiver. Do not remove the current bilateral consent checks as a shortcut to standing maker.

## Readiness and Authority Owners

- [V1-DELIVERY-MATRIX](V1-DELIVERY-MATRIX.md): release scope and end-to-end acceptance.
- [V1-ARCHITECTURE-DECISIONS](V1-ARCHITECTURE-DECISIONS.md): recorded owner decisions and remaining resource/deployment choices.
- [V1-MICRO-IMPLEMENTATION-PLAN](V1-MICRO-IMPLEMENTATION-PLAN.md) has 122 catalogued tasks for the **EVM/Base lane** across six phases, plus a Parallel lanes section covering X/L-ZEC/L-HEVM/L-SOL/L-NEAR/X.CROSSCHAIN. It defines dependencies and future acceptance; it is not exercised evidence.
- [Z2Z-V1-ROADMAP](Z2Z-V1-ROADMAP.md): existing top-level todo owner; track microtask IDs there rather than creating a parallel release tree.
- [V1-P2P-PROTOCOL-SPEC](V1-P2P-PROTOCOL-SPEC.md): candidate discovery/gossip/coordination design; reconcile its contradictions at P0.05–P0.07 before affected implementation.
- [V1-TESTNET-SELECTION](V1-TESTNET-SELECTION.md) and [V1-P2P-STORAGE-DECISION](V1-P2P-STORAGE-DECISION.md): per-lane network/asset descriptors and the selected per-owner PostgreSQL design. Neither approves deployment or SQL execution.
- [Phase 0 integration report](research/2026-10-06-phase0-coverage-invariants.md) plus its domain reports: per-ID status, owner answers, remaining research work plans.
- [PROVING-COST-SOLUTIONS](PROVING-COST-SOLUTIONS.md): resource qualification contract.
- [PRODUCT](PRODUCT.md), [ARCHITECTURE](ARCHITECTURE.md), [MODULES](MODULES.md): product, invariants and existing ownership seams.
- [BLOCKERS](BLOCKERS.md): sole readiness register; use §4.1 samechain prerequisites, not simplified/renamed native S-gates.
- [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md): sole exercised-evidence checkpoint.
- [SERVER-INDEPENDENCE](SERVER-INDEPENDENCE.md), [SQL-VERIFICATION](SQL-VERIFICATION.md) and applicable module contracts: recovery, operational restrictions and exact interfaces.

Native S1–S7/M1–M5 keep their original meanings and are now **active L-ZEC obligations**. Strict GD2 private-market failure remains a blocker: decentralizing transport does not solve output leakage, and bilateral-only disclosure is minimization, not a waiver. Claim only exercised, explicitly qualified disclosure/network/asset scope.

## Technology Stack and P2P Boundary

Compose the existing Rust workspace (`protocol`, `zcash`, `proofs`, `chains`, `runtime`) with Tokio/clap/serde, the existing samechain relations and owner-local prover, and EVM contracts/Foundry. Candidate lane toolchains are Solana SBF and NEAR wasm, selected per lane spec. SP1 remains the first proving **CANDIDATE**, not a qualified selection. PostgreSQL remains the only authorized active SQL engine.

**P2P stack:**
- **Installed:** libp2p 0.56 TCP+Noise+yamux, ping/identify, bounded seeded Kademlia, configured reconnect, ephemeral identity.
- **Planned:**
  - persistent identity;
  - a neutral lane beacon (PeerId + lane + protocol version only);
  - direct bilateral RFQ/session request-response;
  - BackingClaim verification;
  - optional independent relay for introduction and DCUtR only.
- Order terms are disclosed only to the selected counterparty, so order-term gossip is not used.
- QUIC/mDNS/GossipSub are gated by their bounds work (P0.07).
- Focused node modules go in `runtime`; there is no sixth `p2p` crate.

Peer identity is separate from wallet/financial identity. Authenticate and domain-bind versioned messages, but treat advertisements as untrusted hints until the required independent backing/ownership/current-spentness contract is satisfied. Peer signatures, known roots or another peer's RPC response alone cannot establish funded/spendable orders. Direct coordination binds the exact session, role, chain/deployment and packet; exchange only permitted public data and proof/authorization artifacts, never keys, note openings or private proving witnesses, even encrypted. Negotiation timeout does not release submitted or `Unknown` rights.

Bootstrap peers serve discovery only. Qualify reconnect, independent peer replacement and zero-paid network access; no company bootstrap, paid VPS, peer verifier or relay becomes money authority, owner prover or mandatory recovery permission.

## Decisions and Approval Status

Use the linked decision documents and BLOCKERS for authoritative updates; the following is the current planning baseline, not a second readiness register.

| Decision | Current evidence-backed status / required closure |
|---|---|
| V1 delivery scope | P2P owner-local `z2z-node`, CLI, samechain first journey on public-testnet assets, makers and takers online with fresh exact-packet consent per fill, supported partial rights and full company-off recovery. Native ZEC, the other lanes and cross-chain are **active parallel** obligations. Standing maker remains V2. |
| Public testnet/assets — P0.03 | First lane: **Base Sepolia 84532** (engineering default). Lanes: HyperEVM 998, Solana Devnet, NEAR testnet, Zcash testnet. Assets (owner): Native plus a **new** fixed-supply 6-decimal constructor-only token per lane, with no admin/hooks/proxy. RPC/finality (owner): two operators agree on a common finalized hash; an owner-run non-validating node may be the second source (design only); never call this consensus. Qualify **Solidity 0.8.34 / Cancun** per EVM lane. No deployment or distribution permission. |
| Owner-local durability — P0.04 | **Owner-selected design target:** each owner self-operates PostgreSQL, by default on the owner node. The DB holds digests/identities only. Exact certificates and signed-tx bytes go in owner-local immutable encrypted release capsules fenced before escape. Latest owner approval selects the already-running Docker PostgreSQL container for existing gated isolated-schema tests/create-drop, conditional on private verified-TLS connection inputs and schema guards. No installation/start/restart/reconfiguration, other-container use or operational migration permission follows. |
| Discovery privacy/backing — P0.05 | Owner: bilateral-counterparty-only disclosure. Proposed: a dedicated non-executable BackingClaim relation plus block-pinned TRUSTED_NODE state. Strict GD2 remains **unmet**. The finite compatibility experiment and its kill criteria are in the network report. |
| Wire/coordination design — P0.06–P0.07 | Owner packet order: public descriptors → freeze packet → encrypted backup + read-back → consent → proof → Released CAS → export. Session codec and bounds are proposed in the network report. They freeze in their own spec/plan review before code. |
| Proving/resources — P0.08, P1.23 | **UNQUALIFIED.** Owner: methodology only, no heavy trial now. ≤15 min per owner proof is a provisional objective, not a guarantee. Genuine all-mode wrapping, exact target admission, privacy/recovery qualification before funding. Per-lane verifier costs (Solana CU, NEAR gas) are unmeasured. |
| Recovery/private use — P0.10 | User approved the generated-key samechain encrypted snapshot/restore spec and plan (**next code wave**). Owner: a verified offline independent-failure-domain backup before funding and before each new release capability. Default: one random 32-byte owner backup key on offline media. Production secrets, the held production command, signing/proving/funding remain unauthorized. |
| Deployment/actions — P0.11, P5.01–P5.03 | **No deployment authorization**, including local Anvil. Network selection/design approval is distinct from deployment, allowances, signing/submission, funding, retries, SQL execution and outage-drill approval. Each requires its applicable specific permission. |

## Microtask Plan and Dependency Order

Read [V1-MICRO-IMPLEMENTATION-PLAN](V1-MICRO-IMPLEMENTATION-PLAN.md) before implementation. It expands the existing roadmap into **122 catalogued microtasks in six Phase 0–5 buckets**: 119 required/base tasks plus three conditional alternative-proof tasks P1.19–P1.21. User authorized execution on 2026-10-06; task completion still requires observed acceptance. Estimates and future checks are not results or external-action permissions.

| Phase | Tasks | Scope |
|---|---|---|
| 0 | P0.01–P0.12 (12) | Scope, threat boundary, testnet/assets, storage, privacy/backing, wire/network, measurement, finality, recovery and approvals. |
| 1 | P1.01–P1.23 (23) | Existing owner-local prover, complete resource/privacy measurements, genuine wrapping/exact admission and conditional alternatives. |
| 2 | P2.01–P2.28 (28) | Long-running node, libp2p discovery/gossip/coordination, owner isolation, durable restart/`Unknown` and CLI. |
| 3 | P3.01–P3.23 (23) | Witnesses, genuine proofs, authorized real full/partial/cancel/withdraw, atomic rollback/retry and restart. |
| 4 | P4.01–P4.18 (18) | Encrypted backup, clean restore, history/witness reconstruction, local proof/sign/independent submit and actual company-off recovery. |
| 5 | P5.01–P5.18 (18) | Early authorized deployment, two-user P2P acceptance/evidence and final security/privacy/user/operator/documentation review. |

Follow task dependency edges, not numeric phase order. **Controlled in-process-VM P4.01–P4.05 and P1.23 precede deployment; actual authenticated P5.03 deployment precedes deployed-context pre-deposit cold restore P4.11; P4.11 precedes first funded P3.13.** Creation restore does not require a previously admitted note; funded spend/recovery requires actual admitted history. Final funded cold drills follow the lifecycle. Existing roadmap Phase 6 security/documentation remains covered by **P5.14–P5.18**.

Storage/protocol/backing decisions block their affected slices; permitted nonfinancial work may proceed independently. A measured failed proving run can inform alternative research but never counts as proof qualification. Preserve archived plan provenance, already implemented primitives and all remaining native/V2 obligations; do not re-execute completed consolidation or implement through an open blocking decision.

## Storage — Design Selected, Execution Held

A **bounded volatile discovery cache** holds only rebuildable public peer/lane data. It is not durable storage for owned orders, prepared intents, reservations, authorized bytes or pending financial outcomes.

**Durable node storage design:** each owner self-operates PostgreSQL (owner decision2026-10-06). The owner subsequently approved existing isolated-schema tests and selected the already-running Docker PostgreSQL container, narrowly superseding the earlier local/Docker endpoint restriction. PostgreSQL remains the only SQL engine; SQLite and unrelated local test endpoints remain prohibited. There is no mandatory company database. Pending financial state is not disposable discovery data.

SQL-dependent verification remains **NOT RUN — selected container authorized; TLS/connection/schema qualification pending**. Parent observed the running `postgres` container `621cc7e67d78` on published port5432; assigned read-only qualification is checking actual TLS/version and handling connection inputs privately. Only existing gated tests and their own isolated schema create/drop are authorized once strict verified TLS, private `Z2Z_TEST_DATABASE_URL`, safe `Z2Z_TEST_PG_SCHEMA_PREFIX` and `Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES=yes` satisfy [SQL-VERIFICATION](SQL-VERIFICATION.md). No install/start/restart/reconfiguration, Testcontainers, operational migration/reset, production keys, heavy proving, transactions or funds. Container selection does not waive strict URI/TLS checks or imply a SQL pass. An unrelated shell's exports cannot update the existing agent execution environment; no feature build/test may overlap the in-progress default workspace run.

## Proving — Owner-Local, System TBD After Benchmark

**Owner-local proving (system TBD after benchmark). Proving feasibility UNQUALIFIED until benchmarked on target hardware.** Must measure existing SP1 first. SP1 is the integrated **CANDIDATE**, not a committed V1 proof-system selection. Circom, Halo2 and other owner-local alternatives are **CANDIDATES** requiring constraint/resource measurements and independent financial-relation, privacy, setup, verifier and recovery qualification.

The checkpoint records retained artifacts, a source-derived recursion-key component lower bound and an observed capped OOM without a certificate; these are not whole-prover peaks or minimum-RAM measurements. The user's i5-11400H / 16GB machine is the benchmark target, not a guaranteed supported configuration. **Resource targets: TBD after benchmark.** No CPU/RAM/storage minimum or proof-latency commitment is established.

1. Benchmark **existing SP1 `prove-owner` first** with the actual samechain guest and controlled non-production witnesses. Do not reimplement an existing circuit or infer wrapping resources from CPU execution/cycle counts.
2. Record source/ELF/program/setup pins, available RAM, process limits/swap, peak whole-prover/child/shared-memory usage, actual wall time, scratch/storage, proof result and failure stage.
3. Cover creation, both bilateral fill roles, cancel/exit, withdrawal and recovery proving across supported witness sizes. Select node-only and full-prover acceptance targets from measured results; keep them TBD until then.
4. Require genuine wrapping and independent admission against the exact authority/verifier/expected journal. SDK self-verification alone is not frozen EVM compatibility.
5. **If SP1 cannot qualify**, benchmark owner-local optimization/alternative **CANDIDATES** preserving the same ownership, consent, conservation, uniqueness and recovery relations. Require constraint/resource and verifier measurements before selection; no guessed savings or specific alternative commitment.

**Owner-local only:** witnesses contain secrets. No paid GPU/cloud prover, Succinct Prover Network, shared remote prover or witness upload fallback. No required paid infrastructure; zero paid proving services does not mean zero gas, storage or hardware use.

Qualify private diagnostics, SDK/Gnark shared-memory ownership/cleanup, scratch files and retained buffers under normal exit, crash and OOM. Direct execution suppresses guest diagnostics; asynchronous workers require process isolation, null diagnostic descriptors, bounded authenticated request/results and owner-selected descriptor-validated 0700 per-run scratch. Observe exit without losing worker identity before owned-group cleanup; accept a certificate only after successful lifecycle cleanup and independent target-compatible verification against caller pins and parent-computed complete journal. Scratch deletion/worker isolation is not an erasure-complete claim; record remaining private sinks and retention limits.

## Immutable Verifier and Funded Lifetime

**Existing implementation, not a V1 proof-system commitment:** `contracts/evm/src/SamechainAuthority.sol` constructs its frozen SP1 verifier and immutably pins `verifier`, `verifierCode` and `ownerProgram`. There is **no in-place VK change or verifier upgrade**. A benchmark-supported proof-system, verifier or owner program VKey change requires a **new authority deployment**, reviewed contract changes where applicable, specific deployment authorization, new client/deployment/artifact pins and independent genuine-proof/funded/recovery qualification.

Preserve old signed/funded bytes, deployment versions, usable artifacts and recovery paths. Replacement deployment does not migrate assets, invalidate old rights or authorize retiring funded rules/artifacts.

**Current Fill2, not a remaining whole-Terms implementation task:** [reviewed construction](superpowers/specs/2026-10-06-independent-owner-fill-design.md), [protocol](../crates/protocol/src/samechain/fill.rs), [owner codec/relation](../crates/proofs/src/samechain.rs), [runtime](../crates/runtime/src/samechain.rs) and [guest](../crates/proofs/methods/samechain/src/main.rs) implement frozen packet + public E + ordered A/B opaque leaves + independent private `own_salt`. Each authenticated input supplies only its own policy; no counterparty policy/common blind/witness exchange. `review-fill --packet FILE --execution FILE --role a|b --witness-stdin` requires independently approved canonical FillExecution frame2 and exact E/embedded packet equality, not JSON or approval inferred from witness stdin. Guest mode0 is byte0 + one OwnerWitness frame2, without a duplicate packet prefix; execute/prove keep independent `--packet` equality preflight. Only Fill witness/relation fields are2, outer packet/journal/schema and note/order/policy/tree/AEAD/ciphertext/creation/single/withdrawal/blinds remain1. Preserve [legacy fill1 artifacts](../legacy/samechain-fill-v1-pre-fill2-20261006/manifest.json), no conversion/runtime fallback/migration. New ELF/program requires specifically authorized new immutable authority and genuine all-mode target/recovery qualification. [Checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) owns actual current evidence and completed independent source reviews; independent source/setup/program qualification stays UNVERIFIED. Native private-opening availability is addressed only for samechain: durable backups/P2P orchestration/backed discovery, wrapping/funded/recovery/strict GD2 remain open; E quantities are counterparty-visible, not secrecy evidence.

## Financial and Execution Invariants

- Chain authority enforces money; gossip/cache/database/signature/inspection are not financial settlement facts.
- Bind exact chain/deployment/code/verifier/program/schema, assets, quantity/net-price/fees, beneficiaries, input/path and complete packet consent. Relays may submit only unchanged owner-authorized bytes; no unilateral signing or mutation.
- Proof verification, unique nullifier/right consumption, output append and asset transfers form one atomic transition. Failed proofs/transfers roll back and preserve eligible retry rights.
- Every settled partial fill is independently successful; only the correct residual stays open or cancels. Cancel cannot undo paid fills or revive spent backing.
- Persist prepared intent before export/sign/send. `Unknown` is nonterminal, not a timeout-release trigger; reconcile actual chain consumption before freeing capacity or retrying.
- Exact public descriptors must form one byte-identical canonical packet before either owner consents/proves. Persist certificate-release exposure before export: permissionless eligible fills can execute without a later preview ACK. Timeout/disconnect/local abort never revoke a certificate or unlock Released/Unknown backing; reconcile real expiry/finalized consumption first.
- Mark `Completed` only after actual correct transfer and required inclusion/finality observations. Simulation, proof generation, calldata or SQL credit are not payment.
- Pinned independent RPC/checkpoint observations remain explicitly TRUSTED_NODE observations, not independently validated consensus. Handle incomplete history, reorg and unavailability without invented terminal outcomes.

## Full Company-Off Recovery — V1 Required

Before irreversible funding, retain an owner-controlled encrypted bundle with actual secrets/capabilities, authorized context/bytes, exact asset/deployment descriptors, needed witness inputs and independently usable prover/artifact copies.

Exercise clean-process cold restore with company services/bootstrap unavailable; reconcile stale backups/`Unknown` against current consumption; acquire complete authenticated commitments/ciphertexts and spentness through independent chain access; decrypt/validate owned outputs and rebuild paths/witnesses; generate real cancel/withdraw proof locally; review/sign with owner wallet; submit unchanged authorized bytes through independent relay/direct chain; verify actual arrival and correct consumed/residual rights, including failed submission/transfer and valid retry.

Cover funded unfilled orders, supported partial proceeds/remainder and pending outcomes. Observation/decryption alone is insufficient. Cold restore is **not deferred to V2**; company independence differs from independently validating consensus.

The existing explicit approval hold on new secret-bearing production `check-appended-note-recovery` behavior remains binding.

**Scoped approvals (2026-10-06):**
- The generated-key samechain encrypted bundle/restore spec, plan, implementation and checks are approved ("Cho phép bundle và restore bằng khóa tự sinh").
- The earlier undecided backend was superseded by per-owner PostgreSQL. Later approval permits existing isolated-schema tests and selects the already-running Docker PostgreSQL container only; private connection inputs, strict verified TLS and schema scope still require qualification. No service/container lifecycle changes or broader operational/action permissions follow.

No production key consumption, production scanner/command invocation, real signing/submission or financial recovery is authorized. A restored private snapshot never resolves Released/Unknown.

## Permissions and Preservation

- Never request/print/commit/expose private keys, seed phrases, API tokens, DB credentials, FVK or private witnesses. Secret URI/config stays outside repo/chat/argv/log; DB operators must not receive witness inputs.
- No deployment **including local Anvil**, signing/submission, mainnet target, fund movement, publish/push or destructive operational migration without specific authorization. An implementation request grants none. Before transaction approval show cluster, signer/fee payer, recipients, assets, amounts, fees and simulation result.
- Synthetic generated-key/in-process VM checks are not real network transactions or money acceptance. Do not consume production secrets without applicable approval.
- Preserve operational PostgreSQL stores, legacy SQLite journals/sidecars, encrypted custody and funded ELF/VK/setup identities. No blanket target clean, inferred empty capacity, auto-conversion or decommission. Data migration needs separate authorization, exclusive writer fence and exact identity/state/amount/payload reconciliation.
- Preserve existing crate/package/binary names and protocol domains, widths/endian order, state tags, process frames and original migration bytes. Use existing conventions; no second financial runtime, speculative services, shims or fake fallbacks.

## Implementation and Verification Contract

Reuse `crates/{protocol,zcash,proofs,chains,runtime}` and `contracts/{evm,solana,near}` according to MODULES. Existing native-ZEC behavior is retained and is the base of the active L-ZEC lane. Native relations and proving stay in proofs, public inspection and clients in chains, and orchestration, storage and the CLI in runtime. Keys, signing and proving remain owner-local.

After explicit implementation authorization, follow the microplan dependencies: resolve applicable storage/network/privacy/backing/resource/testnet prerequisites; benchmark current prover; build P2P/node/CLI while independent qualification proceeds; qualify pre-funding recovery/artifacts; then under specific deployment/signing/funds approvals exercise genuine-proof/funded full/partial/cancel/withdraw/failure/restart/company-off acceptance. Do not substitute a centralized server/frontend, unverified-hints-only market or external venue journey for the requested V1.

Use disjoint agent ownership; parent integrates and runs verification once after edit waves. Children do not duplicate integrated checks. Keep completed source consolidation closed unless current evidence reveals a defect. No Git setup/commit/push authorization follows.

Maintain requirement → microtask ID → artifact/scenario → observed result → status (implemented/compiled/exercised/NOT RUN/blocked) in the existing checkpoint/readiness owners. Distinguish pure/native, CPU guest, wrapped proof, target VM, SQL, funded network and full recovery evidence. Required adverse cases include valid-first/invalid-second bilateral proof, wrong context/beneficiary/fees, receiver/token failure, replay/double spend, competing fills/cancel, process loss before/after send, `Unknown`, stale backup, retained-root churn and valid retry.

First-journey completion requires two users to discover genuinely backed counterparties, authorize real fills, observe correct transfers/proceeds/remainder, restart safely and complete full company-off recovery on qualified owner hardware.

Record in the checkpoint:
- genuine proof bytes;
- exact artifact/deployment/asset pins;
- measured resources;
- actual testnet transaction hashes;
- state/balance changes;
- trust/finality assumptions;
- rollback/retry/recovery evidence.

No fixtures, compilation, CPU journals, simulation or UI substitute. State every missing prerequisite, and never label a narrowed or unverified slice complete.

First-journey acceptance is **not** project completion. Native ZEC, HyperEVM/HyperCore, Solana, NEAR and cross-chain lanes each need their own acceptance. It is also not mainnet readiness, an audit, or solved strict privacy.
