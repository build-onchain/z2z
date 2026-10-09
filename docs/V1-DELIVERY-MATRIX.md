# Z2Z V1 Delivery Matrix

## Active release acceptance — superseding scope (2026-10-06)

The latest owner-approved release is **one protected native-ZEC route**, one direction, full quote, both users online for agreement, selected counterparty/link and four app screens. Working default: native shielded ZEC on a qualified Zcash testnet → ETH on Base Sepolia; neither usable source notes nor target deployment are claimed ready/authorized. U sells ZEC/buys ETH; S buys ZEC/supplies ETH. Exact arming/claim/refund order depends on a selected reviewed native construction; source-payment authority may not escape before independently verified target protection. Direct P/Q is the previous incomplete candidate, not locked release architecture.

The [roadmap R1–R10](Z2Z-V1-ROADMAP.md#active-approved-release--one-protected-native-zec-route-2026-10-06) owns the complete 30-task next-work checklist and its acceptance/dependencies: R1 financial/privacy go/no-go; R2 actual wallet/full source history/hostile outcomes; R3 original native composed proof/resources; R4 prefund/atomic target allocation; R5 both-owner durability/backup; R6 selected quote orchestration; R7 user-owned frontend contract/secure companion; R8 authorized deployment/deployed-context pre-deposit restore; R9 actual trades/failures/company-off recovery; R10 independent security/usability/limited release.

**Latest policy/research choice:** the owner approved bilateral privacy with explicit disclosure and investigation of a different native construction. [R1.2's matrix](ARCHITECTURE.md#approved-release-decision--2026-10-06) accepts exact bilateral terms/fees/own results, exact public ETH addresses/amounts/code/transactions and possible IP/timing/linkage inference; keys/FVKs/private witnesses remain local. **R1.2 policy-definition DONE; implementation/privacy verification future R3/R10.** Strict GD2 is no longer this release's constraint; historical analysis remains. S1–S7/M1–M5 financial rights, no company custody/loss, source validity, once-only and independent both-role recovery remain binding. Handle every reachable hostile branch or prove protocol-enforced prevention; excess return cannot be removed without sound prevention and explicit retained-rights review. Direct P/Q financial NO-GO persists, alternative selection remains open, and research approval is not mechanism/trust approval. No release date, mock, payment directory or samechain proof substitute.

Reuse existing per-owner PostgreSQL, custody and transport under current permission/evidence scope; no new database install or manual PostgreSQL/CLI/prover prerequisite for ordinary app users. The companion and four-screen integration are required now; coordinate with, never take over, the sibling frontend. The older samechain 122-task/all-lanes matrix below is retained backlog/provenance, **not first-release prerequisites**; “GUI later” excludes only wider GUI scope, not this minimal app. Existing funded rights/artifacts stay usable. No new implementation/resource/secret/SQL/deployment/signing/funds/outage/mainnet authorization follows.

## Superseded delivery baseline — retained acceptance for later lanes

**Updated:** 2026-10-06  
**Scope:** two levels.

- **First passing journey:** samechain. Owner answer Z1 says the first passing journey is samechain; choosing Base Sepolia for it is an engineering default, not owner approval. The journey uses the existing 122-ID catalog: `z2z-node` P2P discovery, CLI, bilateral fresh-consent full/partial fills, cancel/exit, withdrawal, real owner-local proofs, real testnet assets and complete company-off recovery. The owner allows it to release first.
- **Whole project:** additionally requires every active lane and pair:
  - L-HEVM: spot, then isolated position-claim research toward the full Core use cases.
  - L-SOL: owner-ZK on Devnet.
  - L-NEAR: native NEAR first, NEP-141 later.
  - **L-ZEC:** native ZEC with S1–S7/M1–M5. Wrapped ZEC never substitutes.
  - X.CROSSCHAIN: all pairs in parallel. Token/collateral legs come first, and position-claim research is active.

The first journey's release does **not** complete the project. GUI and standing maker remain V2.

This is an acceptance contract, **not evidence that deliverables are complete**. [BLOCKERS](BLOCKERS.md) owns readiness; [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md) owns exercised evidence. Documentation, compilation, CPU execution and negative tests do not establish genuine wrapped-positive or funded acceptance.

**Exercised prerequisites — 2026-10-06:** direct Linux authenticated transport passes10 process checks and a sustained33s two-node smoke; public setup measurement, bounded unsafe-run refusal, controlled both-owner partial/restored native corpus and dedicated-child diagnostic defaults are exercised and source-reviewed. Exact results live in the native checkpoint. These do not close discovery/backing, durable node state, genuine wrapping/admission, encrypted cold recovery or funded acceptance below.

## V1 Core Deliverables

### 1. Samechain Proof-Controlled Assets

**User journey:** deposit Native/qualified ERC20 → admitted owned note → backed order → bilateral fill → proceeds/remainder → cancel eligible remainder or withdraw.

**Required acceptance:**
- Genuine owner-local wrapped proofs accepted by the independently pinned authority/verifier with the exact expected journals.
- Fresh exact-packet consent from both online parties for every fill; supported partial fills conserve backing and leave only correct residual rights.
- Current [reviewed Fill2](superpowers/specs/2026-10-06-independent-owner-fill-design.md) binds frozen packet/E/ordered opaque A+B leaves and private per-owner `own_salt`, not both policies/common blind. [Actual protocol](../crates/protocol/src/samechain/fill.rs)/[witness](../crates/proofs/src/samechain.rs)/[CLI](../crates/runtime/src/samechain.rs) require independently selected canonical E frame2 via `review-fill --packet FILE --execution FILE --role a|b --witness-stdin`; both packet and E must equal witness contents. Integrate this existing native construction with durable backups/session orchestration, not a new whole-Terms exchange. Counterparty-visible quantities are not GD2 secrecy or advertised backing.
- Actual asset transfers observed for creation/fill/withdrawal and eligible cancel/exit.
- Invalid proof/context, valid-first/invalid-second bilateral proof, receiver/token-transfer failure, replay and competing fill/cancel leave atomic state/transfer rollback and permit only valid retries.
- Spent rights cannot be revived by restart, stale backups, timeout or a cached order row.

### 2. P2P Discovery and CLI Trading

**Required acceptance:**
- Long-running Rust `z2z-node` composes existing native protocol/proofs/chains/runtime; no second money authority.
- Independent nodes discover backed orders through authenticated, versioned, bounded gossip and reconnect synchronization.
- CLI create/discover/list/fill/cancel/withdraw/status/sync/recover drives actual node and chain state.
- Backing/spentness checks do not trust gossip or a peer signature as financial proof.
- Company bootstrap provides discovery only; alternative peers/bootstrap replacement and direct chain access remain usable without company services.
- No mandatory hosted backend, shared order database, paid VPS or frontend bridge in the V1 critical path. The sibling frontend remains user-owned and retained for later production integration.

### 3. Durable Node State

**Storage: per-owner PostgreSQL design target selected (2026-10-06); SQL execution held.** Each owner's own PostgreSQL holds lane-keyed digests and identities. Executable certificate, signed-transaction and preimage bytes live only in an owner-local encrypted release capsule. Release order: capsule durable → `Released` CAS → export, on every sink. A **bounded volatile discovery cache** holds rebuildable public advertisements only. See [storage decision](V1-P2P-STORAGE-DECISION.md).

[SQL-VERIFICATION](SQL-VERIFICATION.md) remains binding: no local SQL execution, no SQLite. SQL-dependent checks remain NOT RUN until a private URI and an authorized isolated scope exist. Capsule, snapshot, release gate, schema file and pure state machines can be implemented and compiled without SQL.

**Required acceptance:** owner-local storage durably retains prepared intents, reservations, `Released`/`Submitted`/`Unknown` outcomes and the release capsules across process loss. It imposes no mandatory company infrastructure, loses no pending liabilities and never resurrects consumed rights. Existing SQL/SQLite funding journals, sidecars and encrypted custody are preserved. Data migration requires separate authorization and writer-fenced exact reconciliation.

### 4. Complete Company-Off Recovery

**Required before irreversible funding and before each new release capability:** an owner-controlled encrypted recovery bundle with a verified copy on offline media in an independent failure domain. It holds usable secrets/capabilities, authorized context/bytes, exact deployment/assets and independently usable prover/artifact copies for the funded lifetime. The generated-key immutable snapshot spec and plan are approved in writing; implementation has not started.

**Full acceptance drill:**
1. Company services/bootstrap unavailable; restore the encrypted bundle in a clean process.
2. Acquire complete authenticated commitments/ciphertexts and current spentness through independently selected chain access at pinned blocks.
3. Decrypt owned outputs, validate commitments and rebuild exact paths/witnesses for proceeds/remainder.
4. Reconcile stale backups and pending/`Unknown` intents without reviving consumed rights.
5. Generate the real cancel/withdrawal proof on qualified owner hardware.
6. Review/sign with the owner's wallet and submit unchanged authorized bytes via a non-company relay/direct route.
7. Observe actual asset arrival, final consumption/residual rights, failed submission/transfer behavior and permitted retry.

Cover funded unfilled orders, supported partial proceeds/remainder and pending outcomes. Observation or decryption alone is not recovery completion. Independent RPC/checkpoint observations remain a stated trust assumption (two operators agreeing on a finalized hash), not validated consensus. Fully validating native-ZEC history belongs to active lane L-ZEC. Existing explicit approval gates for new secret-bearing recovery behavior remain binding.

## Resource and Verifier Qualification

See [PROVING-COST-SOLUTIONS](PROVING-COST-SOLUTIONS.md) for the measurement contract and [V1 architecture decisions](V1-ARCHITECTURE-DECISIONS.md) for unresolved choices.

**Proving feasibility UNQUALIFIED until benchmarked on target hardware.** The [native checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) records setup/artifact sizes, a source-derived component lower bound and a capped OOM without a certificate, not a whole-prover peak or hardware minimum. The user's i5-11400H / 16GB machine is the benchmark target, not a guaranteed supported configuration.

**Must measure existing SP1 first. Resource targets: TBD after benchmark.** Benchmark existing `prove-owner` using the actual samechain guest and controlled non-production witnesses. Record available RAM, process limits/swap, whole-prover/child/shared-memory peak, wall time, storage, result/failure stage and supported operations/witness sizes. Require genuine wrapping and exact target admission; no RAM/CPU/storage minimum or latency commitment is established.

**Owner-local proving; system TBD after benchmark.** SP1 is an integrated **CANDIDATE**, not a qualified selection. If it cannot qualify, Circom, Halo2 and other owner-local systems remain **CANDIDATES** requiring constraint/resource measurements and independent relation, setup, privacy, verifier and recovery qualification. Witnesses contain secrets: no paid GPU/cloud prover, shared remote prover or private-witness upload path is accepted. Zero paid proving infrastructure does not eliminate chain gas, storage or hardware use.

**Verifier deployment:** SamechainAuthority constructs its frozen SP1 verifier and immutably pins verifier/code and owner program. A proof-system, verifier or program VKey change requires a **new authority deployment**, plus reviewed contract changes for a different verifier, explicit deployment authorization, updated client/artifact/deployment pins and independent genuine-proof/funded/recovery qualification. There is no in-place VK switch. Old funded rights and original artifacts remain usable; redeployment does not authorize asset migration or retirement.

**Fill2 artifact boundary:** [guest mode0](../crates/proofs/methods/samechain/src/main.rs) is byte0 + one OwnerWitness frame2, no duplicate packet prefix; execute/prove independently compare `--packet`. Fill relation/consent fields are2 within unchanged outer journal/packet/schema1; note/order/policy/tree/ciphertext and creation/single/withdrawal/blinds remain1. Preserve [original fill1 artifacts](../legacy/samechain-fill-v1-pre-fill2-20261006/manifest.json) without conversion/fallback or automatic asset migration. New ELF/program requires specifically authorized new immutable authority and genuine all-mode proof/target/recovery qualification. Current source reviews are complete; [native checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) alone owns actual new-artifact CPU/program/correspondence evidence and limits, with independent source/setup/program qualification still UNVERIFIED. This is not wrapped/funded/private-market/recovery readiness.

## First Journey / Whole Project / V2 Matrix

All entries below are **required acceptance**, not completion marks. Each lane is qualified and reported separately.

| Feature | First passing journey (samechain; Base by engineering default) | Whole project (active, parallel) | V2 |
|---|---|---|---|
| Samechain create/fill/cancel/withdraw | Genuine proof admission, actual transfers, rollback/retry, residual rights | Same per lane: HEVM spot, SOL, NEAR (native first, NEP-141 later), each an immutable authority | Wider scale/device qualification |
| HyperCore positions | — | Isolated position-claim research toward the full Core use cases; owner-side Core execution is not the design | — |
| Resource qualification | Measure existing SP1 first; UNQUALIFIED; targets TBD | Per-target verifier cost (EVM/SOL/NEAR) | Wider hardware |
| Verifier / program changes | Immutable pins; a new authority plus complete requalification | Same per lane | Reviewed, rights-preserving migrations |
| Maker fills | Both online; fresh consent per exact fill | Same | One opening signature, maker-offline standing multi-fill |
| Owner recovery | Verified offline backup, cold restore, history, proof, sign, submit, arrival | Per lane, plus cross-chain preimage/lock/refund recovery | Additional devices |
| Discovery / UI | P2P `z2z-node`, native CLI, replaceable bootstrap | Lane-tagged beacons/sessions | GUI, secure companion |
| Durable persistence | Per-owner PostgreSQL design, X.REL-DIGEST; SQL execution held | Same journal keyed by lane | Optional HA, never money authority |
| Native ZEC (L-ZEC) | Not part of the samechain first journey (owner answer Z1) | **Required:** P/Q/history/net classification/excess/uniqueness/privacy/recovery, actual delivery, ZEC↔{Base, HEVM, SOL, NEAR}; no wrapped substitute | — |
| Cross-chain fills | — | **Required:** all pairs, token/collateral legs first (HTLC CX-1, not atomic or private), CX-2 research | — |
| Privacy | Strict GD2 Blocked; bilateral disclosure is minimization, not a waiver | Same; the HTLC hash links chains | Sound construction and evidence |
| Signing | Owner-local CLI, exact authorization | Per-lane key scope; mutually exclusive tx replacement | GUI/hardware wallet |
| Network release | Base Sepolia pins and qualified assets, specifically authorized actions | HEVM 998, Solana Devnet, NEAR testnet, Zcash testnet: each authorized separately | Mainnet, separately reviewed |

## Critical Path and Gate Mapping

1. Durable storage design target is selected (per-owner PostgreSQL). Next: SQL execution scope, then exact Base testnet asset/deployment pins. Resource targets remain TBD after benchmark.
2. Measure existing SP1 first. Qualify artifacts, private-data boundaries, genuine wrapping and exact verifier admission before committing to a system or targets.
3. Implement `z2z-node` discovery, synchronization, CLI orchestration and durable restart/`Unknown` handling; non-financial work may proceed alongside proving qualification.
4. Under specific deployment/signing/funds authorization, exercise actual funded full/partial/cancel/withdraw lifecycle, atomic failures and valid retry.
5. Exercise the complete company-off recovery drill and record actual asset arrival.

Use **BLOCKERS §4.1/§4.2 prerequisites**, not repurposed S-gates. Native S1–S7/M1–M5 are active L-ZEC requirements for whole-project completion. Lanes, cross-chain and L-ZEC proceed in parallel and are not gated behind the first journey. SQL holds and strict privacy blockers are not closed by any lane split.

## Evidence and Permissions

Record hardware/configuration, source/ELF/program/setup/verifier/asset/deployment pins, genuine proof bytes, actual testnet transaction hashes, finality assumptions, balance/state changes, full rollback/retry, restart/`Unknown` and company-off recovery results. Record NOT RUN or blocked items explicitly; use the checkpoint rather than a second progress ledger.

No deployment (including local-node), signing/submission, fund movement, production-secret use, operational migration, mainnet action or code push follows from this document. SQL execution requires the approved private URI/scope; do not expose credentials. Synthetic generated-key/VM checks are not funded network acceptance. Testnet success is not mainnet readiness, an external audit, strict-private matching or full native-ZEC completion.
