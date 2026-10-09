# Z2Z V1 Todo and Roadmap

## Active approved release — one protected native-ZEC route (2026-10-06)

**This section supersedes the earlier samechain-first/CLI-only/all-lanes-active first-release plan below.** The owner approved the narrower product: one pair, one direction, full quoted trades, both parties online for agreement, a selected counterparty/shared link, and four app screens. The working route is **native shielded ZEC on a qualified Zcash testnet → native ETH on Base Sepolia**; the target/network choice is an engineering default, not proof that a usable Ironwood/v6 testnet note, wallet, history or deployed verifier exists. No wrapped/transparent-ZEC, custody, payment-directory or unprotected HTLC substitute.

**Roles and retained protection:** U sells ZEC/buys ETH; S buys ZEC/supplies ETH. Both are users with their own wallet, review, status and independent recovery. The owner now approves **investigating a different native settlement construction**, not selecting or implementing one. No executable source-payment authority may escape before independently verified target protection; exact arming/claim/refund order follows the reviewed selected construction. Direct P/Q remains the previous incomplete candidate, not a mandatory design. Online agreement/full-quote UI does not make either party honest or remove hostile partial/alternative/mixed-input/overpayment cases.

**Goal:** a usable protected exchange of real testnet assets, not a presentation demo. Compose the existing Rust protocol/zcash/proofs/chains/runtime, transport, per-owner PostgreSQL and encrypted custody; no new database project, mandatory company service, paid/private remote prover or parallel money authority. Ordinary users must not manually run PostgreSQL, CLI commands or prover tooling. The local companion owns the secure lifecycle; the sibling frontend remains user-owned and is integrated by an agreed contract, not taken over here.

**Source contracts:** [ARCHITECTURE §7](ARCHITECTURE.md#7-native-shielded-zec-outbound--approved-financial-contract-incomplete) and [BLOCKERS §4](BLOCKERS.md#4-native-cross-chain-protocol-gates-s1s7) retain S1–S7/M1–M5 financial protection, source validity, loss prevention, once-only consumption and both-role company-off recovery. Their previous P/Q-specific mechanisms are conditional on construction selection, not a lock against alternatives. This is the next-work checklist, not a new readiness register; [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md#concrete-blockers-to-the-entire-protocol) owns observed evidence. Only R1.2's policy decision is complete; all implementation/qualification acceptance remains pending. No release date is justified while native settlement construction is unresolved.

### R1 — Release contract, privacy and first go/no-go (M1/M3/M5; S2–S5/S7)

**R1 status update, 2026-10-07 (later wave):** the owner **accepted the §13 bounded-window contract** for route 1a (SETTLEMENT-RESEARCH §13; replaces the lifetime obligation with the disclosed W1–W8 envelope + residual stranded-funds risk for this release only) and **approved the §12.1 DKG session-kinds amendment** (kinds 10/11/12 applied to V1-P2P-PROTOCOL-SPEC §7.2). Construction path: route 1a (fresh 2-of-2 threshold J). **R1.1 freeze is now unlocked** and is the next acceptance task; R1.3 moves from investigation to freeze-prep; the R2+ qualification surface (audit, threshold-FVK, R2.2 history/finality, target capability, composed proofs) is unchanged and still gates actual acceptance. The W1–W8 sheet still needs its [MEASURE]/[OWNER] values before the freeze is final.

**R1 status, 2026-10-06:** the owner selected **“Bilateral privacy with explicit disclosure”** and **“Investigate a different native settlement construction.”** The approved [disclosure matrix and decision](ARCHITECTURE.md#approved-release-decision--2026-10-06) replace strict GD2/own-result noninference **for this release only**; historical strict-GD2 analysis remains unchanged and is not a current release constraint. **R1.2 policy-definition DONE; implementation/privacy verification remains R3/R10.** R1.1 freeze and R1.3 feasibility remain open: the direct P/Q candidate is still financial **NO-GO** for its existing witness/excess/composition gaps, not a general impossibility result. Alternative research may proceed; downstream actual acceptance needs a selected feasible construction, independent review and applicable action approvals. No alternative mechanism, custody/trust change or financial-rights removal is approved.

- [ ] **R1.1 — Freeze the selected one-route contract.** After construction selection/review, bind U/S rights, actual source note/pool/format/cohort and target asset/deployment, authenticated quote/receiver authority versus funding payer, exact amounts/fee payers/caps/net receipts, finality/freshness and cancellation/terminal rules. Acceptance: reviewed states cover unsigned quote through actual transfer and independent recovery; payment release follows verified protection, Unknown remains nonterminal, and any refund condition is consensus-enforced and proven safe. Do not freeze existing code fields or invent concrete pins before qualification.
- [x] **R1.2 — Define approved bilateral disclosure policy (policy only).** Owner-confirmed matrix: selected counterparty sees exact agreed terms, amounts, fees and its own outcome; public ETH addresses/amounts/code/transactions and potential IP/timing/linkage are disclosed. Shielded source does not promise all metadata hidden; keys, FVKs and private witnesses stay owner-local, never with peer/hosted prover. Exact public amounts and inference from agreed terms/own results are accepted, not anonymous matching or strict GD2. Acceptance: policy recorded in ARCHITECTURE's approved matrix; **implementation and measured privacy verification are future R3/R10 work**, not checked here.
- [ ] **R1.3 — Compare native constructions and establish financial go/no-go.** Build a source-cited shortlist and capability matrix for the qualified source pool/cohort, independently obtainable witnesses, source/target authority and every terminal branch. Prove protected exchange, full source validity, U payout without S, S recovery without U, no double use and all reachable hostile outcomes. Existing direct P/Q witness/excess gaps remain NO-GO; alternatives must handle actual facts or prove hostile branches protocol-unreachable, not reject them only in UI. Excess requires actual authorized return, or sound prevention plus explicit review matching retained rights—not an approved removal. Acceptance: independent review, counterexamples/kill criteria and explicit GO/NO-GO before dependent acceptance; research approval is not mechanism/trust approval or runtime readiness. Consolidated comparison + decision menu: [CONSTRUCTION-COMPARISON](research/CONSTRUCTION-COMPARISON.md) (2026-10-07). **Owner decision 2026-10-07: option 1 — stay NO-GO, retain lifetime obligation; research route 1a (route-specific disclosure exception) first.** R1.1/R1.3 acceptance remain open pending complete capability/lifetime evidence from that route. **Follow-up 2026-10-07: route-1a enumeration delivered (SETTLEMENT-RESEARCH §9); §9.4 disclosure model accepted in principle (per-swap grant still mandatory); Q1–Q9 gate list defined.**

### R2 — Native wallet, source proof and hostile/finality safety (M1–M4; S1/S2/S4/S5)

**Actual acceptance depends on R1's selected feasible construction; source/capability research to resolve it is not blocked.**

- [ ] **R2.1 — Qualify the selected native wallet/capability path.** Pin a coherent supported wallet/node/prover cohort and authorized source environment; acquire/validate the actual available U note and exercise the selected construction's payment, claim and both-role recovery capabilities without sharing keys/FVKs/private witnesses. If direct P/Q is selected, qualify unsigned P plus complete local Q and S's U-offline execution; otherwise qualify the reviewed equivalent capabilities, not a mandatory Q packet. Acceptance: source effects/fees/ownership, signatures/proofs/dummies, stale anchors, expiry/branch changes and cancellation grief match the selected relation. Required note preparation is in the user journey, not an assumed wallet feature.
- [ ] **R2.2 — Complete validating history and finality safety.** Implement authentic genesis-through-required-era validity and authenticated checkpoint state, connected consensus/PoW/work, transaction authorization/effects, note creation/anchors and all earlier bound payment/recovery evidence required by the selected construction. Acceptance: invalid or omitted bodies/history/auth roots and eclipse/stale/competing histories cannot yield settlement; explicitly qualified source canonicality/freshness and target finality policies fail closed on reorg/halt. Best-submitted work or two RPCs agreeing is not full consensus validation.
- [ ] **R2.3 — Handle or soundly prevent every hostile outcome.** Cover replacement/same-effect-new-auth payments, third-party/mixed inputs, earlier/late payments, partial/multiple outputs, zero/insufficient net, excess and competing recovery. Acceptance: each branch is either proven unreachable by protocol/consensus enforcement or handled from authentic independently obtainable facts with correct terminal rights. Reachable proportional consideration keeps `U=floor(D*C/A)`, `S=D-U` for `0 <= C <= A`; reachable excess needs actual authorized/proven return. Sound excess prevention needs explicit review matching retained rights, not UI rejection or assumed removal. Missing facts fail release acceptance; `T != P` never alone proves nonpayment.

### R3 — Actual composed financial proof and performance (M3–M5; S1/S2/S4/S7)

**Depends on R2; qualify before building the funded app around a prover.**

- [ ] **R3.1 — Produce the selected native financial proof composition.** Implement the reviewed construction's authentic source validity, authorization, payment/recovery, conservation and unique-consumption proof boundaries with exact quote/source/target context; independently pin source→program, setup and verifier provenance. Acceptance: genuine owner-local positives and altered-history/context/financial-fact negatives verify against the exact target in an authorized local VM, including genuine wrapping wherever required. Preserve original native financial requirements, not unchanged P/Q relations after an approved replacement. Preparation-only, Sprout-prefix, CPU-only or samechain-owner proofs cannot substitute.
- [ ] **R3.2 — Measure the selected whole native proof journey.** With separately approved resource limits, measure actual preparation, full-history/incremental maintenance, settlement/recovery proof work, required wrapping/verification, child/shared memory, disk, cold restore and target gas. Acceptance: reproducible whole-process results on selected owner hardware meet explicitly agreed usable limits; no fabricated RAM minimum/latency or new capacity purchase. Failure drives a same-financial-guarantee reviewed alternative under R1.2 or NO-GO, not silent remote witness upload.
- [ ] **R3.3 — Qualify disclosure, lifetime and replay resistance.** Exercise secret isolation through crash/OOM/cancel/log/scratch paths, source identifier exposure and cross-quote/randomized-commitment/cross-version reuse attacks. Acceptance: measured surfaces match R1.2's approved disclosure matrix, no unapproved private witness/source mapping escapes, composition/uniqueness is independently reviewed, and original proof/artifact/anchor/fee/branch support remains usable across pending recovery. Source expiry does not retire earned payout or funded verification; no anonymous own-result promise.

### R4 — Target prefunding and atomic allocation (M4; S3/S4/S5)

**Depends on R3; reuse existing arithmetic/verifier primitives, not SamechainAuthority as a substitute for native settlement.**

- [ ] **R4.1 — Implement the selected native protected obligation.** Bind real ETH receipt, immutable authorized context/beneficiaries and authenticated source obligation with once-only reservation across versions. Acceptance: wrong funding/domain/asset, duplicate reservation and unilateral revocation of earned/live rights are rejected; U releases payment authority only after independently verified protection. No generic timer refund: a refund is permitted only under the selected, explicitly reviewed consensus-enforced condition that cannot defeat valid payment/claim rights.
- [ ] **R4.2 — Enforce verified actual transfers and retained allocation rights.** Verify the selected construction's financial facts and atomically consume entitlement with all required fixed transfers. Preserve proportional `U=floor(D*C/A)`, `S=D-U` where partial net consideration is reachable; implement actual excess return unless reviewed sound prevention proves it unreachable without removing retained rights. Acceptance: every reachable full/partial/nonpayment/refund branch has correct actual effects; invalid evidence, receiver failure/reentrancy/OOG or second-transfer failure rolls everything back and preserves eligible retry. Credit/proof registration is not paid.
- [ ] **R4.3 — Qualify local adversarial target lifecycle.** Exercise the selected real verifier/escrow with actual in-process VM effects, competing claim/recovery (P/Q if selected), duplicate/late submissions, wrong recipients, reorg/restart and unavailable actors. Acceptance: only finalized correct source/target effects become Completed/Refunded; local timeout, disconnect or stale backup cannot unlock liabilities. Any consensus-conditioned refund must satisfy the reviewed cross-chain safety proof, not a generic clock assumption. VM results are not deployed/funded-testnet evidence.

### R5 — Both-owner capabilities, durability and standalone recovery (M2/M5; S3/S5/S6)

**Uses R1/R2 witness formats and existing stores; must qualify with R4 before any target funding.**

- [ ] **R5.1 — Bind selected native lifecycle to durable custody.** Extend existing owner PostgreSQL digests/identities and immutable encrypted capsules to native reservations, exact selected authorizations, payout/claim/refund/return capabilities and Submitted/Unknown reconciliation; retain Q/P only if selected. Acceptance: crash/concurrent-instance checks prove persist/read-back before capability escape, no secret in SQL/logs/peers and no resurrected spent right. Reuse approved isolated SQL scope; do not install/reset or migrate operational stores.
- [ ] **R5.2 — Deliver complete independent recovery bundles to both roles.** Before funding and every new capability release, preserve each actor's legitimate payment/payout/claim/refund/return data, exact context and original tools/prover/history artifacts on verified offline media in another failure domain; complete S-held Q is required only if that construction is selected. Acceptance: corrupt/missing/stale/mismatched backups fail closed; U and S can each restore and exercise all eligible rights without the other's secrets/cooperation or company services, using a standalone path when the app fails.
- [ ] **R5.3 — Pass both-role clean local recovery before deployment/funding.** Restore in a clean controlled environment with real selected native verifier/escrow outcomes, independent history and owner-local proving; exercise stale/expired capabilities, pending/consumed rights and failed transfer/retry. Acceptance: actual local effects and preserved liabilities match R4 with company services removed, including standalone operation. This is a prerequisite, not public-testnet funded recovery closure.

### R6 — Selected-counterparty quote orchestration (S3/S5/S6)

**Depends on R1–R5 qualification; reuse transport/reconnect, no broad exchange/discovery project.**

- [ ] **R6.1 — Implement one full-quote session/link.** Bind authenticated selected U/S peers, route, amounts/fees/recipients, quote identity and expiry; exchange only approved public/role-visible fields. Acceptance: both roles inspect identical terms; tampering, replay, wrong peers and competing acceptances are rejected; quote/link is neither verified backing nor spend authorization.
- [ ] **R6.2 — Connect the selected safe action order.** Orchestrate preparation → independent backups → target protection → independent arming/finality review → exact authorized source action → evidence/proof → actual transfer according to R1's reviewed construction. Acceptance: crash/disconnect at every boundary resumes idempotently, preserves Unknown/reservations and never advances on peer ACK or cached balance; source authority cannot escape protection. Each signing/funding action still needs its approved scope.
- [ ] **R6.3 — Expose truthful cancellation and status.** Offer only cancellation/recovery actions eligible under the selected reviewed state machine, preserving possibly armed liabilities. Acceptance: both roles see funding/source/proving/target/finality stages, bounded errors and measured or Unmeasured ETA; local timer is not refund authority, any consensus-conditioned refund is accurately explained, full-quote UI hides no partial financial outcome, and success requires actual assets.

### R7 — Four-screen frontend contract and local companion (S6/M5)

**Depends on stable R5/R6 behavior; coordinate the user-owned sibling frontend, do not edit/take it over.**

- [ ] **R7.1 — Agree the four-screen integration contract.** Define Offers/quote-link, Review, Trade status and Recovery for both U and S, including route/fee/prefund/disclosure review, permissions, typed nonterminal states and recovery errors. Acceptance: frontend owner and native backend share exercised request/event examples and acceptance cases; UI never derives financial authority or receives secrets/private witnesses.
- [ ] **R7.2 — Package the secure local companion.** Reuse the node/runtime and existing per-owner persistence to manage startup, wallet access, source readiness, sync, proof jobs, backup and restart behind the app. Acceptance: an ordinary user installs/opens/connects wallet and completes readiness/recovery without manually administering PostgreSQL, CLI or prover; authenticated origin/session binding, exact local consent, locked-wallet and malicious-browser checks protect keys and signing. No mandatory hosted database/prover; provisioning/design is not permission to change this host.
- [ ] **R7.3 — Qualify the integrated four-screen journey with its owner.** Connect the sibling app to real companion sessions, including recovery/import and both financial roles. Acceptance: clean-device interaction, accessibility, wrong network, absent native note, insufficient gas, proof failure and app restart all yield correct recoverable state without mock balances or manual developer repair. Local qualification does not replace real R9 trades.

### R8 — Authorized deployment, assets and pre-deposit restore (M4/M5; S7)

**Depends on R1–R7 and native local M1–M5 qualification; funding remains behind R8.3.**

- [ ] **R8.1 — Freeze release artifacts and action-specific staging approvals.** Pin the actually supported Zcash testnet cohort/history policy, Base Sepolia chain/ETH, exact native verifier/escrow/client artifacts, beneficiaries, gas/fees and independent access. Acceptance: independently reviewed artifact mapping and per-action previews/simulations identify cluster, signer/fee payer, recipients, assets/raw amounts and fees; obtain explicit approval for any deploy/sign/send/asset acquisition. No invented note/network readiness or blanket transaction authorization.
- [ ] **R8.2 — Deploy and authenticate only the approved target.** Execute specifically approved immutable native financial deployment and obtain approved testnet assets/gas for U and S. Acceptance: independent runtime-code/program/verifier/context checks match R8.1; both apps detect wrong pins/networks. Existing source-note qualification actions have their own earlier approvals, not retroactive permission from this step.
- [ ] **R8.3 — Pass actual deployed-context restore before the first target deposit.** On a clean owner-controlled environment, restore each actor's available source/wallet/recovery capabilities and exact deployed target context, validate independent chain access and demonstrate readiness with original usable artifacts. Acceptance: independent offline backup/read-back and consent gates prevent deposit/source-authority release if restore is incomplete; no previously funded target obligation is needed for this check. Funding starts only afterward with separate approval.

### R9 — Real trades, failures and company-off acceptance (S1–S6/M5)

**Depends on R8; each real transaction/failure drill stays within explicit action/outage approvals.**

- [ ] **R9.1 — Complete the real two-user full-quote trade.** Through the four screens, S prefunds, U verifies and pays shielded native ZEC, and U receives ETH after the genuine native financial proof. Acceptance: independently observed source/target transaction effects, balances, finality and measured resources prove both roles' outcomes; retain privacy-safe evidence, not private witnesses in reports.
- [ ] **R9.2 — Exercise authorized adversarial/failure recovery.** Run the selected construction's reachable nonpayment/refund, withheld-cooperation, competing claim/recovery, hostile/excess, failed transfer, insufficient gas and restart/Unknown branches; require protocol-unreachability evidence for excluded cases. Supplement controlled reorg/halt checks where network manipulation is unauthorized. Acceptance: R2/R4 rights and actual recoverable assets hold with safe retries; distinguish testnet from local VM evidence. Unexercised required terminal branches block release.
- [ ] **R9.3 — Complete both roles' funded company-off cold drills.** With company UI/API/indexer/bootstrap/prover/relay/database unavailable, restore from independent backups and original tools, acquire history, prove locally, sign and submit through independent access, and observe actual eligible asset arrival. Acceptance: U payout without S and S recovery without U, including stale backups and pending release reconciliation, work without company rescue; app failure has a usable standalone owner recovery path.

### R10 — Security, usability and limited release (S7/M5)

**Depends on all prior acceptance; native security/privacy gates are not waived by testnet.**

- [ ] **R10.1 — Close independent security and approved-disclosure review.** Review selected financial relations/implementation, source finality, target atomicity, private uniqueness, companion/signer, backups and network metadata; fix findings and re-exercise affected cases. Acceptance: scope/commit/findings and closure map to retained S1–S7/M1–M5 financial rights and R1.2's disclosure matrix, not unchanged strict GD2. No audit/anonymous-exchange claim beyond evidence; no unresolved loss, custody, secret-exposure or recovery blocker.
- [ ] **R10.2 — Pass ordinary-user acceptance and publish usable instructions.** With authorized participants, observe installation, both trading roles and recovery without developer commands; record consented results, not invented interviews. Acceptance: four screens explain actual fees, irreversibility, pending/liveness limitations and key/backup custody; companion packaging, troubleshooting and company-off recovery instructions work from clean environments.
- [ ] **R10.3 — Authorize the limited testnet release.** Reconcile all 30 task acceptances with BLOCKERS/native evidence, exact deployment/version and user/operator runbooks; obtain release approval for the chosen audience and limits. Acceptance: real protected route is usable end to end, every required financial/privacy/recovery gate passes and known environmental assumptions are disclosed; stopping new quotes never disables old funded rights/artifacts/recovery. No mainnet, reverse route, extra asset or broad launch follows.

**Dependency / permission summary:** R1.2 policy is defined; R1.3 construction GO plus R1.1 freeze gate actual R2→R3→R4 acceptance. R5 joins R4 before R6/R7→R8 deployment→deployed-context restore→separately approved funding/R9→R10. Alternative/source-capability research may resolve R1 now; financial NO-GO blocks downstream actual acceptance, not all research. Current approval covers these decisions, docs and investigation only, not an alternative mechanism/trust model, implementation, heavy proving, real secrets, SQL changes, deployment (including local-node), signing/submission/funds, outages or release. Existing isolated PostgreSQL evidence/scope is not new installation or operational-migration permission.

**Retained later, not first-release prerequisites:** the samechain 122-ID catalog, wider P2P discovery/marketplace, deliberate user partial/standing-maker/offline multi-fill, reverse/multiple ZEC routes, HyperEVM/HyperCore, Solana, NEAR, all-pairs crosschain, wider GUI stories/hardware wallets, LP/agents/ZSA/Intents, scaling and mainnet. Reuse implemented primitives; do not delete funded code, journals, custody, proofs/artifacts or old owners' rights. Every reachable hostile partial/excess case remains protected now, unlike optional partial-order UX; protocol-enforced prevention needs the R1/R2 review, not a wallet restriction. Minimal four-screen app/companion is required. Historical strict-GD2 work remains intact outside this release's explicit policy change.

## Superseded first-release plan — retained backlog and provenance

Everything below records the earlier samechain-first roadmap. Its unchecked tasks, old “active parallel”, “V1 success”, “next wave” and CLI-only/GUI-later labels are **not the active first-release checklist** and do not override R1–R10. Keep their acceptance/history for future work and reusable primitives; no old task is completed or deleted by this scope change. Historical checkpoint statements are not current evidence; use the latest native status and SQL verification. Only this scoped precedence update was made, not a claim that every older document has been reconciled.

## Phase 0 — Reconcile scope and unblock architecture

**Microtasks:** P0.01–P0.12 in the [micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md#phase-0--scope-testnet-and-privacy-decisions-12-microtasks).

- [ ] Replace the active "Complete Z2Z" todo tree with this split; keep full-protocol work as active lanes or V2 as recorded, never marked completed.
- [ ] Align decisions/prompt/delivery matrix/BLOCKERS/plans with: **P2P node, CLI, maker online, samechain first journey, full company-off recovery, parallel active lanes**. (Docs integration 2026-10-06; see the [Phase 0 integration report](research/2026-10-06-phase0-coverage-invariants.md).)
- [ ] Correct contradictory recovery statements: cold restore and the independent proof/sign/submit/verify path are **V1**. Observation/decryption alone cannot close recovery.
- [ ] Per-node durable storage: the owner selected **self-operated PostgreSQL per owner** as the design target (default on the owner node; digests/identities only, executable bytes in an owner-local encrypted capsule). SQL execution needs an approved private URI/test scope. No SQLite. Existing journals and SQL restrictions are preserved.
- [ ] Specify the P2P protocol. Owner decisions: bilateral-counterparty-only disclosure; direct connections plus optional independent relay. Engineering defaults: a neutral lane beacon, a direct RFQ session, and a BackingClaim relation (proposed). Bootstrap provides discovery, never financial authority.
- [ ] Establish measurable node/prover RAM, storage and latency targets. Owner decisions: methodology only for now; ≤15 min provisional proof objective. Do not promote the 8/16GB targets or vendor timings into guarantees.
- [ ] Select lane testnets and asset pins: Base Sepolia (first), HyperEVM 998, Solana Devnet, NEAR testnet, Zcash testnet. Assets: Native plus a new fixed-supply 6-decimal constructor-only token per lane. Finality: two operators agree on a finalized hash. Deployment, signing and funds need explicit authorization.

## Phase 1 — Qualify zero-cost owner-local proving first

**Microtasks:** P1.01–P1.23 in the [micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md#phase-1--owner-local-proving-setup-measurement-and-alternatives-23-microtasks); P1.19–P1.21 are conditional measured optimization/alternative branches, not default extra implementations.

- [ ] **Benchmark existing `prove-owner` on the user's i5-11400H / 16GB machine** with the actual samechain program and controlled, non-production witnesses. Record available RAM, process limits, swap, peak whole-prover memory, `/dev/shm` usage, wall time, disk use, proof result and failure stage.
- [ ] Measure creation, both bilateral fill roles, cancellation/exit and withdrawal, including the supported witness sizes. A tiny guest or CPU execution benchmark is not full wrapped-proof qualification.
- [ ] Qualify SP1/Gnark private-data boundaries before real owner witnesses: shared-memory ownership/cleanup, abnormal termination/OOM, scratch files, diagnostics/trace sinks and retained buffers. Report remaining limits; do not claim erasure-complete.
- [ ] Independently qualify source → ELF → program VKey, setup/PK/VK provenance and exact frozen target verifier compatibility; retain usable local artifacts for recovery.
- [ ] Generate a genuine wrapped owner certificate and demonstrate acceptance against the exact samechain authority/verifier and expected journal—not only SDK verification or calldata construction.
- [ ] If SP1 cannot meet measured hardware targets, benchmark a zero-paid-service alternative against the **same ownership, conservation, authorization and recovery relations**. Select using measured resource and verifier evidence; include any required guest/contract migration and independent review.
- [ ] Keep witnesses owner-local. No paid cloud prover, witness upload, mocked verifier or deferred proving substitute satisfies V1. "Zero-cost proving" does not mean zero chain gas or storage requirements.

**Blocker:** Current evidence records a 4GiB-capped OOM without a certificate, not a demonstrated 16GB-machine success or failure. The approximately 5.61GB recursion-array lower bound and 5.86GB raw PK are not total peak measurements. Genuine positive proof admission remains unqualified.

## Phase 2 — Implement `z2z-node` and P2P discovery

**Microtasks:** P2.01–P2.28 in the [micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md#phase-2--long-running-node-libp2p-gossip-and-cli-28-microtasks). The unverified-advertisement/independent-backing conflict and protocol privacy/partial-fill contradictions require P0.05–P0.07 resolution before affected implementation.

> Protocol/storage work can proceed alongside proving qualification; funded operation cannot bypass Phase 1.

- [ ] Implement the long-running Rust **`z2z-node` in this repository**, composing the existing protocol/proofs/chains/runtime rather than creating a second money authority.
- [ ] Implement **libp2p networking**, authenticated peer connections and discovery/reconnect behavior. Demonstrate direct/alternative-peer operation without a required company bootstrap.
- [ ] Implement the **neutral lane beacon plus bilateral RFQ sessions**: canonical versioned messages, no public order terms, replay/dedup, bounded untrusted messages, late-join. Order-term gossip is not used (bilateral disclosure).
- [ ] Implement a local counterparty view with independently checked backing (BackingClaim) and current spentness. A peer signature or cached row is not proof of spendable funds.
- [ ] Implement **light chain sync**: authority/deployment/token observations, block-pinned inspection, note/root/NF state caching, bounded resource usage, and two-operator finalized agreement.
- [ ] Implement per-owner **durable storage** (self-operated PostgreSQL design; executable bytes in an encrypted release capsule): preserve restart/recovery data across process lifecycles.
- [ ] Implement **CLI commands**: start node, discover peers, create backed order (deposit), fill (bilateral consent), cancel/exit, withdraw, and inspect settlement status.

**V1 architecture differs from a standalone backend server:** coordination runs over P2P, there is no shared company database, and each node holds its own custody, wallet and proving authority.

## Phase 3 — Funded samechain lifecycle and atomic settlement

**Microtasks:** P3.01–P3.23 in the [micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md#phase-3--witness-generation-genuine-proofs-and-funded-lifecycle-23-microtasks). Funded entry additionally requires P4.05 pre-funding restore, P5.03 authenticated deployment and action-specific signing/funds approval.

> Requires Phase 1 proving qualification and Phase 2 node implementation.

- [ ] Exercise only the separately authorized **P5.01–P5.03 deployment** prerequisite: SamechainAuthority/tree/codec and qualified verifier/program pins on the selected testnet; no duplicate deployment lane.
- [ ] Run **funded create**: real owner deposit → genuine wrapped proof → contract acceptance → commitment/root/NF state update → observe actual testnet token transfer and emitted events.
- [ ] Run **funded bilateral fill**: two real owners, both fresh consents, both proofs → atomic dual-NF consumption → both output transfers → both recovery ciphertexts → observe actual receipts and updated state.
- [ ] Run **funded withdraw**: owner proof → NF consumed → owner receives asset → observe actual transfer and balance change.
- [ ] Demonstrate **atomic rollback**: invalid proof rejected without state mutation; receiver revert preserves sender rights; valid retry after transient failure.
- [ ] Exercise **race/reorg/restart resilience**: pending settlement across process/peer restart, chain reorg handling, duplicate submission rejection and final state reconciliation.
- [ ] Measure and document **actual gas costs**, proving latency, node resource usage and funded operation prerequisites.

**Acceptance:** Real testnet assets move according to proof-controlled rules; invalid operations leave all rights unchanged; funded failures are retryable without loss.

## Phase 4 — Complete company-off recovery

**Microtasks:** P4.01–P4.18 in the [micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md#phase-4--encrypted-backup-restore-and-cold-recovery-18-microtasks). P4.01–P4.05 qualify before funding; full funded cold drills execute after actual create/partial settlement.

> User-required V1: owner can recover with company services completely unavailable.

- [ ] Design and implement **encrypted backup bundle format**: owner keys, recovery keys, note secrets/openings, context/witness metadata, immutable authorized bytes and restoration instructions.
- [ ] Implement **cold restore flow**: load backup bundle → authenticate saved deployment/pins → independently sync required chain history from available RPC → reconstruct note/witness data → rebuild local state without company services.
- [ ] Implement **independent proof generation**: owner proves owned-note withdrawal using only backup data, chain observations and local prover—no company proving service, no witness upload.
- [ ] Implement **owner signing and arbitrary submission**: sign transaction locally → submit via any available relay (not only company endpoint) → monitor settlement via any RPC → verify actual asset receipt.
- [ ] Demonstrate **complete drill**: starting from zero local state + backup bundle, owner successfully withdraws real testnet assets with company node/bootstrap/services/database offline.
- [ ] Exercise **retry after failure**: failed submission, insufficient gas, receiver revert, stale witness—owner independently regenerates proof/retries/verifies using only backup and chain access.

**Acceptance:** Owner controls recovery entirely; company disappearance does not lock funds; backup bundle + chain access + owner hardware sufficient for complete asset retrieval.

## Phase 5 — Deployment, P2P acceptance, security review and documentation

**Microtasks:** P5.01–P5.18 in the [micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md#phase-5--deployment-network-acceptance-and-existing-phase-6-review-18-microtasks). P5.14–P5.18 retain the original Phase 6 review/documentation obligations as mandatory V1 release tasks.

> Combines all prior phases into usable trading journey.

- [ ] Implement **maker flow**: owner creates backed order → deposits via samechain create → advertises to P2P network → waits for taker.
- [ ] Implement **taker flow**: discover orders via gossip → verify backing independently → prepare bilateral fill → both parties consent → execute atomic settlement.
- [ ] Implement **cancel/withdraw flow**: maker cancels unfilled order → uses cancel-or-exit to recover assets → withdraws via independent proof.
- [ ] Demonstrate **two-user end-to-end journey** on testnet: both run `z2z-node`, discover each other, create/fill/settle order, observe real asset transfers, verify recovery works for both parties.
- [ ] Exercise **network resilience**: peers connect/disconnect, bootstrap replacement, gossip propagation delays, order expiry, race conditions between competing fills.
- [ ] Document **testnet deployment artifacts**: contract addresses, program/verifier pins, bootstrap node endpoints, required RPC access, gas/fee policies.

**Acceptance:** Real users can trade real testnet assets P2P using only `z2z-node` CLI; all parties independently verify; recovery works; company provides discovery only, not financial authority.

### Security review and documentation — retained original Phase 6

> Mandatory Phase 5 release work, not optional polish; covered by P5.14–P5.18.

- [ ] Conduct **source review**: authority/tree/codec contracts, samechain relation, P2P protocol, recovery flows, owner/witness isolation.
- [ ] Verify **privacy boundaries**: measure actual txid/nullifier/amount/timing/order/network/recipient linkage and secret isolation; do not assume notes/historical fills are unlinkable or that P2P resolves strict GD2.
- [ ] Document **threat model**: trusted/untrusted components, company-offline scenarios, adversarial peers, chain reorg attacks, recovery failure modes.
- [ ] Write **user documentation**: install `z2z-node`, connect to testnet, create first order, fill order, recover from backup, troubleshooting.
- [ ] Write **operator documentation**: run bootstrap node, monitor network health, handle peer reports, coordinate testnet resets.
- [ ] Update **BLOCKERS.md and NATIVE-IMPLEMENTATION-STATUS.md** with actual V1 evidence: measured resource usage, qualified proving, funded lifecycle results, recovery drill outcomes.

**Acceptance:** Documentation reflects actual working system; users can follow guides to trade; operators can maintain network; security properties are explicit.

---

## V1 Success Criteria

**V1 is complete when all of these are demonstrated with evidence:**

1. Two users running `z2z-node` on weak hardware (8–16GB RAM).
2. They discover each other via P2P, with no central server required.
3. A backed order is created with a real testnet asset deposit.
4. The order is filled with atomic bilateral settlement (full and partial).
5. Both parties receive correct assets (real testnet transfers observed).
6. Either party can withdraw remaining assets.
7. Both parties can recover with the company offline (cold restore drill).
8. Real wrapped proofs are generated locally (measured resources).
9. Process restart preserves state.
10. The network functions with the company bootstrap offline.

These criteria are **pending**. Evidence owners are [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md) and [BLOCKERS](BLOCKERS.md). They apply per lane; the first journey proves them on Base Sepolia only.

**Evidence required:**
- Real testnet transaction hashes
- Actual token balance changes
- Resource measurements (RAM, time, storage)
- Recovery drill logs
- P2P network packet traces
- Contract state observations

**NOT required for the first journey** (still required for the whole project unless listed under V2):
- Native ZEC routes, HyperEVM/HyperCore, Solana, NEAR and cross-chain fills. These are **active parallel lanes**, see the [micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md#parallel-lanes-active-obligations-beyond-the-122-id-evmbase-catalog).
- Mainnet deployment, external security audit, mobile app, scale/load testing.

---

## Active parallel lanes (required for project completion)

- **L-ZEC native Zcash.** Full Ironwood history proofs, source classifier, net/excess, uniqueness, recovery and native escrow. Pairs ZEC↔{Base, HyperEVM, Solana, NEAR}. Archived native plan Tasks 1–10, S1–S7/M1–M5.
- **L-HEVM HyperEVM 998.** Spot first (EVM-fixed token, then Core-linked). HyperCore positions: all features, foundational first, via isolated position claims (investigation).
- **L-SOL Solana Devnet.** New owner-ZK program with an SP1 v6.1.0 verifier port. The three-ACK escrow stays separate provenance.
- **L-NEAR NEAR testnet.** Owner-ZK. Native NEAR first, then NEP-141.
- **X.CROSSCHAIN all pairs.** HTLC first. It is not atomic and makes no privacy claim. Proof-verified release is active research. Token/collateral legs come first; position-claim trading is research.
- **Strict GD2 privacy.** Active blocked gate, no waiver.

## V2 Deferred Features

- **Maker offline multi-fill**: standing authorization, quantity/price limits, maker-recoverable variable outputs.
- **NEAR Intents/1Click** adapter (separate from owner-ZK L-NEAR).
- **GUI application**: desktop/web interface (all 71 archived stories).
- **Hardware wallet support**: Ledger/Trezor signing modes.
- **Mainnet deployment**: production contracts, audited code, real money.
- **Public LP/Raydium, agents, ZSA, scale optimization**.

---

## Current execution checkpoint

Use [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md) for exact observed commands/results and [BLOCKERS](BLOCKERS.md) for release qualification. Existing authority/relations/inspection/isolated producer are source primitives, not a completed trade.

- Reviewed public `owner-program` derivation and controlled generated creation runner are implemented and exercised; full wrapping/admission is still unqualified.
- Direct Linux authenticated `z2z-node` transport, owner-local setup measurement/refusal, both-owner restored native corpus, dedicated-child diagnostic defaults and bounded acquired public-history coherence are exercised/source-reviewed prerequisites—not verified backing/trading/full recovery. Actual hash-pinned history CLI integration is active.
- Phase 0 decisions are recorded in the [integration report](research/2026-10-06-phase0-coverage-invariants.md) and its domain reports. Remaining research has work plans, not just labels. No phase is completed by writing documents.
- Funded testnet execution, SQL lifecycle and company-off recovery remain NOT RUN under their prerequisites/permissions.

Next proving acceptance needs a safely accounted actual all-mode wrapped run on target hardware and qualified private worker lifetime/resources. Independent public-history/CLI work continues without publishing private order fields, signing or creating financial authority.
