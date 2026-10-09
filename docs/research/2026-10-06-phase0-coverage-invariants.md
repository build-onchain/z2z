# Phase 0 coverage, invariants and canonical integration design — 2026-10-06

Owner: ConfiguredPlanCoordinator (configured PLAN model `bddevlab/claude-opus-5.5:max`). This is a planning and research report. No product source, test, build, SQL, prover, network or chain action was performed. Inputs are the four frozen domain handoffs (PlanCoverageInvariants, PlanDurabilityRecovery, PlanPrivateDiscoveryNetwork, PlanTestnetProverPolicy) and direct reads of the current docs/source cited below. Domain reports from the three multichain helpers will be integrated per §6. **Writing this report closes no gate.**

## 1. Status vocabulary

Each item gets exactly one status:

| Status | Meaning |
|---|---|
| SOLVED-TECH | Source-grounded technical answer; only doc integration remains. |
| PROPOSED-MECHANISM | Concrete design exists but needs a written spec and plan review before code. |
| RESEARCH-OPEN | No accepted construction. A falsifiable branch with kill criteria is defined. |
| OWNER-DECISION | Needs an explicit user choice. Options are relayed via Main. |
| ACTION-HELD | Needs action-specific permission (SQL, resources, network, deploy, sign, funds, secrets). |
| EXTERNAL-INPUT | Needs facts that don't exist yet (addresses, operators, hardware envelope). |

Document completion is never a gate closure. BLOCKERS stays the sole readiness register, and NATIVE-IMPLEMENTATION-STATUS stays the sole exercised-evidence record.

## 2. Authoritative user answers in force

1. V1 gets a detailed execution graph. V2 gets an individually source-linked backlog with research gates. No obligation is deleted.
2. Each written spec **and** each implementation plan is reviewed before its code wave.
3. Durability design target: each owner self-operates PostgreSQL. This is a design choice only. It grants no install, service, URI, schema, migration or execution permission.
4. Order disclosure goes only to the selected bilateral counterparty. There is no GD2 waiver and no inferred backing.
5. Reachability: direct connections plus an optional independently operated relay. No universal NAT claim. Checks are limited to generated loopback.
6. Immutable generated-key operation snapshots are approved as a written spec and plan. Planning has priority over backup code.
7. A verified offline, independent-failure-domain backup is required before funding and before each new release capability. Same-machine fsync covers crash/restart, not disk loss.
8. Output sequence: public unauthorizing descriptors → freeze complete packet/witness → encrypted publish and read-back → consent. No standalone output capsule.
9. EVM testnets "Hyperliquid and Base". HyperEVM covers spot **and** HyperCore positions, with all features, foundational first. The direction is isolated position claims (investigation). Spot ships first: an EVM-fixed token, then a Core-linked one. Owner-side Core execution is not the selected design.
10. Assets: Native plus a **new** vanilla fixed-supply, 6-decimal, constructor-only ERC20 with no admin, hooks or proxy. No deployment or distribution permission.
11. RPC/finality: two operators must agree on one common finalized hash. This is not a consensus claim.
12. Resources: methodology only. No heavy trial.
13. Proof latency objective: ≤15 min per owner operation. Provisional, not a guarantee.
14. **Native ZEC, NEAR, Solana and HyperEVM are active parallel lanes**, not V2. Settled sub-choices:
    - Solana: a new owner-ZK program on Devnet; the three-ACK escrow is separate provenance.
    - NEAR: owner-ZK on testnet, native NEAR first. NEP-141 stays active; claimable credit is proposed, not adopted. Intents/1Click is V2 backlog.
    - Every lane is immutable. On NEAR that means no access keys **and** no reachable upgrade path.
15. Cross-chain fills are **active, all pairs in parallel**. HTLC (CX-1) comes first, with no atomicity or privacy claim. Proof-verified release (CX-2) is active research. Token/collateral legs come first; position-claim trading is active research.
16. The first passing journey is samechain. Native ZEC is required for the whole project but not for the first journey, and wrapped ZEC never substitutes for it. **Base Sepolia as the first lane is an engineering default, not an owner approval.**
17. Release: the first passing lane releases first. The other lanes and cross-chain remain active, so the project is not complete at that point.
18. Catalog: the 122 IDs are kept, with L-HEVM/L-SOL/L-NEAR/X namespaces added (L-ZEC reuses the native plan Tasks 1–10 and S/M gates).
19. Second finality source: an owner-run non-validating node is allowed, design only; running it needs separate resource approval.
20. Docs update is authorized 2026-10-06. Each new code wave still needs its own spec and plan review.

Defaults that are engineering choices, not owner decisions (all overridable):
- neutral lane beacon plus direct RFQ;
- PostgreSQL on the owner node, storing digests only (X.REL-DIGEST);
- one offline 32-byte backup key;
- HEVM latest-state reads re-pinned before and after each read;
- relay used only for introduction/DCUtR;
- mutually exclusive transaction replacements;
- Solana recent-blockhash transactions;
- timelock margins defined by rule, with numbers set after measurement.

## 3. Plan and spec manifest (complete)

Active: `docs/V1-MICRO-IMPLEMENTATION-PLAN.md` (122 IDs: 12/23/28/23/18/18; 119 base plus conditional P1.19–P1.21), `docs/Z2Z-V1-ROADMAP.md`, `V1-DELIVERY-MATRIX.md`, `V1-ARCHITECTURE-DECISIONS.md`, `V1-P2P-STORAGE-DECISION.md`, `V1-P2P-PROTOCOL-SPEC.md` (candidate, not frozen), `V1-TESTNET-SELECTION.md`, `V1-RESOURCE-TARGETS.md`, `PROVING-COST-SOLUTIONS.md`, `Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md`.

Current slices:
- `superpowers/{specs,plans}/2026-10-06-independent-owner-fill*`: reviewed and implemented Fill2. Source/CPU evidence only.
- `superpowers/{specs,plans}/2026-10-06-samechain-private-snapshot*`: approved generated-key snapshot; library and clean-process restore implemented with focused evidence in [native status](../NATIVE-IMPLEMENTATION-STATUS.md). The later broad run failed during Wave B RED; no post-snapshot broad green or funded recovery claim.
- `superpowers/{specs,plans}/2026-10-06-samechain-release-lifecycle*`: rev 3 Tasks 1–3 capsule/journal/consumer guard source implemented; fresh specification review, both scoped source reviews and focused negative checks passed. SQL behavior is NOT RUN and genuine wrapped capsule/export positives remain BLOCKED; the full lifecycle and P3.08 acceptance are not closed.

Historical/archived (preserved, not rewritten):
- `history/plans/2026-09-28-architecture-doc.md`
- `history/plans/2026-10-01-ziquid-workspace-frame.md`
- `history/plans/2026-10-01-native-protocol-implementation.md` (**Tasks 1–10**)
- `history/plans/2026-10-03-z2z-implementation-integration.md` (Tasks 1–6 implemented, Task 7 SQL evidence open, ten continuation rows)
- specs from 2026-09-28, 10-01, 10-02 and 10-03
- the immutable Kerb imports (`docs/imports/kerb/**`: safety-core plan/spec, hackathon/roadmap/test plans for both trees, mechanism specs, design review, B01–B30 register)
- the 71 archived stories A01–H07 in `history/PRODUCT-OVERVIEW-AND-FRONTEND-HANDOFF.md`

Chain target slots:
- `contracts/evm`: SamechainAuthority, solc 0.8.34, Cancun.
- `contracts/solana`: public legacy-SPL **three business-ACK** escrow, not owner-ZK.
- `contracts/near`: empty layout slot.
- `crates/chains/src/hypercore*`: offline spot order/cancel preparation, lane B.

## 4. Source contradictions to fix in canonical docs (SOLVED-TECH unless noted)

| # | Where | Fix |
|---|---|---|
| C1 | Microplan:20 says "native Tasks 1–9" | Tasks 1–10. Map Task 10 to retained S7/M5 native acceptance, not V1. |
| C2 | Microplan:49, D4:278 say testnet prose is still 0.8.28 | The testnet doc is already corrected. Keep the actual compiler/chain qualification as a task and drop the stale contradiction claim. |
| C3 | Microplan P3.03 (:197) backs up before P3.04, against answer 8 | Split into P3.03a *prepare* (before P3.04) and P3.03b *persist + read-back* (after P3.04). P3.05 depends on P3.04 and P3.03b. No output capsule. |
| C4 | P4.02/P4.03 read as requiring the full PostgreSQL journal | Split private-envelope/capability-restore qualification (no SQL edge) from cross-journal release/funding integration (keeps P0.04/P2.05/P2.06 edges). A snapshot never resolves Released/Unknown. |
| C5 | `owner_worker.rs:658–715` prints the complete certificate to stdout with no release hook | P3.08 gates **every** export: stdout, file, peer, relay, DB upload. P2.22 is only one sink. |
| C6 | MODULES:3,46; ARCHITECTURE:113; prompt:43 say z2z-node/networking is absent | Current: libp2p 0.56 TCP/Noise/yamux/ping/identify plus bounded seeded Kad, configured reconnect, ephemeral identity. Missing: persistent identity, mDNS, QUIC, GossipSub, orders, backing. |
| C7 | Microplan:99–100 list history as proposed | PublicHistory, `inspect-history` and the preparation seams exist (§5.3). Remaining work: scanner, checkpoint, finality, lifecycle. |
| C8 | BLOCKERS:17 lists standing maker as a V1 closure duty | Move it to V2 in §4.1. |
| C9 | BLOCKERS:122 says the samechain relation is unimplemented | Fill2/creation/single/withdrawal are implemented within native/CPU scope. Remaining gates: wrapping, setup, resources, backing, durability, funded. |
| C10 | V1-ARCHITECTURE-DECISIONS: hosted backend as current; "Solana deferred" (:249); archive question | Record as historical/resolved. Solana is now an active lane (answer 14). |
| C11 | Roadmap:116–125 success criteria use checkmarks | Use a neutral criterion list linking evidence owners. |
| C12 | docs/README.md does not index the current 10-06 plans/snapshot spec | Add current-slice navigation with scope, parent IDs and non-closure. |
| C13 | Roadmap:152 / BLOCKERS §5 / decisions put NEAR/Solana/Hyperliquid as V2 or "additional venues" | Answer 14 supersedes: active lanes per §6. Kerb/NEAR-Intents research stays provenance. |
| C14 | P4.11/P5.03/P3.13 and D4 assume one deployment | Per-lane deployment/restore/first-funding chains (§6). The existing IDs remain the EVM/Base lane. |
| C15 | Microplan:9 tech stack is "EVM contracts/Foundry" only | Add per-lane target toolchains as **candidates** (Solana SBF/Anchor-or-native, NEAR wasm). Selection belongs to the lane tasks. |

## 5. Shared invariants and roles (P0.02 basis)

### 5.1 Invariants (source-grounded on the EVM lane; each other lane must re-establish them on its own target)

- **I1 Money authority.** Creation binds payer/value/token deltas. Fill verifies both proofs before consuming either NF, appends all outputs and transfers atomically, and reverts everything on failure. Source: `SamechainAuthority.sol:109–277`.
- **I2 Released capability.** Anyone may execute paired valid certificates while eligible. Expiry rejects only `timestamp > E`, so equality is still executable. ACK/abort/timeout/disconnect never revoke. A lock clears only when, for **every** outstanding packet on that input, the finalized F has `timestamp(F) > E`, or a required NF was consumed at or before finalized F, **and** effects are reconciled through F. Expiry alone never proves earlier non-execution; missing history stays Unknown.
- **I3 Membership ≠ spentness.** A coherent append replay can miss an NF-only withdrawal (`history.rs`). Root/count/signature never proves backing or global unspentness.
- **I4 Fresh bilateral authority.** Own policy and salt stay local. Exact B/E/leaves/C. Any mutation needs fresh assembly, review and consent.
- **I5 Public/private separation.** The snapshot restores capabilities, never status. The PostgreSQL journal holds no openings, keys or witnesses. Exact release bytes and locks are committed before the first export.
- **I6 Outcome.** Completed requires actual correct transfers at selected finality. Proof, simulation, receipt hint or DB row is not payment.
- **I7 Funded lifetime.** Immutable verifier/program pins. A new program or backend needs a new approved authority deployment. Old bytes and artifacts are preserved.
- **I8 Native separation.** Samechain lanes never close S1–S7/M1–M5/GD2.
- **I9 Lane isolation (new).** Every lane has its own authority identity, program/verifier pins, asset descriptors, finality policy, journal scope and backup context. Evidence from one lane never qualifies another. Cross-lane fills go only through X.CROSSCHAIN (CX-1 HTLC, which is not atomic).

### 5.2 Roles

| Role | May | Must not |
|---|---|---|
| Owner (maker/taker) | Select pins/terms, prepare own outputs, review, consent, prove, sign approved actions | Share policy, salt, openings, recovery keys or witnesses; infer eligibility from its own path/cache |
| Counterparty/peer | Get bilateral descriptors, negotiate, verify, permissionlessly submit | Get the other side's witness, choose its deployment/E, confer backing, revoke via ACK |
| Prover worker | Prove a frozen own witness, return internal certificate | Choose payouts/fees, read capability from peer requests, upload, export before the journal gate |
| RPC/history provider (two agreeing operators) | Report pinned state/logs/receipts | Be called consensus, cause latest/timeout fallback or unlock |
| Owner PostgreSQL | Hold exact public lifecycle records with fenced CAS | Hold secrets, mint rights, mark Completed from a row/ACK |
| Bootstrap/relay | Reachability, carrying unchanged public bytes | Sign, decide payment, be mandatory for exit |
| Lane authority (EVM contract / Solana program / NEAR contract) | Verify fixed-program journals; consume, append and transfer atomically | Have admin, upgrade or sweep powers (every lane is immutable, owner decision), or be treated as qualified merely because it exists |
| Fee payer | Sign the approved exact envelope | Mutate beneficiaries, fees or terms |
| Company/Zoss | Replaceable discovery/acquisition | Exit veto, hosted keys, financial facts from quorum receipts |

### 5.3 Current exact interfaces (reuse; do not recreate)

- `crates/runtime/src/samechain/preparation.rs`: `prepare_note_membership` (:25–79), `prepare_note_creation` (:100–165), `prepare_note_withdrawal` (:228–325), `prepare_cancel_exit` (:326–435), `prepare_fill_outputs` (:436–531).
- `crates/proofs/src/samechain.rs`: `OwnerWitness`, `review_owner_fill`, `verify_owner_relation` (:79–90, 469–566).
- `crates/proofs/src/artifacts.rs`: `OwnerInput{Fill,CancelExit,Withdrawal,Creation}`, `prove_owner`, `verify_owner_certificate`. These are SHA-only exact frozen v6.1.0 verifier pairing; guest modes 0–3.
- `crates/chains/src/samechain.rs:58–207`: four `build_*_call` → `UnsignedCall`, EVM ABI only.
- `crates/chains/src/samechain/inspection.rs`: `InspectionScope`, `SamechainInspectionClient`. One EIP-1898 hash, EVM only.
- `crates/chains/src/samechain/history.rs`: `PublicHistory`, bounded at 2048 blocks / 4096 notes / 8192 NFs / 16 MiB. Assumes the provider is complete.
- `crates/runtime/src/node/*`: transport described in C6.
- `crates/runtime/src/store.rs`: native inventory `ActorStore`. **Not** a samechain journal.

The guest relation (`crates/proofs/methods/samechain`) and the protocol codecs are chain-agnostic bytes. `Deployment`, the call builders, the inspection client and history are EVM-specific. That boundary is where the multichain shared seams sit (§6.2).

## 6. Multichain integration design

### 6.1 Catalog rule (owner-confirmed)

- The 122 IDs keep their exact text and criteria as the **EVM/Base lane catalog**. HyperEVM spot reuses SamechainAuthority under the X.02 lane tag. Its deltas, and HyperCore position claims, are L-HEVM.\*.
- New namespaces are added and nothing is renumbered:
  - **X.\***: shared seams and X.CROSSCHAIN.
  - **L-SOL.\***, **L-NEAR.\***, **L-HEVM.\***.
  - **L-ZEC**: reuses native plan Tasks 1–10 and the S/M gates.
- The roadmap, prompt and microplan state that the 122 IDs do **not** cover other lanes. Lane task tables live in microplan § Parallel lanes and the domain reports. Each lane gets its own reviewed spec and plan before any code.

### 6.2 Shared seams (X.\*; proposed, no universal API invented)

| ID | Seam | Today | Needed |
|---|---|---|---|
| X.01 | Lane descriptor | `Deployment` is an EVM address/chain ID | A per-lane closed enum of exact identity pins: EVM chain ID+address+codehash; Solana cluster genesis hash+program ID+programdata hash+upgrade authority None; NEAR chain ID+account+code hash+no access keys. These are bound into packet/journal domain bytes. |
| X.02 | Relation/journal domain | Guest journal binds the EVM deployment | Lane-tagged domain in the journal. Needs a **new program/ELF and new authority deployments** (I7). The old fill1/Fill2 EVM artifacts are preserved. |
| X.03 | Proof wrapping per target | SP1 Groth16 → frozen v6.1.0 Solidity verifier | Same Groth16 proof, verified on each target. Solana via alt_bn128 syscalls; NEAR via alt_bn128 host functions [INFERENCE until PlanChainsProverPolicy confirms pinned sources and cost]. Exact public-input/vkey equivalence is checked per lane. |
| X.04 | Asset model | ETH + ERC20 codehash pin | Native + one fixed-supply 6-decimal token per lane: ERC20 / SPL mint with mint and freeze authority None / NEP-141 with no owner methods. Exact-transfer delta checks per lane. Storage-deposit (NEAR) and ATA rent (Solana) are lane-specific costs. |
| X.05 | Chain client | EVM inspection/history/call builders | A per-lane client behind a narrow trait **only where ≥2 implementations exist**: pinned state read, complete event/effect acquisition, finalized-anchor agreement across two operators, unsigned call/instruction/action build, simulation. |
| X.06 | Finality/outcome reducer | none | One lane-independent reducer over lane-supplied `(finalized anchor, effects, NF consumption, timestamp)`. I2 lock predicate per lane clock. Solana uses slot/blockTime and NEAR uses block timestamp [INFERENCE: equality semantics of each target's expiry check must be specified in its program]. |
| X.07 | Journal | none | One PostgreSQL schema keyed by lane descriptor. Per-lane CAS/fence/tombstone. No cross-lane state. |
| X.08 | Backup | Snapshot spec binds EVM deployment/token | The snapshot `SnapshotSelection` gets a lane descriptor via a **new envelope version**, preserving v1. The independent-media requirement applies per lane before each lane's funding. |
| X.09 | Discovery/session | Transport only | The session envelope binds the lane descriptor(s). A cross-lane RFQ also binds both lanes, h and native-unit deadlines (X.SESSION.CROSS). |
| X.10 | Action packets | EVM preview | Per-lane preview fields: signer/fee payer, recipients, assets/raw units, fees (EVM gas+L1 data; Solana CU+priority+rent; NEAR gas+storage deposit), simulation, finality policy. |

### 6.3 Per-lane obligation checklist

This is the minimum each lane's spec must answer. Helper reports supply the evidence.

Each lane must cover: target authority construction and immutability, verifier and cost, NF/tree/root retention, atomic consume/append/transfer and rollback, expiry semantics, asset control, finality and two-operator agreement, RPC limits for pinned historical state, complete effect acquisition, fees/rent/storage, node and toolchain identity, journal scope, backup context, cold restore before first funding, company-off exit, faucet/test-asset access, and action-packet fields.

Lane notes:
- **EVM/Base:** existing 122 IDs.
- **HyperEVM:**
  - The default RPC serves only latest state and limits `eth_getLogs` to 50 blocks, which blocks InspectionScope's pinned hash.
  - Dual small/big blocks: the 3M-gas small-block limit may not fit authority deployment or fill gas without the HyperCore `evmUserModify` big-block action. That would itself be a Core action needing approval [needs verification].
  - Priority fees are burned.
  - Source: hyperliquid.gitbook.io HyperEVM, dual-block and JSON-RPC pages, retrieved 2026-10-06.
- **Solana:** the new owner-ZK program is not the existing three-ACK escrow, which stays as provenance. Verifier compute budget, the transaction size limit (1232 B) against the 356-byte proof plus a ≤64 KiB packet, and account/ALT layout are RESEARCH-OPEN. A packet staging account or buffer is likely required, and it must not weaken atomicity.
- **NEAR:** async cross-contract calls break single-transaction atomicity for NEP-141 transfers. The design must specify a callback/rollback state machine, or hold assets in-contract with internal accounting before payout. This is RESEARCH-OPEN with kill criteria: the branch is killed if any reachable path loses or double-credits funds on callback failure.

## 7. Material questions (all answered 2026-10-06)

- MQ1–MQ9, batch 2 (HQ1/HQ2/XQ1/XQ2/NQ1/DQ1/DQ2) and Z1–Z3 are all answered; the answers are recorded in §2 items 9–20.
- Engineering defaults that the owner did not choose are listed in §2.
- No material owner question remains open for the first journey.
- Lane specs may surface new questions. Those go to the owner via Main.

## 8. P0.01–P0.12 resolution matrix

Domain details are in `2026-10-06-phase0-{durability-recovery,testnet-prover-policy,private-discovery-network}.md`. **Decision-acceptance update, 2026-10-06:** DONE below means the exact microplan selection, policy or integration criterion is satisfied, not downstream implementation, qualification or readiness. Earlier source observations elsewhere in this report retain their dated scope. The owner subsequently approved the written networking freeze in the protocol spec §7; its implementation still requires the corresponding reviewed plan.

| ID | Acceptance (microplan) | Current evidence | Contradiction | Status | Resolution / interface | Future verification | Remaining owner / permission |
|---|---|---|---|---|---|---|---|
| P0.01 | Roadmap 0–6 → IDs; V2/S not closed | §3 manifest; canonical microplan/roadmap/prompt integration and historical independent docs review | Original omissions corrected in canonical docs | DONE — scope binding | Lane namespaces §6.1 | Each implementation/lane still needs its own acceptance evidence | — |
| P0.02 | Role/invariant matrix; no generic verified flag or company veto | Reviewed §5 roles and I1–I9; canonical docs integration | SOL/NEAR must re-establish the same invariants in their lane designs | DONE — invariant/threat boundary | Owner, peer, prover, RPC, journal, authority and company powers separated | Independent review of matrix per lane spec | Reviewer (H) for each later lane |
| P0.03 | Chain/RPC/explorer/faucet/token/compiler recorded | Base 84532 / HyperEVM 998; primary-source explorer and trust records in [testnet selection](../V1-TESTNET-SELECTION.md); solc 0.8.34/Cancun and asset answer 10 | HyperEVM default RPC is latest-only, without EIP-1898; Core faucet requires mainnet deposit | DONE — selection descriptors; Base first remains an engineering default | Per-lane descriptors X.01 and assets X.04 recorded; deployment unapproved | Qualified independent operators, gas access and actual deployed pins remain separate; read-only RPC/bytecode qualification under Q permission | Q network-read and later action-specific permissions |
| P0.04 | One storage path; PostgreSQL-only; legacy retained; URI ≠ migration | Answer 3 selects per-owner PostgreSQL; [current native checkpoint](../NATIVE-IMPLEMENTATION-STATUS.md#2026-10-06--actual-postgresql-runtime-verification) records PostgreSQL18.4 verified TLS, 373 runtime tests / 42 suites / 7 ignored and passing all-target Clippy | Old "undecided" and SQL-NOT-RUN labels are superseded; storage selection is not full lane-aware lifecycle qualification | DONE — storage-choice acceptance; selected isolated SQL runtime hold exercised | Preserve legacy identities; Wave B EVM journal remains a slice, not full reservations or lane-keyed X.07 | Genuine positive capsule/export and full lifecycle remain separate acceptance edges | Existing Docker endpoint, test-only TLS/restricted role/reload and owned isolated schemas were specifically approved; no operational migration/reset or broader service permission |
| P0.05 | Backing/ownership/spentness relation, or stays blocking; no GD2 waiver | Network report §2.4 executed finite model: buyer limit 8 / seller 6 vs 10; 20 versus 0 legal positive allocations, own-result support intersection only no-trade | Hints/signatures/root existence cannot satisfy backed-order acceptance | BLOCKED — proposed discovery relation is not approved; finite K1 incompatibility observed for this world pair, strict GD2 unmet | Dedicated non-executable relation/domain per lane; never reuse OwnerCertificate as an ad; no general privacy-impossibility inference | Reviewed backing construction and unchanged-adversary privacy acceptance remain unmet; do not repeat the same finite enumeration | Reviewer; no GD2 waiver |
| P0.06 | FillAccept negotiation only; descriptors → packet → consents → proofs; release irrevocable | Reviewed Fill2; protocol spec §5; P3.03a/b ordering; capsule-only proving and pre-export release guard | Original ordering/export contradictions reconciled; actual financial execution remains unqualified | DONE — wire/state semantic reconciliation | Exact packet and fresh local consent; partial remainder retained; no witness exchange; session transport never revokes released authority | Generated loopback sessions and genuine late permissionless execution after abort remain downstream checks | Reviewed implementation plan; action-specific permissions |
| P0.07 | libp2p version/features, QUIC own TLS, bounds, no 6th money crate | Owner-approved [protocol spec §7](../V1-P2P-PROTOCOL-SPEC.md#7-resource-limits-and-message-validation) freezes exact IDs/framing, selected versions, admission/query/cache/concurrency ceilings and bounded adaptation requirements | Original 4 KiB / 96 KiB candidates and upstream defaults are superseded as design choices, not rewritten source facts | DONE — minimal networking design freeze | Existing runtime placement; canonical §7 bounds, TCP+Noise+yamux / QUIC own TLS, zero-paid direct/optional-independent-relay path | Reviewed implementation plan and actual bounded transport/codec tests; loopback generated checks only under current scope | Network permission beyond loopback held; no financial approval |
| P0.08 | Methodology: cgroup/shm/children/corpus/schema | Resource targets and prover handoff define run classes, environment, nonsecret schema and separate charged peak/RSS/shared-memory accounting | Historical 4 GiB OOM/component sizes are not target-hardware qualification | DONE — measurement methodology only | Methodology adopted; per-lane verifier cost is a separate measurement class | Actual corpus boundaries, private-sink and resource qualification remain downstream; no heavy trial until resource packet approved | User: resource-run packet (answer 12: none now) |
| P0.09 | Lifecycle states; release-before-export; finalized/reconciled unlock; RPC ≠ consensus | Testnet/prover policy §5 and durability X.LIFE define Base finalized anchor, missing/contradictory-history handling and provider replacement; answer 11 | Current inspection/history does not implement all timestamp/finality/receipt acquisition; HyperEVM finality remains unqualified | DONE — EVM/Base trust/finality/outcome policy | Two operators agree on a common finalized anchor; strict > expiry or finalized required-NF consumption plus complete reconciliation; contradictory anchors fail closed | X.06 reducer and RPC qualification; lane-specific finality and effect reconciliation remain downstream | Q permission; resource approval for any owner-run second source |
| P0.10 | Backup inventory; generated vs production; held recovery command untouched | Before-funding inventory and private-use boundary recorded; generated-key clean-process snapshot restore; current runtime includes release-journal7 / release-CLI8 ordering with invalid-certificate fixture | Snapshot and SQL ordering are not independent-media backup, genuine proof restoration or an offline prover kit | DONE — recovery/private-use approval boundary | Full catalogue/cloned-writer/lifecycle implementation remains separate; new lane-aware X.08 version needs review; v1 preserved; offline 32-byte backup key is the engineering default | Independent-media/kit and genuine VM/wrapped restore remain unexercised; current runtime green supersedes the earlier no-post-snapshot-green hold | Production secret use, offline-media/drill and held recovery command remain separately scoped; generated-key approval is not production approval |
| P0.11 | Per-action previews; credentials out of chat/argv; no blanket permission | Testnet/prover policy §6 includes applicable per-lane fees, simulation, signer/recipients/assets; durability report separates SQL, service, media, restore and replacement packets | Earlier "per-lane fee fields missing" is superseded by the existing packet definitions | DONE — action authorization packet format | X.10 fields and independent exact-action approval; credentials outside chat/repo/argv/logs | Concrete preview and approval before each applicable action; no blanket testnet/mainnet/Anvil permission | Every action separately |
| P0.12 | Integrate into existing docs; no parallel ledger; frozen interfaces | Canonical 2026-10-06 integration; historical whole-doc review and accepted scoped fixes; D1–D8 retain sole BLOCKERS ownership | Earlier pending-independent-review label superseded; no repeat audit needed | DONE — decision integration and guarded task interfaces | Accepted contracts linked; proposed/open blocking interfaces cannot authorize dependent implementation | New lane/wave specs and implementation plans still need their own reviews; no downstream gate closure | Action-specific permissions unchanged |

**Only P0.05 remains unfinished in this decision-task set.** This does not mark all Phase 0, any product/lane, strict GD2, genuine proving, funding or recovery acceptance complete. The genuine journey still depends on the separate implementation, resource, artifact, independent-media, deployment and action-specific gates above; neither an obsolete SQL-URI hold nor the now-approved network design freeze should be counted again as an unresolved decision.

## 9. Scoped canonical edit plan

The edit plan runs in two waves.
- **Wave 1** consists of answer-independent corrections. It can start now.
- **Wave 2** follows the MQ answers and the three helper reports.

Main verifies once, after Wave 2.

**Wave 1**
- E1: microplan C1, C2, C3 (P3.03a/b and P3.05 dependencies), C4 (P4.02/P4.03 edge split), C5 (P3.08 every export), C7. No ID is removed or renumbered.
- E2: BLOCKERS C8, C9. Status semantics are unchanged; nothing is marked resolved.
- E3: MODULES / ARCHITECTURE / prompt C6.
- E4: README C12; roadmap C11.
- E5: V1-ARCHITECTURE-DECISIONS C10 (historical choices; P0.04 records the selected per-owner PostgreSQL design target only).

**Wave 2**
- E6: Add the answer-14 multichain scope (C13–C15) to the prompt, roadmap, delivery matrix and decisions. Wording: active lanes, with the 122 IDs labeled as the EVM lane.
- E7: Testnet selection becomes per-lane descriptor sections (done by the chains slice).
- E8: P2P spec (P0.05–P0.07 helper report).
- E9: Storage decision (P0.04/P0.10 helper report).
- E10: Resource targets / proving cost (P0.08 helper report).
- E11: Microplan Phase 0 table gets a per-ID status column pointer to this matrix; add X/L task tables as **separate reviewed lane plans** under `docs/superpowers/plans/`, linked from the microplan.

Wave 2 lane task tables (L-SOL/L-NEAR/L-HEVM) are drafted from the helper reports, then reviewed before any code (answer 2).

## 10. Retained V2/native crosswalk (unchanged obligations)

- Native plan Tasks 1–10 → M1–M5 / S1–S7. Task 10 = full adverse/lifetime/resource/manual/security acceptance.
- Integration plan Task 7 SQL evidence plus ten continuation rows: native history, classifier/uniqueness/recovery, target/manual, private market, standing maker, reverse/Hyperliquid A, external HyperCore B, software/frontend, other lanes, whole-product report.
- Rows that are now active lanes keep their provenance link:
  - L-ZEC: native history, classifier, uniqueness, recovery, target, manual.
  - L-HEVM: Hyperliquid A/B.
  - L-SOL/L-NEAR: "other lanes".
  - X.CROSSCHAIN: cross-chain.
- Unchanged V2: standing maker (C04–C08, C11), GUI (all 71 stories as later integration), hardware wallets, mainnet, Raydium LP/1Click/Intents/agents/ZSA. Strict GD2 privacy is an active blocked gate, not V2.

## 11. Evidence ceiling

Read-only docs/source/handoff research and three official Hyperliquid doc pages (retrieved 2026-10-06). Existing workspace results (1099 checks / 91 suites, artifact 3208) are pre-planning source evidence reported by the checkpoint, not verification of these claims. Facts marked [INFERENCE] are unverified.
