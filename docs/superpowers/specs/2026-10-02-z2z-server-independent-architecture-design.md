# Ziquid / Z2Z — server-independent architecture redesign

> **Status — 2026-10-06:** still a docs-only proposed architecture. Active lanes are native ZEC (L-ZEC, first-class, not V2), L-HEVM, L-SOL, L-NEAR and X.CROSSCHAIN (HTLC first, all pairs in parallel, no atomicity/privacy claim). No implementation/gate change follows.

**Requested design/documentation work, 2026-10-02.** User authorizes deep research/review and refactoring all shared docs for the expanded product. This spec records a **proposed architecture**, not approval to change implementation, weaken privacy/economics, deploy or move funds. Namespaces stay unchanged; Z2Z future product name.

## 1. Intent and acceptance

One product can offer ZEC quotes, P2P markets, separately chosen external spot, and later LP/agents/ZSA. Hosted company processes automate discovery, proving assistance and transaction submission but must not be the only way to exercise a qualifying user's money rights. User can retain/download the actual tools/artifacts and private data, inspect and prove locally, then submit without a company server/signature.

Acceptance requires **route-specific** state transitions and an actual company-off drill before release: observe authentic state, cancel/exit unused samechain capital, complete existing eligible funded obligation, replay-safe retry, verify actual transferred asset. No artificial promise of new fills without counterparties, guaranteed gas/chain inclusion or universal ZEC recovery. Missing privacy/witness/source-return constructions remain blockers.

## 2. Three considered approaches

| Approach | Strength | Why not default |
|---|---|---|
| Merge custodial Kerb ledgers into one crosschain account and add self-submitted proofs | Reuses local safety records. | A proof cannot force ZEC committee signers to spend; SQL/ACK/MPC authority and required exits remain offchain. Fails user requirement when custody operators disappear. |
| Build new private crosschain rollup/chain with sequencer/bridge/global state | Could express rich matching, batching and data transition proofs. | Creates extra source verification/DA/forced-exit/upgrade/bridge/prover assumptions, not a shortcut to hidden source facts or strict output privacy. No current proof/consensus construction or approved economics. |
| **Wallet-owned authorization and proofs, deployment-scoped onchain money authority, replaceable discovery/relay services** | Separates money permissions from company; programmable-chain assets can use atomic local proof transitions; native crosschain relation stays distinct. | Recommended docs direction. Actual circuits/resources/privacy/asset semantics still require qualification; does not solve blocked native hostile-spend/excess or inherited GD2 requirements. |

No new universal vault, cryptographic primitive, chain or permanent crosschain credit is selected. A product app spanning chains does not make balances fungible or transfers atomic across chains.

## 3. System ownership

1. **Wallet/native client:** keys, note secrets/openings, exact consents, private witnesses, encrypted durable recovery bundles, local proof generation and direct submission. Thin native consumer is part of protocol acceptance, not deferred TypeScript/UI work.
2. **Protocol/proofs:** canonical typed domains, units, action rights/consumption, circuit relation and prover/verifier artifacts. Separate samechain ownership/conservation/order relation from full Zcash history/payment/classification relation. No generic `verified` fact.
3. **Target contracts/programs:** authentic asset custody/control, eligible commitment roots, nullifier/intent consumption, immutable funded rules, exact atomic asset effects. Money state is onchain for qualifying proof-controlled routes, not SQL only.
4. **Source/history clients:** raw complete source data, independently checked history policies, target finality/state/log reconstruction. RPC/indexer provenance is not source validity.
5. **Replaceable services:** quotes/order discovery/matching proposals, read-only indexing, proof work with scoped consent, relaying. They cannot mint money rights, redirect outputs, set unsigned fees, retire funded paths or censor protocol-authorized submitters via a company allowlist.
6. **Legacy custody adapters and external venues:** separate authority class, disclosed limits. Kernel sharing does not turn committee credit, HyperCore fill or Zoss receipt into native settlement fact.

Existing `crates/protocol`, `zcash`, `proofs`, `chains`, `runtime` and target contract builds remain packaging base. Expanded roles are conceptual until reviewed implementation plan; no crate scaffolding, imported source migration or forced PostgreSQL/SQLite convergence.

## 4. Onchain workflows

### A. Proposed programmable-chain proof-controlled asset lifecycle

Deposit actual qualified asset and commitment/recovery ciphertext atomically; wallet stores note capability. Owner reconstructs current tree from independent chain data, proves ownership/unspentness/domain/authorization and requests transfer or owner exit. Contract verifies and consumes capability plus actual transfers atomically. Direct user submission and relayer submission share one validator, not fallback trust model.

**Selected candidate:** when exact fill quantity is known, each recipient locally creates/checks and backs up its exact outputs (received asset, own change and remainder), then both owners authorize a common immutable fill digest. Per-owner proofs/composition must not require shared secret export; verifier checks semantic exact terms/outputs, limits, backing, conservation, signatures and consumed capability. Ciphertext bytes are bound to authorization; encryption correctness is established by owner-local output preparation/check, **not an invented existing ZK encryption relation**. Partial fill mints disjoint exact successor quantity/rights; each further arbitrary partial fill needs fresh owner confirmation. Owner offline prevents new authorization, not owner exit or an already fully authorized settlement. Unattended partial fill using circuit-enforced encryption or finite templates is a separately unselected construction, not quietly implemented here. Cancellation consumes the same backing capability as fill, so one chain-order winner controls remaining funds. Sender/relayer replacement never rewrites authorized fee beneficiary/recipient.

**Selected membership/liveness policy:** retain all authenticated historical membership roots/tree generations for the samechain deployment with live deployment-wide nullifier/capability checks, not a sliding proof-root window. Unrelated appends/tree rollover therefore do not require regeneration of an offline owner's already-authorized private proof/signature. Explicit signed expiry, orphan/unaccepted root or actually consumed/canceled generation still rejects. Retained roots add state/storage/gas costs to qualify and must not permit per-tree double spend; this is not native Zcash anchor retention. Order cancellation atomically consumes/invalidates the shared backing generation, rejecting all outstanding F1/F2 digests on it; one packet-only revocation does not cancel the order or release principal.

**Not a completed strict-private auction.** Encrypted inputs/signed trades can support transactional safety with declared output leakage, but the inherited strict noninference requirement under trader/matcher collusion remains unresolved. Such a looser market cannot be enabled under that label without explicit owner decision.

### B. Existing native Zcash-outbound workflow

Retain local complete Q / unsigned P / independent U witness → irrevocable destination prefund → user independent check → source authorization → full accepted history/effects/auth/classification/uniqueness proof → destination atomic proportional allocation/transfers. One-real-note/one-obligation, full validation/no SPV, dust/fixed beneficiaries, same-effect auth changes, earlier payments, net consideration and actual source excess return requirements unchanged.

Native source key controls Zcash spend, not destination contract. Q self-return is only valid when same input unspent and packet lifetime valid. Proving history does not reconstruct all unavailable private hostile-input ownership/debit facts. S-received source ZEC cannot be returned by target contract without actual source-authorized capability. All-hostile independent terminal recovery/excess return blockers remain **blocking**, not indefinite pending counted complete.

### C. Retained custody market and external spot

Kerb local financial bookkeeping/custody records remain valuable source evidence, not autonomous exit construction. They may serve explicitly classified legacy/custody workflows only after scope approval; committee native signing is not relayer optionality. HyperCore user account/native tools may continue without Ziquid app, but venue semantics/account controls/chain and asset authorities remain dependencies. No external-spot automatic remainder routing or perps.

Reverse Zcash and Solana crosschain markets need their own constructions; do not transpose outbound proof to get bidirectional support.

## 5. Data, privacy and rule lifetime

Onchain **verifier** is not local proving code/keys; public content hash is not durable data availability. Required recovery data must be on appropriate chain or reconstructible/archived independently; owner private secrets cannot be recovered if lost. Correct output ciphertext/opening recoverability must be part of authorized relation, not only emitted hash. Mutable log/history retention, roots window/full tree, branch/anchor expiry and actual proof resources must be tested.

Default new qualifying deployments pin code/verifier/asset semantics, no admin sweep/exit veto, no company-only settle/cancel/withdraw. New version is separate opt-in deployment; funded old rules, artifact access and replay domains remain. Underlying asset issuer freeze, source chain upgrades, RPC/history availability, sequencer/validator censorship and gas remain explicit assumptions.

Privacy dimensions: source note/payment, order content/intake/accepted identity, adversarial own results, public destination/linkage, external venue. No unconditional claim derived from one ZK proof or more participants. Strict GD2 is retained known failure of selected old mechanisms, not fixed by this architecture diagram.

## 6. Manual operations and verification

[SERVER-INDEPENDENCE](../../SERVER-INDEPENDENCE.md) owns the exact stage/action matrix, bundle format goals and drills. Native consumer operations are interface goals, **not commands already implemented**. Existing CLI arithmetic/generated fixture is not money movement.

Design verification includes adversarial model checks for cancel/fill/partial/replay atomicity and independent source-privacy impossibility traces, documentation claim/source traceability and link/provenance checks. Model checks prove only their stated transition model, not actual circuits/contract execution, chain-valid history or funded company-off operation. Full runtime drills require implementation and action approvals later.

Additional mandatory samechain qualification traces from independent review: F1/F2 with different relayers/fees/proof representations share backing → owner cancels generation → both rejected; fully authorized A/B packet → A offline → unrelated accepted-root churn/tree rollover → B submits exact packet without A witness/signature refresh, with current nullifier/cancel/signed-expiry checks. These traces remain implementation-unrun; model reasoning is not claimed target execution.

## 7. Documentation cutover

Research outputs: [server independence research](../../research/SERVER-INDEPENDENCE-RESEARCH.md), [crosschain/market research](../../research/CROSSCHAIN-MARKET-RESEARCH.md). Comprehensive review records every current and archived source file in [architecture review](../../research/ARCHITECTURE-REVIEW.md).

Canonical product/architecture/module/blocker and all five functional specs must link this new design/independence owner and remove source-vs-current ambiguity. Older exact designs/plans/research/audits/imported 53-doc archive stay dated evidence, not competing current approvals. If architecture prose is reorganized, retain old version as attributed snapshot and update all current references; preserve anchors that still describe actual native requirements, not empty compatibility sections.

No builds/code/transactions/push/publication are part of this docs-only cutover. No gate changes to Passed. Final user presentation must explain the product, owner-driven flow, server automation and manual path, then state unresolved matching/native-crosschain/venue limits plainly.
