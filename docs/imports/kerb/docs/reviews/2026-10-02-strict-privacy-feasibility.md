# Kerb strict privacy: implementation prerequisite

Status: reasoned mechanism analysis with independent arithmetic checks, not a runtime audit or privacy proof for a working system. Retrieval/analysis date: 2026-10-02. The objective remains implementation of every core and major Kerb module; this document does not narrow it to a simulator, scaffold or nontrading protocol.

## Decisions in the current conversation

1. User requests building all core/major Kerb architecture.
2. User selects **retain strict privacy; redesign first**, not an own-result leakage waiver.
3. User permits changing **auction/output semantics**, not changing the matcher threat model or redefining privacy modulo disclosed outputs.
4. No deployment, real-key signing, broadcast, funding, mainnet, publication, commit or push is authorized.

The existing candidate's FAA/coordinator privileged views are separate from matcher privacy. The matcher adversary can control or collude with a legitimate trader and learn that trader's own outputs/assets. Strict noninference here means that protected changes to honest orders or accepted identities must not change that adversary's observable view, even with permitted auxiliary information. This is stronger than ordinary cryptographic input privacy modulo outputs.

## 1. Existing exact-auction impossibility

Fix an adversarial buyer q=2, limit=12. Alice sells q=1 at private limit6 in world0 or10 in world1. A second genuine, noncolluding seller sells q=1 at independently unknown limit U in {1,2,3}; the same U distribution is used in both worlds. Remaining eight-slot entries are padding.

Both worlds fully fill two lots. The maximizing price plateaus are [6,12] and [10,12]. The specified half-even midpoint is9 versus11. The buyer's own exact price reveals Alice's secret bit with certainty. For event E={buyer sees price9}, Pr[E|world0]=1 and Pr[E|world1]=0.

An independent throwaway arithmetic check enumerated U=1,2,3 and observed (filled lots, own price)=(2,9) versus(2,11) in every case. This checks written mechanism arithmetic only, not Arcis execution or a deployed privacy experiment.

This failure survives perfect MPC, encrypted client outputs, hidden pooled collateral, role separation and a genuine minimum cohort. The output itself distinguishes the worlds. Random padding or private permutations do not alter the correct output marginal. Current public epoch-bound escrow separately exposes membership/identity.

Sources: [candidate mechanism§6](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md#6-matching-rules-and-confidentiality-of-results), [review F1](../docs/superpowers/specs/2026-10-01-kerb-design-review.md#f1--structural-privacy-failure-still-open--blocking), [prior output-leakage research§9](../../zolana-research-2026-09-30/privacy-admission.md#9-output-leakage-and-observer-acceptance).

## 2. Changing outputs cannot conceal the trader's actual asset disposition

Suppressing fill receipts or exact prices does not conceal an adversarial trader's own delivered assets, final balances, withdrawals or refunds. A useful exchange must eventually convey the participant's enforceable disposition; permanently withholding both result and assets is not the requested protocol.

Consider an adversarial buyer limit8 and an honest seller limit6 versus10. With no independently prefunded maker/sponsor delivering substitutes:

- In the limit10 world, a buyer/seller limit-respecting trade is impossible. Buyer delivery must be0.
- Perfect noninference requires the same buyer-delivery distribution in the limit6 world.
- Therefore buyer delivery must also be0 in that world, even though a mutually acceptable trade exists.

A finite check considered seller quantities1/2 and asks6/10. Common legal allocations across the protected worlds were exactly {0}. Randomized perfect noninference requires identical distributions, hence the same restriction. This does not assert that every scoped privacy definition forbids trading; it establishes the conflict for the currently retained unconditional definition and permitted adversary/corpus.

## 3. Remedies must change a requirement, not claim a cryptographic fix

| Proposal | What it actually changes or leaves unresolved |
|---|---|
| Hidden pool, batched funding/withdrawal | May remove direct membership joins; does not hide adversarial net asset results. Ordinary public SPL amounts/recipients/timing still require end-to-end analysis. |
| Fixed price, hidden limits | Execution/no-execution still depends on whether an honest limit accepts that price. |
| Random/noisy allocations or prices | Bounded differential privacy permits inference and is not unconditional noninference. Exact equal distributions face limit/conservation constraints. |
| Minimum genuine cohort | Additional unknown traders do not eliminate the marginal-limit price trace; knowledge/independence is not established by wallet count. |
| Robust crossing invariant over all protected inputs | Can avoid distinguishing output only where one output is legal in every world; the legal no-cross world forces0 in the trace. Treating this as the complete protocol would substitute a nontrading system. |
| Forbid matcher-controlled traders | Changes the permitted adversary/governance model; proxy/collusion control and public settlement inference still require evidence. Not selected by user. |
| Operator-funded cover inventory | Adds a prefunded counterparty and exposure/economic model. A genuinely input-independent dealer outcome is not bilateral crossing; no capital or guarantees are approved. |
| Privacy modulo explicit outputs | Standard defensible cryptographic target, but explicitly changes the selected unconditional noninference guarantee. Not selected by user. |

No remedy is marked successful. Changing assets to confidential transfers, adding unbounded cover liquidity, fabricating unknown traders, never settling, or silently weakening limits/ownership/conservation is not authorized.

## 4. Implementation state and preserved scope

Kerb has no inspected protocol implementation or current executable implementation plan. Zoss is being edited concurrently: its Rust protocol crate now exports actual codecs, ordinary Ed25519 authorization and caller-owned AEAD/source-context data types. Source/chains/runtime/target integration must be re-read before depending on it; source inspection alone is not a passing build or chain-support claim.

Subsequent approved work: the [independent safety-core specification](../docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md) and [plan](../docs/superpowers/plans/2026-10-02-kerb-safety-core-build.md) now govern implemented Rust protocol, PostgreSQL journals/inventory, local compiled Solana escrow, unsigned native inspection and runtime processes. [Current implementation/run notes](../README.md#implemented-local-safety-cores-2026-10-02) record exercised behavior and limits. The preceding paragraph is the pre-implementation snapshot; these safety modules do not solve the output-leakage contradiction or implement an approved strict-private auction, FAA/MPC, native threshold signing or funded network settlement.

The full implementation target remains:

- Canonical domain records, units, authorization and an approved auction.
- App-owned source/history/claimant/inventory/credit reconciliation.
- Persistent symmetric holds, entitlement partitioning, epoch decisions and non-rollback journals.
- Actual FAA certificates and encrypted MPC input/verification/results.
- Solana escrow, canonical epoch/fill fences, release/cancel/refund.
- Native Ironwood PCZT/FROST intents, effect checks, nonce recovery and physical change inventory.
- Coordinator/client/operational processes and actual unknown-outcome/finality reconciliation.
- Compiled local integrations and independent review; separately authorized synthetic devnet/Ironwood settlement, refund and recovery evidence.

No core implementation is declared complete. A written implementation spec/plan cannot promise an achievable strict-private funded exchange until a compatible mechanism/security contract is approved. The architectural approval gates remain outstanding. Externally independent operators and action-specific permissions are separate later prerequisites, not solutions to this mechanism contradiction.
