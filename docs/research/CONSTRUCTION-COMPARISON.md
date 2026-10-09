# R1.3 — Native construction comparison and decision menu

**Status: research deliverable, not a construction selection.** Consolidates every R1.3 investigation recorded in [SETTLEMENT-RESEARCH.md](SETTLEMENT-RESEARCH.md) into one capability matrix and an explicit owner decision menu. The owner must select one of the three options in §5 (or extend the research); **no implementation, GO, or release follows from this document alone.** Financial blocker register remains [BLOCKERS §4](../BLOCKERS.md#4-native-cross-chain-protocol-gates-s1s7).

## 1. The four requirements every candidate must satisfy

From the approved contract ([ARCHITECTURE §7](../ARCHITECTURE.md#7-native-shielded-zec-outbound--approved-financial-contract-incomplete), [BLOCKERS §4](../BLOCKERS.md#4-native-cross-chain-protocol-gates-s1s7)):

| # | Requirement | One-line meaning |
|---|---|---|
| N1 | Authentic source validity | Full validating Ironwood/v6 history from genesis, not header claims or two-RPC agreement |
| N2 | Hostile-outcome soundness | Every reachable branch (partial/alternative/mixed/over payment, competing recovery) is handled from independently obtainable facts or proven unreachable |
| N3 | Once-only consumption + exact allocation | Same-J/nullifier/pool mutual exclusion on ONE valid accepted history; proportional `U=floor(D*C/A)`, `S=D-U` where partial is reachable; actual authorized excess return |
| N4 | Both-role independent recovery | U payout without S and S recovery without U, throughout the funded lifetime, with secrets owner-local (no FVK/spend-key sharing) |

Anything satisfying fewer is not a protected exchange under the current obligation set.

## 2. Candidate families compared

| Family | Mechanism (one line) | Source evidence | N1 | N2 | N3 | N4 | Verdict |
|---|---|---|---|---|---|---|---|
| **A. Direct P/Q** (previous candidate) | U proves P locally; S holds complete independently-executable Q (self-return) to force settlement/refund on one history | PayoutWitness/allocate review 2026-10-06 (BLOCKERS); countermodel `A=10,D=100` | Open (full history verifier missing) | **FAIL**: hostile-T classified as success because PayoutWitness recovers matching-P effects only; `T != P` insufficient since replacements may still pay S | **FAIL**: no authorized excess return; allocation authenticates nothing | Open (U witness missing; Q-side OK in principle) | **NO-GO** (recorded) |
| **B. Absence-branch exclusion escrow** | S prefunds; refund only on proof that exact P is absent from ALL blocks in `[h0,H]` on valid canonical chain | §4.1, full analysis pinned | Open | Solid: exclusion is a sound refund basis IF complete-interval witness is real | Open: §4.1 requires explicit allocation/admission/history semantics — undefined, needs future design; the exclusion witness itself must be complete parsed raw blocks, not Merkle-root equality (`[A,B,P,Q]`/`[hash(A|B),hash(P|Q)]`/`[root]` same root) | Partial: refund needs S-side exclusion proof capability without U; heavy verifier work unspecified | **Heavy**: not killed, but largest proof/gas/privacy surface; no local timer fallback |
| **C. Positive-conflict (Q + general-T classifier)** | P pays S; Q preauthorizes same-real-note self-return; refund when valid competing spend T of the SAME committed note is included | §4.2, Zebra nullifier checks | Open | Better than A: general `ConflictingSpendIncluded(T)` predicate; but T≠P still cannot exclude "T pays S anyway" (AuthenticatedNetConsideration missing) | Partial: conflict forces P/Q impossibility, not net-consideration completeness | Q-side exists in principle; T-side witness ownership open | **Open**: audited as top-priority feasibility candidate 2026-10-01; adoption conditions unresolved |
| **D. Constrained joint-note (fresh J, 2-of-2 FROST)** | F funds joint note J; C pays S, R returns U; threshold SpendAuth on both | §7, ZIP312/229/374, frost-tools PR593 | Open | **KILL**: C-signature-share escape bypasses pre-ETH gate; gate must withhold usable SHARES not aggregate | **FAIL under current lifetime obligation**: branch change invalidates both signed C/R (including expiry-zero R) and neither 2-of-2 signer can renew alone | **FAIL**: every standard prover needs the same J FVK/opening + branch private action data; sharing = new permission not granted | **NO-GO** (kill criterion concrete) |
| **E. Finished-packet handoff** | Same J, but U retains ALL private proving data and hands S only completed transactions | §8, ZIP374/PCZT extractor | Open | U retains all witnesses owner-local; D's witness-sharing FAIL is avoided, but §8 does not grade this as a full N2 pass — the same branch-lock kill criterion applies | Same branch lock; plus handoff-order obligations (S arms only after durable finished R exists) | **FAIL**: S cannot re-prove after branch/fee change; pre-R-proof interval leaves S capital unarmed or U unrecovered | **NO-GO** under current lifetime obligation; owner could accept a **disclosed bounded-window contract** instead |
| **F. Skyhook / direct payment + effect proof** | U pays S directly (no joint note); destination escrow pays U on effect proof | §2 R9, prototype inspection | Open | **FAIL**: claim only known-header+inclusion, no rank/finality/source-validation; refund = createdAt+24h clock, not nonpayment proof | Not established | Not established | **NOT PROTECTED**: unsafe/unfinished settlement; trust model ≠ approved |
| **G. Adaptor signatures (Blockstream/PipeSwap)** | Scriptless scripts witness extraction on transparent chains | §2 R8 | n/a | **FAIL**: timeout/full-key release does not revoke success authority | FAIL | FAIL | **NO-GO**: no drop-in RedPallas/consensus integration |

## 3. Cross-cutting prerequisites no family resolves yet

1. **Full validating source history + finality** (N1): the SP1 Sprout guest and native validators are partial; Ironwood/v6 era validation from authentic genesis with authenticated checkpoints is required for every family.
2. **AuthenticatedNetConsideration** (N2/N3 for families A/C): complete input/output accounting distinguishing U-owned gross from S-funded contributions; zero-dummy semantics; missing facts fail closed to Unknown/Pending.
3. **Excess return** (N3): `C > D` reachable cases need actual authorized return or reviewed sound prevention — no family supplies this today.
4. **Threshold crypto cohort** (families D/E): re-randomized threshold SpendAuth via audited library is an explicit integration prerequisite; ordinary FROST does not supply it; PR593's cohort is not the installed cohort.
5. **Privacy composition** (all families): public txid/receiver/openings link chains deterministically; hiding proofs (inclusion/exclusion, same-real-input relation, per-order uniqueness) are separately implemented ZK statements, not automatic from "it's shielded" or "it's ZK".

## 4. Bounded-window contract (the only E-variant escape hatch)

Owner may explicitly accept a **disclosed bounded-window contract** for family E, trading away guaranteed indefinite recovery for a finite, enumerated envelope:
- supported branch/anchor/fee variants enumerated and signed at quote time;
- latest safe F release/inclusion and mandatory recovery opportunity defined;
- early-R cancellation/fee rights agreed;
- residual risk of stranded ZEC/armed ETH if recovery does not finish inside the window, disclosed as a product term.

A cutoff, expiry-zero, or promised automation cannot enforce this — it is an owner product decision, not an engineering fix.

## 5. Decision menu (what the owner must pick)

1. **Keep lifetime obligation, select none of A–F → stay NO-GO.** Continue source/capability research (e.g., the two research routes in §7/§8 of SETTLEMENT-RESEARCH: route-specific disclosure exception, or finished-packet handoff) until some family supplies complete capability/lifetime evidence.
2. **Accept bounded-window contract (family E variant).** Explicitly enumerate and sign the window; accept stranded-funds residual risk as a disclosed product term. Unlocks R1.1 freeze, then R2+ qualification.
3. **Re-scope the product.** E.g., payment/request without exchange enforcement, or samechain-lane first release — a product decision recorded in ARCHITECTURE, not a settlement fix.

**Decision artifact available:** option 2 now has a concrete draft parameter sheet — [SETTLEMENT-RESEARCH §13](SETTLEMENT-RESEARCH.md) (W1–W8 window parameters, residual-risk statement, acceptance checklist) — so the choice can be made against an explicit window rather than an abstraction.

**Owner selection — 2026-10-07: option 1 (stay NO-GO, continue research), route 1a (route-specific disclosure exception) first.** Recorded decision: the lifetime obligation is retained; no construction is selected; the next research deliverable is the precise per-role enumeration of fresh-J viewing/opening/signing/proving material (§9 of SETTLEMENT-RESEARCH) under the explicit rule that any sharing requires new owner permission, not covered by bilateral terms/results disclosure. Option 1b (finished-packet handoff) remains the fallback route if 1a fails its capability gate. **Owner selection update — 2026-10-07 (later wave): the owner ACCEPTED the §13 bounded-window contract (menu option 2) for route 1a, and APPROVED the §12.1 DKG session-kinds amendment.** Consequences: route 1a becomes the selected construction path with the disclosed stranded-funds residual (§13.3) as a product term; the R1.1 freeze is unlocked; R1.3 moves from investigation to freeze-prep; every R2+ qualification still applies unchanged, and the bounded window replaces the lifetime obligation for this release only. Recorded in Z2Z-V1-ROADMAP (R1), BLOCKERS and NATIVE-IMPLEMENTATION-STATUS.

**Follow-up 2026-10-07: route-1a enumeration delivered (SETTLEMENT-RESEARCH §9) and the §9.4 disclosure model accepted in principle by the owner** — per-swap grants remain mandatory, wallet keys stay owner-local, and Q1–Q9 (§9.6) define the remaining qualification surface. No implementation, GO or release follows.

## 6. What would change a family's verdict

| Verdict | Changes if |
|---|---|
| A NO-GO | independently obtainable hostile-T witnesses + authorized excess return designed and reviewed |
| B heavy | complete-interval exclusion circuit + gas/prover envelope measured acceptable; privacy composition reviewed |
| C Open | AuthenticatedNetConsideration circuit + general-T witness ownership designed; Q real-note workflow qualified |
| D/E NO-GO | fresh threshold setup audited AND branch-lock kill criterion removed (needs a consensus covenant or owner-bounded window). Partial progress recorded in [SETTLEMENT-RESEARCH §10](SETTLEMENT-RESEARCH.md) and §11.3a: in-cohort DKG + rerandomized primitives implemented (`ziquid-threshold`, tested) plus Q3 review checks and the Q4 `ShareGate` primitive, and a real PCZT spend of a threshold-keyed note authorized by the FROST aggregate (§11.3a integration transcript); audit + threshold-FVK construction remain open |
| F not-protected | deployed escrow gains source-validation + nonpayment-proof refund; re-audited |

## 7. Evidence provenance

Every family's row cites the pinned sources in [SETTLEMENT-RESEARCH.md](SETTLEMENT-RESEARCH.md) (§2 primary-evidence table, §4 alternatives, §7/§8 investigations). This document adds no new source findings; it restructures existing recorded evidence for decision-making. Retrieval date of the underlying pins: 2026-10-06 wave, recorded in SETTLEMENT-RESEARCH.
