# V1 Release Contract — one protected native-ZEC route (R1.1 freeze — DRAFT)

**Status: draft for owner review and independent review; NOT frozen, NOT a qualification, NOT a permission.** This document is the R1.1 deliverable: it binds the release contract for the route-1a construction (fresh 2-of-2 threshold joint note `J`) under the owner-accepted §13 bounded window (2026-10-07). It invents no pins: every field is `[BOUND]` (decided/recorded already), `[FILL]` (enumerated here from pinned repo facts), `[MEASURE]` (needs testnet measurement before the freeze is final), `[OWNER-CONFIRM]` (owner sub-decision with a proposed default) or `[PIN-AT-R8]` (artifact pin locked at deployment staging). Sources: [ARCHITECTURE §7.0 approved decision](ARCHITECTURE.md#approved-release-decision--2026-10-06), [SETTLEMENT-RESEARCH §8–§13](research/SETTLEMENT-RESEARCH.md), [V1-P2P-PROTOCOL-SPEC §7](V1-P2P-PROTOCOL-SPEC.md) (incl. the 2026-10-07 DKG-kinds amendment), [roadmap R1–R10](Z2Z-V1-ROADMAP.md), [BLOCKERS](BLOCKERS.md), [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md).

## 1. Parties and rights

| Role | Provides | Receives | Independent recovery right |
|---|---|---|---|
| **U** (initiator) | native shielded ZEC (testnet): funds the joint note `J` | ETH only after authentic C-final net-payment proof and actual fixed-beneficiary payout | before F, durably retain preauthorized R and every local completion artifact; after authentic J membership, complete/broadcast R while admissible; independently prove C payment and retry ETH payout if C wins (§8 kits, pending) |
| **S** | ETH: arms the target obligation | agreed net ZEC via C while admissible | before arming, durably retain reviewed finished R, explicitly granted J verification material and independently usable authentic R-return proof/transfer kit without U; final R returns ZEC to fixed U and authorizes ETH return to fixed S (§8, R4/R5 pending) |

Both are ordinary users with their own wallet/review/status/recovery. **Owner-local secrets** (existing-wallet seeds, spending/viewing keys, wallet note openings/private witnesses, and raw threshold key shares/nonce scalars) never leave owner custody. Precisely named **fresh-J auxiliary material** (J's opening plus `nk` or `FVK_J` for verification, per-spend randomizers/trapdoors/witnesses and gated signature contributions) may go only to the selected counterparty under the §9.4 **explicit per-swap grant** ([ARCHITECTURE matrix](ARCHITECTURE.md#approved-release-decision--2026-10-06)); a full `FVK_J` grant exposes every J diversifier/scope, spend detection and the §9.4 derivations, not just one note. In-principle acceptance is neither an executed nor a blanket grant. **Absent that grant, no sharing and no advancement requiring it.** Both rights must be exercisable without the counterparty and without company services (R5.3/R9.3), under the accepted window's limits.

## 2. Source contract (Zcash side)

| Item | Value | Class |
|---|---|---|
| Network | Zcash **testnet** (native shielded ZEC; no wrapped/transparent substitute) | [BOUND] working default |
| Rules era | NU6.3 (Ironwood), testnet activation height **4,134,000** | [FILL] `zcash_protocol 0.10.5` `consensus.rs` (testnet table) |
| Branch ID signed by C/R | **0x37a5165b** (`BranchId::Nu6_3`) | [FILL] same source; branch-change policy in W1 |
| Pool/bundle | **Ironwood** (ProtocolVersion V3 + ValuePool Ironwood): PCZT bundles built with `BundleVersion::ironwood_v3()` (`orchard::pczt::Bundle`); PCZT v2 wire field `ironwood: Option<orchard::v2::Bundle>`; v6 transactions carry `TransactionData::ironwood_bundle()`; cross-address transfers permitted for this pool/version | [BOUND] §9.7 pin + orchard 0.15.5 / pczt 0.9.3 / zcash_primitives 0.30.1 sources; cross-address verified in orchard `bundle.rs` |
| Cohort | orchard 0.15.5, pczt 0.9.3, frost-core / frost-rerandomized 3.0.0, reddsa 0.5.2, zcash_protocol 0.10.5, zcash_primitives 0.30.1 | [BOUND] lock pins |
| Joint note `J` | fresh per swap, created inside the session; keygen = `SpendingKey::from_bytes` over local CSPRNG with rejection retry; ZIP32/seed-derived constructors **forbidden** (API absence); session PCZTs carry `zip32_derivation = None` | [BOUND] §9.9 freeze items |
| `J` spending authority | 2-of-2 FROST group key in the `ak` slot (byte-swap surrogate; orchard#475 threshold-FVK remains a qualification gap, §10.3) | [BOUND] design; gap open |
| `R` (recovery spend J → U) | `q(R)` preauthorized by both sides early (authorization, not a finished spend while J is unmined); finished `R` assembled once membership exists; both sides back up their own `q(R)`/recovery data early and the finished `R` at step 4 | [BOUND] §8/§11.3 steps 2/4 |
| `C` (success spend J → S) | signature **shares withheld** until independently verified target arming (Q4 gate); S needs only the finished extraction to broadcast | [BOUND] §7 gate row; §11.3 steps 6–7 |
| Funding `F` | U releases funding authorization only after `R` preauthorization and durable U-local completion data; F locks U's principal into J, **not consideration delivered to S**. Consensus-enforced F retirement and a usable-child inclusion/finality margin are required by W4, still unresolved. | [BOUND] §8/§11.3 step 3; W4 freeze blocker |

## 3. Target contract (Ethereum side)

| Item | Value | Class |
|---|---|---|
| Chain | Base Sepolia | [BOUND] working default; final network/chain pin at R8 |
| Asset | native ETH | [BOUND] |
| Obligation/escrow artifact | **not yet implemented** — no native-ZEC obligation contract exists (R4). Required properties are bound here; code/artifact pins at R8 | [PIN-AT-R8] |
| Required properties | release only after independently verified source protection; once-only reservation across versions; no unilateral revocation of earned/live rights; verified actual transfers; proportional allocation preserved where partial net consideration is reachable; **no timer/generic refund** — the only refund path is the pre-signed `R` spend | [BOUND] roadmap R4/R1.1 acceptance |
| Arming | S deposits ETH into the approved obligation; **both parties independently verify irrevocable arming** (finality depth per W7) before any `C` material is released | [BOUND] §11.3 step 5–6; W7 open |

## 4. Quote, receiver authority, funding payer

- **Authenticated quote** (R6.1, implementation pending): exact terms, pair/direction, amounts, fee rules, source payout address of S, target payout address of U, deployment/context digests, quote identity and expiry; bound to both peers' authenticated session identities; tampering/replay/wrong-peer/competing acceptance rejected.
- **Receiver authority**: the ETH payout address is bound **byte-identical** in the authenticated quote and re-checked at arming-release; the quote binding is exactly what R6.1 requires (authenticated selected peers, byte-identical terms, tamper/replay/wrong-peer/competing-acceptance rejection). [DESIGN] no separate "consent signature" artifact is assumed beyond the authenticated session/quote binding; [OWNER-CONFIRM] if a stronger proof-of-address-control is wanted.
- **Target-leg arming authority**: only the identity/context authorized in the accepted quote for that quote may arm the obligation, and the `R`-triggered ETH return is fixed to the authorized refund beneficiary — the exact authorization artifact is target-side R4 work [PIN-AT-R8]. Peer identity is never equated with funding authority: the payer is separately identified in the quote.
- **Funding payer ≠ receiver is explicit**: U funds ZEC; S funds/arms ETH; neither can redirect the other's leg. The quote is neither backing nor spend authorization.

## 5. Amounts, fees, caps, net receipts

- V1 scope: **whole-quote full fills only** (one pair, both online at agreement).
- Symbol table for the retained arithmetic: `D` = agreed ETH amount; `A` = agreed **net ZEC consideration delivered to S** (zatoshis), not J principal or a fee-inclusive display; `C_net` = authentic independently verified **net consideration delivered to S**, not J funding or gross decrypted credit. `U_ETH = floor(D * C_net / A)`, `S_ETH = D - U_ETH` for `0 <= C_net <= A`; full `C_net = A` gives U all `D`. `J_value` separately names the authenticated funded note value; funding J alone is not payment. Names distinguish `C_net` from the `C` spend transaction. Source: ARCHITECTURE §7.0 arithmetic.
- Hostile partial/mixed-input/replacement/overpayment cases must be **handled from authentic independently obtainable facts or proven unreachable by protocol/consensus enforcement** — never UI/UI-policy [BOUND] (R2.3 acceptance); excess requires actual authorized return (Q9 open).
- Distinct source fees: `fee_F` is F's funding-transaction fee, separate from `J_value`; `fee_C` and `fee_R` are each bound into that spend's exact effects and checked separately against W3. Freeze binds `J_value`, exact S net receipt `A` in C, exact U net return in R, and every other output/fee — never one undifferentiated source-fee amount. W3 is [MEASURE]+[OWNER-CONFIRM].
- Caps: [OWNER-CONFIRM] proposed default — no protocol-level min/max in V1 beyond testnet dust reality; the UI shows exact amounts.
- Net receipts: exact byte-identical amounts in C/R outputs and the target obligation; **no min/max clamping, no silent amendment** [BOUND]: the packet-expiry agreement rule "reject zero, any mismatch with locally selected expiry, or any later changed expiry; do not choose min/max, silently amend it or re-sign" ([V1-P2P-PROTOCOL-SPEC §7.2](V1-P2P-PROTOCOL-SPEC.md)) plus ARCHITECTURE §7.0's "`C>A` is rejected by the arithmetic, not clamped/gifted/refunded".
- Source-side fee bearers: [OWNER-CONFIRM] — separately state the bearer of `fee_F`, `fee_C` and `fee_R` in the quote. Proposed default: U pays `fee_F` separately and funds sufficient `J_value` for exact S net receipt `A` plus `fee_C`; R returns its exact non-fee value to fixed U under the agreed `fee_R`. This is not a decided output/fee envelope (W3/W6 remain open).
- Target-gas bearers: [OWNER-CONFIRM] proposed default — S pays arming gas; U pays its own payout/retry gas; S needs independently funded R-return/retry gas. Exact bearers/caps/sponsorship, including failed attempts, remain undecided; no deduction from fixed beneficiaries' principal is implied.

## 6. Binding release order and states (unsigned quote → transfer → recovery)

| # | State | Actor | Verification before advancing |
|---|---|---|---|
| 1 | Unsigned quote (negotiating) | U+S | both peers authenticated (session pins); terms byte-identical; expiry agreed; explicit per-swap fresh-J material grant recorded before any sharing |
| 1b | **J keygen (2-of-2 DKG over the session)** | U+S | kinds 10–12 ceremony: DKG only after the transcript-confirmation gate (the initiator's first established message is the Ack carrying `SHA256(signed bytes)` of the signed Hello response); both sides must observe the **same kind-12 `SHA256(PublicKeyPackage)` digest** and the pool pin + J parameters must be frozen before DKGRound1 (§12.1 rules 1/5/6); no dealer; each side keeps only its own share |
| 2 | `R` preauthorized | U+S | both sign `q(R)`; each side durably backs up its own authorization/context and required recovery data; before F, U retains every local R completion artifact and its independent C-payment/ETH-payout kit. No finished R exists while J is unmined; required R4/R5 kits remain unqualified |
| 3 | `J` funded (F released) | U | only after step 2 and a qualified W4 consensus-enforced F lifetime/retirement plus remaining usable-child margin; F locks U principal under the R capability, not payment to S |
| 4 | `J` membership verified; finished `R` assembled and backed up on both sides | U+S | authentic same-J funding/membership/history checked using granted verification material; U completes R; S verifies exact effects/admissibility and durably backs up finished R plus its independently usable authentic R-return proof/transfer kit |
| 5 | ETH armed | S | **immediately before deposit**, independently revalidate current same-J membership/unspent eligibility, accepted history/finality, R's branch/anchor/expiry/fee admissibility and W4/W5 remaining inclusion/finality margin; verify S's durable independent return kit remains usable without U/company services. Unknown/stale facts or insufficient margin prevent arming; then deposit into the approved obligation, not a source-side payment |
| 6 | **Arming verified (both)** | U+S | independently finality-checked target observation (W7); verify exact immutable context/beneficiaries and durable eligible proof/transfer/retry kits before releasing any usable C contribution; **only then** the Q4 gate releases C share material |
| 7 | `C` completed/broadcast | U (S may broadcast finished C) | shares aggregated; broadcast ≠ inclusion ≠ transfer |
| 8 | ETH payout executed | target obligation | payout only from independently verified authentic C-final net-payment protection (R4 capability); C winning preserves U's entitlement despite R submission, U absence, delay or failed proof/transfer; exact retry remains eligible |
| 9 | **Completed** | both observe | actual final effects on both chains match the quote; submission alone is not terminal |
| alt | **Refunded** | via R | only authentic accepted/final **winning R plus exact return effects** can authorize actual ETH return to fixed S; ZEC returns to fixed U. R broadcast/order alone, C expiry or U absence never authorize opposite allocation |
| alt | **Unknown** | — | nonterminal: never treated as failure, never unlocks by time or missing scan; reconciliation per S5 rules |

`T != P` never alone proves nonpayment; Unknown/unobserved history never refunds; local timers are never refund authority (R1.1 acceptance, [BLOCKERS S1–S7](BLOCKERS.md#4-native-cross-chain-protocol-gates-s1s7)).

## 7. Window parameters (owner-accepted §13; values and sub-decisions)

| # | Parameter | Status / proposed value |
|---|---|---|
| W1 | Supported consensus branch set | [FILL] testnet 0x37a5165b (NU6.3) **only**; [OWNER-CONFIRM] proposed default: "no upgrades inside the window" — any testnet upgrade invalidates signed C/R and closes the window for in-flight swaps (disclosed). |
| W2 | Anchor validity envelope | [FILL] qualify actual selected-pool anchor-admissibility semantics and reorg behavior; [MEASURE] realistic usable envelope before any numeric lifetime is chosen. |
| W3 | Fee envelope | [MEASURE] fee/inclusion observations; [OWNER-CONFIRM] exact C/R fee envelope, separate fee amounts/bearers and signed outputs. |
| W4 | Latest safe F release/inclusion and **consensus-enforced F retirement** | [FILL] exact F/C/R consensus expiry/admissibility and definitive source-enforced F retirement (authenticated expiry or accepted conflict), **not quote/session expiry or absent-F observation**; [MEASURE] source progress/upgrade plus usable-child recovery inclusion/finality margin; [OWNER-CONFIRM] numeric cutoff. Unknown values block freeze. Withholding C shares alone cannot prevent late F from stranding U principal. |
| W5 | Mandatory recovery opportunity | [MEASURE] durations for membership acquisition → local proving → durable backup → peer verification → broadcast → accepted inclusion/finality; [OWNER-CONFIRM] accepted minimum under explicit availability/inclusion assumptions, not a promise that broadcast completes recovery. |
| W6 | Early-R cancellation rights | [OWNER-CONFIRM] proposed default: **R is held by both parties; either may broadcast it while admissible; R pays fixed U (broadcaster-independent); S-side early R is disclosed as a grief vector**; [FILL] exact R outputs/fee at freeze. |
| W7 | Source history and target finality assumptions | [FILL]+[MEASURE] separately qualify source canonicality/freshness/competing-history availability/reorg handling and Base Sepolia arming/transfer finality; not merely a guessed confirmation depth. R2.2 gaps prevent current arming verification and advancement to step 6. |
| W8 | Terminal reconciliation (window lapse) | **ACCEPTED** by owner 2026-10-07: funds may remain stranded until an admissible state exists; wording = §13.3 (verbatim into the product disclosure surface, R7 item 3). |

Any late-F exposure left outside the accepted enumerated terms remains an unresolved owner decision, **not a new waiver granted by this draft**; measured margins alone do not enforce transaction inclusion.

**Residual-risk disclosure (verbatim binding text, §13.3):** “If, after F finalizes, no admissible C or R is completed and broadcast before the window's parameters (W1–W5) lapse — e.g. a consensus-branch change, fee-band drift beyond W3, or the actors failing to complete the recovery opportunity W5 — the joint note J may remain unspent with no unilateral path to recover it under the current capability set, and armed ETH stays liable for the duration. This risk is accepted, bounded, and disclosed, not eliminated: no timer, refund rule or automation can enforce recovery that the signed capabilities do not provide.”

**Clarification (additive; the accepted quotation above is unchanged):** broadcast does not discharge this exposure. A C/R broadcast before lapse may remain unmined, be reorged out or lack accepted finality when branch/anchor/expiry/fee conditions cease to be usable; J can then remain unspent with no unilateral renewal, and armed ETH remains liable. W4/W5 must budget accepted inclusion/finality, not only packet completion or submission; accepted/final source effects still require the independently usable target proof and actual fixed-beneficiary transfer.

## 8. Recovery, continuity and disclosure

- **U-alone**: durably holds `FVK_J`, opening, witness, proving artifacts and both `q(R)` plus matching transcript/completion material — completes and broadcasts R while admissible; retains independent authentic C-inclusion/net-payment proof and ETH-payout/retry capability if C wins. This required kit remains R4/R5 work, not evidence of delivery.
- **S-alone**: durably holds its own raw share, exact public signing/context data and the per-swap-granted **J opening plus `nk` or `FVK_J`** needed to authenticate J funding and same-J C/R consumption; independently available source history/effects evidence; reviewed finished R; and **independently usable authentic R-inclusion/return-effect proof inputs, original prover/verifier tools, target-obligation/fixed-beneficiary context, reconciliation records and ETH-return/transfer/retry capability without U**, including independent chain access and gas. S broadcasts retained R while admissible; no re-proving is implied without the separately granted complete §9.3 prover set. Public chain data/finished raw transaction bytes do **not** reveal missing hidden note/nullifier/return relations or supply target witnesses ([§9.8](research/SETTLEMENT-RESEARCH.md)); these bundles remain unqualified R4/R5 requirements.
- **Company-off**: standalone path (R5.2 bundles, R5.3 drills, R9.3 funded drills) — pending, but the contract requires it.
- **Disclosure**: bilateral + public-ETH-leg matrix per ARCHITECTURE, with mandatory per-swap fresh-J grants; the unchanged §13.3 statement **and additive broadcast/inclusion clarification** are shown at Review and Recovery (R7 item 3).

## 9. R1.1 acceptance mapping (draft self-check)

| Acceptance clause | Draft requirement mapping (not observed satisfaction) |
|---|---|
| Reviewed states cover unsigned quote through actual transfer and independent recovery | §6 state table + §8 recovery; reviewed acceptance and both-role exercised recovery remain pending |
| Payment release follows verified protection | F (§6 step 3) locks U principal under preauthorized R and the unresolved W4/W5 envelope; it does not pay S. Only C consideration authorization follows independently verified irrevocable ETH arming (steps 5→6→7); ETH payout additionally requires authentic C-final net-payment protection (step 8). This conditional order is not yet a qualified construction. |
| Unknown remains nonterminal | §6 alt rows; S5 rules |
| Any refund condition is consensus-enforced and proven safe | §6: the only refund is the pre-signed admissible `R` spend — **not a timer** (that half is satisfied). **Conditional, not yet proven safe**: W6 early-R rights/terms remain [OWNER-CONFIRM] + the §8 S-side cancellation/fee rights review is not recorded + the ETH-return leg is target mechanics (R4 pending). Freeze blockers. |

**Freeze blockers before this draft becomes final**: W2–W5 source qualifications/measurements (including F consensus retirement and usable-child inclusion/finality margin); W1/W3/W4/W5/W6 owner confirmations; distinct F/C/R source-fee and target-gas-bearer confirmations, min/max caps (§5); R6 quote/receiver/arming-authority/refund-beneficiary bindings and any stronger ETH-address-control decision (implementation pending); separately qualified R2.2 source history and target finality assumptions (W7); target artifact existence (R4, [PIN-AT-R8]); per-swap grants and both-role durable independent proof/transfer kits/cold drills (R5); §13.5 in-window branch dry runs; Q1 DKG cryptographic/cohort audit and durable J custody/real-transaction signing integration, Q3/Q4 composition review (§11.3a), and pool/J pins recorded before DKGRound1. **Selected-peer real-session DKG driver is implemented and exercised**, per [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md#selected-peer-dkg-network-ceremony--exercised-implementation); it destroys ephemeral shares after digest agreement and supplies no financial custody/signing authority. The older §12.2 driver-absent checkpoint is superseded, not a current blocker.

## 10. Non-claims

This draft does not select, qualify or approve anything beyond the recorded owner decisions: audit of the frost/reddsa cohort, the threshold-FVK construction, real-sighash plumbing, composed financial proofs (N1–N3), target-side arming verification/obligation, R2.2 history/finality and R5 recovery bundles all remain open. No deployment, signing, funding, money movement or mainnet action follows from this document.