# Kerb — documentation authority and retained proposed contract

**Current authority update: 2026-10-01.** Shared-library reuse is adopted as a **documentation direction only** (§0). The retained public-Solana financial contract (§§1–6) remains **PROPOSED — owner review required; design only, unimplemented, unbenchmarked**. Its editorial consistency rule applies within that historical dossier, not across newer private/cross-chain proposals. Neither it nor the Oct1 candidate is approved, audited or implemented by this update.

Historical date of record: 2026-09-28. Evidence in §§1–6 was retrieved 2026-09-26 → 2026-09-28 and must be re-checked before external use; its facts and proposed economics are retained, not rewritten as current runtime evidence.

## 0. Current documentation authority

**Adopted docs-only decision (2026-10-01):** use Zoss as a shared native cross-chain **library core**, with its separately optional non-money messaging profile/runtime. Common source acquisition/parse/decrypt, explicit context/domain/canonical authorization bytes and Solana off-chain submission/observation plumbing run in **Kerb-controlled processes**. No installed dependency, compiled module, source/target support, build scaffold or SDK operation is claimed. [Zoss architecture](../../../../../zoss/docs/ARCHITECTURE.md), [implementation/package map](../../../../../zoss/docs/ARCHITECTURE.md#41-implementation-map) and [Kerb consumer contract](../../../../../zoss/docs/kerb.md) own these contracts. The proposed native `protocol` / `zcash` / `chains` / `runtime` packages and independent target-safe Solana message build are a Zoss responsibility map, not new Kerb services; actual packaging remains Proposed and SDK is deferred until real operations require it.

**Kerb owns financial authority:** a `SourceObservation` is parsed/decrypted evidence, not funding ownership, source validity or accepted history. Kerb must independently bind claimant authorization, exact network/pool/receiver/occurrence and canonical context, controlled unallocated spendable inventory and durable credit issuance/dedup before assigning any credit. FAA/eligibility, holds and entitlement journals, MPC certificates/circuit/results, per-pair schemas, FROST signing, payout/refund, finality, incident/recovery and app state stay Kerb-owned. A `QuorumAcceptedMessage` is optional message-policy acceptance; it is neither that funding claim nor Ziquid's app-owned `VerifiedSettlementFact`. Direct app proof paths need no receipt, proof-to-quorum conversion or universal `verified` boolean. Common authorization code must keep ordinary wallet/Solana Ed25519, vendor Arcis SHA3-512 certificate signatures and native FROST spends explicitly distinct.

**Private state and operational scope:** library reuse adds no mandatory key/viewing party, shared IVK/FVK store, scanner daemon, cross-app private cache, witness store or log. Kerb scanner/viewing capabilities remain with Kerb's designated custody/view domains, separated from matcher and spending keys. Optional Zoss watchers/receipts/quorum/runtime are not library prerequisites or monetary authorities. The diagnostic profile remains **OFF / non-money**; enabling it would need separate viewing/access/privacy/runtime evidence and authorization. Message callback consumption/rollback can permit the **same immutable still-valid receipt** to retry only at the destination; it supplies no cross-chain atomicity, financial refund or recovery guarantee.

**Separate replay and lifetime:** Zoss's one-source-occurrence → one-receipt namespace across routes/profiles/consumers/deployments is explicitly **unresolved**; do not reinterpret it as either per-route or global financial uniqueness. Kerb credit issuance, accepted-order holds, entitlement portions/native intents and Solana monetary transition replay remain separate durable app ledgers. A message epoch/key/revocation or SDK upgrade cannot erase consumed app identities or invalidate an already-funded obligation's witness/evidence/recovery path. [Zoss BLOCKERS](../../../../../zoss/docs/BLOCKERS.md) is the **sole** core gate register, including its shared-library readiness section; no core gate definitions/status tables are copied into Kerb. Documentation adoption closes none of those gates.

**Unapproved and historical documents:** the [Oct1 production-demo candidate](docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md) and [review](docs/superpowers/specs/2026-10-01-kerb-design-review.md) remain financial/private proposals. Public epoch-bound seller membership plus permitted singleton/attacker-own-fill probing is a known **GD2 structural FAIL**, not a successful privacy assumption; shared libraries/opaque receipts do not fix it, approve FAA/MPC/custody selections or authorize a privacy waiver. The [Sep29 spec](docs/superpowers/specs/2026-09-29-kerb-zolana-design.md), [Sep29 review copy](../zolana-review-2026-09-29/README.md), [Sep30 research](../zolana-research-2026-09-30/README.md) and public-Solana contract below are retained history/evidence, not current overall transport-only Zoss authority. No legacy removal, financial cutover, code, dependency change, deployment, signing, funding, publication or push is authorized.

**Product extension — recorded documentation scope, 2026-10-02:** [Hyperliquid expansion](product/17-HYPERLIQUID-EXPANSION.md) records the owner's request for both (A) P2P markets involving eligible Hyperliquid assets and (B) user-authorized external HyperCore spot execution from Kerb. HyperEVM and HyperCore are different execution surfaces of Hyperliquid, not two independently added chains. Asset examples are unqualified candidates, not supported listings. This adds a product direction, not implementation approval or a replacement for the original Solana↔Ironwood scope; the Oct1 candidate remains a narrower dated proposal. Strict privacy/GD2, custody, canonical funding and no-double-use requirements are unchanged. No perps, automatic fallback, live keys/transactions or self-service proof implementation is authorized by this update.

## 1. Identity

| Item | Value |
|---|---|
| Name | **Kerb** |
| Origin | "Kerb trading": the London Metal Exchange's historical off-floor session. Kerb crosses orders when the primary equity market is not the only place to trade. |
| One-liner (≤ 5 words, verb + object) | **Cross tokenized-stock orders directly.** |
| Long one-liner | Kerb matches buyers and sellers of the same tokenized stock before either pays a dealer. |
| Category | DeFi market primitive: periodic, same-mint call auction for tokenized stocks with an optional pre-funded residual maker phase. |
| Primary chain / track | Solana (Colosseum Crypto World's Fair, Solana track). |
| Source idea | Superteam Vietnam Idea Bank row #5 "Dark Pool (spot tokenized stocks)", T2 – Verify first. Kerb deliberately narrows it: **no privacy, TEE, BAM or dark-pool claim in V1.** See [`sources/notion/idea-bank-row-5.md`](sources/notion/idea-bank-row-5.md). |

Trademark, domain, X handle and Colosseum project-name availability: **NOT CHECKED.**

## 2. The problem in one paragraph

Tokenized stocks trade 24/7 on-chain, but most executable liquidity comes from dealers
(RFQ makers, prop AMMs, AMM LPs) whose ability to hedge depends on the underlying equity
market. When that market is closed or thin, dealers widen spreads. A buyer and a seller of
the same token in the same minute each pay a dealer spread, even though they could have
traded with each other. Kerb gives those two orders a place to meet first.

This is a **hypothesis about cost**, not a measured fact. The size of the saving versus
live routes (JupiterZ, AMMs, issuer xChange during its hours) has **not been measured**.

## 3. Proposed mechanism contract (V1)

### 3.1 Units
- Each market is bound to exactly one base mint address, one quote mint (USDC) and **the
  token program id of each leg, recorded separately** (`base_token_program`,
  `quote_token_program`). The base leg is expected to be Token-2022; the quote leg is
  whatever program owns the qualified quote mint. Neither is assumed. A ticker string is
  never an identifier.
- Quantity is expressed in **lots**; `base_lot_raw` = raw base atoms per lot (Token-2022
  raw amount, never the Scaled UI Amount display value).
- Price is expressed in **ticks**; `tick_quote` = quote atoms per lot per tick.
- Quote owed for `q` lots at `p` ticks = `q · p · tick_quote` (u128 checked arithmetic).
- Because settlement uses raw amounts, the economic meaning of a price changes when the
  issuer multiplier changes. Therefore **no epoch may be open across a scheduled multiplier
  activation** (see 3.7).

### 3.2 Orders
A user order binds: `market`, `epoch`, `side` (Bid|Ask), `qty_lots`, `limit_ticks`,
`allow_residual: bool`, `owner`, `nonce`, `distributor` (nullable referrer).
The order is **fully pre-funded** at placement:
- Bid escrows `qty_lots · limit_ticks · tick_quote + max_fee` quote atoms.
- Ask escrows `qty_lots · base_lot_raw` raw base atoms.
No minimum-fill, no hidden/iceberg size, no amendment. Cancellation is allowed only while
the epoch is Open.

### 3.3 Primary clearing (user orders only; oracle-free)
Computed **by the program**, never chosen by a crank or solver.

1. Let `L_min` and `L_max` be the smallest and largest limit tick among live orders (both
   sides). The domain is every integer tick `p ∈ [L_min, L_max]`. `D(p)` = Σ qty of bids
   with `limit ≥ p`; `S(p)` = Σ qty of asks with `limit ≤ p`.
2. `V(p) = min(D(p), S(p))`; `V* = max_p V(p)`. If there are no bids, no asks, or
   `V* = 0`, there is no cross and `p_lo`, `p_hi`, `p*` are absent.
3. If `V* > 0`: `p_lo` = smallest tick with `V(p) = V*`; `p_hi` = largest tick with
   `V(p) = V*`. Proved in [`mechanism/01-MECHANISM-SPEC.md`](mechanism/01-MECHANISM-SPEC.md)
   §2.1: the maximizing set is exactly the contiguous integer interval `[p_lo, p_hi]`
   (`D` nonincreasing, `S` nondecreasing); `p_lo` is a submitted **ask** limit and `p_hi` a
   submitted **bid** limit.
4. **Clearing price** `p* = round_half_even((p_lo + p_hi) / 2)` in tick units: with
   `s = p_lo + p_hi`, `p* = s/2` if `s` is even; otherwise `p*` is the even one of
   `floor(s/2)` and `floor(s/2)+1`. In every case `p_lo ≤ p* ≤ p_hi`, so `V(p*) = V*`.
   No external price feed participates in `p*`. This removes oracle staleness and
   manipulation as a surplus-redistribution vector. Rounding moves `p*` by at most ½ tick
   from the plateau midpoint.
5. Every bid with `limit ≥ p*` and every ask with `limit ≤ p*` is eligible. Exactly `V*`
   lots trade at `p*`. The side with eligible quantity equal to `V*` fills completely.
6. The rationed side fills by **price priority** (bids: higher limit first; asks: lower
   limit first). At the marginal limit level, quantity is allocated **pro-rata** by
   `qty_lots`, floored to whole lots; leftover lots go one at a time in ascending
   `(placed_slot, nonce, owner)` order.
7. Proof obligation: every filled order's limit is satisfied at `p*`; the allocation is a
   pure function of the order set; submitting the same order set in any order yields the
   same result.

Implementation note (compute): the program never scans every tick. It sorts orders (or
verifies a crank-supplied sorted permutation) and sweeps the distinct submitted limits,
which suffices because `p_lo` and `p_hi` are submitted limits: `O(n log n)` with an
in-program sort, `O(n)` after verifying a hint. It never trusts the crank's result; a
wrong hint makes clearing fail, not mis-price.

### 3.4 Residual phase (separate; cannot change primary outcome)
- Residual makers post **signed, fully funded quote ladders** for a specific
  `(market, epoch)` while the epoch is Open. A ladder is up to `K` levels of
  `(price_ticks, qty_lots)` per side (bounds in §3.6 are provisional). Funding is escrowed
  at posting. Makers may cancel only while Open. There is no last look after close.
- After primary clearing is stored, only the **unfilled remainder** of orders with
  `allow_residual = true` is eligible.
- Residual matching never alters `V*`, `p*` or any primary fill. It runs strictly after.
- A residual fill executes at the **maker's level price** (discriminatory) and only if that
  price satisfies the user's limit. User priority: best limit first, then
  `(placed_slot, nonce, owner)`. Maker levels consumed best-price first; across makers at the
  same price, the marginal-lot rule of §3.3 step 6 applies (proportional to remaining level
  quantity, floored, leftover lots by `(posted_slot, maker)`).
- Disclosure: a residual fill price can differ from `p*`. The UI and receipt label each fill
  `CROSS` or `RESIDUAL`.

### 3.5 Fees (proposal to test, not market-validated)
- `fee_bps_per_side = 5` on user notional for CROSS and RESIDUAL fills. Makers pay 0.
- Split of collected fees: protocol 6/10, distributor rebate 3/10 (to the order's
  `distributor`, else protocol), settlement crank 1/10.
- Rounding: each user order pays one fee on its **aggregate** filled notional `N` (CROSS +
  RESIDUAL): `fee = ceil(fee_bps · N / 10_000)`. Buyer pays `N + fee`; seller receives
  `N − fee`. Bid escrow reserves `max_fee = ceil(fee_bps · qty·limit·tick_quote / 10_000)`,
  which always covers `fee` because every fill price ≤ limit. See §3.6 for split dust.
- Revenue accounting: a CROSS lot has two charged user sides (≈ 10 bps of CROSS notional);
  a RESIDUAL lot has one charged user side and a zero-fee maker (≈ 5 bps of RESIDUAL
  notional). No model may apply 10 bps to residual volume.
- The schedule is a hypothesis. Charging 5 bps on residual fills plus a distributor rebate
  on them can make residual routing worse for the user than trading the same maker
  directly. Alternatives (lower residual fee, no rebate on residual) are listed as options
  in [`product/16-ROADMAP-AND-DECISIONS.md`](product/16-ROADMAP-AND-DECISIONS.md) ADR-009;
  this contract changes only when that ADR is decided.
- No token, no liquidity mining, no points in V1.

### 3.6 Epoch lifecycle and liveness
`Open → Closed → Cleared → (per-leg Settled) → Finalized`, plus `RefundOnly`, the
per-leg state `Impaired`, and the advisory per-leg marker `SettlementBlocked`.
- `close_ts = open_ts + epoch_len_s` (V1 default 60 s). Anyone may call `close` after it.
- Anyone may call `clear` after `Closed`; `settle_order` / `settle_maker` only after
  `Cleared`; `refund` only in `RefundOnly` (never after `Cleared`, whose entitlements are
  immutable). Each call is idempotent, pays at most one recipient leg per instruction and
  is bounded per transaction; settlement of an epoch is split across many transactions.
- **Vault isolation.** Every epoch has its own PDA-owned base and quote vaults. No vault is
  shared across epochs or markets, so an impairment is confined to one epoch.
- **Liveness is conditional.** Settlement and refund are permissionless: no admin action is
  needed to *trigger* them. They complete only while the token programs and the issuer
  permit the transfer. A frozen vault, a paused mint or an `Impaired` leg can leave funds
  stuck indefinitely or unrecoverable. Kerb cannot force a transfer the issuer blocks; this
  is issuer risk and must be disclosed wherever liveness is described.
- **Before `Cleared`:** if the epoch is not cleared by `clear_deadline_ts`, or a guard in
  §3.7 fails, it becomes `RefundOnly`: every owner (or anyone on their behalf) may claim a
  refund of their original deposit, subject to the conditional liveness above.
  *Exception:* a vault shortfall on a leg (§3.7) makes that leg `Impaired`. Each escrow
  owner on an impaired pre-clear leg keeps a **nominal claim equal to the original
  deposit**, but no payout is made from that leg and the claim **may never be
  recoverable**. V1 defines no recovery path; recovery is an open question (§3.9).
- **After `Cleared`, the result is final and never reverts to `RefundOnly`.** `clear`
  converts every order and maker ladder into a fixed entitlement ledger (base atoms, quote
  atoms, fee). At clear, per leg, entitlements plus fee obligations equal the recorded
  funded balance of that leg (unsolicited surplus excluded, §3.9). Each `settle_*` pays
  out one entitlement from the vault. Absent an issuer-caused shortfall (§3.7), settling any
  subset never makes another holder's entitlement unpayable.
- **SettlementBlocked (advisory, non-sticky).** A failed Solana instruction rolls back all
  its writes, and no caller can attest why a CPI failed. Therefore:
  - There is no `mark_settlement_blocked` instruction.
  - `settle_*` / `refund` first run a **deterministic preflight** that reads only on-chain
    state of the accounts fixed by the entitlement: the leg's epoch vault, the mint, and
    the recipient's canonical token account for that mint and token program. Checked
    conditions: vault frozen, recipient account frozen, mint paused, recipient canonical
    account missing/closed. A mint fingerprint change is **not** a settlement or refund
    preflight condition: it is checked only at `close`/`clear` and at `open_epoch`
    (§3.7). Blocking an already-fixed claim on it would have no on-chain exit.
  - The caller cannot choose the recipient account. Passing any other destination, wrong
    mint or wrong program is a hard error that reverts; it never records a block.
  - If a preflight condition holds, the instruction succeeds without transfer, emits
    `SettlementBlocked(reason, leg, slot)` and stores the latest reason. The entitlement is
    unchanged and remains `Unpaid`.
  - The marker never gates anything. Every later `settle_*` call re-runs the preflight;
    **exit condition:** the first call whose preflight passes and whose transfer succeeds
    marks the leg `Settled`. A missing recipient account can be recreated permissionlessly
    (canonical associated token account) before retrying. Marking a leg blocked therefore
    gives a griefer nothing: it cannot delay a leg whose preflight would pass.
  - An unexpected CPI error after a passing preflight reverts the transaction; the
    entitlement stays untouched and retryable, and the crank/indexer surfaces it as an
    **off-chain incident**, not an on-chain state.
- Fee rounding: one fee per user order on aggregate CROSS + RESIDUAL notional (§3.5); the
  protocol/distributor/crank split uses `floor` for each share and the remainder stays in
  the fee vault as dust (emitted as an event).
- **Compute bounds are provisional, not measured.** Scale targets: `max_orders_per_epoch`
  64 and `max_maker_levels` 8 per side × 4 makers. They are pending LiteSVM/SBF
  compute-unit and transaction-size benchmarks. **Hackathon MVP bounds:** ≤ 8 user orders
  per epoch, 1 maker, 1 level per side. Scale is by more markets and shorter epochs before
  larger epochs.

### 3.7 Issuer-aware guards (the wedge)
- Market creation snapshots a hash of the mint's extension set and authorities
  (mint, freeze, permanent delegate, transfer-hook program, pause authority, scaled-UI
  update authority). The hash is re-checked at `close`, `clear` and `open_epoch`. A
  mismatch **before `Cleared`** sends the epoch to `RefundOnly`; `refund` then proceeds
  subject only to the §3.6 preflight. A mismatch after `Cleared` does not undo the result,
  does not block `settle_*` (which still runs the §3.6 preflight), and blocks opening
  further epochs on that market until it is requalified.
- **Transfer hooks are refused in V1.** Market creation fails for any base or quote mint
  carrying a `TransferHook` extension, whether or not a hook program is currently set. A
  set hook authority can repoint the hook, and a pinned hook program can itself be
  upgraded, so a hook reviewed at creation could run unreviewed code inside a later payout
  CPI; a reverting CPI is not a safety boundary against a hook that succeeds. Token-2022
  extensions are fixed when the mint is initialized, so a mint without `TransferHook`
  cannot gain one after clear [INFERENCE from Token-2022 extension initialization rules;
  re-verify against the exact token-program version at qualification]. Any hook support
  is a future reviewed amendment, blocked until audited.
- Scaled UI Amount: if `new_multiplier_effective_timestamp` falls inside
  `[open_ts − guard, clear_deadline_ts + guard]`, `open_epoch` is refused; an epoch that
  becomes affected before `Cleared` goes `RefundOnly`.
- Pausable / frozen vault / frozen owner account before `Cleared`: `RefundOnly` where the
  token program permits withdrawal. Where the issuer freezes the vault itself, funds are
  held by issuer action in any state, possibly indefinitely. **This is an issuer risk Kerb
  cannot remove and must disclose.**
- **Permanent delegate / issuer-caused shortfall.** A permanent delegate can move or burn
  vault tokens at any moment, including between a guard check and a transfer, without
  changing the extension hash. **V1 refuses at market creation any mint with a permanent
  delegate set.** If a reviewed exception is ever allowed, it is a release blocker until
  audited and counsel-reviewed.
- **Shortfall is insolvency, not redistribution.** Every guard and settle checks
  `vault_balance ≥ outstanding_entitlements` for the leg it touches. On failure that leg
  becomes `Impaired`: all payouts from that leg stop, nominal claims (post-clear
  entitlements, or pre-clear original deposits) are **not** reduced, reweighted or
  socialized, and a `VaultShortfall` event records the uncovered amount. The unaffected
  leg keeps settling. Kerb defines no restitution, no redistribution of remaining funds
  and no recovery mechanism; impaired claims may never be recoverable (§3.9).
- Equity trading halts are only observable off-chain in V1. The crank does not open epochs
  while a halt is reported, and users can cancel. There is **no on-chain halt oracle
  claim.** Full halt policy is open (§3.9).
- Extensions not on the reviewed allowlist (e.g. any transfer hook, confidential
  transfer with non-zero confidential balances required) cause market creation to fail.
- **Production eligibility is BLOCKED.** No exact mainnet xStock (or other issuer) mint has
  been checked against this allowlist. Launch requires one exact mint that passes every rule
  above, or an approved amendment to this contract. Until then every demo uses test mints
  labelled **SYNTHETIC**, and no document may imply that a named xStock is eligible.

### 3.8 Governance
- Upgrade authority: multisig with timelock. Admin can pause **new** orders and add markets.
  Admin cannot move vault funds, change a stored clearing result, or block refunds.
- Settlement core is a candidate for upgrade freeze after audit.

### 3.9 Open policies (listed, not decided)
- **Impaired-leg recovery.** Whether and how an impaired leg (pre- or post-clear) could
  ever be made whole. V1 has no path; none may be implied.
- **Unsolicited vault deposits.** A surplus above recorded liabilities is quarantined:
  neither a fee nor a claim. Who, if anyone, may sweep it, when, and to where is undecided.
- **Settlement-crank fee attribution.** Which caller earns the crank 1/10 (the `clear`
  caller, each `settle_*` caller, or a split) and how a claim is recorded is undecided.
- **Halt handling.** Halts are off-chain only. Which halt sources count, whether an open
  epoch is closed early or left to clear, and how users are notified are undecided.

## 4. Evidence register (dated, with status)

Legend: **P** primary/first-party doc, **S** secondary, **I** inference, **U** unverified.

| # | Claim | Status | Source |
|---|---|---|---|
| E1 | JupiterZ v2 streams maker orderbooks over gRPC, with last look, settling via Jupiter Order Engine; credentials are team-issued. | P | https://jupiterz.jup.ag/docs/v2 |
| E2 | xStocks xChange is atomic issuer issuance/redemption for **onboarded clients**, ~60 s quote window, spread varies market/extended hours; not holder-to-holder secondary trading. | P | https://docs.xstocks.fi/docs/issuance-and-redemption/atomic-rfq-xchange.md |
| E3 | xChange operates 24/5, liquidity deepest in US regular hours, unavailable weekends; makers co-sign issuer transaction and bundle with user fill via Jito. | P | https://docs.xstocks.fi/developers/xchange-solana-market-maker-guide.md |
| E4 | xStocks are tracker certificates (bearer debt), no shareholder voting rights; not offered to US persons. | P | https://docs.xstocks.fi/docs/product-legal-overview |
| E5 | On Solana xStocks use Token-2022 Scaled UI Amount; raw balance constant, multiplier activates 00:30 UTC day after ex-date; venues advised to pause around activation. | P | https://docs.xstocks.fi/docs/dividends-and-stock-splits.md |
| E6 | BAM Maker Priority Plugin schedules statically enrolled maker price-update txs at batch head (~50 ms); maker updates are visible to non-makers as committed state. It is sequencing, not confidentiality. | P | https://bam.dev/docs/bam/maker-plugin/how-it-works/ |
| E7 | Archer Exchange (Colosseum Cypherpunk Sep 2025, 4th DeFi, accelerator C4) started from dual-flow batch auctions; now runs a CLOB public beta. | P/S | Colosseum Copilot `archer-exchange`; https://solanafloor.com/news/archer-exchange-launches-clob-public-beta-amidst-prop-amm-spoofing-concerns |
| E8 | Blackpool / Darklake (Radar Sep 2024, 2nd DeFi, accelerator C2): private MEV-resistant trading with ZK. | P | Colosseum Copilot `blackpool` |
| E9 | Urani (Renaissance Mar 2024, 1st DeFi & Payments): intent-based aggregator with MEV protection. | P | Colosseum Copilot `urani` |
| E10 | Renegade (dark pool) is live on Arbitrum/Base; CoW Protocol does coincidence-of-wants batches on EVM. | S | Research-agent reports 2026-09-28; https://docs.cow.fi/cow-protocol/concepts/how-it-works/coincidence-of-wants |
| E11 | xStocks live as HyperCore spot markets (NVDAx, SPYx, QQQx, SKHYx, MUx and more) against USDC. | P/S | https://xstocks.fi/news/xstocks-goes-live-on-hyperliquid-bringing-the-markets-deepest-tokenized-equities-framework-to-traders |
| E12 | Robinhood Chain public mainnet (Arbitrum Platform), native Stock Tokens (ERC-20). Holder eligibility and transfer rules **not verified.** | P/U | https://robinhood.com/us/en/support/articles/robinhood-chain-mainnet/ |
| E13 | Bitquery tape 2026-06-29→07-28: weekend xStock volume ≈16 % of weekday; ≈61 % of weekday volume inside NYSE hours; top-10 tickers ≈96 % of volume. Counter-evidence for off-hours depth. | S | https://bitquery.io/investigations/solana-tokenized-stocks-xstocks |
| E14 | Flow Traders (2025-07-03): maker pain = fragmented pre-funding, no unified prime credit, off-hours operational risk; "makers cannot create demand". | P (opinion) | https://flowtraders.substack.com/p/tokenization-in-capital-markets-a |
| E15 | Colosseum World's Fair: submissions due 2026-10-12 23:59 PT; Solana track $100k across 10; Robinhood Chain and Arbitrum tracks $25k across 5 each; judging on functionality, impact, novelty, UX, open source, business plan. | P | https://colosseum.com/legal/Crypto%20World's%20Fair%20Hackathon%20Rules.pdf |
| E16 | Whether one submission may compete in multiple tracks. | **U** | Ask Colosseum. |
| E17 | Same-mint opposite-side flow exists at useful size and frequency. | **U — central hypothesis** | Validation plan, `business/12-GTM-AND-VALIDATION.md`. |
| E18 | Any named buyer, seller, distributor or maker commitment. | **U — none exists** | — |

## 5. Forbidden claims (all documents, pitch, video, UI)

Retained public-Solana dossier policy; no current document may claim these unsupported outcomes either. §0 distinguishes adopted shared-library documentation from unapproved financial/private designs.

Kerb MUST NOT claim, imply or display: private or anonymous trading; dark pool (except when
citing the source idea's title); best execution; guaranteed savings; issuer partnership or
endorsement; committed maker, distributor or user; real liquidity; mainnet deployment;
audited code; BAM, TEE, MagicBlock or Arcium integration; shareholder rights for token
holders; availability to US persons; "first" or "only" anything; buzzwords
(revolutionary, democratizing, redefining, disruptive, seamless). Demo artifacts built on
test mints MUST be labelled **SYNTHETIC**.

## 6. Glossary

- **Cross**: a primary-phase fill between two user orders at `p*`.
- **Residual**: a fill between an unfilled user remainder and a funded maker quote.
- **Distributor**: a wallet/app/broker that routes its users' orders to Kerb and may earn
  a rebate.
- **Crank**: any account calling permissionless lifecycle instructions.
- **Same-mint**: identical mint address, token program and extension-set hash.
- **SourceObservation:** caller-owned parsed/decrypted source evidence; canonical validity, claimant ownership and available inventory are separate Kerb checks.
- **QuorumAcceptedMessage:** optional Zoss message-policy acceptance; not an app funding, payout or refund fact.
- **VerifiedSettlementFact:** Ziquid-owned app proof-verified financial result, not a generic Zoss output or conversion from an observation/receipt.
