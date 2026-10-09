# Kerb V1 mechanism specification

Status: **DRAFT / PROPOSED; design only, not implemented, benchmarked or market-validated**  
Owner role: **Principal market-structure engineer; call-auction/matching-engine design lens (role-play, not a credential)**  
Date: 2026-09-28  
Evidence legend: **P** primary, **S** secondary, **I** inference, **U** unverified; facts marked **U** are unverified. [INFERENCE] labels design deductions and estimates. [`../00-CANONICAL.md`](../00-CANONICAL.md) retained §§1–6 are the editorial consistency reference **within this historical public-Solana proposal**, themselves unapproved.

**Authority banner 2026-10-01:** [current shared-library documentation decision](../00-CANONICAL.md#0-current-documentation-authority) is adopted separately from this retained public-Solana mechanism and the unapproved Oct1 financial/private candidate. Kerb still owns matching/funding/economics/state; optional Zoss diagnosis stays OFF/non-money and **GD2 structural FAIL** is not resolved. These historical auction rules do not override newer owner constraints or approve a financial cutover.

## 1. Domain and integer representation

A market is `(base_mint, base_token_program, quote_mint=qualified USDC mint, quote_token_program, base_lot_raw, tick_quote)`. The two token programs are independent; a ticker or display amount cannot identify an instrument. The order set for one epoch is bounded by `max_orders_per_epoch`: **provisional** scale target 64, hackathon MVP ≤ 8, neither measured (canonical §3.6). All prices are positive integer ticks, all quantities positive integer lots, and every multiplication/addition uses checked `u128` intermediates before checked conversion to token-transfer `u64`. For `q` lots at `p` ticks:

```
base_atoms(q) = q * base_lot_raw
notional(q,p) = q * p * tick_quote                     // quote atoms, exact integer
fee(N) = ceil(5*N/10_000) = (5*N + 9_999)//10_000  // quote atoms
seller_proceeds(N) = N - fee(N)                    // quote atoms; no second rounding
```

The fee is assessed **once per user order** on its aggregate executed notional across CROSS and RESIDUAL, not once per matched lot or counterparty. For a receipt separating phases, assign `fee_cross=fee(N_cross)` and `fee_residual=fee(N_cross+N_residual)-fee(N_cross)`; their sum is the order fee even when residual spans maker prices. A bid's deposit is `notional(q,limit)+fee(notional(q,limit))`; an ask deposits `base_atoms(q)`. This bid fee reserve is sufficient because each executed lot's price cannot exceed the bid limit and `fee` is monotone. A maker bid level escrows `notional(q, maker_price)` with **no** maker fee; maker ask level escrows `base_atoms(q)`. Reject any input whose upper bound cannot fit escrow, entitlement, vault, or transfer types; no silent saturation. Fees are a proposal, not a validated tariff (canonical §3.5).

At `clear`, for each order independently let `N_i=Σ(q_fill_at_price * price * tick_quote)`, counting both phases. An executed bid owes `N_i+fee(N_i)`, receives `base_atoms(filled_lots)`, and receives its unused quote deposit back. An executed ask receives `N_i-fee(N_i)` quote atoms and its unfilled raw base deposit back. Each maker receives the exact quote for filled asks or exact raw base for filled bids and its unused prefunding; makers pay no fee. Split **each order's collected integer fee** `f` into `protocol=floor(6f/10)`, `distributor=floor(3f/10)`, `crank=floor(f/10)`; any integer remainder is fee-vault dust and emitted. A null distributor redirects its already-rounded distributor share to protocol. No fees on unfilled/canceled/refunded escrow. **Which caller earns the crank share** (the `clear` caller, each `settle_*` caller, or a split) and how that claim is recorded is an open policy (canonical §3.9); this spec does not decide it. Revenue arithmetic: a CROSS lot has two charged user sides, a RESIDUAL lot one charged user side and a zero-fee maker; the residual fee and rebate are an open question (product/16 ADR-009).

## 2. User-order book and primary price

A user signs an immutable `(market, epoch, side, qty_lots, limit_ticks, allow_residual, owner, nonce, distributor)` and pre-funds in the same placement transaction. Owner/nonce is unique for an epoch; a canceled order is excluded from clearing. Orders can cancel only in `Open`, reclaiming the whole deposit. The close time is `open_ts+epoch_len_s` (default 60 seconds). `close` is permissionless after that time. No solver supplies `p*`, allocation, or oracle value.

For live orders let `L_min`/`L_max` be the smallest/largest submitted limit tick on either side. For every integer tick `p ∈ [L_min, L_max]`: `D(p)=Σ{q_i : bid limit_i≥p}`, `S(p)=Σ{q_i : ask limit_i≤p}`, `V(p)=min(D(p),S(p))`, `V*=max V(p)`. Ticks outside the domain add nothing (`S=0` below `L_min`, `D=0` above `L_max`). If either side is empty or `V*=0`, primary volume is zero and `p*`, `p_lo`, `p_hi` are absent; residual matching may still run against posted maker ladders. Otherwise `p_lo=min{p:V(p)=V*}`, `p_hi=max{p:V(p)=V*}` and the clearing price is the **marginal-plateau midpoint** `p*=round_half_even((p_lo+p_hi)/2)`. Exact integer rule: `s=u128(p_lo)+u128(p_hi)`; if `s` even, `p*=s/2`; if odd, let `k=floor(s/2)`, choose `k` if `k` even, else `k+1`. Thus `6.5→6`, `7.5→8`.

### 2.1 Plateau lemmas (proved here; checked by the property test in security/08 Q01)

1. **Monotonicity.** Raising `p` can only remove bids from `D` and only add asks to `S`, so `D` is nonincreasing and `S` nondecreasing on the integers.
2. **Contiguity.** Let `M={p:V(p)=V*}` with `V*>0`. If `p1<p<p2` and `p1,p2∈M`, then `D(p)≥D(p2)≥V*` and `S(p)≥S(p1)≥V*`, so `V(p)≥V*`, hence `p∈M`. `M` is exactly the integer interval `[p_lo,p_hi]`.
3. **`p_lo` is a submitted ask limit.** `S` increases only at ask limits. If `p_lo>L_min` and no ask has limit `p_lo`, then `S(p_lo−1)=S(p_lo)` and `D(p_lo−1)≥D(p_lo)`, so `V(p_lo−1)≥V*`, contradicting minimality. If `p_lo=L_min`, `S(p_lo)>0` needs an ask with limit `≤L_min`, i.e. exactly `L_min`.
4. **`p_hi` is a submitted bid limit.** `D(p+1)=D(p)−Σ{q_i: bid limit_i=p}`. If `p_hi<L_max` and no bid has limit `p_hi`, then `D(p_hi+1)=D(p_hi)` and `S(p_hi+1)≥S(p_hi)`, so `V(p_hi+1)≥V*`, contradicting maximality. If `p_hi=L_max`, `D(p_hi)>0` needs a bid with limit `L_max`.
5. **Midpoint inside the plateau.** If `s` is even, `p*=s/2∈[p_lo,p_hi]`. If `s` is odd then `p_lo<p_hi`, so `p_lo≤floor(s/2)` and `floor(s/2)+1≤p_hi`; either choice lies in `[p_lo,p_hi]`. By (2), `V(p*)=V*`.
6. **Sweep sufficiency.** By (3)–(4) both endpoints are submitted limits, so evaluating `V` only at the sorted distinct submitted limits `C` finds `V*` (attained at `p_lo∈C`), the first maximizer `p_lo` and the last maximizer `p_hi`. No per-tick scan is needed; `p*` itself may be a tick in `C`'s gaps.

**Executable pseudocode (logical arrays, not a particular storage layout):**

```text
primary(orders):
    live = orders where not canceled
    bids = live bids sorted by (-limit_ticks, placed_slot, nonce, owner)
    asks = live asks sorted by (+limit_ticks, placed_slot, nonce, owner)
    C = sorted unique limit_ticks from live, ascending
    // Ascending sweep: reverse bids for increasing limits; asks already increasing.
    bid_low = reverse(bids); bid_pos = 0; ask_pos = 0
    d = sum(b.qty for b in bids); s = 0
    Vstar = 0; lo = NONE; hi = NONE
    for p in C ascending:
        while bid_pos < len(bid_low) and bid_low[bid_pos].limit < p:
            d -= bid_low[bid_pos].qty; bid_pos += 1
        while ask_pos < len(asks) and asks[ask_pos].limit <= p:
            s += asks[ask_pos].qty; ask_pos += 1
        // d = D(p), s = S(p); each cursor advances at most n times total.
        v = min(d,s)
        if v > Vstar: Vstar = v; lo = p; hi = p
        else if v == Vstar and v > 0: hi = p
    if Vstar == 0: return (NONE, zero allocations)
    pstar = half_even(lo,hi)
    eligible_bids = bids with limit >= pstar
    eligible_asks = asks with limit <= pstar
    assert min(sum_qty(eligible_bids), sum_qty(eligible_asks)) == Vstar
    for each side independently:
        R = Vstar
        for each price group in price-priority order:
            Q = sum(group.qty)
            if Q <= R: fill every order by qty; R -= Q; continue
            // One marginal group only: floor proportional shares, then distinct
            // leftover lots in time-key order. Since R<Q, each floor share<qty.
            for order in group: fill[order] = floor(R * order.qty / Q)
            L = R - sum(fill[order] for order in group)
            for order in group ordered (placed_slot, nonce, owner) ascending:
                if L == 0: break
                fill[order] += 1; L -= 1
            R = 0; break
        assert R == 0
    return (pstar, fills); pair opposing allocated lots only for receipts,
           without altering either side's allocation or the uniform price
```

Cost: one comparison sort, `O(n log n)`, then a sweep in which each cursor advances at most `n` times, `O(n)`; with a crank-supplied permutation the program only verifies it, `O(n)`. A program MUST verify any crank-provided sorted permutation is a bijection over exactly the active indices and sorted by specified total keys before using it; a wrong hint fails `clear`, it cannot mis-price. The marginal-plateau midpoint can be a tick not present as a submitted limit. A single competitive-side order may be partially filled; marginal-group pro-rata uses original order quantities **at that limit**, not prior fills. Each fractional remainder is `<1` and `L<group_size`, so one pass assigns distinct leftover lots; duplicate time keys are refused at order placement.

## 3. Separate maker residual phase

Makers may each sign one funded ladder per `(market, epoch)`. Ladder bounds are **provisional scale targets**, not measured: up to four makers with up to eight bid and eight ask levels each, pending LiteSVM/SBF compute-unit and transaction-size benchmarks. **Hackathon MVP:** one maker, one level per side. A bid level offers to buy user base; an ask level offers to sell user base. Each level has positive `(price_ticks, qty_lots)`, and each price-side pair is unique within its maker ladder; equal prices across makers are permitted. Posting/replacing a ladder requires a fresh signed posting while `Open` and complete prefunding; cancellation and return of its funds are permitted only while `Open`. Closed ladders admit no repricing or last look. Makers cannot affect the primary computation; the program fixes and persists `V*`, `p*`, primary allocations before applying the following logic in the **same atomic clear result**.

```text
residual(primary_fills, orders, maker_levels):
    remainder[i] = order.qty - primary_fills[i]
    for side in [user Bid vs maker Ask, user Ask vs maker Bid]:
        users = eligible allow_residual with remainder>0
        sort users by (Bid: -limit; Ask: +limit; then placed_slot, nonce, owner)
        prices = distinct opposing maker prices in best-for-user order
                 (for user Bids: ascending ask price; user Asks: descending bid price)
        for user in users:
            for price in prices while remainder[user]>0:
                if not satisfies_limit(user,price): break  // worse prices cannot qualify
                group = funded maker levels at this side and price with remaining qty>0
                R = min(remainder[user], sum(level.remaining for level in group))
                if R == 0: continue
                Q = sum(level.remaining for level in group)
                for level in group: take[level] = floor(R*level.remaining/Q)
                L = R - sum(take[level] for level in group)
                for level sorted by (posted_slot, maker) ascending:
                    if L == 0: break
                    take[level] += 1; L -= 1
                for level in group:
                    level.remaining -= take[level]
                    if side == user Bid vs maker Ask:
                        maker[level.maker].quote_receivable += take[level]*price*tick_quote
                    else:  // user Ask vs maker Bid
                        maker[level.maker].base_receivable += take[level]*base_lot_raw
                remainder[user] -= R
                user.residual_lots += R
                user.residual_notional += R*price*tick_quote
    // Never recompute or mutate primary fills, Vstar, pstar.
```

Repeated price matching is deterministic but can have more work than the primary sweep; the order and ladder caps above are provisional until worst-case CU/transaction-size profiling ([`../architecture/04-ONCHAIN-PROGRAM-DESIGN.md`](../architecture/04-ONCHAIN-PROGRAM-DESIGN.md)); if one `clear` cannot fit, the caps shrink, the semantics do not. Even when `V*=0`, the empty primary allocation is stored before this phase. Residual prices are maker prices, potentially different from `p*`; a receipt MUST identify every fill as `CROSS` or `RESIDUAL`, and for residual show maker price and filled lots.

## 4. Lifecycle, guarding, and settlement

At `open_epoch`, refuse a scheduled Scaled UI Amount activation inside `[open_ts−guard, clear_deadline_ts+guard]`. `close` and `clear` re-read the base mint's extension/authority fingerprint and both per-epoch vault balances against recorded outstanding entitlements. An ordinary fingerprint/multiplier/issuer guard failure **before** `Cleared` enters `RefundOnly`; an epoch not cleared by `clear_deadline_ts` also enters `RefundOnly`. Each owner may then claim a refund of the original deposit, permissionlessly, but only while the token programs and issuer permit the transfer; a frozen vault or paused mint can hold it indefinitely. **Exception:** if `vault_balance < outstanding_entitlements` for a leg, that leg becomes `Impaired`: each escrow owner on it keeps a nominal claim equal to the **original deposit**, no payout is made from that leg, `VaultShortfall` records uncovered atoms, and the claim **may never be recoverable**. The solvent leg's deposits remain refundable. No shortfall redistribution, no invented restitution and no recovery path; recovery is an open question (canonical §3.9). V1 refuses any mint with a permanent delegate set. A shortfall is a release-blocker scenario, not ordinary expected operation.

After `Cleared`, the primary and residual allocations produce a fixed ledger of base, quote and fee entitlements backed by the corresponding epoch vaults at clear; **never** turn a cleared result into `RefundOnly`. A later issuer-caused vault shortfall marks the affected leg `Impaired`, preserves every nominal entitlement and stops its payouts; it does not affect the solvent leg. V1 defines no recovery. An excess unsolicited deposit above recorded liabilities is quarantined, neither a fee nor a claim; who may sweep it is an open policy (canonical §3.9). Verify `vault_balance ≥ outstanding_entitlements` rather than demanding vault equality. Outstanding entitlements are the unpaid nominal claims on that leg; paid claims are removed only on successful token transfer.

Anyone may call bounded `settle_order` / `settle_maker` (only after `Cleared`) or `refund` (only in `RefundOnly`, never after `Cleared`) for one recipient leg per instruction; an epoch settles over many transactions. The recipient is the canonical token account fixed by the entitlement; a caller-supplied different destination, mint or program is a hard error that reverts and records nothing. The instruction checks the per-epoch vault's balance against **all outstanding entitlements on that leg**. If it finds a shortfall, it records `Impaired` and `VaultShortfall` without paying. Otherwise it runs a deterministic preflight over on-chain state only: vault frozen, recipient account frozen, mint paused, recipient canonical account missing/closed. A mint fingerprint change is not a settlement/refund preflight condition: after `Cleared` it only blocks `open_epoch` until requalification and never blocks payout of fixed entitlements (canonical §3.7). If one holds, it succeeds **without transfer**, emits `SettlementBlocked(reason, leg, slot)` and leaves the entitlement `Unpaid`. The marker is advisory and gates nothing: every later call re-runs the preflight, and the first call whose preflight passes and whose transfer succeeds marks the leg `Settled` (a missing canonical associated token account can be recreated permissionlessly first). A griefer therefore cannot delay a leg whose preflight would pass. There is no `mark_settlement_blocked` instruction: a failing token CPI rolls back every write, and no caller can attest why it failed, so an unexpected CPI error after a passing preflight reverts, leaves the entitlement untouched and retryable, and is surfaced by the crank/indexer as an off-chain incident. `Finalized` requires all obligations discharged; an unresolved impaired or issuer-blocked leg cannot be declared paid. See [`../architecture/03-SYSTEM-ARCHITECTURE.md`](../architecture/03-SYSTEM-ARCHITECTURE.md) for trust boundaries and [`../security/08-TEST-AND-VERIFICATION-PLAN.md`](../security/08-TEST-AND-VERIFICATION-PLAN.md) for release verification.

## 5. Computed test vectors

**All numbers here are illustrative SYNTHETIC test-mint examples**, not market prices or qualified xStock routes. No exact mainnet issuer mint has passed the allowlist; production eligibility is **BLOCKED**. Use `base_lot_raw=1,000`, `tick_quote=1,000`, `fee_bps_per_side=5`, no issuer extensions and no transfer fees. `B(q@p)` is a user bid and `A(q@p)` a user ask; `MB/MA` are funded maker bid/ask levels. Deposits are in quote atoms for bids/MB and raw base atoms for asks/MA. `(slot,nonce,owner)` keys are ascending in written order where needed. `p*=—` means no primary cross. `N` and fees are **raw quote atoms, not dollars**: if the quote mint were a 6-decimal USDC-like test mint, `6,000` atoms would display as 0.006 units, so these vectors exercise integer rounding, not realistic sizes. No token decimal-to-UI conversion is used. Every row was recomputed by a throwaway reference script on 2026-09-28 (per order: deposit = payout + refund + fee for bids, deposit = sold base + returned base for asks; base conserved; fee vault = Σ order fees); all rows matched.

| Vector | Orders and funded deposits | `V*`, maximal interval, `p*` | Allocation and entitlements (including all refunds) |
|---|---|---|---|
| **T0 no cross** | B(2@4): `8,000+4=8,004` quote; A(3@5): `3,000` base | `0`; `—`; `—` | Both zero fills; bid gets `8,004` quote back, ask gets `3,000` base back; fee `0`. |
| **T1 single cross** | B(2@7): `14,000+7=14,007` quote; A(1@5): `1,000` base | `1`; `[5,7]`; `6` | CROSS `1@6`, `N=6,000`; buyer gets `1,000` base, pays `6,003` and receives `8,004` quote back; seller gets `5,997` quote; fee vault `3+3=6`. |
| **T2 rationed bids** | B₁(2@8): `16,008` quote; B₂(3@6): `18,009`; B₃(4@6): `24,012`; A(6@4): `6,000` base | `6`; `[4,6]`; `5` | Higher-price B₁ fills `2`; four remaining lots at bid 6 allocate floors `⌊4·3/7⌋=1`, `⌊4·4/7⌋=2`, leftover one to earlier B₂ ⇒ B₂=`2`, B₃=`2`. Each buys `2@5`: `N=10,000`, fee `5`, base received `2,000`; bid refunds respectively `6,003`, `8,004`, `14,007`. The **single ask order** sells 6 lots for `30,000`, pays one aggregate fee `15` and receives `29,985`; fee vault `5+5+5+15=30`. |
| **T3a half-even down** | B(1@9): `9,005` quote; A(1@4): `1,000` base | `1`; `[4,9]`; `(4+9)/2=6.5→6` | CROSS `1@6`; `N=6,000`; buyer fee `3`, refund `3,002`, base `1,000`; seller proceeds `5,997`; fee vault `6`. |
| **T3b half-even up** | B(1@10): `10,005` quote; A(1@5): `1,000` base | `1`; `[5,10]`; `(5+10)/2=7.5→8` | CROSS `1@8`; `N=8,000`; buyer fee `4`, refund `2,001`, base `1,000`; seller proceeds `7,996`; fee vault `8`. |
| **T4 separate residual fill** | B(3@7, residual=true): `21,011` quote; A(1@5): `1,000` base; MA(2@6): `2,000` base | `1`; `[5,7]`; `6` | CROSS `1@6`, then RESIDUAL `2@6` against MA. Buyer gets `3,000` base, aggregate `N=18,000`, fee `9`, pays `18,009`, refund `3,002`. Seller gets `6,000−3=5,997` quote; maker gets `12,000` quote, no fee; fee vault `9+3=12`. Primary volume and price remain `1@6`. |
| **T5 maker limit rejected** | B(2@5, residual=true): `10,005` quote; A(1@4): `1,000` base; MA(1@6): `1,000` base | `1`; `[4,5]`; `4` (4.5 rounds to even 4) | CROSS `1@4` only; maker ask `6>bid limit 5`, so no residual. Buyer gets `1,000` base, pays `4,002`, refund `6,003`; seller gets `3,998`; maker gets its `1,000` base back; fee vault `4`. |
| **T6 residual with no cross, maker tie** | B(5@8, residual=true): `40,020` quote; MA₁(2@7): `2,000` base; MA₂(4@7): `4,000` base | `0`; `—`; `—` | RESIDUAL `5@7`, `N=35,000`; floor maker shares `⌊5·2/6⌋=1`, `⌊5·4/6⌋=3`, remaining one goes to earlier MA₁ ⇒ MA₁ sells 2, receives `14,000`; MA₂ sells 3, receives `21,000` and gets `1,000` base back. Buyer gets `5,000` base, fee `18`, quote refund `5,002`; fee vault `18`. |

For T4's bid fee `9`, floor shares are protocol `5`, distributor `2`, crank `0`, dust `2`; for the ask fee `3`, shares are protocol `1`, distributor `0`, crank `0`, dust `2`. Assuming the bid has a non-null distributor and the ask has none, the `12` atoms in the fee vault equal `6` protocol + `2` distributor + `0` crank + `4` dust. If the bid instead has a null distributor, its `2`-atom distributor share redirects to protocol. These tiny illustrative notionals expose integer fee dust and weak micro-order crank compensation; economics need validation, not concealment.

## 6. Proof obligations, not claims of implementation

1. **Maximality/feasibility.** `V*` is the largest possible same-mint user/user volume; `p*∈[p_lo,p_hi]`, every allocated buyer limit ≥ its executed price, every seller limit ≤ its executed price; both CROSS sides fill exactly `V*` lots.
2. **Determinism.** Reordering account metas, crank calls, or instructions representing the same final order/ladder set cannot affect price, allocation, fee, or entitlement; active owner/nonce and maker/side/price uniqueness make sorting total. Pro-rata leftovers are bounded and cannot overfill.
3. **Separation.** Removing all maker ladders leaves primary results identical. Residual volume never exceeds user remainders with opt-in, maker funded quantities, or limit prices; no one receives a nominal entitlement unsupported by recorded prefunding at clear, but issuer action could later remove backing.
4. **Solvency.** At solvent clear, fixed nominal entitlements plus fee obligations equal the **recorded funded** balances per leg, ignoring quarantined unsolicited surplus; require actual per-epoch `vault_balance ≥ outstanding_entitlements` at every guard and settle. If an issuer causes a shortfall, stop payouts from the impaired leg and emit uncovered amount; do not reduce, reweight, or socialize nominal claims. The unaffected leg stays usable. Check notional, reserve and token-transfer conversions for overflow.
5. **Liveness boundaries.** Before clear, deadline/guard produces RefundOnly claims on original deposits that anyone may trigger without admin discretion, **except** shortfall produces Impaired for the affected leg (nominal claim = original deposit, possibly never recoverable); after clear, result immutability survives issuer pauses and CPI rollback. Completion of any settlement or refund depends on the token programs and issuer permitting the transfer; a frozen vault can hold funds indefinitely. Neither a halt report nor an off-chain route quote is an on-chain fact in V1.
