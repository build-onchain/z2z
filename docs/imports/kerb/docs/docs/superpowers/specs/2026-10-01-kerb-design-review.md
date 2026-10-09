# Kerb integrated architecture — adversarial design findings

**2026-10-01 · reasoned review, not runtime audit.** Parent records the full substantive findings received from independent DesignAdversary before its final response was replaced by a short follow-up. No code/network/transactions/actual privacy experiment was performed by reviewer. [Primary integrated proposal](2026-10-01-kerb-production-demo-design.md) now incorporates the policy corrections below. All implementation, roster, security and lawful-operation evidence remains U.

**Authority update 2026-10-01:** [Kerb current authority](../../../00-CANONICAL.md#0-current-documentation-authority) adopts **shared Zoss source/context/domain/Solana client library reuse as documentation only**. No financial/private candidate, FAA/MPC/custody choice or privacy waiver is approved. The known F1/GD2 structural FAIL below remains blocking; common domains/libraries, opaque receipts and caller-isolated processes do not resolve it.

## F1 — Structural privacy failure, still OPEN / blocking

**Trace:** eight slots include padding, attacker-owned contra orders and ONE natural seller Alice. Alice's public epoch-bound escrow exposes participating seller identity. Matcher owns the other clients/knows their ciphertexts and legitimately decrypts their own fills. Subtracting known inputs leaves Alice; padding is not another independently unknown funded seller. If Alice ask is6 or10 and attacker bids8, fill occurs iff ask6, revealing private limit without breaking encryption/MPC. Public transfer/source identifies seller. This permitted execution contradicts the unchanged unconditional no-single-matcher content AND accepted-identity guarantee.

**Disposition:** primary§6 explicitly records known GD2 failure, not U privacy-success expectation. FAA/admin separation, private prices, random IDs, padded rows, Cerberus or Zoss receipt cannot erase information implied by public collateral membership and a participant's own result. Don't exempt own-result inference or present fake clients as anonymity. Private collateral/membership redesign could address public membership but **does not alone** solve active price/quantity probes. Precise compositional/auxiliary-information/output boundary and validated design needed; weakening guarantee requires explicit owner decision. No private funded production-demo readiness claimed.

## F2 — Universal payout predicate prevented buyer refunds — policy corrected

Old signer paragraph required finalized SPL delivery before every native ZEC signature. No-cross/aborted/excluded buyers have no delivery, so valid unused-credit refund couldn't execute.

**Now:** typed SellerPayout requires exact SPLReleased+active seller liability. BuyerRefund instead requires matching final unused or fenced exclusion/abort/cancel disposition, immutable buyer refund destination, live inventory and no competing same-portion intent; explicitly no SPL delivery prerequisite. Common PCZT/effect/sighash checks remain. Runtime not verified.

## F3 — Caller-selected whole-book encryption owner — policy corrected

Full certified order book sealed to independent coordinator could be exfiltrated if caller supplies its own output Shared/context key while all cert/root/funding checks pass.

**Now:** coordinator key/version pinned to epoch/config/queued computation and every extraction; client owner equals certified one-use result key. No arbitrary input.owner/full-book caller key or recovery reveal. Vendor .from_arcis owner semantics are source evidence, not implemented Kerb gate.

## F4 — Restored signer journals allow two distinct-input refunds — recovery requirement explicit

Unanimous refund intentX signed with noteA but broadcast ambiguous. Three signers restore pre-intent backups; FINAL chain state still visible; new intent for same business portion uses noteB. Both transfers may mine—chain nullifiers only prevent same-note spend, not business-claim double pay. Restored FROST nonce state also risks nonce reuse/key compromise.

**Now:** signed acknowledgement binds predecessor head/hash, writer generation, entity prior/next version and exact effects; persist before monetary signature. Non-rollback high-water/used-intent/nonce history and independently retained heads required; missing journal/all potentially live signed effects ⇒ Disputed/halt. This is fail-stop trust/operations requirement, not BFT certification; corrupt spend threshold still theft risk.

## F5 — Partial FINAL activation freed unused backing — policy corrected

Canonical FINAL visible while private allocation application incomplete; worker treats M−N free while old full M hold still present; replay creates overlapping dispositions.

**Now:** SAME AllocationActive predicate for refunds AND release: finalized exact result digest, complete authenticated chunks, unanimous matching acknowledgement and fully applied private journal. Partial apply/root or chunk not sufficient. Final epoch can't ordinary-abort; explicit filled cancel mutually exclusive SPL cancel/release and private no-live-native-intent fences.

## F6 — Root relations conflated — distinct commitments specified

Ciphertext membership root differs from plaintext certified digest; reading mutable/wrong account offsets with a claimed valid root can execute wrong set. Raw public escrow-list hash dictionary enumerable, not hiding.

**Now:** Rct over exact sealed account bytes/layout/owner/index/generation; private-opening randomized Cholds for exact hold membership/versions; Corder FAA plaintext commitment recomputed in encrypted circuit. Authenticate queued account/root provenance, not plaintext-to-ciphertext equality fiction. Hidden hold↔slot link is explicit business authority testimony, not ZK proof. Public escrow membership privacy failure remains F1.

## F7 — Operation ID collision/ABA and wall-clock expiry — policy corrected

Per-hold generation1 plus market/epoch/Prepare aliases multiple entities. Restore/new epoch reusesgeneration can revive stalecert. Rechecking accepted expiry at delayed MPC time mutates set or tempts early refund.

**Now:** deployment/pair/epoch/stable entity/hold/portion/intent ID+monotonic generation+prior version+transition; retained consumedIDs/terminalmarkers acrossrestore/rotation/closure. Eligibility/cert expiry fixed at canonical admission cutoff; expiry rejects new admission, never releases accepted backing. Transaction/release deadline separate.

## Integration constraints retained

- FAA and coordinator intentionally learn full order/identity/payment mappings, must be outside matcher control/access graph; no global anonymity/blind issuance claim.
- Arcis certificate SHA3-512 signature is not nativewallet/Solana Ed25519/FROST; select vendor SDK scheme and exact encrypted verifier, client-secret possession commitment, canonical vectors. No actual circuit interoperation yet.
- SDK0.15 account-read + generated packing and fixed-size single-transaction extraction are source-supported choices. Exact sealed input/root/offset/output authenticity, fixed8 capacity/CU/callback/retrieval must be observed.
- Full buyer max-debit and seller atoms held at prepare through delayed MPC, zeroFill or unknowncommit. Final filled/unused portions disjoint, inventory/change separate, no credit from change.
- ReserveFill != liveRelease. DurableFirstLegPrepared before signaturehandoff; explicit finalizedcancel excludesrelease and private nativepayout intents before filled return.
- Unanimous business decisions serialize honest durable policy, native2of3 spends retain collusion/withholding risk; no cross-chain atomicity/unilateral ZEC refund.
- [Zoss shared-core consumer contract](../../../../../../../../zoss/docs/kerb.md) now separates native library reuse from optional messaging. Source/context/domain/Solana clients run in **Kerb-controlled processes** without a mandatory daemon, watchers/IVK handoff/receipt/quorum or added viewing party. Kerb verifies claimant/ownership/canonical-history/controlled inventory/durable credit dedup before credit; FAA/MPC/holds/journals/FROST/payout/refund and recovery stay app-owned. Ordinary wallet/Solana Ed25519, Arcis SHA3-512 certificates and native FROST domains remain explicitly distinct.
- Caller/per-pair keys, private caches/cursors, source/claimant/order maps, witnesses, logs/backups/support access stay isolated from matchers, Ziquid and optional message workers; library reuse does not establish that operating separation. No universal proof/consensus engine, generic `verified` boolean or proof-to-quorum conversion is added.
- Optional message diagnosis stays **OFF / non-money** and money workflows must run without its runtime. Private signed provenance and opaque public receipt retain no default public locator/height/value/privatehash; receipt never credit/hold/payout/refund/negative/reverse/effect proof. Atomic retry is the same immutable still-valid receipt on the destination only, not cross-chain recovery.
- Zoss one-source→one-receipt namespace across routes/profiles/deployments remains unresolved, not app financial uniqueness. Kerb credit/hold/portion/intent replay and funded witness/evidence/recovery lifetime stay independently durable through message revocation/library upgrades. [Zoss BLOCKERS](../../../../../../../../zoss/docs/BLOCKERS.md) is the sole core gate register, including named shared-library acceptance; no core/runtime/privacy gates pass by this adoption.

## Verification and closure status

Independent reviewer performed document/source reads only. F2/F3/F5/F6/F7 prose changes and F4 explicit requirement exist in primary proposal; none is tested code. F1 remains a known design-level failing corpus requiring a new validated mechanism or an explicit scope decision, not a numeric confirmations/operator-signature fix. Parent's later local state/arithmetic smoke is reported separately in primary proposal; it cannot prove privacy, actual consensus/finality/CPI/database/FROST effects or production readiness.
