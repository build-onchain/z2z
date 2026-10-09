# Client SDK — TypeScript packages/sdk và external UI

**Consumer, not money authority.** `packages/sdk` is a private TypeScript ESM package/build with an empty `export {}` entry point; no quote/wallet/settlement/manual/Rust binding APIs. Native P/Q/proof/source-acquisition/encrypted custody/PostgreSQL primitives, samechain owner relations, immutable target authority, unsigned calls and limited trusted-node inspection exist as recorded in [native status](../NATIVE-IMPLEMENTATION-STATUS.md); genuine funded execution, complete financial proofs and manual lifecycle remain unqualified. Latest user priority activates integration for a real usable journey while production continues; broader SDK/WASM/FFI packaging is still deferred. User owns the separate frontend, engineering owns native/backend/secure transport; [frontend handoff](../history/PRODUCT-OVERVIEW-AND-FRONTEND-HANDOFF.md) owns the full story map. Independent thin native execution remains core acceptance, not deferred with packaging.

**Active lane scope:** native ZEC is an active first-class lane (L-ZEC) in the whole pipeline, not V2; L-HEVM, L-SOL, L-NEAR and X.CROSSCHAIN (HTLC first, all pairs in parallel, no atomicity/privacy claim) are active parallel lanes. The SDK is a consumer of these lanes' canonical native rules; its own packaging stays deferred and it never becomes a money authority.

[PRODUCT](../PRODUCT.md) owns product lanes; [ARCHITECTURE](../ARCHITECTURE.md) behavior; [MODULES](../MODULES.md) packaging; [BLOCKERS](../BLOCKERS.md) enablement. [SERVER-INDEPENDENCE](../SERVER-INDEPENDENCE.md) owns bundle/stage/manual rules and [independence research](../research/SERVER-INDEPENDENCE-RESEARCH.md)/[cross-chain research](../research/CROSSCHAIN-MARKET-RESEARCH.md) source/data/venue limits. UI is a separate future consumer, not a sole key/witness/artifact store. This docs-only proposal authorizes no new lane/code/namespace migration, sign/send/deploy/fund or private witness delegation.

## 1. Small conceptual interface và ownership

The future SDK presents exact intent/venue/trust/privacy/fee disclosures, coordinates **owner-controlled** authoring/proving/signing, requests bound operations, reconstructs observations with provenance and reports actual outcomes/ETA. It never supplies settlement authority, modifies original funded rights or signs from hosted secrets. Existing native rules/encodings and target interfaces own validation; SDK does not create a second economic or proof policy.

| Conceptual consumer operation | Required interface/invariant |
|---|---|
| Inspect intent/route/deployment | Exact network/execution domain/asset ID/raw units/recipient/amount/limit/fees/expiry/custody/privacy/finality; actual support and required owner/issuer/venue powers. Ticker/address shape is insufficient. |
| Prepare/export/restore owner artifacts | Call owner-native functions through a future reviewed interface; private bundle/witness handles stay user-local. Prepare recovery and restore original public/private artifacts before funding/releasing capability. |
| Approve exact action | Display complete domain/terms/output/fees/signer/fee payer; explicit consent per financial/signing scope. Local wallet/signer enforces it, not server checkbox alone. |
| Build/prove/simulate/submit | Consume actual native proof/target methods once available, bind original context/allowed program, submit direct or selected arbitrary relay without company admission signature for existing rights. No private note/FVK/master key to relay. |
| Reconstruct/reconcile/retry | Authenticate original chain/venue history/finality and durable exact pending operations, verify actual balances/consumption/output recovery, retain Unknown fences; never infer no effect from missing response. |
| Observe state/`RecoveryEstimate` | Route-specific source/target/venue provenance/as-of/pending reasons/actual shares; no generic `verified=true`, paid from tx hash or timer-refund interface. |

Rust↔TypeScript transport/bindings (including WASM/FFI) are **not selected or implemented**; future package is a consumer of canonical native rules, not proof of a browser-local full-history prover. Native direct/manual path must function first without SDK/UI/company. No universal wallet/proof engine/bridge/new chain/omnibus balance is introduced.

### Route consent remains distinct

| Lane | Required consent/authority disclosure |
|---|---|
| Native one-way Ironwood ZEC→local EVM | Unsigned P/complete local Q/no U FVK to S; early-Q cancel/fee option; irrevocable prefund before P authorization; full validating source history/all-input net consideration/proportional fixed shares/actual source excess return; source+target data/finality/prover risks. Full path not enabled. |
| Samechain proof-controlled P2P | Native owner relations and actual immutable EVM authority source exist, but genuine certificate/backed lifecycle remain unqualified. Both owners' exact consent, usable output recovery, current backing/successor/cancel race and actual atomic effects are required; not native ZEC custody escape. |
| Retained Solana↔Zcash custody/private market | Migrated local safety code/target VM evidence exists; PostgreSQL verification and complete network/private-market/source-custody lifecycle remain unqualified. Native transfer still requires actual custody signers; credit/ACK/proof intake is not unilateral ZEC spend authority. |
| Eligible Hyperliquid-asset P2P | Qualify exact Core/EVM/token/native identity/backing/units/owner transfer control and actual settlement construction; no ticker-based HYPE/ZEC or global balance/atomicity claim. |
| **Separately chosen external HyperCore spot** | Public external account/venue action/fill/nonce/fee/withdrawal controls; only spot/no perps/leverage; no automatic P2P remainder or privacy downgrade. Venue/network/issuer remains authority/dependency. |
| **Cross-chain HTLC (X.CROSSCHAIN)** | Per-pair construction CX-1 first: asymmetric hash/time-locked two-phase settlement between lane authorities. **No atomicity and no privacy claim** — the shared public hash links the chains and conflicts with strict GD2. Requires per-pair reorg/finality budgets, censorship windows, secret-reveal finality race, staggered timeouts, late-claim/refund mutual exclusion, per-pair observer/DA, responder exposure and a durable preimage-release fence. Perp positions cannot be hashlocked; only tokens/collateral. |
| Public LP/provider/1Click/agent/future ZSA | Explicit lane-specific asset/backing/issuer/provider/position/spend permissions and activation gates. Retained scope, deferred where documented; never source-settlement fallback or implied user authorization. |

Selecting P2P does not authorize external spot or vice versa. Quote/matching candidate is not mutual trade consent or optimal-price proof; canceled/partial/unknown route must not silently move residual capital to another venue.

## 2. Ordering, invariants và logical state

### Native funded lifecycle — no cancel-by-UI

1. **Draft:** freeze exact quote/context/route/privacy/custody/disclosures; retain independently usable artifact/recovery plan, not a hosted login link. Proposed/blocked routes cannot be advertised as live/private/atomic.
2. **RecoveryPrepared:** wallet has exact nonexecutable P, locally complete Q with every real/dummy action/binding/proof/signature/self-output/fee/ciphertext; U durably retains independent sender witness. S must verify actual no-FVK app certificate/chain admission before funding; local authoring primitive alone insufficient. Q export gives S early cancellation/fee capability with explicit consent.
3. **DestinationArmed:** independent user-native inspection authenticates exact native D/fixed beneficiaries/deployment/code/program/VK/policy/finality and stable genuine-note reservation. Server quote/journal/event does not authorize P. Wrong/cancellable/unfinalized funding or unusable source packet→keep P authorization private.
4. **SourceResolutionPending:** persist exact approval/release/sign/send intent and bytes, then authorize P after gate. Ordinary retry keeps effects; no automatic fee/input/output/expiry/branch replacement or competing economic intent because RPC absent. Same-effect proof/auth update requires real capability/validation, not final-Q fiction.
5. **AllocationReady:** full accepted source history/classification authenticates complete net C. For `A,D>0` and `0<=C<=A`, show actual fixed U `floor(D*C/A)` and fixed S remainder, **dust to S**, no hidden fee. Partial economics chosen; composition/actual escrow path missing. C0 needs actual nonpaying same-real-input conflict. Different T/P′ or new auth is not automatically nonpayment.
6. **Actual terminal:** destination verifies/consumes/both fixed transfers atomically, reverts all if either fails; report terminal only after correct actual asset effects/finality and required source relation/return. Full `C=A` pays U all D, proven C0 refunds S all D; partial shows both shares, not binary “full paid/refunded”. Q branch also validates actual agreed U self-return; arbitrary T need not return U principal.

Earlier admissible bound P/T remains provable once obligation funded; no activation lower cutoff. Same v6 effects/new auth/anchor remains P. Consensus expiry stops invalid late source mining, **not** claim/retry deadline for valid included payment. U self-paying before any obligation exists does not compel S funding.

`EvidencePending` has real dependency/provenance/reason, resumable under original rights; **not successful hostile-terminal delivery**. Arbitrary T can conceal mixed-owner inputs or produce `C>A`. Full independent all-hostile classification/terminal capability and actual independently usable S-authorized excess return remain blockers; no clamp/gift/full-destination-refund/hoped-for cooperation or generic zkVM recovery of missing secrets. Safe Unknown prevents false allocation, not acceptance of incomplete native protocol.

Local `ReservationCancelled` is an unfunded S journal state, not onchain refund. User closes app/cancels signing after destination arm: no P release, but armed funds require real valid source resolution, **not** samechain cancel/timeout/admin authority.

### Proposed samechain lifecycle — selected checked outputs

- **Deposit/owner note:** qualify real asset control/semantics, prepare/restore private note kit and publish complete authenticated output recovery data atomically with actual backing. Public hash/root alone not recoverable note.
- **Candidate terms:** matcher only proposes exact asset/quantity/limit/beneficiary/fee/domain. Once fill quantity known, each recipient/owner prepares exact output and successor openings/ciphertexts, backs them up and locally decrypts/recomputes commitments.
- **Fresh exact Fill2 consent:** compose the existing [reviewed construction](../superpowers/specs/2026-10-06-independent-owner-fill-design.md), [protocol](../../crates/protocol/src/samechain/fill.rs) and [owner relation](../../crates/proofs/src/samechain.rs): frozen packet/public E/ordered opaque leaves/private per-owner own_salt, no complete Terms/common blind. Each owner independently selects canonical E frame2 with `review-fill --packet FILE --execution FILE --role a|b --witness-stdin`, opens only own authenticated policy and authorizes identical packet/C. Native relations/atomic authority source exist, but SDK bindings, durable integration, genuine proofs/admitted funded lifecycle remain unqualified. Relayer acts only after both consents, cannot rewrite effects. E quantities are counterparty-visible, not GD2-secret. Fill-only witness/relation2 and one-copy guest mode0 require new separately pinned ELF/program/authorized immutable authority and all-mode requalification; retain original fill1/non-fill1 identities without migration.
- **Fill/cancel/withdraw:** atomically consume/invalidate the same shared backing/intent generation. Included cancellation creates authorized owner successor/actual withdrawal and rejects every outstanding F1/F2 digest on that generation, including different relayers/fees/proof representations; packet-only revoke is not order cancellation or backing release. [SERVER-INDEPENDENCE §4.3](../SERVER-INDEPENDENCE.md#43-cancel-partial-fill-và-race) owns the rule. Canonical chain winner determines fill or cancellation; API ack/pending signed cancel is not revocation. Existing owner exit must not await company epoch/approval.
- **Partial successor:** retained, not disabled: fresh exact remaining liability/quantity/value/openings/ciphertexts and owner authorization for each known fill; disjoint successor cannot reset original capacity by random note/salt. Cancel only unfilled successor, no undo delivered fill.

Selected recoverability comes from **recipient/owner preparation + local decrypt/opening/commitment check before exact authorization**, plus independent data availability and onchain digest binding. Generic ciphertext-correctness ZK is not assumed; circuit-enforced encryption remains unselected future alternative for truly unattended partial fills. Offline owner prevents **new fills**, not already fully authorized settlement/owner exit; no offline matching-liveness or strict GD2 remedy claimed.

## 3. Durable authority khác observer cache

| Owner/store | Authoritative scope | Consumer cannot infer/do |
|---|---|---|
| U owner wallet/bundle/journal | Secrets/receive capability, note reservation/openings, exact approvals/releases/signed bytes, independent sender witness/Q/consents and original artifact versions. | Cache/public chain does not reconstruct released-unmined authorizations or lost secrets. No witness deletion at TTL/expiry/job ack, no replacement because UI lost state. |
| S durable store/bundle | Inventory TOTAL-cap reservations, immutable funding/signing/Unknown/armed operations, complete Q/private independent terminal/excess-return capabilities and actual reconciliation records. | Current SQLite IDs/digests alone not complete signed-payload or terminal financial authority. Consumer cannot free hold by “not seen”. |
| Onchain native escrow/proposed samechain ledger | Authentic backed obligation/note roots/consumption/intent/successor and exact actual asset effects under original rules. | Server/cache cannot rewrite payee/fee/VK/root rights or declare refund/paid. Actual financial implementations remain missing. |
| External venue/account | Actual canonical action/nonce/order/fill/partial/transfer/position/balance/withdrawal state and permission rules. | Core request/queue/EVM success/log not necessarily Core fill/cancel/transfer or P2P settlement. |
| Observer cache | Rebuildable authenticated source/target/venue history, provenance/as-of/finality/reorg and ETA inputs. | No sole private recovery store/signing authority or authoritative money ledger. |

Before deposit/arm/capability release, local owner must **restore and inspect actual encrypted private bundle and public artifact bytes**. Include original domain/deployment/asset/terms/code/program/VK/PK/witness generator/toolchain/source/ABI/history policy, full needed note/openings/authorized bytes/ciphertext/output mappings and Unknown records. User keys stay private; public manifest/hash/mirror does not provide secret or availability. [SERVER-INDEPENDENCE](../SERVER-INDEPENDENCE.md) owns full kit/lifetime.

Restart authenticates original funded context and reconciles exact signed operations with authentic chain/venue state; backups/tombstones/consumption retained prevent re-fund/re-pay/capacity reset. Source/target reorg invalidates nonfinal cache, not original authorization; stale/incomplete RPC or absent receipt is not proven no effect/nonpayment. `ActorStore` capacity input is **TOTAL including Reserved/FundingPrepared/SubmissionUnknown/Armed**, not already-reduced remaining balance; exact caller actor/asset/deployment scope remains required.

Samechain manual sync needs ordered complete commitments/nullifiers/ciphertexts and authenticated history; owner locally decrypts and recomputes note commitments/current eligible witnesses for **new** proofs, not company branch endpoint. Selected proposed [samechain root policy](../SERVER-INDEPENDENCE.md#32-data-availability-là-protocol-requirement) immutably retains every authenticated historical membership root/tree generation in the same deployment, no sliding expiry/admin pruning: an already fully authorized exact packet remains submit-able by the other owner/arbitrary sender after unrelated appends/rollover with one owner offline, without private proof renewal/secret export/new signature. Input/output tree domains are bound and globally deployment-scoped nullifiers prevent per-tree replay; target still checks live backing generation/cancel/capacity, rejecting unaccepted/orphan roots, spent/canceled backing and explicit signed expiry. Full-tree/history availability must preserve valid funded exits and new-proof reconstruction. Unbounded accepted-root state growth needs measured storage/gas/sync/rollover qualification, not rights-retiring pruning. Native Zcash anchors/Q/source lifetime do not inherit retained-root validity; full native history is not target logs/tree membership.

## 4. `RecoveryEstimate` là ETA, không refund guarantee

The conceptual estimate describes **time to exercise a currently valid right**, not creation of that right or a guarantee. Exact owner semantics stay in [SERVER-INDEPENDENCE](../SERVER-INDEPENDENCE.md)/[MODULES](../MODULES.md); no current measured recovery dataset supports default numbers.

| Field | Required meaning |
|---|---|
| `status` | `Unmeasured` / `Estimated` / `EvidencePending`; none is payout/refund permission. |
| `asOf` | Time and authenticated source/target/venue view underlying estimate; stale/reorg invalidate it. |
| `stage` | Source resolution/history/classification, local proving, destination submission/finality/actual transfer or exact venue operation; unreachable stage says why, no fake countdown. |
| `reason` | Actual missing artifact/witness/authority/prover/gas/recipient/data/chain progress or Unknown dependency. Permanent enablement blocker not presented as completed recovery. |
| `measurementProvenance` | Real path/device/sample/window/scheduling/policy/version when measured; no upstream guest instruction count as settlement runtime estimate. |
| `estimatedDurationOrRange?` | Optional only from actual relevant measurements/assumptions; absent when unmeasured/unsupported, no numeric fallback/confidence invented. |
| `assumptions` | Source/target finality/progress, honest competing-history/history/ciphertext/artifact/private witness availability, usable resources/gas/inclusion/recipient and venue dependencies. |

Do not compare/add Zcash height and EVM height/slot/timestamp as a refund deadline. Overlapping acquisition/proving/submission stages require actual scheduling measurements, not double-counting. Exceeded ETA updates status/reason/asOf **only**; cannot trigger opposite allocation, timeout refund or cancellation of an armed native obligation.

Q may be broadcast early and cannot autonomously reanchor; fee/branch/input/anchor/expiry/proof lifetime matters. Source/target halt/censorship, missing private facts/data/artifacts and permanent recipient/issuer refusal can block progress; disclose limits before consent and while pending. This does not authorize silently narrowing required all-hostile terminal construction to witness-qualified pending.

## 5. Privacy/signing/persistence và errors

**Privacy dimensions stay separate:** shielded source note/payment, public target linkage/amount/recipient/time, private order/intake/accepted identity, matcher collusion/adversarial trader own-result inference, prover/view scope, app/network metadata and external public venue. Source ZK/local proving or onchain atomicity does **not** prove strict private matching. Imported GD2 structural FAIL remains unresolved; no own-result/output-leakage waiver, threat-model narrowing or assumption that MPC/HyperCore fixes it.

Wallet local proof uses real private inputs. Ordinary remote prover sees granted witness, possibly spend-capable secrets; no generic encrypted witness/confidential computing or note-scoped FVK assumed. Never U FVK/spend/master key to S, no server sole key/secret/witness backup. Final Q privately delivered to S discloses locators/cancel option; public hiding proof cannot erase that. Independent U sender output recovery primitive exists, complete eligible payout proof still missing; do not require S to release IVK after payment.

Public statuses/analytics/errors/queues/messages must not expose private PCZTs/P/Q/openings/note/key/FVK/IVK/signing payload/private quote↔source locator map. Job handles/IP/access patterns may correlate even with redaction; private capability/disclosure scope must be reviewed. Public raw chain history is distinct from app-selected private mapping. Public output ciphertext retains metadata/long-term cryptographic exposure and does not recover lost decrypt key.

### External signing/permission model

For separately selected **HyperCore spot**, default is **direct exact per-action user signing**, not broad unattended API-wallet approval. Native venue tooling/account access should continue without Ziquid company, but venue consensus/software/API/issuer/account rules remain required. Core and EVM are distinct execution domains; linked token identity/rounding/account-existence/queued action matters, same L1 is not cross-domain atomicity.

Broad delegated API/agent wallet is **not guaranteed spot-only, no-leverage or incapable of balance movement**; official `agentSendAsset` and account-abstraction permissions illustrate broader surface. Product spot-only backend policy does not cryptographically constrain stolen agent capability. Delegated automation is unselected unless real signer/chain/venue restrictions enforce exact action types/assets/accounts/recipients/caps/fees/expiry/revoke and are qualified. Separate approveAgent/order/cancel/transfer/withdrawal/builder-fee permissions, nonces/env/vault/domain and replay/pruning risks; trade permission is neither withdrawal permission nor absence of other powers. Revocation cannot undo included fills/actions.

LP/1Click/provider route approvals/allowances/custody and agent spending mandates need explicit user choice and enforced scope; no omnibus broad approval or automatic capital migration. Agent default propose→owner approves exact action; unattended execution only under qualified enforced bounds, not this documentation. Legacy ZEC custody still needs actual source signers; proof/relayer substitution cannot replace them.

| Failure/observation | Required consumer behavior |
|---|---|
| Wrong/unsupported route/domain/asset/code/program/beneficiary/fee or native arm invalid | Reject signing/coordination; keep P private. No public/spot/provider/privacy fallback. |
| Incomplete/invalid Q/certificate/dummy/self-output/ciphertext/history | No financial `RecoveryPrepared`/funding prompt; no U FVK workaround or RPC-as-proof. |
| New samechain output not backed up/decryptable/commitment-matching, terms mismatch | Withhold owner authorization; hash-only success insufficient, relayer cannot supply replacement output/fee. |
| Unknown source classifier/hostile input/excess-return capability | Named `EvidencePending`/enablement blocker, no inferred DoesNotPay/full refund/clamp. Partial floor economics are fixed when authenticated. |
| Signing rejected/canceled by owner | No new signed action/send; durable exact no-release state. Native already armed obligation still needs valid resolution, not UI cancel refund. |
| Submitted/final proof or venue action Unknown | Preserve exact signed payload/funding/backing/reservations, reconcile actual source/target/venue effects/fills/positions before retry/new nonce/cancel/release. |
| Transfer/proof/recipient fails/reverts/OOG | Retain exact entitlement/beneficiaries/witnesses and retry conditions; no paid label/redirect/opposite refund. |
| Expiry/ETA crossed/Zoss failure/Delivered | Status-only update, no economic permission. Already valid included payment claim survives. |
| Reorg/restart/new registry/SDK/verifier | Reconcile original funded version/durable records; no duplicate/reinterpretation/auto-reanchor/delete witness or retire rights. |
| Venue/API signer unavailable, broad delegated scope unqualified | Direct owner/native venue path if actually allowed; no invented control/restricted agent guarantee or automatic P2P/spot switch. |

## 6. Dependencies và lifetime

Future SDK consumes [wallet](wallet-authoring.md), [proofs](zcash-proofs.md), [destination](destination-settlement.md) and [solver](solver-operations.md) through reviewed versioned consumer interfaces once real operations exist. UI/package build success does not qualify signer/private proof/client or funded asset path. No Rust binding/WASM choice or TypeScript reimplementation of canonical economics is implied.

Actual Zoss dependency/source acquisition exists in native `zcash`; claiming “no imports/no integration anywhere” is stale. Broader native reusable plumbing and optional non-money transport are separate from nonexistent TS SDK APIs. [Zoss](../../../zoss/docs/ARCHITECTURE.md)/[its register](../../../zoss/docs/BLOCKERS.md) own shared/message readiness; `SourceObservation` ≠ `QuorumAcceptedMessage` ≠ `VerifiedSettlementFact`. No memo/inbox/watcher/IVK/quorum/receipt/runtime/shared viewing daemon required for DEX direct proof; current local EVM needs no Zoss EVM message endpoint. No shared cross-app private store or copied financial authority.

Funded rules/artifacts/data are **original pinned versions**, not registry `latest`: code/program/VK/PK/schema/history/target ABI/asset adapter/root/fee/beneficiary/consumption domains and actual public/private bytes remain usable until actual terminal. New deployment/version/migration is separate owner opt-in, no admin sweep/company allowlist/pause indefinitely vetoing existing exit. Whole dependency graph includes proxy/VK registry/asset issuer/program upgrade/runtime/chain powers; codehash/version string alone not immutable rights. Preserve full authentic history/ciphertexts/root refresh and practical prover resources; hash/CID alone not storage availability, onchain verifier not local circuit/proving key.

Message roster/epoch/revocation/library/SDK update cannot retire funded claims or source-expiry confiscate valid included payment. Source upgrades/Q mineability, chain halt/censorship/finality/history, gas/prover/user secret loss/issuer freeze and external venue controls remain distinct assumptions. No guaranteed matching liquidity or unconditional trustless/private label across all routes.

### Independent manual surface — native acceptance, not TS deliverable

The required standalone native consumer can inspect authentic deployments/assets/rules; import/export/restore encrypted bundles and actual artifact bytes; reconstruct notes/source/target/venue state with independent data; verify owner's granted capability; locally prepare/prove/check authorized action; build exact transaction and simulate; obtain explicit user signer/fee-payer approval; submit via own node/arbitrary selected relay; reconcile actual asset effects/Unknown/retry. These are **interface goals, not commands currently implemented**.

Remove company UI/API/matcher/indexer/prover/artifact CDN/relayer/signers and clean-restore pinned local kit. Qualifying samechain owner can cancel/withdraw remaining backing and execute already fully authorized action; new fills still require owners' fresh exact consent. Native U must complete eligible payout with S offline and S must complete valid source recovery/all-hostile/excess case with U offline, without new company/private witness release. Current full manual/native financial capabilities absent; this remains release blocker, not excuse to defer them to SDK.

External HyperCore owner uses venue-native own signer/tools to inspect/cancel/trade/withdraw under **actual** rights; company-off does not remove venue/issuer dependencies. Legacy custody owner may query/reconcile retained records but missing native custody signers means no unilateral ZEC payout. Public/provider/ZSA lanes need separate exact constructions/support/action approval, no universal manual bridge or new chain selected.

## 7. Acceptance tương lai — REQUIRED, runtime Open

Separate **core/native acceptance now required by design** from **future SDK consumer acceptance**. No tests/builds/UI drills/actions were run in this docs refactor; [status](../NATIVE-IMPLEMENTATION-STATUS.md)/[BLOCKERS](../BLOCKERS.md) retain evidence/gates.

| Scope/scenario | Required observed behavior before that claim |
|---|---|
| Core native independent lifecycle | Actual company-off clean bundle/artifact restore, authentic source/target history, local full proof, direct exact authorized submit and real fixed proportional transfers/retry; U and S independent paths including arbitrary hostile-T/actual source excess return. SDK/UI cannot block it. |
| Core proposed samechain owner | Actual backed ledger/per-owner composition/atomic validator; recipient local exact output/backup/decrypt/commitment check before fresh common-digest fill consent, partial successor/residual cancel race/replay/full-tree/history limits. **Fully authorize → one owner offline → unrelated root churn + tree rollover → other submits exact packet without renewal**; **F1/F2 different fees/relayers/proof representations on shared generation → included cancel → both reject**. Unaccepted/orphan-root, signed-expiry/spent/canceled backing and cross-tree replay negatives, measured unbounded accepted-root costs per [central drills](../SERVER-INDEPENDENCE.md#8-verification-trước-claim-autonomoustrustless-class); offline new-fill limit explicit, no native armed cancel substitution. |
| SDK exact consent/route | Wrong same-looking network/address/ticker/program/asset/terms rejected; no P2P→spot/provider/public switch or broad agent approval from intent; displayed action and enforced signer/domain/fee permissions agree. |
| SDK native state/partial | Full/zero/partial shares agree authentic C and approved floor/dust, earlier P/T/same-effect auth/paying variant no false refund; Unknown/excess/missing capability not terminal. No pure-proof/log/credit/tx hash/Delivered-as-paid. |
| SDK durability/outcomes | Crash/export/sign/send/Unknown/reorg/stale cache/backup restore preserve exact authorization/active TOTAL reservations/consumption; actual source/target/venue reconciliation before retry/cancel/release, no double funding or resurrected fill. |
| SDK external spot permissions | Default direct exact owner signing; if delegation later selected, actual enforced spot/action/cap/recipient/fee/expiry/revoke scope qualified including broader API powers, exact nonces/account/domain, fill-cancel/partial/transfer Unknown and no auto remainder/perps. |
| SDK source/market privacy | No private source locator/key/opening in public status/error/queue/analytics/transport; prover disclosure/own-result/market threat model audited separately. Strict GD2 cannot be labeled passed by consent/samechain/ZK. |
| SDK ETA | Unmeasured no fabricated numeric fallback, real future measurement provenance/as-of/scheduling/reorg invalidation, exceeded estimate changes status only; source/target heights not refund clock. |
| SDK funded lifetime/manual | Old pinned rights/resources still directly consumable after new UI/SDK/verifier release/source expiry; no `latest` reinterpretation/company admission/pause veto, actual local kit and manuals independent of company endpoints. |

**Current gaps:** SDK APIs/bindings and trading frontend integration are not implemented; latest real-journey priority supersedes blanket UI deferral for required integration only. Native financial proof/armed escrow/manual driver, independent all-hostile terminal/excess return, qualified wrapped artifacts/resources/lifetime and genuine samechain funded lifecycle remain missing. Strict GD2 remains blocked and PostgreSQL tests await secure nonlocal configuration. Source authority/codec/tree/calls/inspection existence does not change those gates or authorize funds actions.
