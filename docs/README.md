# Ziquid / Z2Z — tài liệu chung

**Delivery scope — 2026-10-06.** The first passing journey is samechain. Its lane defaults to Base Sepolia by engineering default, not owner approval. The journey covers: `z2z-node` in this repo, P2P discovery, CLI trading, maker online with fresh bilateral consent per fill, full/partial proceeds and remainder, owner-local proving, **full company-off recovery** and real testnet assets.

Releasing the first journey does **not** complete the project. The whole project additionally requires these lanes, all ACTIVE in parallel:
- **L-HEVM:** spot, then isolated position-claim research.
- **L-SOL:** owner-ZK on Devnet.
- **L-NEAR:** native NEAR first, NEP-141 later.
- **L-ZEC:** native ZEC. Wrapped ZEC does not substitute.
- **Cross-chain fills:** every pair.

V2 keeps: GUI, standing-maker offline multi-fill, hardware wallets, mainnet, Intents/1Click, LP/agents/ZSA.

Ziquid là repo gốc; Z2Z là tên sản phẩm hướng tới. P2P là chợ người mua/người bán trong DEX; samechain/crosschain là construction thanh toán, không sản phẩm thay thế P2P. [PRODUCT](PRODUCT.md#p2p-nằm-ở-đâu-trong-dex) giữ product hierarchy và broader vision. V1 scope không chứng minh strict-private matching đã giải, funded lifecycle đã chạy hoặc full protocol đã complete.

## 1. Đọc phần nào cho câu hỏi nào?

| Câu hỏi | Owner |
|---|---|
| Agent phải implement V1 theo instructions nào? | [Z2Z-V1 implementation prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md) — sole active implementation brief. |
| V1 chọn thiết kế gì, build theo dependency nào, acceptance là gì? | [V1 decisions](V1-ARCHITECTURE-DECISIONS.md), [V1 microplan](V1-MICRO-IMPLEMENTATION-PLAN.md) dưới [V1 roadmap](Z2Z-V1-ROADMAP.md), [V1 delivery matrix](V1-DELIVERY-MATRIX.md). |
| Idea sản phẩm, user flows và broader V2 vision? | [PRODUCT](PRODUCT.md). |
| Hệ thống, route authority, onchain/offchain workflows và invariants? | [ARCHITECTURE](ARCHITECTURE.md). |
| Khi company/app/bootstrap mất: giữ dữ liệu nào, restore/prove/sign/submit thế nào? | [SERVER-INDEPENDENCE](SERVER-INDEPENDENCE.md). |
| Module/interface/package và functional contracts ở đâu? | [MODULES](MODULES.md) và [functional specs](#3-functional-specs). |
| Điều kiện còn thiếu trước enable/release? | [BLOCKERS](BLOCKERS.md) — sole readiness/gate register. |
| Native code thực sự đã chạy gì, artifact/resource evidence ở đâu? | [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md) — exercised-evidence ledger. |
| Public hints, durable journals và private custody nằm đâu? | [V1 storage decision](V1-P2P-STORAGE-DECISION.md): mỗi owner tự chạy PostgreSQL (design target), DB chỉ giữ digests; release capsule mã hóa nằm ở local. [SQL-VERIFICATION](SQL-VERIFICATION.md) giữ no-local-SQL hold. |
| Proving options và qualification cần gì? | [PROVING-COST-SOLUTIONS](PROVING-COST-SOLUTIONS.md), [V1 resource targets](V1-RESOURCE-TARGETS.md); targets TBD, số đo thực tế thuộc native status. |
| Primary-source research và dated architecture reasoning? | [Research](#4-research-và-lịch-sử); không competing requirements hoặc release evidence. |
| Kerb import/source cutover, provenance và permissions? | [CONSOLIDATION](CONSOLIDATION.md), [unchanged import archive](imports/kerb/README.md). |

Thứ tự đọc: **V1 delivery matrix → PRODUCT → ARCHITECTURE → MODULES → V1 prompt → V1 microplan → BLOCKERS/native status**, rồi recovery, SQL và relevant research/module contracts. Dated spec/plan không thay active V1 instructions; unchecked historical tasks không được coi đã complete.

## 2. V1 docs

| Document | Vai trò |
|---|---|
| [V1-ARCHITECTURE-DECISIONS](V1-ARCHITECTURE-DECISIONS.md) | P2P/CLI release decisions, boundaries và unresolved choices. |
| [V1 roadmap](Z2Z-V1-ROADMAP.md) | Existing top-level todo owner và retained V2 lane; phase là scope bucket, không strict numeric execution order. |
| [V1 micro-implementation plan](V1-MICRO-IMPLEMENTATION-PLAN.md) | Detailed task IDs/dependencies: pre-funding proving/cold restore và specifically authorized deployment phải có trước funded acceptance; không second todo/status register. |
| [V1-DELIVERY-MATRIX](V1-DELIVERY-MATRIX.md) | Required delivery scope/acceptance; requirements không phải passing evidence. |
| [Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md) | Sole active engineering prompt. |
| [V1 consolidated summary](V1-CONSOLIDATED-SUMMARY.md) | Scope summary; không second gate hoặc checkpoint register. |
| [Proving cost solutions](PROVING-COST-SOLUTIONS.md) | Owner-local, zero-paid-service options và measurement requirements; không hardware guarantee. |
| [V1 P2P protocol spec](V1-P2P-PROTOCOL-SPEC.md) | Candidate wire/coordination construction; public-field gossip chỉ generated non-secret tests, private-market release blocked pending field-by-field disclosure/backing review. |
| [V1 storage decision](V1-P2P-STORAGE-DECISION.md) | Public hints / PostgreSQL journal per owner (digests only) / private encrypted files và release capsule; SQL execution held. |
| [V1 resource targets](V1-RESOURCE-TARGETS.md) | Whole-prover và node measurements; không measured target-hardware feasibility, no-proof fallback hoặc silent downgrade. |
| [V1 testnet selection](V1-TESTNET-SELECTION.md) | Exact network/asset qualification candidates; không deployment/signing/funds approval. |
| [Phase 0 research 2026-10-06](research/2026-10-06-phase0-durability-recovery.md) | Domain reports: [durability-recovery](research/2026-10-06-phase0-durability-recovery.md), [coverage-invariants](research/2026-10-06-phase0-coverage-invariants.md), [private-discovery-network](research/2026-10-06-phase0-private-discovery-network.md), [testnet-prover-policy](research/2026-10-06-phase0-testnet-prover-policy.md). Proposed mechanisms, không phải evidence. |
| 2026-10-06 specs/plans | [Independent owner Fill2 spec](superpowers/specs/2026-10-06-independent-owner-fill-design.md)/[plan](superpowers/plans/2026-10-06-independent-owner-fill.md); [private snapshot spec](superpowers/specs/2026-10-06-samechain-private-snapshot-design.md)/[plan](superpowers/plans/2026-10-06-samechain-private-snapshot.md) (generated-key library + clean-process restore implemented; focused and serialized SQL-off workspace evidence in [native status](NATIVE-IMPLEMENTATION-STATUS.md)); [release lifecycle spec](superpowers/specs/2026-10-06-samechain-release-lifecycle-design.md)/[plan](superpowers/plans/2026-10-06-samechain-release-lifecycle.md) (rev3 guard/capsule/journal source implemented; focused negatives, both scoped source reviews and default-workspace1120checks/93suites/2ignored passed; SQL behavior NOT RUN, genuine wrapped capsule/export positives BLOCKED; not complete P3.08 or financial acceptance). |

```text
Owner-local node + secrets/recovery data + local proving/signing
  -> exact authorized transition
  -> samechain verifier / onchain asset authority
  -> actual asset arrival + durable reconciliation

Replaceable peers/bootstrap/discovery/relay
  -> coordination only, never money authority or mandatory exit approval
```

Weak-hardware node consumption và whole-prover consumption phải được đo riêng; targets TBD. Witness không được upload cho paid/cloud/shared prover hoặc exchange giữa peers, kể cả encrypted. Separate bounded volatile public hints, owner-local encrypted files và public durable journal: owner đã chọn mỗi owner tự vận hành PostgreSQL, mặc định trên owner node, chỉ giữ digests/identities; executable bytes ở encrypted release capsule. Đây là design selection, không install/service/SQL-execution permission, không SQLite fallback hoặc private custody SQL. Existing journals/sidecars, ELFs, proof/setup identities, signed/funded artifacts và no-local-SQL restrictions vẫn được giữ.

Public-field gossip chỉ là **non-secret generated test construction**, blocked cho private-market release pending field-by-field disclosure/inference và backing/ownership/current-spentness review. Root/vault balance/signature không proof backed order. Bilateral coordination phải assemble identical exact public output-descriptor packet trước cả hai role proofs; secrets/openings/private terms/witnesses ở owner-local. Permissionless certificate export tạo exposure đến chain-enforced expiry hoặc finalized shared-capability consumption/invalidation; ACK/timeout không revocation/unlock, pending `Unknown` vẫn phải reconcile. Full/partial/remainder và full recovery là V1 required, không deferred.

Current [reviewed Fill2 construction](superpowers/specs/2026-10-06-independent-owner-fill-design.md) and [source contract](modules/zcash-proofs.md#samechain-relation-and-authority-source--no-native-source-proof-substitution) replace the historical whole-Terms/common-blind gap with frozen packet/public E/ordered A+B opaque leaves/private per-owner own_salt. Active review is `review-fill --packet FILE --execution FILE --role a|b --witness-stdin` with independently approved canonical execution frame2. Guest mode0 carries only byte0 + OwnerWitness frame2; non-fill/note/tree/schema/outer journal stay1. New ELF/program needs authorized new immutable authority and genuine all-mode qualification; preserve original fill1 artifacts, no conversion/migration. [Checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) owns current native/CPU/correspondence and completed source-review evidence, not independently qualified source/setup/program/wrapping/funded/backup/privacy. E quantities are counterparty-visible.

## 3. Functional specs

- [Wallet authoring](modules/wallet-authoring.md): owner secrets/local proving, native P/Q, independent witnesses, recovery bundles và authorization release.
- [Proofs](modules/zcash-proofs.md): native full-history/payment/classification/uniqueness; separate samechain ownership/conservation/order/recovery relations.
- [Destination](modules/destination-settlement.md): immutable funded authority, exact verification/consumption/transfer, native escrow và samechain cancel/fill.
- [Solver operations](modules/solver-operations.md): quote/Q/prover/relay workers, capacity, `Unknown`, reconciliation và signer isolation.
- [Client SDK](modules/client-sdk.md): retained future UI/SDK contract; GUI/bindings không V1 critical-path substitute cho native CLI delivery.

Canonical core files giữ stable paths: PRODUCT, ARCHITECTURE, MODULES, SERVER-INDEPENDENCE, BLOCKERS, NATIVE-IMPLEMENTATION-STATUS, SQL-VERIFICATION, CONSOLIDATION và ZOSS-OVERVIEW. Native S/P/M gates vẫn là native gates; samechain V1 không redefine/close chúng. Strict GD2 structural failure không được waiver bởi P2P transport hoặc bilateral safe settlement.

## 4. Research và lịch sử

### Research — nguồn, lập luận và counterexamples

- [Server-independence research](research/SERVER-INDEPENDENCE-RESEARCH.md): recovery data/proof resources, immutable funded-version lifetime và source-ledger limitations.
- [Crosschain/market research](research/CROSSCHAIN-MARKET-RESEARCH.md): nguồn cho route/consensus/venue/strict-privacy; làm nền cho các lane cross-chain/L-ZEC đang ACTIVE.
- [Settlement research](research/SETTLEMENT-RESEARCH.md): historical alternatives, paying-conflict/exclusion/refund counterexamples; không active construction approval.
- [Architecture audit](research/ARCHITECTURE-AUDIT.md) và [architecture review](research/ARCHITECTURE-REVIEW.md): dated findings/model ceilings; không runtime/security certification.
- [Zoss overview](ZOSS-OVERVIEW.md): dated shared-library/messaging snapshot. Live seam ownership thuộc MODULES/ARCHITECTURE; maturity phải đối chiếu actual source/status.

### History — superseded prompts, reports và discussion

- Superseded prompts: [original native ZIQUID brief](history/ZIQUID-IMPLEMENTATION-SYSTEM-PROMPT.md), [expanded Z2Z brief](history/Z2Z-IMPLEMENTATION-SYSTEM-PROMPT.md). **Không dùng làm active implementation instructions.**
- Dated reports: [progress 2026-10-04](history/PROGRESS-2026-10-04.md), [status/progress 2026-10-05](history/STATUS-AND-PROGRESS-2026-10-05.md). Current exercised evidence thuộc native status; không cộng independent test totals.
- [Archived product/frontend handoff](history/PRODUCT-OVERVIEW-AND-FRONTEND-HANDOFF.md): complete 71-story record; current product authority là PRODUCT, GUI belongs to later production và sibling frontend vẫn user-owned.
- [Completed integration review](history/IMPLEMENTATION-INTEGRATION-REVIEW.md): dated source-discovery baseline/hazards, không new V1 build order.
- [Orderbook/onchain-rights brainstorm](history/BRAINSTORM-2026-10-05-ORDERBOOK-AND-ONCHAIN-RIGHTS.md): saved ideas/owner discussion, không expansion authorization.
- [Pre-redesign architecture](history/2026-10-02-pre-redesign-ARCHITECTURE.md), [module snapshot](history/2026-10-02-pre-redesign-MODULES.md), [snapshot manifest](history/2026-10-02-pre-redesign-MANIFEST.json): immutable historical bytes. Internal old-layout links intentionally remain frozen; the [snapshot link inventory](history/SNAPSHOT-LINK-INVENTORY.md) records all affected destinations and working current replacements.
- Retained design/provenance records: [server-independent redesign](superpowers/specs/2026-10-02-z2z-server-independent-architecture-design.md), [integration design](superpowers/specs/2026-10-03-z2z-implementation-integration-design.md), [integration plan](history/plans/2026-10-03-z2z-implementation-integration.md), [native design](superpowers/specs/2026-10-01-native-protocol-implementation-design.md), [native plan](history/plans/2026-10-01-native-protocol-implementation.md). Historical approval preserves only its original scope.
- Other archived dated plans: [workspace frame](history/plans/2026-10-01-ziquid-workspace-frame.md), [architecture documentation](history/plans/2026-09-28-architecture-doc.md). All four local dated execution plans live under `history/plans/`; original checklists remain historical, not V1 progress.
- [53 imported Kerb docs](imports/kerb/README.md) retain their original tree, MANIFEST hashes and link report; import/source-reported results are not newly exercised integrated evidence.

Zoss [architecture](../../zoss/docs/ARCHITECTURE.md), [readiness](../../zoss/docs/BLOCKERS.md), [DEX boundary](../../zoss/docs/private_dex.md) và [Kerb source contract](../../zoss/docs/kerb.md) remain independently owned. Source observations/quorum receipts are non-money; they do not establish payout/refund/entitlement correctness.

## 5. Current implementation instruction

**Current implementation instruction — 2026-10-06:** follow the [Z2Z-V1 implementation prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md), [actual microplan](V1-MICRO-IMPLEMENTATION-PLAN.md) dependencies and existing [V1 roadmap](Z2Z-V1-ROADMAP.md). Start existing owner-local proving qualification within authorized scope; documentation updates do not complete Phase 0 or establish measured execution. Autonomous technical execution does not grant external-action permissions. Real proving, backed P2P CLI full/partial trading and full company-off recovery are V1 acceptance, not observation-only substitutes. Only BLOCKERS and the checkpoint own readiness/exercised closure; this README is navigation, not another status register.

No signing/broadcast/deploy/funding/mainnet/new viewing party/publication/commit/push or operational data migration authorization follows from these documents. PostgreSQL-only/no-local-SQL-test hold remains until explicitly superseded; credentials/private witnesses remain private. Contract/circuit existence is not regulatory immunity, canonical-chain proof, asset arrival or full terminal recovery.
