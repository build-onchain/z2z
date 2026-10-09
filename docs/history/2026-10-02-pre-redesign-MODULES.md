# Ziquid — protocol monorepo, module map và ownership

**Native protocol implementation đang chạy; settlement proof/escrow chưa complete.** User approved [design](../superpowers/specs/2026-10-01-native-protocol-implementation-design.md)/[plan](../superpowers/plans/2026-10-01-native-protocol-implementation.md): full validating source proofs, proportional settlement, one-note/one-obligation in one EVM deployment; SDK/UI/bindings deferred. [Observed status](../NATIVE-IMPLEMENTATION-STATUS.md) sở hữu current runnable inventory/evidence, gồm native P/Q/subrelations/durable journal, EVM allocation/base verifier và actual `zoss-zcash` acquisition; không full financial verifier/escrow/destination client. Gates Open/Blocked. Earlier frame/docs-only authorization là lịch sử; sign/broadcast/deploy/fund/new-viewer/Git actions vẫn chưa authorize.

**Expanded Ziquid, future Z2Z — docs-only 2026-10-02:** [PRODUCT](../PRODUCT.md) sở hữu phạm vi sản phẩm, [CONSOLIDATION](../CONSOLIDATION.md) import/route decisions; [ARCHITECTURE](../ARCHITECTURE.md) behavior, file này packaging/ownership, [BLOCKERS](../BLOCKERS.md) readiness. [Kerb archive](../imports/kerb/README.md) giữ docs/source-reported evidence, không Kerb packages/code hoặc local readiness trong repo này. Market/credit/custody/external venue/user-proof responsibilities mới bên dưới **proposed, chưa package/process assignment**; không implementation authorization hoặc thay native M1–M5.

## 1. Quyết định chia module

Chọn **một protocol monorepo với native Rust core Cargo workspace**, TypeScript SDK và chain-specific contracts có builds riêng trong cùng repo. **UI ở repo riêng chưa đặt tên; [Zoss](../../../zoss/docs/ARCHITECTURE.md) là external shared native cross-chain core với messaging profile/runtime tùy chọn, phát triển độc lập.** Reuse thực tế trong [status](../NATIVE-IMPLEMENTATION-STATUS.md) và proposed common roles ở §1.3 không chuyển DEX proofs/economics/keys/state sang Zoss hoặc tạo một service/repo cho mỗi module. Một module logic không bắt buộc một crate/process/repo.

**Tên/namespace hiện tại giữ Ziquid:** Rust `ziquid-*`, TypeScript `@ziquid/sdk`; packages private/unpublished, repo `ziquid-dex`. **Z2Z chỉ là tên sản phẩm tương lai** theo [PRODUCT](../PRODUCT.md), không code/package/repo rename hoặc registry/domain/trademark availability claim. Không đổi UI/Zoss/Kerb namespaces từ hợp nhất docs.

| Functional module | Code responsibilities | Path / ownership đề xuất | Tài liệu |
|---|---|---|---|
| Wallet authoring/authorization | Unsigned P, locally proved executable Q, user-owned signing/scanning/note witness và payout witness | `crates/zcash`; wallet-local caller compose proof functions khi cần, reuse upstream wallet/crypto | [wallet-authoring](../modules/wallet-authoring.md) |
| Zcash settlement/proofs | Transaction/payment/history circuits, witness preparation, prover và verifier artifacts; source parsing/scanning/witness integration | `crates/proofs` + `crates/zcash`, internal; không evidence/audit project riêng | [zcash-proofs](../modules/zcash-proofs.md) |
| Destination statement verifier | Target-specific proof/domain/version verification | `contracts/evm`, `contracts/solana`, `contracts/near` theo target được chọn; proof artifacts do `crates/proofs` sở hữu | [destination-settlement](../modules/destination-settlement.md) |
| Economic escrow | Fund obligation, fixed beneficiaries, once-only payout/refund và retryable actual transfers | DEX-owned chain contract packages; off-chain clients ở `crates/chains` | [destination-settlement](../modules/destination-settlement.md) |
| Solver/relayer operations | Quote, durable inventory/funding persistence, Q execution, proof jobs, reconciliation | `crates/runtime` orchestrates `zcash`, `proofs`, `chains`; signer tách low-privilege workers | [solver-operations](../modules/solver-operations.md) |
| Client SDK + intent/order coordination | Intent/quote disclosure, wallet integration, observations/recovery ETA | TypeScript `packages/sdk`, build riêng nhưng cùng monorepo; không server key custody | [client-sdk](../modules/client-sdk.md) |
| UI | Presentation và client interaction qua SDK/wallet | Repo riêng chưa đặt tên; không nằm trong core workspace | [client-sdk](../modules/client-sdk.md) |
| Zoss shared core / optional message profile | Actual acquisition seam qua `zoss-zcash`; common domain/encoding/client reuse theo exports được kiểm tra; separately optional non-money messages, không funds authority | External independently developed infrastructure; [status](../NATIVE-IMPLEMENTATION-STATUS.md) phân biệt integration thật và broader Proposed reuse | [Zoss architecture](../../../zoss/docs/ARCHITECTURE.md), [DEX integration](../../../zoss/docs/private_dex.md), [readiness register](../../../zoss/docs/BLOCKERS.md) |
| Market admission/eligibility — proposed | Exact pair/domain/asset/units, claimant/order authority, funded collateral/accepted policy; eligibility/input certificate trước matching | App-owned logic; **chưa chọn package/process**, không import FAA/MPC service hoặc public identity map | [ARCHITECTURE §4.1](../ARCHITECTURE.md#41-market-accounting-custody-và-user-proof-intake--proposed), [CONSOLIDATION](../CONSOLIDATION.md) |
| Private matching — proposed, Blocked | Admitted funded orders → complete authenticated allocation theo approved feasible mechanism/strict privacy contract | App-owned; packaging/backend chưa chọn. Known imported **GD2 structural FAIL**, không own-result waiver hoặc matcher-threat-model change | [ARCHITECTURE §9](../ARCHITECTURE.md#trust-privacy), [strict-privacy evidence](../imports/kerb/docs/reviews/2026-10-02-strict-privacy-feasibility.md) |
| Funding credit/holds/entitlement journal — proposed | App-verified claimant/history/controlled inventory → durable unique credit, maximum holds, disjoint liabilities/portions, immutable epoch activation/reconciliation | App owns schema/authorization/replay; storage/process undecided, không chuyển Kerb Postgres ledger vào native SQLite inventory | [ARCHITECTURE §4.1](../ARCHITECTURE.md#41-market-accounting-custody-và-user-proof-intake--proposed), [imported safety design](../imports/kerb/docs/docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md) |
| Market custody/effect/recovery — proposed | Designated acquisition/viewing, exact physical input/recipient/change/fee checks, authorized native intents và actual outcome reconciliation | Privilege/view/spend ownership phải design riêng; native threshold signer không business authorizer/matcher. Kerb implementation vẫn external | [ARCHITECTURE §4.1](../ARCHITECTURE.md#41-market-accounting-custody-và-user-proof-intake--proposed), [Kerb checkpoint](../imports/kerb/docs/README.md#implemented-local-safety-cores-2026-10-02) |
| Explicit external HyperCore spot — proposed, hướng B | Separately consented account/market/limits/fee/action signing → exact open/partial/fill/cancel/Unknown reconciliation; transfer là action riêng | External venue interface chưa chọn API/CoreWriter/custody/package; riêng hướng A Hyperliquid assets trong P2P, không reuse reservation/receipt | [ARCHITECTURE](../ARCHITECTURE.md#product), [imported venue evidence](../imports/kerb/docs/product/17-HYPERLIQUID-EXPANSION.md) |
| User-submitted proof intake — future/proposed | Untrusted versioned proof/context → app-specific verification và authorized credit/native-target submission tương ứng | Producer có thể user; verifier/app vẫn sở hữu relation/claimant/history/inventory/uniqueness. Không package mới/custody removal/financial constructor | [ARCHITECTURE §4.1](../ARCHITECTURE.md#41-market-accounting-custody-và-user-proof-intake--proposed), [PRODUCT](../PRODUCT.md) |

**Core, SDK và contracts thuộc `ziquid-dex`; UI và Zoss phát triển ở repo/project riêng.** Upstream wallet/node/crypto/proving và actual selected Zoss code là external dependencies, không DEX-owned projects; broader reuse remains Proposed theo current exports/readiness. Ziquid owns financial schema/authority: protocol rules, app proofs/credit/hold/entitlement semantics, target verification/allocation/actual transfer. Expanded module rows không chọn crate/database/deployment hoặc copy Kerb implementations; imported local safety không integrated private market. Không tách settlement/proofs thành external project hoặc thay native paths.

<a id="11-layout-đã-duyệt--frame-hiện-tại"></a>

### 1.1 Layout đã duyệt — package map, không readiness

Frame-only layout 2026-10-01 là checkpoint cũ; mô tả dưới đây tham chiếu [current status](../NATIVE-IMPLEMENTATION-STATUS.md), không copied test inventory hoặc complete support map.

```text
ziquid-dex/
  Cargo.toml                 native Rust core workspace
  crates/
    protocol/                checked amount/context/encoding/allocation; pure native rules
    zcash/                   upstream P/Q authoring/witnesses; limited Zoss acquisition
    proofs/                  actual source/body/crypto subrelations và native/SP1 guests; incomplete full proof
    chains/                  destination-client slot; no implemented financial client
    runtime/                 native allocation CLI, private SQLite journal và encrypted P/Q custody
  packages/
    sdk/                     empty @ziquid/sdk surface; separate TypeScript build
  contracts/
    evm/                     Foundry allocation và pinned base verifier; no DEX escrow/actual transfer
    solana/                  independent empty target Cargo workspace; no program
    near/                    independent empty target Cargo workspace; no contract
  docs/                      canonical owners, functional specs và imports/kerb/ archive (docs only)
```

Root native Cargo workspace chỉ gồm năm core crates; Solana và NEAR Rust contract workspaces **độc lập root native build**, không kéo target/runtime dependencies vào core workspace. Solidity EVM và TypeScript SDK không Cargo members. Contract builds tách theo chain **trong cùng monorepo**, không ba repos mới. Actual code/phạm vi còn thiếu thuộc [status](../NATIVE-IMPLEMENTATION-STATUS.md): local cryptography/subrelations/journal/allocation/base verifier không complete DEX proof/escrow hoặc target support. Kerb source code không xuất hiện trong tree; consolidation không tạo empty future packages hoặc chạy target builds.

**Path không phải support claim:** chọn chain package khi route cần và target verifier/asset/runtime gates đạt. EVM local native-asset escrow là initial candidate; Base Sepolia staging cần authorization riêng. Solana vẫn candidate. `contracts/near` chỉ layout slot, **không newly approved NEAR settlement route hoặc 1Click adapter**, không route-ready. Không build mọi target chỉ để chứng minh tree.

### 1.2 Core crate dependency map — acyclic

Arrow `A -> B` là intended module dependency direction, không chứng minh mọi API/import đã triển khai. Current upstream/proving/cohort và actual Zoss acquisition thuộc [status](../NATIVE-IMPLEMENTATION-STATUS.md); reuse thêm chỉ theo §1.3 với đúng exports/policy/readiness và approval riêng. Không suy release/MSRV/proving/backend/chain support từ layout; giữ coherent pins và funded artifacts.

```text
runtime  -> protocol, zcash, proofs, chains
zcash    -> protocol + cần thiết upstream wallet/transaction/tree libraries
proofs   -> protocol + cần thiết upstream cryptography/consensus/proving primitives
chains   -> protocol + cần thiết destination client libraries
protocol -> không core crate khác; pure rules/encoding, không network/storage/worker I/O
```

`zcash`, `proofs`, `chains` không import lẫn nhau hoặc `runtime`; shared DEX context/witness encoding đi qua `protocol`, caller compose outputs. `protocol` giữ app schema/rules trên common domain/encoding primitives nếu reuse; `zcash` giữ P/Q authoring và note-witness integration trên source acquisition library; `proofs` vẫn sở hữu circuit witness preparation/constraints/proving/history strategy/verifier artifacts; `chains` giữ exact app call construction/funding/transfer semantics trên genuinely common client plumbing nếu có. `runtime` compose source data → proof → destination submission và giữ durable operator state; không mandatory dependency vào Zoss runtime.

**Wallet-client seam:** user-controlled wallet/local prover compose `zcash` + `proofs`, giữ U spending/viewing keys, note reservations/release records và `PayoutWitnessU`; không cần chạy solver runtime hoặc gửi keys/FVK tới S. Runtime chỉ nhận authorized/redacted artifacts và granted task witnesses. TypeScript SDK dùng versioned wire contracts và wallet interfaces; Rust↔TS binding/transport (kể cả WASM) **chưa chọn**, không giả có bridge đã viết. Target contracts consume pinned statements/proof artifacts, không import native solver/worker/node stack; target-safe shared encoding phải giữ cùng protocol version.

Năm native specs là functional roles, không năm new services/repos: wallet → `zcash`; settlement/proofs → `proofs` + `zcash`; destination → chain contracts/`chains`; solver → `runtime`; SDK → `packages/sdk`, deferred. Native design/plan đã được duyệt, không còn frame-only ceiling. Consolidation chỉ docs; không authorize new market packages/custody/targets, sign/send/deployment/funding hoặc Git actions.

<a id="13-external-zoss-shared-core--proposed-library-reuse"></a>

### 1.3 External Zoss shared core — actual acquisition và proposed reuse

**Docs direction 2026-10-01, actual acquisition checkpoint ghi riêng.** [Zoss shared-native-core](../../../zoss/docs/ARCHITECTURE.md#31-shared-native-core) và [package map](../../../zoss/docs/ARCHITECTURE.md#42-package-repository-and-process-map) là authority của external owner. DEX đã reuse `zoss-zcash` source acquisition theo [status](../NATIVE-IMPLEMENTATION-STATUS.md); coarse common `protocol`/`zcash`/`chains`/`runtime`, target-safe Solana message build và SDK direction không tự chứng minh broader exports/integration/support. Native Ziquid packages ở §1.1 giữ nguyên; Zoss release/receipt không market/native financial authority.

| Shared responsibility / seam | DEX consumer / output | Authority vẫn ở DEX / không suy ra |
|---|---|---|
| Common domain/canonical encoding/authorization primitives — broader reuse Proposed | `protocol` binds app-defined `StatementContext`, signing/digest inputs và version domains | DEX native/payment/allocation và future market/credit/hold/entitlement schema; explicit algorithm/domain, không universal `verify` boolean. Ordinary wallet/Solana Ed25519, Arcis SHA3-512 certificate, native SpendAuth/FROST và HyperCore action-signing roles không interchangeable; helper không governance/key authority. |
| Real upstream source acquisition/parse/decrypt — actual limited `zoss-zcash` seam | `zcash` dưới wallet/solver-owned caller thu raw full block, feeds stronger DEX structural relation với policy-labelled observation; exact limits trong [status](../NATIVE-IMPLEMENTATION-STATUS.md) | Observation không valid accepted-history/effect/auth/ownership/net-payment proof hoặc market funding credit. P/Q/local proving/U witness/source-history strategy vẫn DEX-owned; NU6.3 acquisition không genesis-era support. |
| Genuinely common off-chain chain clients | `chains` có thể reuse pinned RPC/submission/inclusion observation mechanics khi actual common implementation tồn tại | DEX exact call/accounts, signer/fee payer, code/config/finality policy, proof verifier và native transfer/allocation. Local EVM không cần Zoss EVM message endpoint hoặc inferred EVM/Base transport support. |
| Optional message profile/runtime + Solana message contract | Separately selected `MessageTransport`/`QuorumAcceptedMessage`, non-money metadata only | Không dependency của direct source financial proof; không convert app proof thành receipt hoặc import watcher/runtime vào wallet/on-chain DEX build. |

Library consumers không cần Zoss memo/envelope, inbox, watchers, IVK/quorum, receipt hay shared daemon. Acquisition với caller-owned viewing capability chạy trong đúng app-owned process; không tạo viewing party mới, shared IVK/FVK/key store hoặc cross-app witness/cache. U vẫn locally prove complete Q, S chỉ nhận executable packet **không user FVK/spend key**; `PayoutWitnessU` private/durable phía U. Public raw data reuse phải pin network/branch/history provenance, private payment mappings/witnesses/key material cách ly.

`SourceObservation` ≠ `QuorumAcceptedMessage` ≠ target-specific `VerifiedSettlementFact`; không automatic promotion, trust-level ordering hoặc fallback. DEX circuits/proofs đi trực tiếp DEX target verifier, sau actual context/history/classification/uniqueness verification mới financial allocation. [Shared-library readiness](../../../zoss/docs/BLOCKERS.md#7-shared-library-readiness), message G/Z/rejected B register và DEX M/S/P là acceptance riêng; consumer không nhân bản IDs/status/closure table của Zoss. Chưa gate nào closed bởi docs adoption.

### 1.4 Expanded modules không đồng nghĩa expanded packages

Market admission/matching, funding credit/holds/entitlement, custody và external venue là responsibility contracts, không quyết định copy `kerb-*` crates, Postgres, Arcis, FAA/FROST services hay Solana program vào tree. Native modules giữ acyclic map §1.2; package/process/database choice cho lane mới cần reviewed design/authorization riêng. [CONSOLIDATION](../CONSOLIDATION.md) ghi scope/import/route status; [PRODUCT](../PRODUCT.md) ghi product direction, không tạo second architecture hay implementation plan tại đây.

Library sharing không hợp nhất private state: wallet U sở hữu spending/viewing keys và independent payout witness; solver sở hữu Q custody/inventory; future designated market viewing/custody/eligibility sở hữu capability riêng, **matcher không thừa hưởng**. Credit issuance, hold/epoch/portion replay, native intent/input/nonce tombstones, external Core order reservation và optional message receipt ledgers riêng. Các schemas phải bind exact app/domain/version/authority; không cast một fact hoặc receipt sang fact của app khác. No shared IVK/FVK/private witness store, public source↔order map hoặc mandatory shared daemon.

Imported [Kerb local safety evidence](../imports/kerb/docs/README.md#implemented-local-safety-cores-2026-10-02) là source-reported về external implementation, không build/run được xác nhận ở Ziquid hoặc funded-private capability. Historical public-Solana/Oct1 candidates giữ trong archive; **GD2 structural FAIL** không waived, local safety không feasible strict-private auction. HyperCore public execution và future user proof không đổi threat model hoặc bỏ ZEC custody; A P2P asset extension, B external spot và native P/Q path phải được qualify riêng.

## 2. Interface shared — conceptual, không phải SDK đã viết

`StatementContext` phải có một versioned encoding/relation duy nhất dùng bởi wallet, solver, prover và destination verifier. Native encoding/context checks đã có theo [status](../NATIVE-IMPLEMENTATION-STATUS.md), nhưng field/hash/commitment names **không** prove semantic openings, authenticated history/payment/ownership, hiding hoặc uniqueness. Future market funding/order/hold domains không alias native DEX context hoặc Zoss receipt context.

| Nhóm | Binding REQUIRED |
|---|---|
| Source | Network, **Ironwood pool**, consensus branch/transaction format, authenticated checkpoint state, accepted-history/competing-chain/finality policy; exact effect/authentication rules |
| Payment | `sourcePaymentCommitment`, `realInputCommitment`, authenticated **COMPLETE real-input set/ownership** và zero-dummy constraints; exact/supported receiver/value/ciphertext; gross-vs-net predicate: initial all real inputs U-owned, no S/third-party/other-pool/transparent funding; consensus expiry. S-funded support sau này cần quote-bound authenticated solver funding scope/debits, fee policy và independent U proof privacy |
| Order/destination | `orderId`, destination chain/deployment/code/verifier identity, asset/amount, fixed U payout/S refund beneficiaries; order/source-payment consumption relation |
| Proof lifetime | Schema/proof program/verifying-key/version; immutable rule pinning cho funded orders, prover dependencies và recovery support lifetime |
| Economics/privacy | Agreed source/destination fees, Q cancellation capability, disclosure/proving policy, payload visibility; no private opening/FVK/spend material in public queues/logs |

| Artifact/fact | Producer → consumer | Meaning / không được suy ra |
|---|---|---|
| `UnsignedPaymentP` | Wallet → solver/proof implementation | Exact/redacted effects; **không real P SpendAuth**. Quote signature không payment authorization |
| `ExecutableSelfSpendQ` | Wallet → solver | Locally proved, fully authorized self-spend packet trên agreed accepted anchor; SAME real input, all nonzero outputs U-owned, agreed fee. Không gửi user FVK/spending key. **Không tự reanchor/reprove** |
| `PayoutWitnessU` | Wallet → user-controlled proving path | Durable independent sender/effect/ciphertext evidence; U không cần S đưa IVK/proof sau khi đã trả |
| `SourceObservation` | Caller-owned source acquisition → DEX proof/witness preparation | Parsed/decrypted data + explicit provenance/policy; không canonical validity, input ownership hoặc payment proof |
| `PaymentIncluded` | Proof implementation → destination verifier | Authenticated exact/supported-class payment fact trên accepted valid finalized history; mere txid inclusion không đủ effect/ciphertext validity |
| `ValidConflictingSpendIncluded` | Proof implementation → destination verifier | Valid T tiêu thụ authenticated real input của P; cùng source pool/network/history. `T != P` **chỉ exclude exact P**, không proof mọi payment to S absent |
| `PaymentClassification` | Payment circuit → app-specific allocation | `PaysObligation` / `DoesNotPayObligation` / `Unknown`; incoming outputs chỉ gross credit, không net consideration. COMPLETE input ownership/no-S-input hoặc supported authenticated debit relation REQUIRED. Same-effect/new-auth vẫn P; proportional arithmetic đã có nhưng complete arbitrary-T classification và excess source return chưa established |
| `VerifiedSettlementFact` | Target-specific verifier → economic escrow | Context/statement/uniqueness checks đã thực hiện theo selected verifier policy. Đây proposed verified-result contract, không generic boolean từ RPC/quorum |
| `QuorumAcceptedMessage` / optional `MessageTransport` | Zoss message profile → SDK/non-money app | Exact route/quorum acceptance theo disclosed message policy, không `PaymentIncluded` hoặc `VerifiedSettlementFact`; không financial authorization |
| `RecoveryEstimate` | Observer/SDK → user | Estimate/unknown/pending cùng provenance, không refund permission |
| Funding evidence / user-submitted proof — future/proposed | App-owned acquisition hoặc user evidence producer → app funding verifier | Exact versioned context/statement; untrusted bytes. Event/ciphertext/inclusion proof không tự claimant authority, controlled inventory hoặc credit |
| Funding credit — market Proposed | App funding verifier + durable issuance journal → available credit/hold accounting | Claimant/receiver/value/stable occurrence/history và controlled unallocated backing đã phải agree; durable dedup. Không `VerifiedSettlementFact`, custody permission hoặc completed payment |
| Admission hold / allocation / entitlement — market Proposed | Admitted fully reserved orders + complete authenticated activated result → disjoint liability portions | Full maximum debit/quantity retained; immutable epoch disposition, once-only portion rights. Chunk/ACK/timeout không đủ refund; entitlement chưa actual asset transfer |
| Custody effect approval / signed intent / observed transfer — market Proposed | Independent policy/physical-inventory checks → designated signer → exact source/destination reconciliation | Ba quyền/trạng thái khác nhau; business ACK hoặc PCZT effect check không spend signature/mined payout. Input/change/nonce locks retained khi live/Unknown |
| External venue order/fill — HyperCore Proposed | Separately authorized exact action → venue reconciliation | Core account/token/domain/order identity; fill không P2P allocation/native payment hoặc Solana receipt. Partial/cancel race/Unknown giữ exclusive capital reservation |

**Fail-closed:** có conflict nhưng classification/ownership/canonicality/uniqueness chưa prove thì `EvidencePending`, không fabricate nonpayment. Exact P/Q experiment chưa complete hostile-wallet protocol; unsupported T là reachable case phải công bố và giải trước release, không bỏ khỏi acceptance bằng input guard giả.

**M3 gross-vs-net / no-S-input hoặc debit gate:** initial meaningful-payment path dùng cùng một real U note; authenticate COMPLETE set mọi real input U-owned, không S-owned/third-party funding, không hidden inputs ở pool khác/transparent; dummy zero inputs cần authenticated constraints. Input completeness/ownership chưa biết → `Unknown/EvidencePending`, không `DoesNotPayObligation`. Mixed-input T vẫn reachable hostile case, wallet policy guard không loại khỏi release acceptance. Hỗ trợ S-funded T cần quote-bound authenticated ownership/debit relation theo explicit fee policy, U tự prove với privacy không phụ thuộc S giữ witness. Supported authenticated `0 <= C <= A` proportional allocation đã được duyệt; arbitrary-T relation, independent hostile-spend terminal recovery và actual S-authorized source return khi `C>A` còn thiếu theo [native blockers](../NATIVE-IMPLEMENTATION-STATUS.md#concrete-blockers-to-the-entire-protocol), không partial/gift/full-refund shortcut. [Zcash settlement/proofs](../modules/zcash-proofs.md) sở hữu relation chi tiết.

## 3. Flow và state ownership

1. U và S chốt exact intent/quote/context; một existing real owned/available Ironwood note là initial feasibility requirement, không claim generated fixture chain-valid, không extra funding/timing inputs ngầm.
2. U locally prove Q, kiểm ALL nonzero self-output ownership/value/ciphertext/fees; S kiểm usable complete packet + same-real-input relation. U giữ `PayoutWitnessU`; executable P vẫn private.
3. S durably reserve inventory; destination escrow được fund/armed irrevocably với fixed obligation. Wallet independently verify amount/asset/beneficiaries/history/version và destination finality trước release P SpendAuth.
4. P hoặc conflicting T/Q resolve trên source. Workers thu thập/prove facts; custody/private witness không phát sinh chỉ vì relayer permissionless.
5. Destination verifies full context/history/classification/uniqueness fact, app allocates once theo approved relation: authenticated supported `0 <= C <= A` → `U=floor(D*C/A)`, `S=D-U`, dust cho fixed S; proved nonpayment conflict → S; unsupported/excess thiếu source-return evidence/unresolved → pending. Partial transfers hai beneficiaries phải atomic/retryable; actual transfers mới terminal, không callback receipt/withdrawal credit giả `Completed`.

`Draft → RecoveryPrepared → DestinationArmed → SourceResolutionPending → PayoutReady | RefundReady → Completed | Refunded`. `EvidencePending` nonterminal, có thể resume source resolution; Q broadcast, chain receipt hoặc local deadline đều không terminal allocation. Inventory reservation cancelled **trước on-chain arming** khác refund funded escrow. Không solver unilateral withdraw/cancel sau arming.

**Initial local EVM transfer choice:** direct atomic native transfer, cùng transaction verification/consumption; failure rollback attempted consumption và entitlement vẫn retryable. Withdrawal credit chỉ là alternative chưa chọn, được nhắc để tránh label “paid” khi chưa transfer; không runtime mode song song hay recipient-redirection fallback. Chi tiết ở [destination module](../modules/destination-settlement.md#3-allocation-và-actual-transfer-invariants).

P mined trước local activation không tự bị loại khi escrow đã funded: lịch sử admissible và exact binding phải được verify, không artificial lower-height cutoff khiến payout/refund cùng false. Consensus expiry vẫn có hiệu lực; proof nộp sau expiry không hủy entitlement của payment đã validly mined. Nếu U tự gửi trước khi S fund bất kỳ escrow, wallet gate không ép S fund. Recommendation chỉ bảo vệ U tuân thủ ordering; không enforce source signer tùy ý.

### Durable state không phải observer cache

- Wallet owns note reservations, authorization-release records và private recovery/payout witnesses.
- Solver owns transactional inventory reservations, signed funding records và private Q packet custody.
- On-chain escrow owns funded obligation, verified allocation/consumption và actual transfers.
- Observer owns rebuildable source/destination view, reorg reconciliation và estimate; không quyền sửa money allocation.
- Public raw blocks/content-addressed validation work có thể share theo version/policy. Private quote↔payment mapping, openings, FVK, note data và proving job payload không shared public cache.
- Nếu optional message profile được chọn, stable source occurrence→receipt mapping riêng destination replay/app nonce, DEX payment→obligation uniqueness và escrow terminal consumption. **Namespace một source→một receipt across routes/deployments chưa chốt** tại Zoss; không mặc định per-route hay global financial uniqueness. Shared source-data consumers không tự tạo/consume receipt; epoch rotation không reset consumed financial identities.

### Expanded market/venue state ownership — proposed, không cutover native

- **Funding app/journal:** claimant-bound source occurrence và controlled inventory trước unique credit; re-inclusion/restart/change không credit mới. Own credit/hold/epoch/portion/intent replay, không observer/RPC/quorum generic verified constructor.
- **Admission/matcher:** verify funded eligibility/order rights trước approved private mechanism; complete result phải authenticated/activated toàn epoch trước release từng entitlement. Admission/viewing/custody và matcher quyền riêng; no public source↔identity/order map. Known GD2 FAIL giữ nguyên.
- **Market custody:** physical backing, exact input/recipient/change/fee/effects, authorized signing intents và actual outcomes; native ZEC custody/threshold signer là prerequisite riêng, không user-proof removal. Available/locked/provisional/confirmed và liability portions disjoint; sponsor capital riêng. Missing ACK/partial result/timeout/live signed intent/Unknown không free funds; impairment fence new sends, không xóa outstanding claims.
- **External HyperCore:** user separately selects B venue/account/market và exact limit/fees/action authority; agent/API wallet là delegated signer, không AI. Core/EVM là execution domains cùng L1, exact token/decimals/link/balance/control riêng; direction A P2P không tự dùng order book B. Reservation tách P2P/Core/EVM/Solana/Ironwood; enqueue/success/cancel request không fill/no-effect. Không perps/leverage/automatic fallback; transfer riêng sau actual freed inventory và new consent.
- **Future user-proof intake:** verify app-specific relation/claimant/history/controlled backing/dedup, không promotion event→credit→spend hoặc bypass native `VerifiedSettlementFact`. Witness availability/independent recovery/privacy vẫn phải solve; database transaction/ACK/MPC không cross-chain atomicity.

Native wallet keys, P/Q arming/release ordering, funded verifier/recovery lifetime và actual-transfer terminal vẫn theo §3/[ARCHITECTURE §7](../ARCHITECTURE.md#settlement). Expanded intent/hold/entitlement không thay native escrow hoặc tạo bidirectional route. [BLOCKERS](../BLOCKERS.md) giữ readiness; source Kerb safety evidence không local integration.

## 4. Refund chỉ ước tính thời gian — quyết định đã duyệt

ETA tách stage: source Q/T inclusion + required source confirmations/history evidence → proving → destination submission/finality → actual transfer. Không cộng hoặc so trực tiếp height/slot hai chain. Stages overlap thì model estimate phải phản ánh scheduling, không cộng hai lần hoặc hứa upper bound.

`RecoveryEstimate` conceptual fields: `status = Unmeasured | Estimated | EvidencePending`, `asOf`, `stage`, `reason`, `measurementProvenance`, `estimatedDurationOrRange?`, `assumptions`. Chưa có measurements nên không điền số phút/percentile/confidence giả. Nếu có dữ liệu thật, report sample scope/window và policy/version; stale input invalidate estimate. Quá estimate cập nhật status/reason, **không authorize refund**. Censorship/halt/unavailable witness/proof có thể kéo pending không bounded. Không timer/admin/quorum fallback đổi trust model âm thầm.

## 5. Dependencies và version/repository discipline

Reuse existing upstream node/wallet/crypto/proving libraries, không tự viết curve, consensus node, wallet hay new proof system để tạo danh sách repo dài. Cohort phải pin coherent Ironwood/v6/domain/prover/verifier versions; README role không bằng runtime compatibility. Orchard library có thể phục vụ Orchard protocol/ Ironwood domain theo version, không gộp tree/pool/nullifier namespace. Sapling library không thay Ironwood engine. RPC/full block acquisition là data source, không automatically canonical validity proof.

Source proof rules và destination verifier artifact phải pin cùng statement schema; funded orders giữ usable old proving/verification/recovery path. Proxy/code/registry address version string không bảo đảm immutable rules. Pending có thể indefinite, expiry không tự là safe retire date. Messaging roster/epoch/revocation hoặc Zoss/SDK release **không** quyết định financial proof/witness/recovery lifetime; no auto-upgrade fallback phân bổ tiền.

`crates/runtime` chạy bounded low-privilege proof jobs; tách process heavy prover khi workload thật cần, không solver key trong permissionless proving process. `crates/proofs` output facts/proof artifacts, **không command trả ai bao nhiêu**. Economic escrow/app owns amounts/beneficiaries; Zoss owns common infrastructure và optional non-money messages, không DEX consensus/proof engine/settlement. SDK coordination không universal bridge facade/plugin registry.

## 6. Acceptance order — native gates và expanded prerequisites riêng

| Milestone | Required observable evidence | Chưa được suy ra |
|---|---|---|
| M1 — relation/state specification | Exact P/Q, early historical P/T, cancellation capability, unknown-T pending, transfer/replay/retry rules nhất quán | Logical state table không source cryptographic proof |
| M2 — executable Q feasibility | U offline sau setup; S dùng Q complete locally proved packet, không user FVK/spend key; SAME real input, actual U self-return, agreed fee; anchor/branch/expiry policy | Happy path không eternal reanchor/upgrade/liveness guarantee |
| M3 — payment classifier, gross-vs-net/no-S-input hoặc debit gate | Complete single-T inputs/outputs/actions/receiver binding; authenticated all-U input set/zero dummy ban đầu; exact/replacement/partial/overpay/bad ciphertext; independently provable U payout. Mixed U+S input gross đủ nhưng net zero/insufficient giữ pending | Gross không payout; unknown completeness/ownership không nonpayment/full refund. Không loại hostile T bằng wallet guard; actual proportional relation/independent terminal/excess-return proof còn phải complete |
| M4 — source facts → one local EVM native-asset escrow | Actual valid-history/effect/auth/real-input/historical-inclusion facts; context/replay/uniqueness enforced; actual payout/refund + offline/fork/failed-transfer traces | Mock fact flags, quorum receipt, raw txid inclusion không gate Pass |
| M5 — private composition/resource/lifetime | Hiding facts and uniqueness, public-surface linkage, witness disclosure, cost/proof size/gas/recovery/version lifespan | Public source/destination locators không private Cross-Chain proof |
| Later staging | Source/local/privacy evidence, exact network/signers/asset/fees/simulation và authorization riêng | Docs approval không deploy/sign/mainnet permission; Solana adapter không inherit EVM support |

Zoss shared-library readiness riêng với optional message G/Z và DEX M1–M5/S/P; actual acquisition/common-encoding reuse không source-proof hoặc financial gate Pass. Public Solana LP, optional 1Click, autopilot và future ZSA không dependency của M1–M5; không automatic LP migration. Market/admission/custody, Hyperliquid A/B và user-proof intake cũng không entry prerequisite hay implementation approval từ native plan. Chúng cần own reviewed design, exact asset/domain/control/history/credit/reservation/privacy/actual recovery evidence theo [ARCHITECTURE](../ARCHITECTURE.md#roadmap)/[BLOCKERS](../BLOCKERS.md), chưa hỗ trợ route. Whole-interval absence branch giữ trong [research](../SETTLEMENT-RESEARCH.md) như alternative, không engine bắt buộc để bắt đầu positive-conflict route.

## 7. Nguồn và protocol repository precedents

Source mechanism evidence: [research §4.2](../SETTLEMENT-RESEARCH.md#42-positive-conflict-refund-candidate--audit-bổ-sung-2026-10-01), [audit §9](../ARCHITECTURE-AUDIT.md#9-positive-conflict-alternative--không-assume-exclusion-bắt-buộc), canonical E21. Repo-role observations được ghi riêng dưới đây; chỉ **Verified source responsibilities**, không audit, interoperability proof hoặc benchmark. Ngày đọc 2026-10-01; publication dates không được suy từ retrieval date.

### 7.1 Arbitrum và ZKsync — học trách nhiệm, không sao chép repo count

| Repo / primary README | Verified source role (đọc 2026-10-01) | Áp dụng cho DEX **[INFERENCE]** |
|---|---|---|
| [OffchainLabs/nitro](https://github.com/OffchainLabs/nitro/blob/master/README.md) | Integrated optimistic-rollup node/execution/proving stack | Validation/proving tightly coupled có thể chung repo; không cần tạo DEX rollup/node |
| [OffchainLabs/prysm](https://github.com/OffchainLabs/prysm/blob/develop/README.md) | Go Ethereum consensus client; beacon-chain/validator/admin roles | Consensus client khác application escrow; không dependency Zcash được đề xuất |
| [OffchainLabs/token-bridge-contracts](https://github.com/OffchainLabs/token-bridge-contracts/blob/develop/README.md) | ERC-20 bridge app xây trên Nitro messaging; gateways/routers | App economic custody khác protocol messaging; không copy token mint/bridge vào Zoss |
| [OffchainLabs/nitro-contracts](https://github.com/OffchainLabs/nitro-contracts/blob/develop/README.md) | Core rollup/fraud-proof contracts và precompile interfaces, riêng token bridge | Logical target verifier riêng escrow dù ban đầu chung package |
| [OffchainLabs/arbitrum-sdk](https://github.com/OffchainLabs/arbitrum-sdk/blob/main/README.md) | TypeScript bridging/message lifecycle/network/contract client library | SDK đọc/submit đúng interfaces; không authority settlement hay finality guarantee |
| [matter-labs/zksync-era](https://github.com/matter-labs/zksync-era/blob/main/README.md) | Rollup implementation, core/prover subsystem gồm binaries và libraries | Multi-module không nhất thiết polyrepo; bounded prover worker theo workload thật |
| [matter-labs/zksync-withdrawal-finalizer](https://github.com/matter-labs/zksync-withdrawal-finalizer/blob/main/README.md) | Rust L1/L2 monitor + PostgreSQL operational state + finalization submission, companion contract | Permissionless recovery worker giúp execution, không tự tạo entitlement/proof hay deadline guarantee |

Prysm là Ethereum consensus-client precedent, không Arbitrum token bridge hay Zcash proof engine. Token bridge README đặc biệt thể hiện **messaging protocol ≠ money-bearing application**, phù hợp việc Zoss không giữ escrow. Finalizer operational automation không substitute chain/proof correctness.

### 7.2 Zcash — reuse upstream cryptography/wallet/node layers

| Repo / primary source | Verified source role (đọc 2026-10-01) | Reuse candidate / caveat |
|---|---|---|
| [zcash/sapling-crypto](https://github.com/zcash/sapling-crypto/blob/main/README.md) | Sapling cryptographic implementation | Chỉ supported Sapling history khi cần; không Ironwood engine |
| [zcash/librustzcash](https://github.com/zcash/librustzcash/blob/main/README.md) | Rust wallet/protocol/storage/PCZT workspace; README cảnh báo parse không prove consensus validity | Wallet authoring integration candidate; v6/Ironwood PCZT source support không executable P/Q runtime Pass |
| [zcash/pasta_curves](https://github.com/zcash/pasta_curves/blob/main/README.md) | Pallas/Vesta curve arithmetic | Existing dependency qua supported crates; không settlement module/new curve fork |
| [zcash/zallet](https://github.com/zcash/zallet/blob/main/README.md) | Full-node RPC wallet, beta/incomplete RPC, không designed as stable Rust library | Possible RPC integration/reference, không mặc định embedded SDK hay proven P/Q export |
| [zcash/orchard](https://github.com/zcash/orchard/blob/main/src/lib.rs) | Orchard-family protocol; source có separate `ValuePool::Ironwood`, V3 semantics | Existing note/action/key/PCZT/prover primitives với correct pool/domain/version; không new history/payment-class circuit |
| [zcash/halo2](https://github.com/zcash/halo2/blob/main/README.md) | Proving-system workspace, consumer crates `halo2_proofs`/`halo2_gadgets` | Existing backend nếu selected implementation cần; không ready-made canonical/private DEX verifier |
| [zcash/incrementalmerkletree](https://github.com/zcash/incrementalmerkletree), [member README](https://github.com/zcash/incrementalmerkletree/blob/main/incrementalmerkletree/README.md), [bridgetree](https://github.com/zcash/incrementalmerkletree/blob/main/bridgetree/README.md), [shardtree](https://github.com/zcash/incrementalmerkletree/blob/main/shardtree/README.md) | Common Merkle types, marked-leaf witnesses/checkpoints, partial/out-of-order witness maintenance | Existing note witnesses; root không tự authenticated history, note tree không block transaction proof |
| [ZcashFoundation/zebra](https://github.com/ZcashFoundation/zebra/blob/main/README.md) | Existing Rust Zcash full node | Source ingestion/validation candidate; RPC node assertion không transferable destination-validity proof |
| [zakura-core/zakura](https://github.com/zakura-core/zakura/blob/main/README.md) | README xác định Zcash full node fork từ Zebra; performance/compatibility là maintainer claims | Alternative ingestion sau exact release/RPC/history-retention checks, không benchmark đã verify; related forks không independent evidence mặc định |

**Source survey 2026-10-01:** [PCZT source](https://github.com/zcash/librustzcash/blob/main/pczt/src/lib.rs) có v6/Ironwood bundles; [signer](https://github.com/zcash/librustzcash/blob/main/pczt/src/roles/signer/mod.rs) tách authorization; [Orchard prover](https://github.com/zcash/orchard/blob/main/src/pczt/prover.rs) yêu cầu FVK/note/witness/alpha/rcv và reject deferred anchor. Đây dated role/source observations; local builder/redaction/proving evidence hiện tại đọc [status](../NATIVE-IMPLEMENTATION-STATUS.md), không node/chain acceptance. Mutable `main` READMEs không approved lockfile; mechanism research giữ pinned revisions trong §4.2.

**Không tạo** replacement Sapling/Orchard/curve/Halo2/tree/node projects. `crates/zcash` consumes coherent existing wallet/transaction/witness primitives; `crates/proofs` bổ sung missing transaction/payment/history relations và proof artifacts; chain contracts thực hiện economic settlement. Zallet, Zebra hoặc Zakura selection chưa chốt bằng repo name; minimum RPC/historical-data/privacy và correct consensus/network cohort phải prove.

### 7.3 Evidence limits và internal artifact ownership

Tất cả **16 repo người dùng liệt kê** đã có primary-source role evidence ở bảng trên. Không build/test/run benchmark, dependency compatibility hoặc security audit. Supplemental GitHub API requests có access restrictions ở một số Zcash repos; không kết luận absent/archived từ fetch failure hoặc claim mọi repo active. No implementation/deploy/import license approval phát sinh từ role survey.

`crates/proofs` sở hữu circuit/witness/prover/verifier artifacts; `crates/protocol` sở hữu versioned rules/schema; chain contract packages sở hữu target verification và economic execution. Artifacts cần reproducible builds, license/upstream pin/security review và conformance evidence khi implementation được authorize; funded old orders giữ usable original proving/verification/recovery path. **DEX owns economic semantics**, không biến proof library thành quote/funding worker. Zoss independent release không retire settlement verifier. UI và Zoss external; core/SDK/contracts internal, không thêm SDK/contracts/proofs repos. 16 repo-role precedents trên giữ nguyên, không compatibility/build/security pass.

Current [Zoss architecture](../../../zoss/docs/ARCHITECTURE.md), [readiness register](../../../zoss/docs/BLOCKERS.md) và [DEX integration](../../../zoss/docs/private_dex.md) sở hữu reusable core/message contracts, không native hoặc market settlement authority. Prior transport-only/joint-note wording là historical; actual limited acquisition theo [native status](../NATIVE-IMPLEMENTATION-STATUS.md), không EVM message endpoint, verified history hoặc funds quyền. DEX circuits/history/payment/target-verifier/financial gates giữ internal và Open. [PRODUCT](../PRODUCT.md)/[CONSOLIDATION](../CONSOLIDATION.md) và [archive wrapper](../imports/kerb/README.md) giữ expanded Ziquid/future Z2Z/provenance, không nhập Kerb implementation hoặc inheritance readiness.
