# Z2Z — brainstorm order book và quyền onchain, 2026-10-05

## 1. Vì sao có tài liệu này?

Owner yêu cầu lưu các brainstorm mới để giữ context. Đây là **hồ sơ cuộc thảo luận và khuyến nghị**, không phải spec đã duyệt cho implementation mới, support/listing claim hoặc authorization deploy/sign/send/fund. Scope production hiện tại và mọi yêu cầu native/P2P/privacy/manual recovery vẫn giữ nguyên. [PRODUCT](../PRODUCT.md) tiếp tục sở hữu scope hiện hành; [BLOCKERS](../BLOCKERS.md) sở hữu readiness.

## 2. Owner đã nêu gì?

1. Hỏi người dùng mua một Hyperliquid position thì Z2Z xử lý thế nào, và đã tokenized chưa.
2. Đề xuất nâng tầm Z2Z thành một advanced decentralized order book cho nhiều tài sản/quyền: Hyperliquid spot/perpetual positions, NEAR tokens, Solana tokens, ZEC/shielded ZEC và những quyền crypto/onchain khác.
3. Hỏi đây có phải bản scale-up của idea hiện tại và nên làm từng bước hay current product chạy thật trước rồi mở rộng.
4. Xác định nơi lưu dữ liệu là vấn đề quan trọng: PostgreSQL, chain hay nhiều chain.
5. Hỏi sự khác biệt với LayerZero.
6. Yêu cầu lưu brainstorm và báo status/progress; phản ánh đã chờ lâu.

**Diễn giải thận trọng:** owner quan tâm tích cực tới tầm nhìn lớn; chưa lựa chọn một construction cụ thể cho transferable perpetual positions, shared order-distribution network, public/private book mới, chain trung tâm hoặc universal vault. Không coi câu hỏi/brainstorm là phê duyệt bỏ các acceptance hiện tại.

## 3. Tầm nhìn được thảo luận

> Z2Z là sàn có order book riêng để mua bán tài sản crypto và những quyền onchain có thể thực sự chuyển giao.

Đây là bản mở rộng của DEX/P2P hiện tại, không phải đổi thành một messaging protocol. Một marketplace không có nghĩa mọi tài sản nằm cùng vault, cùng custody, cùng ledger, cùng privacy hoặc atomic across chains.

Order book tìm buyer/seller và đề xuất điều kiện; settlement phải kiểm backing, exact consent, consumption, effects, partial remainder và recovery. Cơ chế chứng minh trạng thái không tự trao quyền chi underlying asset.

### Những thứ không được gộp

| Instrument | Điều cần thực hiện | Giới hạn |
|---|---|---|
| Solana/NEAR tokens | Định danh asset, quyền transfer và actual settlement đúng chain | Đã là token; không bọc lại chỉ để gọi là tokenization |
| Hyperliquid spot asset | Actual eligible asset transfer hoặc một backed claim được disclose rõ | Spot asset, account balance và EVM wrapper không tự fungible |
| Native/shielded ZEC | Actual source spend authority và selected private settlement construction | Receipt/wrapped token không tự cung cấp shielded ownership, recovery hay ZEC signing |
| Vault share | Contract kiểm underlying assets/accounting, manager permissions và redemption | Share của vault không phải một vị thế long cụ thể |
| Specific perpetual position right | Enforce collateral isolation, changes/close authority, funding/loss/liquidation và redemption | Position snapshot/proof/NFT không đủ; seller không được giữ quyền phá backing |

**Hiện chưa tokenized Hyperliquid positions.** External integration có real testnet reads và unsigned spot proposals; chưa thực thi trade. Perps/leverage chưa selected implementation scope. Hyperliquid-asset P2P cũng chưa qualified.

## 4. Decentralization có nghĩa gì ở đây?

- Company server không được tự đổi recipient/quantity/price/fee hoặc tùy ý chi tài sản của qualifying route.
- Actual validator/contract/program enforce backed rights và consumption; PostgreSQL row không thay thế.
- Existing owner withdraw/cancel/settle rights không cần chữ ký mới của company khi services biến mất.
- Complete recovery data, private capabilities và usable proving artifacts phải độc lập có sẵn; hash/root/alternate relayer không đủ.
- Replaceable matcher có thể propose; valid settlement không tự chứng minh best execution, fairness hoặc accepted-set completeness.
- Offchain order service do company vận hành vẫn có concentration ở discovery/availability nếu không có đường khác; không gọi toàn bộ sàn decentralized chỉ vì settlement onchain.

Private/public book là tradeoff chưa quyết định mới: public depth công khai price/quantity/activity; strict-private matching hiện có GD2 structural conflict. Không silently publish orders hoặc hạ adversary/own-result privacy để đạt orderbook launch.

**Current samechain construction:** mỗi known fill cần fresh exact owner consent và recipient-prepared recoverable outputs. Arbitrary unattended fills khi owner offline chưa được phép suy ra. Đã fully authorized packet khác với tạo một fill mới offline.

## 5. Khuyến nghị thứ tự giao hàng

Đây là khuyến nghị từ assistant, không xác nhận các mốc đã hoàn thành:

1. **Real usable current journey:** two known owners, một qualified samechain pair, deposit → exact partial fill → actual proceeds withdrawal → cancel/withdraw remainder → refresh/restart/manual rights. Không fake balances, canned success hoặc accepting verifier. Đây không thay thế full private discovery/matching.
2. **Complete own order market:** actual backing/admission/discovery/fill/cancel/reconciliation, privacy construction và owner company-off rights. Giữ native full-protocol obligations song song, không giảm scope.
3. **Eligible existing assets:** thêm từng exact asset/route có demand và control/settlement/recovery evidence, không bật universal chain support.
4. **Qualified vault shares:** control/accounting/redemption thật; Hyperliquid vault là candidate nghiên cứu, chưa selected deployed route.
5. **More complex position rights:** chỉ sau khi giải collateral/funding/liquidation/manager/close/redeem authority và xác nhận nhu cầu.

Showcase là mốc giao hàng thật của cùng product, không demo mode riêng, không điểm dừng production. Không hứa ETA/volume/liquidity dựa trên tầm nhìn lớn. Cần phân biệt người muốn chuyển vị thế/quyền với người chỉ muốn close/reopen; chưa có demand validation cho expansion.

## 6. Data storage — hybrid, nhiều authority rõ

| Data | Proposed/required home | Authority và recovery |
|---|---|---|
| Actual assets/collateral/backing | Domain/chain/venue thực sự kiểm chúng | Solana program, NEAR contract, HyperCore account, HyperEVM vault hoặc Zcash spending rules tương ứng; support không tự tồn tại |
| Enforceable ownership/consumption/cancel/settle | Validator/contract/program/venue có quyền thực | SQL/index/receipt không tạo money permission |
| Order discovery/proposals | Offchain services/direct exchange hoặc future reviewed distribution network | Ký/authorization và settlement validate; decentralized order distribution chưa implemented |
| Public recovery bytes | Chain data/events khi route cho phép + independently available archives | Complete ciphertext/metadata cần truy xuất; root/hash/short-lived blob không DA |
| Search/charts/activity/observations | PostgreSQL/indexers | Rebuildable policy-labelled views, không authoritative balances |
| Reservations/prepared/Unknown operations | Durable actor-scoped PostgreSQL hoặc owner-local record theo workflow | Không disposable cache; restart/ambiguity giữ fences, timeout không release money |
| Secrets/openings/witnesses | Owner-local storage và encrypted recovery backups | Không hosted plaintext SQL/public chain/WebStorage/analytics; mất key không phục hồi bằng hash |
| Public prover/circuit/tool artifacts | Actual retained owner copies/independent mirrors | Hash integrity != availability hoặc setup soundness |

Không chọn central chain/global multichain money ledger mới. Multiple-chain copies không equivalent backing hoặc atomicity. Legacy custody signer dependence không biến mất khi đặt records onchain. SQL hiện dùng PostgreSQL và tests NOT RUN pending secure nonlocal URI/scope; không local SQL.

## 7. LayerZero — overlap và khác biệt

Theo primary docs đọc trong cuộc thảo luận, LayerZero cung cấp crosschain messaging với application-configured verification/execution; OFT có source debit burn/lock và destination credit mint/unlock cho token được tích hợp. Application vẫn sở hữu business logic. Z2Z hướng tới market/order execution và route-specific enforceable delivery/recovery, không xây một LayerZero mới.

- Nếu chỉ wrap/move token giữa chains, overlap rất lớn; đây không phải điểm khác biệt đủ mạnh.
- LayerZero có thể là transport/route dependency nếu một construction được chọn và qualify. Chưa tích hợp hoặc authorize route đó.
- Message verified không tự chứng minh đúng financial predicate, position control/redemption, source custody quyền hoặc buyer received đúng asset.
- Không claim LayerZero không thể hỗ trợ exchange: applications có thể xây phía trên. So sánh khác tầng, không verdict security tốt/xấu hoặc không có đối thủ.
- Điểm khác biệt **mong muốn**, chưa chứng minh bằng delivered product: own order market cho qualified assets/rights, exact buyer/seller authority, actual delivery/remaining rights và company-independent permitted recovery; shielded Zcash là riêng nếu construction thực sự qualified.

## 8. Primary sources và mức evidence

Đọc ngày2026-10-05; các live docs không nêu publication date ở đoạn đã đọc, có thể thay đổi. Không có onchain qualification, signing hoặc transaction execution từ việc đọc:

- [Hyperliquid vaults](https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/vaults): official docs mô tả tokenized HyperEVM vaults, customizable accounting, ERC-4626-style approach và CoreWriter/precompiles. **Source evidence**, không chứng minh arbitrary existing position ownership transfer hoặc Z2Z implementation.
- [HyperCore interaction](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/interacting-with-hypercore): read interfaces và CoreWriter actions; order/vault transfers delayed, enqueue/execution riêng. Scope/availability từng environment cần qualify.
- [LayerZero architecture](https://docs.layerzero.network/v2/concepts/layerzero-protocol-architecture): messaging/business logic/interface/verification/execution distinction.
- [OFT technical reference](https://docs.layerzero.network/v2/concepts/technical-reference/oft-reference): source debit/destination credit, peers/configuration/decimal/asset-specific caveats và roles.
- [DVN security stack](https://docs.layerzero.network/v2/concepts/modular-security/security-stack-dvns): app-specific security thresholds/configuration; không suy mọi route có cùng security hoặc decentralization.

Current first-party repo authorities: [PRODUCT](../PRODUCT.md), [ARCHITECTURE](../ARCHITECTURE.md), [SERVER-INDEPENDENCE](../SERVER-INDEPENDENCE.md), [SQL-VERIFICATION](../SQL-VERIFICATION.md), [native status](../NATIVE-IMPLEMENTATION-STATUS.md), [71-story frontend handoff](PRODUCT-OVERVIEW-AND-FRONTEND-HANDOFF.md), [implementation prompt](Z2Z-IMPLEMENTATION-SYSTEM-PROMPT.md).

## 9. Chưa quyết định / chưa authorize

Public/private order-distribution mechanism; shared market pricing/priority/fairness policy; whether to list vault share vs specific position; exact Hyperliquid controller/redemption/liability model; chain/asset/venue activation; bridging/messaging choice; economic/legal eligibility; demand and liquidity evidence. Không có new universal vault, bridge, rollup, perps/position-token implementation, real-key use, deployment, funding, mainnet, SQL execution hoặc private witness outsourcing authorization từ brainstorm này.

## 10. Owner clarification — resting order và nhiều counterparties

Owner sửa product framing: không yêu cầu hai người cùng lúc nạp tài sản hoặc chọn sẵn một counterparty. Một maker tạo Buy/Sell order, funding/backing đúng tài sản và chờ người khác chấp nhận giá/phí. Cùng một logical order có thể được nhiều takers fill ở các thời điểm khác nhau tới khi đủ quantity; không giới hạn một buyer với một seller cho cả order.

Phân biệt kết quả: mỗi fill đã settlement thành công là một giao dịch thành công/final, không chờ order đầy mới công nhận. Order aggregate ghi original quantity, settled filled quantity và live remaining quantity; `PartiallyFilled / Open` nghĩa là đã có phần thành công và chỉ phần dư còn treo, không toàn bộ trade pending. `Filled / Complete` chỉ khi không còn quantity cần fill; cancel chỉ tác động quyền phần dư, không đảo các fill đã final. Fill đang submitted/Unknown phải giữ reservation riêng và không cộng thành settled fill hoặc trả capacity cho taker khác. Backing còn lại không thể sử dụng đồng thời cho fills vượt quantity; race/cancel phải được authority enforce, không SQL ACK.

**Owner confirmed subsequently: “yes just once time”.** Maker ký một lần khi mở order; không quay lại duyệt/ký từng fill. Sau khi backing hợp lệ, nhiều takers được fill trong phạm vi asset/quantity/price/fees đã ký kể cả maker offline. Existing current samechain code vẫn yêu cầu recipient-prepared exact outputs và fresh owner consent cho mỗi known fill, nên chưa đáp ứng requirement này. Cần reviewed standing authorization, taker-executable proof/input authority và maker-only recoverable receipts/successors mà không giao maker spend/viewing secrets cho taker/server. Không pretend confirmation đã giải strict GD2/privacy/asset custody/crosschain recovery hoặc cho phép signing/deployment/funding thực. Cancel/amend là thao tác owner riêng nếu owner chủ động yêu cầu, không approval bắt buộc cho mỗi fill; policy thay đổi cần authorization mới, không sửa ngầm terms đã ký.

## 11. Standing authorization — primary-source comparisons, not adopted constructions

Retrieved2026-10-05; publication/update dates not established. These are first-party protocol documents inspected during engineering research, not executed interoperability/privacy/financial tests.

| Source | Exact observed mechanism | Boundary for Z2Z |
| --- | --- | --- |
| [CoW intents](https://docs.cow.fi/cow-protocol/reference/core/intents), [signing schemes](https://docs.cow.fi/cow-protocol/reference/core/signing-schemes) | Signed order binds sell/buy tokens and amounts, kind, partial-fillability, fee, receiver, validity and balance modes. Deployment/chain-specific EIP-712 domain protects replay. Pre-signing an already filled order does not make it tradable again. | Evidence for constrained standing-intent fields, not shielded maker inputs, private matching or recoverable encrypted successors. No adoption of its signer/solver/settlement model or current-network readiness claim. |
| [Penumbra batch swaps](https://protocol.penumbra.zone/main/dex/swap.html), [SwapClaim](https://protocol.penumbra.zone/main/dex/action/swap_claim.html) | V1 describes public input burns/private output claims; sealed-bid batching is labelled future. SwapClaim is self-authenticating without fresh spend authorization because original swap commits receiver and claim constrains assets/amounts to stored batch data. Claim proof still uses full swap plaintext, FVK-derived/nullifier witness and membership; it can claim only once and mint only to committed address. | Useful separation of opening authority and constrained later claim, but not a persistent arbitrary multi-taker limit order. No maker FVK delegation permitted in Z2Z; no claim that public-burn/batch model satisfies strict GD2. A deferred owner claim also needs genuine asset-backed entitlement and independent data, not a financial-success placeholder. |
| [RAILGUN conditional/atomic primitives](https://docs.railgun.org/developer-guide/engine-1/example-primitives) | Wallet proof binds adaptContract/adaptParams; core restricts submitting contract but leaves application validation to adapter. Atomic-swap example bundles transactions and checks each committed output is paid by another bundled transaction. | Exact conditional bundle authority is not generic one-signature future-fill authority. It does not make maker private input/output witnesses available or prove arbitrary future recovery. No wrapper/adapter adoption or privacy waiver. |

[INFERENCE] Opening signature is only one part of standing execution. A sound design must independently establish exclusive maker backing available to later fills, immutable admissible quantity/net-price/fee policy, exact taker authority, one consumption/conserved residual, and maker-only recoverable proceeds without new maker private witnesses. Compare scoped standing escrow and constrained deferred owner claims against proof-composition/recipient-encryption candidates; do not assume ciphertext or a static proof can synthesize hidden facts. Current known-fill code remains unchanged until a reviewed construction is viable under retained privacy/authority requirements.

Standing construction review must pin price/quantity/fee units and budget semantics explicitly: per-fill net-price bounds cannot be replaced by an eventually favorable aggregate; a total signed fee/debit cap cannot reset after each partial generation or be charged repeatedly by splitting fills. Any per-fill fee rule must be separately signed as such, not inferred from an aggregate cap. Buy requested quantity and payment backing are different units; checked rounding/conservation must preserve both. Logical cancellation must prevent the same opening authorization from resurrecting remaining quantity or fee budget through later generations/new packet representations. These are design acceptance boundaries, not implemented standing fields or an invented fee policy.

## 12. Public execution handling versus private signing

Confirmed operating model: server may handle execution after authorization—accept permitted public/non-sensitive order data and public payloads such as signed authorization, calldata or proof output; submit unchanged transactions; observe inclusion; retry only under the same operation rules; and reconcile outcome. The user's wallet/local companion handles private keys, seed/FVK, private witnesses, recovery openings and any secret-bearing proof/signing. Server-only signing, hidden payload mutation, private-witness upload and money authority from a database `approved` row are not defaults. The blockchain/contract remains the final state machine; local locks/journals only prevent duplicate local work. This is a product boundary, not an implemented server/API claim.
