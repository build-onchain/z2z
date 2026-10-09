# Hợp nhất Kerb vào Ziquid mở rộng — tài liệu và source cutover

**Quyết định tài liệu 2026-10-02; source cutover 2026-10-03.** User chọn repo Ziquid làm gốc, hướng tên sản phẩm Z2Z sau này, thay đề xuất trước dùng Kerb làm umbrella. Đợt đầu chỉ nhập tài liệu; yêu cầu tiếp theo đã cấp quyền autonomous hợp nhất implementation và hoàn thành toàn bộ sản phẩm. Source đã được chuyển vào destination như §4; original sibling/history không bị sửa. Product/repo rename, signing/funds/deployment và readiness không suy ra từ cutover.

**Redesign 2026-10-02:** [Redesign spec](superpowers/specs/2026-10-02-z2z-server-independent-architecture-design.md), [SERVER-INDEPENDENCE](SERVER-INDEPENDENCE.md) và [ARCHITECTURE-REVIEW](research/ARCHITECTURE-REVIEW.md) giữ proposed system/workflows và constraints chưa giải. Samechain owner-proof relation vẫn là hướng mới, không native hostile-spend/GD2 fix từ migrated market target. Qualifying company-off rights cần wallet-owned witnesses, usable artifacts/data và immutable funded authority; custody market không tự đạt điều kiện đó. **2026-10-03:** [integration design](superpowers/specs/2026-10-03-z2z-implementation-integration-design.md) và [executing plan](history/plans/2026-10-03-z2z-implementation-integration.md) hướng dẫn autonomous implementation không routine approval waits; không signing/broadcast/deployment/funding hay operational-data migration permission.

## 1. Tài liệu nào là chuẩn chung?

| Câu hỏi | Tài liệu chịu trách nhiệm |
|---|---|
| Sản phẩm chung làm gì, phục vụ ai, từng đường giao dịch là gì? | [PRODUCT.md](PRODUCT.md). |
| Đọc tài liệu theo thứ tự nào? | [docs README](README.md). |
| Hành vi, quyền hạn, privacy và thanh toán? | [ARCHITECTURE.md](ARCHITECTURE.md), các [module specs](MODULES.md). |
| Code/package ở đâu, ai sở hữu? | [MODULES.md](MODULES.md). |
| Điều kiện còn thiếu để enable/release? | [BLOCKERS.md](BLOCKERS.md). |
| Native Ziquid thực sự đã chạy gì? | [NATIVE-IMPLEMENTATION-STATUS.md](NATIVE-IMPLEMENTATION-STATUS.md). |
| Đã nhập gì, nguồn nào, liên kết và byte thay đổi thế nào? | [Import README](imports/kerb/README.md) và manifest đi kèm. |
| Owner xử lý thế nào khi UI/server/relayer mất? | [SERVER-INDEPENDENCE.md](SERVER-INDEPENDENCE.md), design-only stage/action matrix và drills. |
| Tổng review/research và lý do chọn kiến trúc? | [ARCHITECTURE-REVIEW](research/ARCHITECTURE-REVIEW.md), [server research](research/SERVER-INDEPENDENCE-RESEARCH.md), [crosschain research](research/CROSSCHAIN-MARKET-RESEARCH.md). |
| Lane nào đang active (2026-10-06)? | Native ZEC là lane hạng nhất active (L-ZEC), không phải V2; L-HEVM, L-SOL, L-NEAR và X.CROSSCHAIN (HTLC trước, mọi cặp song song, không claim atomicity/privacy) là active parallel. Đọc [README gốc](../README.md) và [PRODUCT](PRODUCT.md). |

Kerb `00-CANONICAL.md` được giữ nguyên vai trò **thẩm quyền của hồ sơ nguồn theo ngày**, không thành tài liệu chuẩn ngang hàng với PRODUCT/ARCHITECTURE/BLOCKERS chung. Các spec/plan nguồn có approval cụ thể chỉ giữ phạm vi cũ; không cấp quyền triển khai sản phẩm mở rộng.

## 2. Quy tắc chuyển tài liệu

- Nhập cả `docs/`, `zolana-review-2026-09-29/` và `zolana-research-2026-09-30/` dưới `docs/imports/kerb/`, giữ đường dẫn tương đối của nguồn, kể cả `docs/docs/superpowers/`.
- Giữ bản Kerb nguồn; không xóa, đổi tên, hoặc sửa nguồn. Không có hai docs chung đang được duy trì: hướng sản phẩm mới ở Ziquid; bản nhập là snapshot xuất xứ, không bản song song để viết feature mới.
- Giữ nội dung lịch sử, số liệu, nguồn, hạn chế và tên Kerb/Zolana trong archive. Không replace toàn bộ tên thành Ziquid/Z2Z.
- Chỉ sửa đích liên kết tương đối trong bản nhập khi việc di chuyển làm link không còn trỏ đúng nguồn; manifest giữ hash nguồn và dấu vết từng thay đổi. Không tạo symlink/stub/code copy để che link hỏng.
- Archive links tới code Kerb vẫn trỏ repo nguồn theo provenance của lần nhập, không sửa history thành destination evidence. Current module/code authority ở Ziquid theo §4 và [MODULES](MODULES.md), không aliases vào sibling. Link Zoss vẫn tới sibling Zoss, không chuyển ownership.
- Kiểm kê mọi tài liệu ngoài ba roots nếu phát hiện; không nhập artifact build, khóa, secrets, operational stores hoặc agent-context instructions. Manifest là danh sách chính xác những gì đã chuyển.

## 3. Những khác biệt đã thống nhất

| Vấn đề | Quyết định chung | Điều không suy ra |
|---|---|---|
| Tên/gốc dự án | Expanded Ziquid là gốc; Z2Z là tên tương lai. | Chưa rename directory, crate, binary, SDK; chưa kiểm tra trademark/domain. |
| P2P và báo giá | Private P2P market và solver RFQ là hai cơ chế tìm đối ứng khác nhau. | Báo giá không tự là auction/order book; user crossing không tự là pool. |
| Đường Hyperliquid | Asset P2P đủ điều kiện và external HyperCore spot là hai hướng riêng. | Không tự route phần dư, không perps, không tự có bridge/asset fungibility. |
| Privacy | Giữ yêu cầu riêng cho matcher/order, shielded source, linkage và venue public. | Private payment không chứng minh private matching, MPC không sửa output leakage. |
| GD2 candidate nguồn | Retain known structural FAIL và strict privacy/no-waiver; autonomous work phải tìm cơ chế khả thi dưới contract hiện hữu. | Source cutover không fix hoặc biến FAIL thành chưa benchmark; không routine approval wait thay technical work. |
| Custody | Migrated market giữ custody ZEC/public SPL-ACK authority; native Ziquid giữ direct payment/prefund/proof. | Không chuyển market credit thành `VerifiedSettlementFact`, native spend authority hoặc gọi market noncustodial. |
| User gửi proof | Hướng sản phẩm cần thiết kế riêng; prover/relayer không nhất thiết server. | Proof source không tự chứng minh claimant/inventory, chi ZEC custody, cấp quyền trade Core hoặc tạo atomicity. |
| Vốn và lệnh | Unique physical backing, hold/reservation/entitlement, fee capital và reconciliation không chồng nhau. | Unknown/timeout/restart/cancel request không tự unlock tiền. |
| Native route đầu | Giữ Ironwood ZEC → EVM local workstream đã duyệt; actual public SPL target là market safety authority riêng. | SPL fixture transfers không bidirectional native Solana route, arbitrary private matching hoặc support mọi EVM. |
| Source/library | Zoss shared core độc lập; app vẫn sở hữu quyền tiền/private state. | Observation/receipt/quorum không cấp credit, payout hoặc refund. |

## 4. Trạng thái implementation — source đã ghép, sản phẩm chưa complete

### Destination ownership trong repo này

Kerb source thực sự đã chuyển vào `crates/protocol/src/market`, `crates/zcash/src/custody`, `crates/runtime/src/market` và `contracts/solana/{interface,program,harness}`; records/effect checks/signature domains/target semantics được giữ, không alias hoặc wrappers gọi lại sibling. Single `ziquid` CLI có allocation và `market` migration/replica/inspection/reconciliation/local-safety commands. Năm native crate roles và separate target builds không trở thành five money authorities mới; source market vẫn tách viewing/acquisition, eligibility/FAA nếu chọn, matcher, business effect authorizer và native spend signer.

**PostgreSQL-only active SQL:** native `store::ActorStore` inventory và migrated market ledger dùng shared transport/schema policy nhưng **separate configured schemas, scopes và money authority**. Native checked-U256 TOTAL cap/funding fences không market credits/holds; encrypted owner P/Q custody vẫn separate local files. SQL test targets compiled only; **SQL NOT RUN**, không local SQL tests, chờ private URI/isolated scope theo [SQL-VERIFICATION](SQL-VERIFICATION.md). Existing SQLite journals/sidecars và original Kerb operational DBs được giữ, không automatic data migration. PostgreSQL indexer là potential future use, chưa implemented từ cutover.

[Native status](NATIVE-IMPLEMENTATION-STATUS.md) owns current destination commands/counts/evidence. Actual Solana SBF/interface/compiled ELF và generated synthetic canonical three-business-ACK SPL transfers đã chạy; đó là **public legacy-SPL target**, không owner-ZK, source-ZEC payment/history/signing, SQL-backed combined lifecycle, strict private matching hay complete native manual consumer. Local P/Q/source-history subrelations, EVM allocation/base verifier và raw Zoss acquisition không complete financial certificate/DEX escrow/client.

### Hồ sơ Kerb nguồn được giữ nguyên

[Source implementation/run notes](imports/kerb/docs/README.md#implemented-local-safety-cores-2026-10-02) giữ Rust/PostgreSQL local safety/process/Solana synthetic/unsigned Ironwood evidence theo ngày. Lần nhập docs không rerun/chứng nhận các số liệu đó; later destination checks ở current status có scope riêng, không cộng source counts thành integrated proof. Original sibling/archive/manifests và operational stores không bị sửa.

Full source/history, FAA/MPC strict private matching, independent native proving/signing/broadcast/settlement/terminal ownership/excess-return, private uniqueness, wrapped resource qualification và company-off manual path vẫn thiếu. `LocalFixture` native payout không mined Zcash payment. Xem [feasibility nguồn](imports/kerb/docs/reviews/2026-10-02-strict-privacy-feasibility.md) và [current blockers](BLOCKERS.md); code relocation không đóng những acceptance này.

## 5. Điều còn phải giải để hoàn thành implementation

1. Cơ chế matching và privacy khả thi, giữ threat model/giới hạn/phân bổ đã yêu cầu hoặc có quyết định thay đổi rõ của user.
2. Đường market đầu cụ thể, hướng đi, tài sản, custody, finality, return/recovery và nghĩa vụ khi một chân đã trả.
3. Định nghĩa tương thích giữa order/allocation/credit/hold và native obligation; khác miền cần domain/version riêng, không generic `verified` boolean.
4. Quyền claimant, source/history, controlled spendable inventory và durable physical-identity dedup trước cấp credit; payout và refund theo state thật.
5. Hướng user tự submit: relation, witness khả dụng, anti-replay/consumption/transfer, server-offline submission và lifetime của funded rules.
6. Giữ destination ownership/packaging và independent target builds; actual migration không blanket rename hoặc permission reset/import funded operational data.
7. Autonomous full implementation được phép theo current user instruction, không routine reviewed-design approval waits. Deploy/sign/broadcast/funding/mainnet/publish/commit/push và thay custody/privacy authority vẫn cần quyền hành động/contract cụ thể.

Các yêu cầu này thuộc [BLOCKERS](BLOCKERS.md), không lý do âm thầm bỏ nửa sản phẩm hoặc gọi integrated safety core là completed DEX. [Archived full-project prompt](history/Z2Z-IMPLEMENTATION-SYSTEM-PROMPT.md) giữ broader mission; current implementation instruction là [V1 prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md). Routine decision-making không thay external action permission.

## 6. Refactor không xóa provenance

Current owners và năm module specs được refactor theo system/route/manual/data authority. Prior specs/plans/research/audit/overview giữ dated evidence và approval scope, thêm supersession/navigation thay đổi history claims. [Pre-redesign architecture](history/2026-10-02-pre-redesign-ARCHITECTURE.md) và [module snapshot](history/2026-10-02-pre-redesign-MODULES.md) lưu nội dung trước rewrite, source/snapshot hashes và link-only relocation trong [manifest](history/2026-10-02-pre-redesign-MANIFEST.json).

53 imported source Markdown files vẫn đối chiếu MANIFEST, không editorial sửa để che privacy/custody findings. Samechain note ledger và mutual swap composition mới chỉ proposed; reverse Zcash/Hyperliquid assets/venue-qualified capabilities và strict private matching vẫn cần construction riêng. Có self-submit proof không đồng nghĩa có source spend authority hoặc thêm quyền bất chấp trạng thái lệnh.
