# Kerb documentation import — nguồn của Ziquid mở rộng

**Snapshot/import: 2026-10-02.** Nguồn: `/home/harry-riddle/dev/github.com/build-onchain/kerb`. Đích: `ziquid-dex/docs/imports/kerb/`. Toàn bộ **53 tài liệu standalone Markdown** được đưa sang; Kerb nguồn không bị sửa/xóa. Code, Cargo manifests/locks, fixtures, build outputs, databases, private operational state và agent-context files không được nhập.

Đây là hồ sơ xuất xứ, **không phải sản phẩm Kerb đã merge code vào Ziquid**, không giấy phép chạy các plans hoặc giao dịch. [PRODUCT](../../PRODUCT.md), [CONSOLIDATION](../../CONSOLIDATION.md), [ARCHITECTURE](../../ARCHITECTURE.md), [MODULES](../../MODULES.md), [BLOCKERS](../../BLOCKERS.md) là thẩm quyền chung mới. Ziquid là gốc; Z2Z là tên sản phẩm tương lai, chưa rename namespace.

## 1. Toàn bộ phạm vi nhập

| Root nguồn được giữ nguyên dưới archive | Số files | Nội dung |
|---|---:|---|
| [`docs/`](docs/README.md) | 29 | Canonical/README, architecture, mechanism, security, business, legal, pitch, product, source captures, reviews và nested `docs/docs/superpowers` specs/plans. |
| [`zolana-review-2026-09-29/`](zolana-review-2026-09-29/README.md) | 18 | Hồ sơ review có ngày, gồm canonical, architecture, mechanism, legal, security, business, pitch và roadmap. |
| [`zolana-research-2026-09-30/`](zolana-research-2026-09-30/README.md) | 6 | Research protocol/custody, privacy/admission, business/legal, inventory và scope/evidence. |

[MANIFEST.json](MANIFEST.json) ghi từng source-relative path, source/import SHA-256, kích thước và link rewrites. Số lượng roots lấy từ inventory thực, không chỉ copy `docs/` rồi bỏ hai dossiers ngoài root.

Không phát hiện local assets hoặc standalone PDF/text/office docs khác trong inventory nguồn. External images/PDFs/web citations không được tải lại. Rustdoc nằm trong source code vẫn ở Kerb. Nếu nguồn thay đổi sau snapshot, manifest không tự đồng bộ; cần import update có provenance riêng.

## 2. Đọc các phần còn liên quan hiện tại

1. [Source README](docs/README.md) và [canonical §0](docs/00-CANONICAL.md#0-current-documentation-authority): authority nguồn, library direction và local safety status.
2. [Approved independent safety spec](docs/docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md) và [build plan](docs/docs/superpowers/plans/2026-10-02-kerb-safety-core-build.md): chỉ local safety increment, không approval full financial/private candidate.
3. [Strict-privacy feasibility](docs/reviews/2026-10-02-strict-privacy-feasibility.md): GD2 structural failure và strict/no-waiver decision; không sửa được bằng MPC hoặc payment privacy.
4. [Hyperliquid scope](docs/product/17-HYPERLIQUID-EXPANSION.md): asset P2P và external HyperCore spot riêng, chưa implement; user-proof discussion riêng.
5. [Zolana concept/actors](docs/reviews/2026-10-02-zolana-concept-and-actors.md): giữ hai dossiers cùng native cross-chain thesis, khác historical public-Solana proposal.
6. [Oct1 candidate](docs/docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md) và [review](docs/docs/superpowers/specs/2026-10-01-kerb-design-review.md): unapproved candidate và findings, không lựa chọn kiến trúc đã đạt privacy.

Các file business/legal/pitch/source captures được giữ đầy đủ, không biến hypothesis, vendor statement hoặc counsel question thành market validation/legal conclusion.

## 3. Nội dung nào current, historical hoặc known failing?

- **Implemented-local/source-reported:** Rust records, PostgreSQL journals/reservations, acknowledgement processes, local Solana synthetic safety transfers và unsigned Ironwood inspection ở **repo Kerb**. Các command/source paths trong archive yêu cầu chạy tại repo đó. Không chạy lại kết quả trong đợt import.
- **Approved-local:** Oct2 safety spec/plan. Không native proving/FROST/broadcast, strict-private matching hoặc funded network approval.
- **Proposed/known failing:** Oct1 financial/private candidate có GD2 structural FAIL. User giữ strict privacy; không có waiver/threat-model change từ hợp nhất.
- **Historical:** public-Solana stock/USDC auction/residual/fee/pitch/legal dossier, rejected message/wire assumptions và source observations có ngày. Các root Zolana vẫn cần giữ vì nguồn/evidence khác nhau, không disposable duplicates.
- **Recorded expansion:** Hyperliquid hai hướng và future user-submitted proofs, chưa support/enable. Source canonical không tự supersede canonical chung.

### Bất nhất nguồn cần giữ dấu vết

1. [Zoss–Kerb overview](docs/reviews/2026-10-02-zoss-kerb-overview.md) có no-code/preimplementation observations cũ; source README/local safety supersede phần status đó. Không coi mọi Kerb module còn empty.
2. Safety plan có successive dated completion/test records **và các acceptance còn Open**. Không chuyển dòng Open thành Passed từ code existence hoặc README mới; source status synchronization cần owner verification.
3. Safety spec mô tả thứ tự CPI/state; source inspection báo program thực tế lưu state trước CPI và cần rollback atomically khi CPI fail. Spec wording không phải proof của source-order hoặc rollback mới trong import.
4. Fee/auction/custody choices của các proposal có ngày không đồng nhất. Không kế thừa một fee/model/candidate selection thành product contract chung.
5. Research có old absolute-path/line references và session `artifactNNN` evidence IDs không có local files. Giữ như snapshot citations, không tạo fake artifacts hay pretend live paths.

## 4. Chính sách liên kết và byte fidelity

- Giữ original relative tree của ba roots để internal dossier links hoạt động, kể cả `docs/docs/superpowers/`.
- **79 đích link external-relative được rebase** trong bản nhập, chủ yếu sibling Zoss, để vẫn trỏ nguồn thật sau thay đổi độ sâu. Không sửa content claims/headings/names/approval status. Từng `from`/`to` có trong MANIFEST.
- Link tới implementation Kerb vẫn dependency ngoài repo, không code đã chuyển. Inline code/commands và old absolute citations được giữ nguyên làm bằng chứng có ngày; chạy từ Ziquid không được bảo đảm.
- Không tạo compatibility symlink, dummy code hoặc copy Zoss để che link lỗi. Link/anchor hỏng từ nguồn phải ghi nhận riêng trong [verification report](LINK-REPORT.json), không đổi interpretation nguồn để làm check xanh.
- External website links và external sibling readiness chưa được refresh bằng kiểm tra runtime/network. Snapshot không phải chứng nhận link web, privacy, audit, legality hoặc funds safety.

Các tài liệu nguồn có thể nói về private witnesses, FVK/custody/nonce và participant/legal topics. Đợt import không export operational data hoặc credential values; publication cần review/authorization riêng.
