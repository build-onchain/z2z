# Spec: Global docs cho ziquid-dex

> **Status — 2026-10-06:** historical docs design. Active lanes are native ZEC (L-ZEC, first-class, not V2), L-HEVM, L-SOL, L-NEAR and X.CROSSCHAIN (HTLC first, all pairs in parallel, no atomicity/privacy claim); the 2026-10-02 supersession header below still governs this document.

> **Authority/supersession update — 2026-10-02.** This Sep28–Oct1 document is a historical docs design, not an active rule limiting the repository to one engineering file, public-LP-first build order, transport/`Attested` authority or frame-only implementation. Preserve its dated decisions/sources/unchecked checklist. Current direction/behavior/packaging: [PRODUCT](../../PRODUCT.md), [ARCHITECTURE](../../ARCHITECTURE.md), [MODULES](../../MODULES.md); actual code/cohort/results: [native status](../../NATIVE-IMPLEMENTATION-STATUS.md); sole readiness: [BLOCKERS](../../BLOCKERS.md). Manual existing-money rights/data/resources: [SERVER-INDEPENDENCE](../../SERVER-INDEPENDENCE.md); docs-only expanded proposal: [redesign spec](2026-10-02-z2z-server-independent-architecture-design.md).
>
> The “no code/frame-only/no Zoss imports” present-tense notes below are old snapshots, not present permissions or inventory. Selected native priority now retains local complete Q, full validation/no SPV, proportional fixed actual transfers, independent all-hostile terminal recovery/excess return and manual native consumer acceptance; TS/UI remain deferred. Proposed samechain owner-controlled bilateral notes are unimplemented, legacy custody lacks unilateral ZEC exit and strict GD2 remains unresolved. No old source retrieval/date/contest statement, checklist, permission or gate status is renewed by this header; action authorization remains separate.

**Retained historical alignment notes and design body follow.**

- Ngày khởi tạo: 2026-09-28; nội dung lịch sử chốt 2026-09-29; status alignment 2026-09-30.
- **Trạng thái: HISTORICAL / SUPERSEDED; current-pointer alignment 2026-10-01.** Body/checklist giữ record cũ, không current scope/build/evidence coverage/`Attested` interface. [ARCHITECTURE](../../ARCHITECTURE.md), [BLOCKERS](../../BLOCKERS.md), [MODULES](../../MODULES.md), [README](../../README.md) current authority: unsigned P + locally-proved complete Q/no user FVK cho S → full-T/net-consideration/source-history proofs → solver-prefunded local native EVM actual transfers → privacy/lifetime. [Zoss shared native core](../../../../zoss/docs/ARCHITECTURE.md) external, **message profile non-money optional**, future library reuse Proposed/chưa imports/dependencies. [Sole Zoss register](../../../../zoss/docs/BLOCKERS.md) giữ G/Z/B và separate library acceptance; [DEX integration](../../../../zoss/docs/private_dex.md) current boundary. Transport-only/source-refund-first body historical, không current authority; facts/checklist/authorization lúc đó giữ nguyên. No gate Pass hoặc implementation authorization từ docs adoption.
- Không dùng git theo lựa chọn của người dùng. **Tại thời điểm spec lịch sử:** repo chưa có code; cập nhật tài liệu không phải triển khai sản phẩm. Current repo có frame-only code/layout theo [MODULES](../../MODULES.md), không completed protocol; body lịch sử dưới đây không current frame authorization.

## 1. Mục tiêu và đầu ra

Một tài liệu engineering duy nhất, `docs/ARCHITECTURE.md`, mô tả mục tiêu, bằng chứng, ranh giới, interface đề xuất, privacy/trust, cổng xác minh và quyết định chưa chốt. README tóm tắt sản phẩm dự kiến và giới hạn hiện tại cho người đọc bên ngoài; không thay thế kiến trúc. Không tạo code, scaffold hoặc file engineering thứ hai.

Tài liệu phải giúp kỹ sư phân biệt: điều đã quan sát được với đề xuất; LP công khai với settlement cross-chain shielded; giao thông điệp với chuyển tài sản; OrderVenue native với LP; điều kiện cần trước khi mở từng tuyến.

## 2. Quy tắc bằng chứng

- Mọi thành phần, interface và mitigation chưa xây đều là **Proposed**. Không có DEX, agent execution, tích hợp Zoss hay quote giao dịch đang chạy trong repo.
- Gắn nguồn, ngày và phạm vi cho **Verified** (ghi rõ vendor API, on-chain, source hay vendor claim khi cần); **Assumption** có nguồn gốc và cách xác minh; **Unresolved** có điều kiện đóng; luật cuộc thi không truy cập được công khai là **User-provided**. Không biến forum, paper đề xuất hoặc snapshot thành bằng chứng triển khai.
- Trong `ARCHITECTURE.md` hiện tại: E1 chỉ là catalog SPL mint `A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS`; E6 là mint authority còn tồn tại, controller/backing chưa xác định; E4 là metadata pool từ Raydium API + RPC owner check; E5 là snapshot vault 2026-09-29, **mint của từng vault chưa được đọc trực tiếp**. Không coi snapshot, TVL hay công thức x·y=k là executable quote; cần kiểm tra mint vault, quote và slippage thật trước khi giao dịch.
- Phase 0 công khai: không gọi là private, shielded, atomic, trustless hoặc migration tự động. Không hứa khả năng rút, hạn quyền agent, refund hoặc custody an toàn nếu chưa có primitive và test chứng minh.

## 3. Năm ranh giới sản phẩm cần tách bạch

1. **Public Solana LP (Proposed):** pool ZEC/USDC dùng wrapped SPL ZEC; venue CPMM là ứng viên, CLMM cũng được quan sát nhưng vault không cho biết thanh khoản trong range. LP/swap, owner, amount, pool và thời gian đều công khai. Người đã có SPL ZEC là phạm vi đầu tiên; bridge/mint control là rủi ro riêng.
2. **Optional public 1Click route (Proposed):** adapter NEAR 1Click chỉ cho pair được API hỗ trợ và sau khi kiểm tra điều khoản/tính sẵn có. ZEC được NEAR ghi là transparent-only. Điều khoản developer §4.1(h) đòi địa chỉ ví nguồn không bị che khi dùng API; không thể dùng tuyến này để quảng bá shielded cross-chain hoặc ZECATHON Cross-Chain privacy.
3. **Optional Zoss transport (Proposed):** [Zoss](../../../../zoss/docs/ARCHITECTURE.md) là thiết kế chuyển thông điệp/attestation theo Endpoint–Verifier–Route; `AttestedQuorum` là giả định tin cậy, không phải proof canonical-chain. Zoss không giữ tiền, không tạo settlement, timeout refund hoặc bằng chứng phủ định rằng chưa thanh toán. Không hàm ý tích hợp đã chạy.
4. **Independent shielded settlement research (Blocked):** luật khóa, claim và hoàn trả tài sản mỗi chain là việc của settlement app riêng, không của transport. [Atheon ZWAP paper](https://zwap.atheon.xyz/) (2026-03-27) mô tả ECDH multiplicative aggregate-key lock + hash-lock với chứng minh ZK off-chain buộc cùng secret; đường Zcash cụ thể trong paper là transparent P2SH và lộ amount/timing/solver graph. [Orchard-native early-access forum claim](https://forum.zcashcommunity.com/t/zwap-trustless-shielded-atomic-swaps-for-zcash-early-access/55874) về sau là tuyên bố nhà cung cấp, không phải chứng minh từ paper hay xác minh Ironwood/Solana. Source-side refund, absence proof, Stuck recovery, watcher privacy và anonymity set cần giải trước khi có tuyến chuyển giá trị.
5. **Native ZSA OrderVenue (Future/Proposed):** [ZIP 226](https://zips.z.cash/zip-0226), [227](https://zips.z.cash/zip-0227), [228](https://zips.z.cash/zip-0228) còn Draft. ZIP 228 định nghĩa order/matching/bundle, không định nghĩa LP pool/share. Không tự chuyển vị thế LP Solana thành native ZSA.

## 4. Kiến trúc và interface đề xuất

Core độc lập chain giữ Intent/policy/authority/position logic; adapter và venue chạm chain. `LPVenue` phải khai báo capabilities cho CPMM (không range) và CLMM (có range), không hardcode `RaydiumClmmVenue`. `OrderVenue` là ranh giới khác với LP. `SettlementAdapter` chỉ mô tả ứng viên cross-chain, không ngụ ý payout/refund đã khả thi; mode `Attested` xác nhận mức tin cậy vận chuyển thông điệp, không biến Zoss thành lớp settlement. Mỗi tuyến phải khai báo `PrivacyDisclosure` theo từng leg; từ chối yêu cầu không đáp ứng được thay vì âm thầm hạ cấp.

Agent grant, ký có giới hạn, pause và đường rút là vấn đề thiết kế và xác minh, không bảo đảm người dùng hiện có. Interface pseudo-code không phải API được triển khai. Token định danh bằng chain và mint/asset ID, không bằng symbol. Khóa, grant và quyền rút cần threat model bao gồm hành vi khi pause, khi agent bị lộ khóa, và khả năng exit trực tiếp nếu được pool/wallet hỗ trợ.

## 5. Roadmap độc lập và rủi ro

- P0 public LP/swap chỉ mở sau khi xác minh người kiểm soát mint authority/backing, đo executable liquidity bằng simulation theo kích thước giao dịch, chọn pool đúng mint, chốt tham số slippage và cơ chế exit; ngưỡng quyết định phải dựa trên đo lường, không bịa.
- Agent LP là nhánh độc lập: grant enforcement, signing boundaries, revoke/pause, giới hạn thua lỗ và fork simulation cần proof riêng; không mặc nhiên theo sau P0.
- Optional 1Click route là nhánh công khai riêng, kiểm tra pair và điều khoản tại thời điểm tích hợp. Optional Zoss transport không mở cổng settlement. Shielded settlement research có gate riêng, chặn khi chưa bảo đảm refund/recovery và kiểm chứng privacy/chain compatibility. ZSA venue chỉ xét khi ZIPs được kích hoạt, có client và liquidity/matcher.
- Theo luật ZECATHON do người dùng cung cấp nhưng trang sign-in chặn kiểm tra công khai, rò rỉ privacy có thể bị loại. P0 công khai không đáp ứng yêu cầu Cross-Chain “without unshielding”; không tự chọn track hoặc diễn giải đó là phán quyết của giám khảo.

## 6. Checklist xác minh tài liệu (không phải kết quả test)

- [ ] E-rows có nguồn chính, ngày, nhãn bằng chứng, giới hạn và điều kiện đo lại; mint/pool đúng địa chỉ, snapshot khác executable liquidity, claim từ vendor khác proof.
- [ ] README, kiến trúc và các quyết định có cùng năm ranh giới và cùng trạng thái Proposed/Blocked/Future; không có câu mô tả code hoặc route đang chạy.
- [ ] Sơ đồ, interface, flow và trust table phân biệt Zoss transport với value-bearing settlement; không hứa automatic refund, atomicity hoặc custody safety.
- [ ] Roadmap có gate riêng cho P0, agent, 1Click, shielded settlement, ZSA và ZECATHON; không có ngưỡng bịa hoặc migration LP tự động.
- [ ] Link nội bộ/nguồn chính kiểm tra được; Mermaid được kiểm tra bằng cách phù hợp môi trường hoặc giới hạn render được ghi rõ. Không còn TODO/TBD hay thuật ngữ privacy áp vào P0.

Checklist là tiêu chí kiểm tra tài liệu, không xác nhận các gate kỹ thuật đã pass.
