# Kerb — mở rộng sang Hyperliquid

**Trạng thái ngày 2026-10-02:** theo yêu cầu của người dùng, ghi nhận **cả hai hướng**: đưa tài sản Hyperliquid vào thị trường P2P của Kerb, và cho phép đặt lệnh spot trên HyperCore từ giao diện Kerb. Đây là quyết định về phạm vi tài liệu/sản phẩm, **không phải phê duyệt triển khai**. Tích hợp Hyperliquid chưa được cung cấp; không có cặp tài sản, hợp đồng, ví được ủy quyền hay đường chuyển tiền nào được tài liệu này xác nhận hoạt động.

Việc xây dựng protocol đang được tạm dừng để làm rõ tài liệu. Không sửa mã, cài dependency, triển khai, ký/gửi giao dịch hay chuyển vốn theo ghi nhận này. Không thêm perps, đòn bẩy hoặc tự động chuyển phần lệnh còn dư sang HyperCore.

Thẩm quyền hiện tại nằm ở [canonical §0](../00-CANONICAL.md#0-current-documentation-authority). [Spec safety-core đã được phê duyệt](../docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md) vẫn giữ nguyên phạm vi. Mục tiêu đầy đủ **native Solana↔Ironwood**, custody ZEC và yêu cầu strict privacy không bị thay thế bởi hướng Hyperliquid. [README hiện tại](../README.md#implemented-local-safety-cores-2026-10-02) phân biệt bằng chứng local safety với những phần chưa được chứng minh.

Quy ước bằng chứng: **P** = nguồn sơ cấp; **I / [INFERENCE]** = suy luận; **U** = chưa xác minh. Mô tả từ tài liệu Hyperliquid là phát biểu của nhà cung cấp, không phải kết quả kiểm chứng độc lập của Kerb. Các quy tắc an toàn dưới đây là yêu cầu nếu tích hợp được phê duyệt sau này, không phải tính năng đã có.

## 1. Hai hướng khác nhau, không gộp thành một thị trường

| | A — tài sản Hyperliquid trong P2P Kerb | B — spot HyperCore từ giao diện Kerb |
|---|---|---|
| Người dùng làm gì? | Đặt lệnh với người dùng khác trong thị trường do Kerb quản lý. | Chủ động chọn nơi thực thi bên ngoài, rồi đặt lệnh trên order book HyperCore. |
| Ai khớp lệnh? | Cơ chế Kerb, sau khi có thiết kế được phê duyệt và đáp ứng privacy. | HyperCore; không phải cơ chế đấu giá/khớp lệnh P2P của Kerb. |
| Tài sản đến từ đâu? | Tài sản chính xác và inventory đã được định danh, kiểm tra, khóa cho cặp Kerb đó. | Số dư spot thực sự sử dụng được trong tài khoản HyperCore đã chọn. |
| Kerb chịu trách nhiệm gì? | Admission, quyền sở hữu, holds, phân bổ, nghĩa vụ thanh toán, custody, finality và phục hồi theo thiết kế của cặp. | Hiển thị đúng nơi thực thi, điều kiện, quyền ký và kết quả; không ghi một lệnh Core thành giao dịch P2P. |
| Thanh khoản có nghĩa gì? | Cần người mua/người bán hoặc nguồn vốn đối ứng được phê duyệt riêng; không tự thừa hưởng order book HyperCore. | Chỉ thanh khoản thực tế của cặp spot HyperCore được chọn, tại thời điểm đặt lệnh; không bảo đảm khớp đủ. |

**Ví dụ minh họa, chưa được định danh/đủ điều kiện:**

- **HYPE/ZEC:** minh họa hướng A, một người giao tài sản HYPE đã chọn và nhận native ZEC; người còn lại giao ZEC và nhận HYPE. Không khẳng định đây là cặp niêm yết HyperCore, cặp Kerb đã được duyệt, hay đường chuyển tài sản đã tồn tại.
- **HYPE/USDC trên Solana:** minh họa hướng A nếu một chân là tài sản HYPE trên miền Hyperliquid đã chọn và chân kia là đúng mint USDC trên Solana. Đây là giao dịch giữa các chain, không phải lệnh spot Core sử dụng trực tiếp số dư USDC Solana.
- Hướng B phải chọn **cặp spot thực sự tồn tại và đã được kiểm tra trên HyperCore**. Một ticker USDC trong giao diện không chứng minh đó là cùng tài sản hoặc cùng số dư với USDC Solana.

Không có xác nhận niêm yết, mint/contract/token ID, thanh khoản, provider, tư cách pháp lý hay đối tác cho các ví dụ trên (**U**). Ticker chỉ giúp đọc ví dụ; không phải định danh hay chứng cứ fungibility.

## 2. HyperEVM và HyperCore: hai miền thực thi của cùng một L1

Nguồn **H1** mô tả Hyperliquid là một L1, có hai thành phần thực thi:

- **HyperEVM:** môi trường smart contract EVM. Đây là nơi cần xem xét khi nói tới hợp đồng escrow hoặc tài sản ERC-20; không được suy ra rằng hợp đồng Kerb đã có ở đó.
- **HyperCore:** miền thực thi native có spot order book. Lệnh, hủy và khớp spot ở đây không tự trở thành giao dịch trong hợp đồng P2P Kerb.

Không gọi đây là “thêm hai blockchain độc lập”. Tuy nhiên, cùng một L1 không làm số dư, định danh tài sản, quyền ký và trạng thái giữa hai miền tự đồng nhất, cũng không tạo atomic settlement với Solana hay Ironwood.

Nguồn **H2** mô tả read precompiles và **CoreWriter** để tương tác giữa HyperEVM và HyperCore. Tài liệu phân biệt việc đưa action vào hàng đợi với việc thực thi trên Core và nêu độ trễ cho order actions. Vì vậy, một EVM transaction thành công hoặc một log CoreWriter chưa phải chứng cứ lệnh Core đã khớp. Đọc số dư qua precompile cũng không chứng minh Kerb có quyền chi tiêu số dư đó. **Chưa chọn** API trực tiếp hay đường hợp đồng CoreWriter cho sản phẩm.

### Không tự ánh xạ Core token thành ERC-20

Nguồn **H3** yêu cầu liên kết cụ thể giữa `Core spot` và `EVM spot` trước khi chuyển đổi. HYPE là trường hợp riêng: số dư native trên HyperEVM, không mặc nhiên là ERC-20. Wrapped HYPE cũng không được tự đồng nhất với HYPE native.

Chính tài liệu Hyperliquid cảnh báo không mặc định fungibility chính xác, không bảo đảm linked contract là ERC-20 hợp lệ hay có đủ supply tại system address, và có sai khác decimals/làm tròn. Một liên kết token không thay cho kiểm tra bytecode, quyền quản trị/nâng cấp, số dư bảo chứng và hiệu ứng chuyển thực tế.

**Yêu cầu của Kerb:** định danh riêng network và miền Core/EVM, token ID hoặc địa chỉ contract/native asset, decimals, account/custody owner và đường chuyển được kiểm tra. Inventory ở Core, EVM, Solana và Ironwood không được gộp chỉ vì cùng ticker. Chuyển tài sản giữa các miền phải đối soát đúng phần đã chuyển; không đồng thời đếm số dư cũ và số dư mới làm bảo chứng hai nghĩa vụ.

## 3. Câu chuyện người dùng

Các câu chuyện dưới đây diễn tả hành vi mong muốn, **chưa có sẵn để sử dụng**.

### A — trao đổi P2P trong Kerb

1. **Người bán** chọn cặp tài sản chính xác đã được phê duyệt, kiểm tra chân HYPE nằm ở Core hay EVM, số lượng, giá tối thiểu, phí tối đa và địa chỉ nhận tài sản đối ứng. Người bán ký việc cấp vốn và lệnh của mình; không ký thay người mua.
2. **Người mua** kiểm tra tài sản sẽ nhận, nguồn vốn của mình, mức chi tối đa, limit và nơi nhận. Với ví dụ HYPE/ZEC, tiền ZEC chỉ trở thành credit sau kiểm tra claimant, lịch sử canonical, inventory được kiểm soát và chống cấp credit trùng; proof hay thông báo nạp không tự đủ.
3. Kerb giữ đủ tài sản/số tiền tối đa cho lệnh, làm admission và khớp theo cơ chế riêng đã được phê duyệt. Không dùng việc có order book HyperCore để giả định lệnh P2P sẽ khớp hoặc để bỏ qua vấn đề privacy hiện tại.
4. Nếu khớp một phần, người dùng thấy phần đã khớp, nghĩa vụ còn chờ thanh toán và phần có thể hoàn lại **tách biệt**. Chỉ kết quả/phân bổ đầy đủ có thẩm quyền và trạng thái chain phù hợp mới cho phép giải phóng phần không dùng.
5. Nếu không khớp, bị loại, hủy hợp lệ hoặc abort, người dùng nhận lại phần được phép theo trạng thái bất biến và bằng chứng custody. Timeout không tự cấp quyền hoàn tiền. Thứ tự thanh toán cho cặp Hyperliquid chưa được lựa chọn; không sao chép máy móc quy tắc `SPLReleased` sang HYPE.

Với HYPE/USDC Solana, người bán không phải tự nạp cả hai chân; mỗi bên cấp vốn cho chân của mình. Việc không có bridge được chọn không được che bằng token “đại diện”, credit không có backing hoặc một chuyển tiền giả trong giao diện.

### B — giao dịch spot bên ngoài qua giao diện Kerb

1. **Người dùng chủ động chọn “spot HyperCore”**, tách khỏi lựa chọn P2P Kerb. Giao diện hiển thị tài khoản thực thi, cặp/token ID, nguồn số dư, nơi tài sản nhận sẽ nằm và dữ liệu giá còn hiệu lực hay chỉ tham khảo.
2. Người dùng xác nhận số lượng, limit, thời hạn/điều kiện lệnh, khả năng partial fill, phí giao dịch và các phí chuyển/gas áp dụng. Không dùng hạn mức hoặc fee schedule lịch sử của Kerb làm phí mặc định của HyperCore.
3. Người dùng ký đúng action, hoặc chủ động phê duyệt một delegated signer với phạm vi đã được rà soát. Việc kết nối ví, xem quote hay ký lệnh P2P không phải quyền đặt lệnh Core.
4. Lệnh thực thi trên HyperCore. Kết quả phải phân biệt đã gửi, đang chờ, đang mở, đã khớp một phần, đã khớp, đã hủy và `Unknown`; không báo “đã nhận trên Solana” chỉ vì spot trade ở Core đã khớp.
5. Nếu người dùng muốn rút/chuyển sang EVM, Solana hoặc nơi khác, đó là thao tác riêng với tài sản, đường chuyển, phí, finality và quyền nhận được kiểm tra. Không có đường đã được duyệt thì giao diện phải nói không khả dụng, không giả lập bridge.

Không chọn tự động dùng HyperCore khi P2P không khớp. Một lần giao dịch ngoài sau P2P chỉ có thể được đề nghị khi phần vốn đã thực sự được giải phóng, quote/limit/phí/đích được cập nhật và người dùng đồng ý riêng. Hủy hoặc chuyển hướng một lệnh đang mở không phải cách bỏ qua reservation.

## 4. Trách nhiệm, quyền ký và custody

| Thành phần | Trách nhiệm nếu được tích hợp | Không có thẩm quyền chỉ nhờ vai trò này |
|---|---|---|
| Ví/người dùng | Cho phép cấp vốn, lệnh, hạn mức, phí và đích nhận chính xác; duyệt ủy quyền riêng nếu có. | Không dùng một chữ ký cho mọi miền hay coi “connect wallet” là quyền chi tiền. |
| Giao diện/định tuyến Kerb | Phân biệt A/B, hiển thị trạng thái và điều kiện, chuẩn bị yêu cầu đúng quyền. | Không tự đổi nơi thực thi, nâng limit/phí, đổi người nhận hoặc tự chuyển vốn. |
| Admission/ledger Kerb | Xác minh quyền claimant; giữ credit, holds, inventory, nghĩa vụ và lịch sử đối soát của P2P. | Không phát hành credit vì API báo thành công; không coi Core balance công khai là inventory Kerb kiểm soát. |
| Custody/chủ số dư | Kiểm soát đúng tài sản và kiểm tra hiệu ứng trước quyền chi; giữ input/nonce/intent còn sống. | Signer lệnh Core không mặc nhiên sở hữu hoặc được rút tất cả tiền; custody ZEC không biến thành signer Core. |
| HyperCore/HyperEVM và nguồn chain | Cung cấp thực thi và bằng chứng trạng thái của miền tương ứng theo chính sách được kiểm tra. | Không tự chứng minh claimant, không thay ledger Kerb, không bảo đảm thanh toán chain khác. |
| Thư viện Zoss nếu tái sử dụng | Acquisition/observation/context/client plumbing trong process Kerb theo canonical §0. | `SourceObservation` hay `QuorumAcceptedMessage` không cho quyền đặt lệnh, cấp credit, payout hay refund. Messaging vẫn OFF / non-money. |

**Custody chưa được chọn cho tài sản Hyperliquid.** Không quảng cáo “non-custodial” chỉ vì dùng ví người dùng hoặc smart contract. Nếu Kerb hay contract giữ tài sản, cần nêu ai có thể chi, ai có thể chặn, quyền nâng cấp và khả năng mất/treo tiền. Nếu hướng B dùng số dư trực tiếp của người dùng trên Core, số dư đó vẫn không được đưa vào ledger P2P như bảo chứng của Kerb.

### “Agent wallet” là delegated signer, không phải AI

Theo **H4**, `API wallet` còn được gọi là `agent wallet`: master account phê duyệt một ví để ký thay cho master/sub-account. “Agent” ở đây **không yêu cầu AI**, bot hay bên tạo thanh khoản. API wallet dùng để ký; truy vấn số dư phải dùng địa chỉ tài khoản thực tế.

Không suy từ tên `agent` ra quyền tùy ý rút/chuyển mọi tiền, cũng không khẳng định signer chỉ có đúng quyền trade nếu chưa kiểm tra action cụ thể. Trước khi đề xuất ủy quyền cần rà soát **chính xác** action được phép, account/sub-account liên quan, cách phê duyệt, thu hồi, hết hạn, builder fee nếu có và hậu quả nếu key bị lộ. Tài liệu này chưa chọn signer hay quyền cho Kerb.

**H4** còn cảnh báo nonce theo signer, có thể dùng chung giữa sub-account, và nonce state của API wallet bị prune trong một số trường hợp; tái dùng địa chỉ có thể khiến action đã ký bị replay. Đây là lý do cần giữ lịch sử ý định/quyền ủy quyền của Kerb, không coi đổi ví hay xóa cache là hết nghĩa vụ. Theo **H5**, `sign_l1_action` và `sign_user_signed_action` là hai signing schemes khác nhau; không thay bằng chữ ký Solana Ed25519, business acknowledgement hoặc FROST ZEC.

## 5. Limit, phí, đích nhận và vốn không được dùng hai lần

Đây là ranh giới an toàn, không phải thiết kế lại safety-core hiện có:

- **Consent riêng theo nơi thực thi:** lệnh phải ràng buộc đúng miền, tài khoản/cặp, side, số lượng, limit, mức chi và phí tối đa, đích nhận và điều kiện/thời hạn. Quote hiển thị không phải cam kết giá hoặc bảo đảm khớp. Không lén thêm builder/platform fee hoặc tự đổi điểm đến sau chữ ký.
- **Reservation độc quyền:** cùng một phần tài sản không được vừa backing hold P2P, vừa khả dụng để gửi lệnh Core hoặc rút/chuyển. Lệnh Core đang mở và nghĩa vụ Core chưa rõ kết quả phải được giữ riêng; số dư tổng không thay cho số dư thực sự còn dùng được. Phí do sponsor chịu phải có vốn riêng, không dùng thiếu hụt backing người dùng.
- **Partial fill:** phần đã khớp, phần còn nằm trong lệnh và phần đã được giải phóng không chồng nhau. Hủy phần còn lại không đảo ngược phần đã khớp. Với P2P, nhận một chunk kết quả không đủ để giải phóng credit khi chưa có toàn bộ phân bổ và activation hợp lệ.
- **Cancel có race với fill:** yêu cầu hủy hoặc mất kết nối không chứng minh lệnh chưa khớp. Cần đối soát đúng lệnh/intent và trạng thái có thẩm quyền trước khi giải phóng phần còn lại; không tự đặt lệnh mới trên cùng vốn để “bù” một lần gửi chưa rõ kết quả.
- **`Unknown` giữ khóa:** lost response, timeout, restart, thiếu callback hoặc nonce đã dùng không có nghĩa “thất bại, không có hiệu ứng”. Không tạo intent cạnh tranh hoặc hoàn lại tiền chỉ vì chờ lâu. Giữ bằng chứng và đối soát exact action/order/fill/chuyển tài sản.
- **Cô lập ledger:** miền deployment/network/pair, inventory, credit, hold, obligation và replay của P2P phải tách với lệnh Core bên ngoài. Một fill Core không được làm receipt P2P; một chuyển Core↔EVM không được cấp hai credit; không reset lịch sử bằng nâng cấp SDK/đổi signer.

Spec hiện tại chỉ định domain gồm Solana và Ironwood cùng các ràng buộc asset/program cụ thể; local Solana dùng synthetic legacy SPL. Các safety invariant là cơ sở để xem xét mở rộng, **không chứng minh API/domain/escrow hiện có đã hỗ trợ Hyperliquid**. Phạm vi phê duyệt cũ không tự mở rộng khi thêm tên tài sản trong tài liệu.

## 6. Finality, non-atomic settlement và privacy

**Finality của nguồn là việc riêng:** Kerb phải xác minh network/miền, action hoặc transaction occurrence, account/receiver, lượng tài sản, quyền claimant, lịch sử canonical và inventory có thể chi dưới chính sách finality được phê duyệt. “Gửi được”, chữ ký hợp lệ, HTTP thành công, callback, event enqueue hoặc một số dư đọc được không phải tất cả các kiểm tra đó.

**H1** mô tả `one-block finality` của HyperCore kế thừa HyperBFT. Đây là phát biểu nhà cung cấp, không phải phép đo của Kerb và không cho phép bỏ chính sách source observation/finality. Không lấy finality Core để chứng nhận một linked ERC-20 an toàn, một chuyển tiền ngoài chain đã đến, hoặc payout native ZEC đã hoàn tất. Các nguồn đã đọc có nội dung nhắc testnet hoặc trạng thái mainnet theo từng tính năng; phải kiểm tra lại đúng môi trường, không tự coi mọi ví dụ trong docs là đang khả dụng.

**Giao dịch giữa Hyperliquid và Solana/Ironwood là non-atomic.** Một chân có thể hoàn tất trong khi chân kia bị từ chối, mất đáp ứng, chưa rõ hoặc bị custody giữ lại. Ledger transaction, quorum business acknowledgement và thư viện chung không làm hai chain commit cùng lúc. Thu hồi khóa/API wallet, hủy order hay timeout không đảo ngược chân đã trả; không hứa refund cưỡng chế hoặc lịch hoàn tiền nếu chưa có khả năng thực tế. Không có bridge/provider hoặc bảo đảm thanh khoản tự động được lựa chọn ở đây.

**Strict privacy và GD2 giữ nguyên.** [Hồ sơ feasibility](../reviews/2026-10-02-strict-privacy-feasibility.md) cho thấy vấn đề public membership/identity và own-result/asset-disposition inference của candidate; thêm tài sản hoặc order book ngoài không sửa được vấn đề đó. Không tuyên bố HyperCore có “private execution” cho Kerb. **H1** mô tả order/cancel/trade minh bạch; **H2** mô tả enqueue và execution xuất hiện trên explorer. Địa chỉ, lượng, thời điểm, kết quả riêng của trader và liên kết nạp/rút vẫn phải nằm trong phân tích end-to-end.

Hướng B không được trình bày như cách lách hoặc giảm yêu cầu strict-private của hướng A. Việc ghi nhận một sản phẩm spot công khai bên ngoài không phê duyệt privacy waiver, matcher threat model mới hay funded-private enablement. Không quảng cáo “ẩn danh tuyệt đối”, “không thể suy luận” hoặc “riêng tư nhờ cùng L1/MPC” từ các nguồn này.

## 7. Tự nộp proof là thảo luận riêng

Khả năng người dùng tự nộp funding proof trong tương lai chưa được phê duyệt triển khai. Kể cả một proof phù hợp có thể giúp kiểm tra nguồn, nó vẫn không tự:

- Chứng minh quyền claimant và inventory custody có thể chi nếu các điều kiện đó chưa được kiểm tra.
- Cấp quyền đặt/hủy lệnh HyperCore, phê duyệt API wallet hoặc chuyển Core↔EVM.
- Biến native ZEC thành số dư spot Core, loại bỏ threshold custody ZEC hay xóa nghĩa vụ payout/refund.
- Tạo atomic settlement, thanh khoản đối ứng hoặc giải quyết GD2.

Quyền chứng minh sự kiện, quyền ghi credit và quyền chi tài sản là ba việc khác nhau. Không dùng một receipt/boolean `verified` để gộp chúng.

## 8. Điều kiện cần trước khi cân nhắc triển khai

Đây là danh sách điều kiện để ra quyết định, **không phải code plan, lịch giao hàng hay phê duyệt ngầm**:

1. **Phê duyệt phạm vi riêng:** người dùng duyệt thiết kế cụ thể cho A và/hoặc B. Không tự chọn thứ tự giao hàng, cơ chế fallback, perps, leverage, bridge hay provider.
2. **Định danh và đủ điều kiện:** kiểm tra chính xác asset/market/account/network, Core↔EVM link nếu dùng, contract code/authorities, decimals, inventory và quyền sử dụng. Những cặp minh họa vẫn U cho đến khi có chứng cứ này.
3. **Signing/custody:** chốt chủ vốn, quyền ký theo action, phê duyệt/thu hồi API wallet nếu có, khả năng spend/rút/chặn và quản trị key. Bên ký Core, business authorizer, Solana signer và native ZEC custody không thay thế nhau.
4. **Safety và phục hồi:** chốt nguồn/finality, reservation, partial fill/cancel race, unknown outcome, anti-replay, inventory conservation, phí và đích bất biến. Cần bằng chứng cho đường thực thi thực tế; local safety trên tài sản synthetic không đủ chứng minh đường Hyperliquid.
5. **Privacy và pháp lý:** với P2P private, có cơ chế đáp ứng yêu cầu giữ nguyên và giải quyết các blocker hiện tại; với spot ngoài, công bố đúng bề mặt quan sát và không mượn nhãn private. Rà soát điều kiện sử dụng, phạm vi người dùng/jurisdiction và trách nhiệm custody/venue; chưa có kết luận pháp lý (**U**).
6. **Ủy quyền hành động cụ thể:** code/dependency là quyết định sau tài liệu; deploy, ký, broadcast, vốn thật, mainnet, publish hay push cần đúng phê duyệt riêng. Tài liệu chính thức Hyperliquid không phải sự cho phép hành động thay người dùng.

## 9. Nguồn và mức độ xác minh

**Ngày truy xuất tất cả nguồn bên ngoài dưới đây: 2026-10-02.** Đường dẫn được tìm từ `llms.txt`, sau đó đọc live bản Markdown chính thức. Các trang được đọc không nêu ngày xuất bản/cập nhật trong nội dung trả về; **không gán ngày 2026-10-02 làm ngày phát hành** hoặc suy lịch sử triển khai từ đó. Đây là snapshot tài liệu nhà cung cấp, không phải kiểm tra mạng/cặp/contract hay benchmark. Không dùng các con số throughput, giá hay danh sách thị trường làm bằng chứng cho quyết định này.

| ID | Nguồn sơ cấp chính thức | Phát biểu đã đọc / phạm vi dùng | Giới hạn và phân biệt suy luận |
|---|---|---|---|
| H0 | [Hyperliquid Docs — llms.txt](https://hyperliquid.gitbook.io/hyperliquid-docs/llms.txt) | P: mục lục dẫn tới H1–H6. | Không chứng minh readiness, ngày triển khai hay các cặp được Kerb duyệt. |
| H1 | [About Hyperliquid](https://hyperliquid.gitbook.io/hyperliquid-docs/about-hyperliquid.md) | P: một L1, hai thành phần HyperCore/HyperEVM; Core spot order books, hoạt động minh bạch và phát biểu one-block finality. | Không có xác minh độc lập finality hoặc privacy của Kerb. Không suy “hai chain mới”, thanh khoản được bảo đảm hay private Core execution. |
| H2 | [Interacting with HyperCore](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/interacting-with-hypercore.md) | P: read precompiles, CoreWriter, action limit/cancel; order actions có enqueue và execution tách biệt. | Phần read precompiles nói testnet; chưa kiểm tra availability trên môi trường đích. I: enqueue/read không đủ làm chứng cứ fill/quyền chi của Kerb. |
| H3 | [HyperCore <> HyperEVM transfers](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/hypercore-less-than-greater-than-hyperevm-transfers.md) | P: phải link token; HYPE nhận thành native EVM balance; cảnh báo fungibility, arbitrary bytecode, thiếu supply/ERC-20 checks và decimals. | Không xác minh một link, contract, supply hoặc đường rút cụ thể; không tạo bridge Solana/Ironwood. Các đoạn trạng thái mainnet không được dùng làm ngày phát hành hay lời bảo đảm tính năng hiện tại. |
| H4 | [Nonces and API wallets](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets.md) | P: API/agent wallet là signer được master phê duyệt; truy vấn bằng account thật; nonce theo signer; pruning/reuse có rủi ro replay. | Trang này không đủ xác nhận toàn bộ permissions theo action. Quyền cụ thể, signer Kerb và custody vẫn U; không suy AI hay unrestricted fund access. |
| H5 | [Signing](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing.md) | P: hai signing schemes `sign_l1_action` / `sign_user_signed_action`; chi tiết payload/encoding có thể làm sai signer. | Không có SDK/chữ ký/tích hợp nào được thử ở đây. I: phải giữ riêng miền chữ ký Core với quyền Solana/business/ZEC. |
| H6 | [Order types](https://hyperliquid.gitbook.io/hyperliquid-docs/trading/order-types.md) | P: limit hoặc giá tốt hơn; GTC, ALO, IOC và khả năng suborder không khớp đủ được mô tả. | Trang bao gồm cả loại lệnh không phải spot. Không suy mọi loại lệnh dùng được cho sản phẩm này; chưa chọn TIF hay xác minh cặp. Partial/cancel/Unknown là yêu cầu an toàn, không lời bảo đảm thực thi. |

**Nguồn nội bộ và thẩm quyền:** [canonical §0](../00-CANONICAL.md#0-current-documentation-authority), [safety spec §§1, 3–9](../docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md), [local implementation và giới hạn](../README.md#implemented-local-safety-cores-2026-10-02), [strict-privacy feasibility](../reviews/2026-10-02-strict-privacy-feasibility.md), [concept và actor review](../reviews/2026-10-02-zolana-concept-and-actors.md), [roadmap/decision history](16-ROADMAP-AND-DECISIONS.md). Các nguồn nội bộ giữ mục tiêu, ownership và invariant hiện có; không được dùng để giả nhận Hyperliquid đã tích hợp.
