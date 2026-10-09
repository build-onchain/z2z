# Ziquid / Z2Z — sản phẩm chung

## Phạm vi phát hành đã thu gọn — quyết định mới nhất 2026-10-06

**Thay thế samechain-first/CLI-only và mọi-lane-song-song cho bản phát hành đầu tiên:** một cặp, một chiều, giao dịch toàn bộ báo giá, hai bên online khi thỏa thuận, chọn đối tác/link và bốn màn hình Offers/quote, Review, Status, Recovery. Working default: **native shielded ZEC testnet → ETH Base Sepolia**, không phải network/note/deployment đã ready hoặc được phép deploy. U bán ZEC/mua ETH; S mua ZEC/cấp ETH. Payment authority chỉ release sau khi U tự kiểm target protection/finality; order/capabilities cụ thể phải theo construction được chọn và review, không mặc định P/Q. Mỗi bên giữ wallet, witness/backup và recovery độc lập.

[Roadmap R1–R10](Z2Z-V1-ROADMAP.md#active-approved-release--one-protected-native-zec-route-2026-10-06) giữ nguyên 30 task IDs. Owner chọn **bilateral privacy with explicit disclosure** và **investigate a different native settlement construction**; [matrix đã duyệt](ARCHITECTURE.md#approved-release-decision--2026-10-06) cho counterparty exact agreed terms/fees/own outcome, chấp nhận public ETH exact amounts/addresses/code/txs và IP/timing/linkage inference; keys/FVK/private witnesses chỉ local. **R1.2 policy-definition DONE; implementation/privacy verification future R3/R10.** Strict GD2/own-result noninference chỉ được thay cho release này, historical analysis giữ nguyên. No company custody/loss-prevention/recovery waiver. Full history, correct reachable hostile allocation/excess protection, private once-only và both-role company-off recovery vẫn bắt buộc; sound protocol prevention cần explicit review tương đương quyền giữ lại, không UI rejection. Direct P/Q financial NO-GO còn nguyên; alternative research không chọn mechanism/trust model. R1.1 freeze/R1.3 feasibility còn open, không release date hay samechain-owner certificate thay native financial composition.

App dùng local companion tái sử dụng runtime/transport/PostgreSQL riêng/custody hiện có; user bình thường không phải tự chạy PostgreSQL, CLI hay prover. Frontend sibling thuộc user: phối hợp integration contract, không takeover. Bản demo phải chuyển **real testnet assets**, không mock/custody/wrapped hoặc transparent-ZEC substitute. Bốn màn hình/companion là scope hiện tại; samechain 122 tasks, các chain/cặp khác, marketplace rộng, deliberate partial-order UX, maker-offline và wider GUI/production giữ backlog sau, không first-release prerequisites. Không xóa primitive, funded rights, journals hoặc recovery artifacts cũ.

**Quy tắc đọc phần dưới:** các nhãn V1/samechain-first/active parallel/GUI-later, selected-P/Q và unchanged strict-GD2 release constraint là baseline cũ, bị quyết định trên supersede có phạm vi; financial/loss-prevention/recovery và owner-local secret invariants vẫn giữ. Không tuyên bố mọi tài liệu cũ đã đồng bộ. Quyết định cho scope/policy/docs và alternative investigation, không cấp quyền alternative implementation/trust change, heavy proving, secret use, SQL provisioning/migration, deploy/sign/send/funds hoặc mainnet; permission riêng và observed evidence mới nhất vẫn quyết định.

## Baseline trước khi thu gọn — giữ product direction và provenance

**Design basis 2026-10-02; V1 scope consolidation 2026-10-06, chưa sản phẩm hoàn chỉnh.** Ziquid là repo gốc của tài liệu hợp nhất Kerb; **Z2Z là tên dự kiến**, chưa rename existing repo/package/binary. V1 yêu cầu mỗi user chạy `z2z-node` local cho P2P discovery/gossip, coordination và owner-local proving, không mandatory centralized backend. [V1 prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md), [delivery matrix](V1-DELIVERY-MATRIX.md), [roadmap](Z2Z-V1-ROADMAP.md), [122-microtask plan](V1-MICRO-IMPLEMENTATION-PLAN.md) và [decisions](V1-ARCHITECTURE-DECISIONS.md) own active scope. [Native status](NATIVE-IMPLEMENTATION-STATUS.md) giữ observed evidence; [CONSOLIDATION](CONSOLIDATION.md) giữ provenance. Planning không deployment, money execution hoặc privacy waiver.

## 1. Idea trong một câu

**Z2Z đang xây một DEX mua bán tài sản trên cùng chain và giữa các blockchain. Chợ P2P riêng là một phần chính: người mua và người bán đặt lệnh để giao dịch với nhau. Người dùng cũng có thể nhận báo giá từ bên nhận đổi hoặc chủ động chọn sàn ngoài. App/server hỗ trợ, nhưng với từng đường đạt điều kiện, người dùng vẫn có cách tự thực hiện quyền tiền khi công ty ngừng hoạt động.**

Sản phẩm hướng tới hai việc cùng lúc: bảo vệ phần thông tin giao dịch có thể bảo vệ được, và không trao quyền duyệt tiền tùy ý cho server. Không hứa mọi chain/tài sản đều kín, mọi giao dịch không custody, hoặc user luôn lấy lại tiền ngay khi hết giờ.

### V1 milestone — samechain-first, không toàn bộ sản phẩm

**V1 required journey:** hai owner chạy `z2z-node` CLI → tìm order qua P2P → kiểm exact backing/deployment/asset → owner-local prove và fresh exact packet consent từ cả maker+taker đang online → create/full hoặc partial fill/cancel/withdraw → nhận actual testnet assets và đúng quyền còn lại → restart/reconcile → encrypted backup/cold restore, independent history/witness, local prove, owner sign và direct/alternate-relay submit khi company off. Backup/artifact kit và controlled cold restore phải qualify **trước funding**; funded recovery drill phải chứng minh actual asset arrival, không chỉ decrypt/CPU journal/calldata.

Hành trình đầu tiên là samechain (owner answer Z1), dùng Native và một ERC20 vanilla fixed-supply 6 decimals. Chọn [Base Sepolia](V1-TESTNET-SELECTION.md) là **engineering default**, không phải owner approval. Pins và action approvals vẫn pending. Không mock verifier, không dùng Anvil thay testnet.

[Storage](V1-P2P-STORAGE-DECISION.md): design target là **PostgreSQL riêng của từng owner**. PostgreSQL chỉ giữ digests/identities. Bytes certificate/signed-tx nằm trong release capsule mã hóa ở local. Không có quyền chạy SQL local; giữ approved-private-URI hold. SP1 là candidate; proving feasibility và resource targets chưa qualify.

**Phát hành lane đầu tiên không có nghĩa là hoàn thành dự án.** Các lane sau ACTIVE song song, không thuộc V2:
- **L-HEVM:** spot trước, rồi nghiên cứu isolated position claims hướng tới đầy đủ use cases Core.
- **L-SOL:** owner-ZK trên Devnet.
- **L-NEAR:** owner-ZK, native NEAR trước, NEP-141 sau.
- **L-ZEC:** native ZEC với đủ P/Q, full source history, net classification, excess, uniqueness, privacy và recovery. Wrapped ZEC không thay thế được.
- **Cross-chain fills:** mọi cặp chạy song song, kể cả ZEC↔{Base, HEVM, SOL, NEAR}. Token/collateral legs trước (HTLC, không atomic và không private).

**Còn V2:** maker ký một lần rồi offline (standing multi-fill), GUI, hardware wallet, mainnet, Intents/1Click, LP/agents/ZSA. Strict GD2 vẫn Blocked. Hành trình samechain không đóng S1–S7, M1–M5 hoặc private-market gates.

### P2P nằm ở đâu trong DEX?

**P2P là chợ người mua/người bán của Z2Z, không một dự án hay tiện ích bên ngoài DEX.** V1 maker mở backed order rồi cùng taker online để kiểm/prove và fresh authorize từng exact full/partial fill; chain enforce settlement và remainder. **V2 target** maker ký một lần khi mở backed order, takers fill trong asset/quantity/net-price/fee limits kể cả maker offline. Standing construction và strict-private matching chưa qualify. Không có đối ứng thì không khớp; không phải nhắn tin rồi nhờ admin xác nhận tiền.

DEX là toàn bộ sàn, gồm chợ lệnh, báo giá, kiểm quyền, thanh toán, hủy/phần còn lại và đường tự sử dụng. **P2P nói ai giao dịch với ai; DEX nói sàn và cơ chế thực hiện giao dịch.** Settlement cùng-chain/cross-chain là cách thanh toán, không chợ riêng cạnh tranh với P2P. HyperCore là venue ngoài user chọn; LP/AMM là hướng khác giữ lại, chưa chọn AMM riêng làm cơ chế chính.

Đây là product direction, không khẳng định toàn bộ sàn đã private/decentralized hoặc ready. Hành trình samechain đầu tiên có acceptance riêng. Native ZEC (L-ZEC) và các lane khác là active obligations. Standing maker và strict privacy vẫn còn. Thành công của lane đầu không đóng các nghĩa vụ đó.

## 2. Người dùng sẽ làm được gì?

1. **Chợ P2P — V1:** maker tạo/fund backed Buy/Sell order; hai owner online chuẩn bị exact recipient-recoverable outputs, tự kiểm và ký fresh consent cho từng full/partial fill. Mỗi settled fill thành công riêng; `PartiallyFilled / Open` giữ proceeds đã thành công và live remainder, `Filled / Complete` khi đủ quantity. Cancel chỉ remainder; Submitted/Unknown giữ reservation, không unlock capacity. **V2 standing-maker:** owner-confirmed one-opening-signature/many-offline-fills requirement vẫn giữ; fresh V1 consent không đáp ứng target đó. Gossip/proposal không tạo quyền tiền.
2. **Đổi native ZEC — ACTIVE (L-ZEC):** solver có vốn thật và irrevocably khóa target trước source authorization. Vẫn required: independent U payout và S recovery, full validating history, net classification, excess return. RFQ chỉ là cách tìm giá, không thay chợ P2P.
3. **Settlement:** samechain atomic bilateral exchange trên từng lane. Cross-chain dùng HTLC CX-1 (không atomic), CX-2 proof-verified đang nghiên cứu, còn native P/Q source proofs thuộc L-ZEC. Không có một proof chung cho mọi chain hoặc mọi custody ZEC. Standing maker thuộc V2.
4. **HyperCore:** spot trước. Isolated position claims là research ACTIVE. Owner-side Core order execution không phải design đã chọn. Current offline proposals chưa có execution readiness.
5. **Pool, agent, ZSA, Intents — V2/later:** giữ các nghĩa vụ authority/privacy/recovery riêng cho từng route.

Hướng P2P tài sản Hyperliquid và hướng spot HyperCore là hai việc riêng. Các cặp HYPE/ZEC, USDC/ZEC hoặc token cổ phiếu/ZEC là candidates theo hồ sơ nguồn, chưa support/listing/eligibility claim.

## 3. Hai cách sử dụng cùng một quyền

### Bình thường: V1 node/CLI; V2 ứng dụng

V1 chạy own node → tìm đối ứng P2P → kiểm asset/deployment/backing và disclosure/fees → cả hai owner online tự review/prove/ký exact fill → direct hoặc replaceable relay gửi đúng payload → reconcile actual final effects. V2 GUI dùng cùng rules/runtime, không parallel money implementation.

**Phân quyền cần nhớ:** blockchain/contract/program mới là nơi có consensus và quyết định trạng thái tiền cuối cùng: order còn bao nhiêu, nullifier đã dùng chưa, fill/cancel nào thắng và transfer có thành công không. Phần mềm local của user là wallet/agent bảo mật, không phải một blockchain consensus riêng; nó giữ key/witness/recovery, kiểm tra state, ký/prove và gửi payload. Nếu có nhiều local instances, local journal/lock chỉ giúp tránh gửi trùng; chain nonce/nullifier/generation và thứ tự giao dịch mới là nguồn quyết định.

Peer/optional relayer chỉ nhận approved public advertisements, packet, public proofs/consents và exact authorized calls. Không nhận seed/private key/FVK/private witness/recovery opening kể cả dạng encrypted witness exchange; không tự ký, đổi recipient/fee/asset/quantity hoặc tạo quyền bằng DB `approved`. Public gossip fields và backing labels cần review trước enablement; signed advertisement không tự prove backing/spentness.

**V1 delivery là phần mềm P2P chạy được qua CLI:** `z2z-node` trong repo này compose existing native runtime cho discovery/gossip, coordination, chain observation, local proving và manual recovery. Company bootstrap optional/discovery-only; alternate bootstrap/direct peers và independent RPC/relay phải usable. Không mandatory hosted API, shared DB, paid VPS/remote prover hoặc frontend bridge. GUI/user-owned sibling frontend giữ V2; existing `ziquid` surface không rename. Node/proving/storage/recovery qualification chưa hoàn chỉnh, không readiness claim.

**V1 maker online, fresh consent per fill; V2 maker ký một lần lúc mở order rồi offline.** Standing input authority và maker-only recoverable variable receipts/successors vẫn cần sound reviewed construction, không sửa bằng DB row mở hoặc chia sẻ maker secrets. Cả hai scope đều giữ settled portions và cancel chỉ live remainder.

### Khi app/server không còn: dùng công cụ riêng

User giữ encrypted recovery bundle và đúng công cụ/circuit/proving artifacts từ trước. Với đường đủ điều kiện, user dùng own node hoặc nguồn chain độc lập để đọc state, rebuild witness, tạo proof ở máy của mình, ký và gửi trực tiếp hoặc nhờ relayer khác. Contract kiểm cùng quy tắc như đường tự động.

**Không phải nút "rút tất cả bất chấp giao dịch đang xảy ra".** User chỉ thực hiện quyền còn lại: rút tiền chưa dành cho nghĩa vụ không thể hủy, cancel phần lệnh chưa khớp, nhận payout đã có bằng chứng hoặc thực hiện recovery đúng predicate. Không thu hồi tài sản đã giao và không tạo buyer/solver khi thị trường không có đối ứng.

Contract/verifier còn onchain không đủ: note secrets, lịch sử, dữ liệu output, proving keys, phần cứng tạo proof, gas và chain hoạt động vẫn cần. [SERVER-INDEPENDENCE](SERVER-INDEPENDENCE.md) mô tả từng stage và điều kiện manual.

## 4. Những đường giao dịch không có cùng mức độc lập

| Đường | Quyền tiền ở đâu? | Mục tiêu/manual và giới hạn |
|---|---|---|
| **Proof-controlled cùng chain — V1 bilateral, maker online** | Contract/program kiểm owner proof, authentic admitted rights, authorization và actual backing. | Fresh exact consent cả hai owner mỗi full/partial fill; independent cancel/ordinary-note withdrawal/recovery. Native/CPU creation/Fill/Cancel/Exit/withdrawal và four-mutator EVM authority source (receipt, retained roots/counts, global NF, atomic manifests) đã có; genuine wrapped-positive certificate/program/asset qualification, funded lifecycle, cold restore/company-off asset arrival chưa có. Source code không funded acceptance. |
| **Native shielded ZEC (L-ZEC) — ACTIVE** | User ký source ZEC; target verifier/escrow kiểm source financial proofs rồi chia/chuyển tài sản đích. | Chạy song song với hành trình samechain. Required: independent user payout và solver recovery, all-hostile classification witness, terminal recovery, actual excess return. Chưa claim route trustless hoàn chỉnh. |
| **Chợ nguồn Kerb dùng custody** | SPL escrow và designated ZEC custody signers; credit/hold journals không source spend authority. | Không đạt company-offline unilateral ZEC execution nếu custody signer mất/từ chối. Giữ local safety evidence nhưng phải redesign financial route trước claim autonomy. |
| **External HyperCore spot** | Own account và venue rules/signing. | Đã có offline exact order/cancel proposals và CLI, không ký/gửi/reserve/reconcile; requested fee cap chưa venue-enforced. Venue-native tools vẫn phụ thuộc Hyperliquid. API/agent wallet không mặc định spot-only; conservative per-action user signing tới khi restrictions được kiểm. |
| **Public LP/provider** | Pool, issuer, provider và đúng ví theo từng route. | User-owned LP có protocol-native tools; provider custody/refund không tự cưỡng chế được. Không gắn nhãn privacy/trustless chung. |

**Default thiết kế cho deployment mới đủ điều kiện:** tiền đã funding giữ nguyên code/verifier/luật; không company allowlist duyệt exit/settle, không admin sweep hoặc sửa funded obligation. Phiên bản mới user chủ động chọn. Đây là tradeoff: lỗi protocol không được tùy ý sửa bằng admin; cần qualification/audit trước và migrate tự nguyện. Issuer/chain/proxy dependencies phải kiểm riêng.

## 5. Privacy — bảo vệ điều gì, chưa bảo vệ được điều gì?


**V1 không bằng full privacy.** Owner-local witnesses và encrypted backup là trust boundaries, không strict-private market proof. [P2P protocol](V1-P2P-PROTOCOL-SPEC.md) public gossip cần review exact disclosed terms, backing/ownership/spentness claims, peer IP, timing và correlation trước enablement (microtasks P0.05–P0.07/P5.14–P5.15). GD2 vẫn Blocked; full privacy giữ V2 obligation. Không tự cho phép public matching bằng disclosure-only waiver; thiếu reviewed construction thì affected release task vẫn blocked.
- **Phần Zcash:** giữ ZEC shielded trên chặng nguồn, không đưa full spending/viewing keys cho bên nhận đổi. Địa chỉ/số tiền/thời điểm ở chain đích và API vẫn có thể nối hai phía.
- **Note/asset cùng chain:** proof có thể kiểm ownership/conservation mà không public mọi opening nếu có circuit đúng. Deposit/exit/token identity/output data/public venue vẫn có leakage scope; chưa đo hoặc audit.
- **Lệnh và matcher:** mục tiêu nguồn Kerb giữ strict privacy trước matcher có thể hợp tác với trader. Kết quả của chính trader có thể tiết lộ lệnh người khác. **MPC, private pool hoặc contract kiểm proof không tự sửa được mâu thuẫn này.** Existing candidate có GD2 structural FAIL; signed bilateral safe settlement không bằng strict-private auction.
- **HyperCore/public pool:** dữ liệu theo venue có thể công khai, không trở thành kín vì đi qua app.

Không tự giảm yêu cầu strict privacy, đổi adversary hoặc thêm cover-liquidity không có vốn. Các phương án thay privacy/economics cần owner quyết định riêng; tới lúc đó private-market enablement Blocked. Xem [review tổng thể](research/ARCHITECTURE-REVIEW.md) và [research](research/CROSSCHAIN-MARKET-RESEARCH.md).

## 6. Chain và phạm vi

- **L-ZEC Zcash Ironwood/v6 — ACTIVE:** native source. Real local crypto và finite source validators chưa phải composed financial proof hay full route qualification.
- **EVM/Base Sepolia (engineering default, first journey):** exact pins chưa có. Local VM evidence không phải public-testnet acceptance. Deploy, kể cả Anvil, cần approval.
- **L-SOL Devnet owner-ZK — ACTIVE:** program mới; three-ACK escrow giữ riêng. Solana không thừa hưởng EVM qualification.
- **Programmable-chain samechain:** native owner relation, CPU guest, manual preflight và EVM authority source có scoped evidence. Genuine wrapped proofs, funded lifecycle và cold recovery chưa qualify.
- **L-HEVM 998 — ACTIVE:** spot (fixed ERC20 trước, Core-linked sau), position-claim research. Core và EVM là các surface khác nhau. Core actions held.
- **L-NEAR testnet owner-ZK — ACTIVE:** native NEAR trước, NEP-141 sau. Payout credit chỉ PROPOSED. Intents/1Click là V2.
- **LP/agent/ZSA:** V2, mỗi cái có gates riêng.

Ticker không asset identity; wrapped ZEC không mặc định native ZEC/backing. Token cổ phiếu cần exact mint/program/issuer/transfer eligibility và legal review; nguồn business/legal là giả thuyết có ngày, không authorization hoặc legal conclusion.

## 7. Đang tới đâu và thứ tự công việc

**Chưa có lần đổi tiền thật hoàn chỉnh hoặc manual company-off drill đạt yêu cầu.** Native Ziquid có real local authoring/proof subrelations, checked accounting, encrypted custody/PostgreSQL inventory và limited Zoss acquisition; SQL vẫn NOT RUN pending private URI, không local test. Samechain [reviewed Fill2](superpowers/specs/2026-10-06-independent-owner-fill-design.md) và [actual owner relation](../crates/proofs/src/samechain.rs) dùng frozen packet/public E/ordered opaque A+B leaves/private own_salt, không counterparty policy/common blind. `samechain review-fill --packet FILE --execution FILE --role a|b --witness-stdin` yêu cầu canonical E frame2 owner chọn độc lập, exact E/embedded packet equality rồi key/path/policy/AEAD/fees/net/conservation/successor trước consent bytes, **không ký**; check-fill dùng embedded packet, signed checks chỉ xuất public packet/journal. Guest mode0 là byte0 + một OwnerWitness frame2; non-fill/note/tree/outer journal/schema/blinds giữ1. New ELF/program cần authorized new immutable authority và genuine all-mode proof/target/recovery qualification; giữ old fill1 identities, không auto-conversion/migration. [Status](NATIVE-IMPLEMENTATION-STATUS.md) giữ current native/CPU/correspondence/completed source-review evidence, không independent source/setup/program/wrapping/backing/funded/privacy/backup acceptance. E quantities shared với counterparty, không GD2 secrecy. Private stdin bounded/erasing; không server secrets. Migrated market/SPL safety và HyperCore offline proposals không private/full-network settlement hoặc signer/submit/fee-cap/durable-reconciliation readiness.

**Active order:** [122 microtasks](V1-MICRO-IMPLEMENTATION-PLAN.md) expand roadmap Phase 0–6: scope/privacy/storage/testnet decisions → measured owner-local proving → node/durable orchestration → genuine funded full/partial/cancel/withdraw → complete company-off recovery → release review. Pre-funding backup/kit/cold-restore qualification precedes irreversible deposit; approved deployment precedes funded acceptance. Current authority source/accepted-root/NF/atomic manifest and native semantic slices are real, not genuine certificate/asset/funded lifecycle evidence. Native S1–S7/M1–M5 and full native completion obligations remain V2, unchanged/open/blocked; all-hostile/excess/uniqueness are not avoided by V1. SQL NOT RUN pending approved private URI, no local SQL; proving/resource, production-secret recovery, action and privacy holds remain. [BLOCKERS](BLOCKERS.md) alone owns readiness; [status](NATIVE-IMPLEMENTATION-STATUS.md) owns observed results, not this scope summary.

Zoss phát triển riêng, giúp common source/context/client infrastructure; app giữ keys/private state và financial authority. Không nhận payout/refund từ message quorum/receipt.

**Câu present đúng mục tiêu:** “Z2Z đang xây một DEX có chợ P2P để người dùng đặt lệnh mua bán với nhau, có báo giá để đổi tài sản và có lựa chọn sàn ngoài. Sàn hướng tới bảo vệ thông tin giao dịch và để quyền tiền được kiểm theo điều kiện user đã đồng ý, thay vì server tùy ý duyệt. App giúp tự động hóa; với từng đường đã kiểm chứng, user vẫn có công cụ tự thực hiện quyền khi app mất. Hiện chưa có sàn tiền thật hoàn chỉnh; private matching và native cross-chain vẫn còn blocker.”

**Context mới đã lưu:** [order book/quyền onchain/storage/LayerZero brainstorm](history/BRAINSTORM-2026-10-05-ORDERBOOK-AND-ONCHAIN-RIGHTS.md) ghi owner ideas, assistant recommendations và unresolved choices; không tự activate perps/tokenization/public matching/universal bridge. [Status/progress2026-10-05](history/STATUS-AND-PROGRESS-2026-10-05.md) phân biệt actual user delivery với primitive/test evidence. Ưu tiên current usable real journey trước expansion, full production obligations giữ nguyên.

[ARCHITECTURE](ARCHITECTURE.md) owns behavior; [MODULES](MODULES.md) packaging/interfaces; [BLOCKERS](BLOCKERS.md) readiness; [SERVER-INDEPENDENCE](SERVER-INDEPENDENCE.md) manual data/workflows; [status](NATIVE-IMPLEMENTATION-STATUS.md) observed code. Docs design không code/sign/broadcast/deploy/funding/mainnet/publish/commit/push hoặc namespace rename approval.
