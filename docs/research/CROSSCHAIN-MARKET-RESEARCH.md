# Cross-chain market research — authority, privacy và thiết kế Ziquid mở rộng

**Ngày nghiên cứu/truy xuất: 2026-10-02. Phạm vi: nguồn sơ cấp và đề xuất thiết kế, không triển khai.** Ziquid là dự án gốc; Z2Z là tên dự kiến. Tài liệu này không đổi namespace, chuyển code Kerb, chọn nhà cung cấp, cho phép giao dịch/deployment hoặc đóng gate.

**Bằng chứng:** **P** = passage/code sơ cấp đã đọc; **V** = tuyên bố nhà cung cấp/tác giả chưa kiểm chứng độc lập; **I / [INFERENCE]** = suy luận theo giả định được nêu; **D / Proposed** = thiết kế cần xây/review; **U / Open** = chưa thiết lập. Ledger §14 ghi URL, đoạn trích, scope và limitations; mọi URL được truy xuất 2026-10-02, không lấy retrieval date làm release date. Default-branch/live docs có thể đổi; pin commit khi đã lấy được.

Thẩm quyền hiện có vẫn là [PRODUCT](../PRODUCT.md), [ARCHITECTURE](../ARCHITECTURE.md), [MODULES](../MODULES.md), [BLOCKERS](../BLOCKERS.md), [native status](../NATIVE-IMPLEMENTATION-STATUS.md) và [CONSOLIDATION](../CONSOLIDATION.md). [Kerb archive](../imports/kerb/README.md) giữ provenance/history, không biến local safety nguồn thành implementation đã tích hợp. Đây là research input cho redesign, không second canonical architecture.

## 1. Kết luận thiết kế

1. **Discovery/quote/matching/relay ở ngoài quyền quyết định tiền.** Ví giữ bí mật và recovery data; deployment-scoped verifier/asset state quyết định theo authorization/bằng chứng. Hosted UI/server tự động hóa nhưng không được là signer, database, root publisher hoặc kho witness duy nhất cần cho quyền đã cấp vốn. Đây là requirement, chưa implementation.
2. **Ba proof/authority khác nhau:** same-chain proof-authorized asset transfer; source Zcash validity/history/payment classification; native ZEC custody/spending. Proof trên Solana/EVM không ký SpendAuth của note Zcash; Halo2 bundle proof không phải DEX financial certificate. [Z2–Z7, S1–S3]
3. **Giữ native P/Q priority và toàn bộ acceptance.** Q complete local → S irrevocably prefund/arm → U kiểm độc lập → release P authorization → source outcome/classification → allocation và actual transfers. Không thu hẹp all-hostile terminal recovery hoặc actual S-authorized excess source return khi `C>A`. ZK không lấy lại witness chưa available; Q không lấy lại ZEC mà S đã nhận. [N1]
4. **Bidirectional cần construction riêng.** Reverse EVM/Solana→native ZEC cần payout authority, independent witnesses, source refund và timing/data availability riêng; không đảo mũi tên P/Q rồi gọi hai chiều. [A1–A3; I]
5. **CoW có open solver competition, nhưng settlement permissioned.** `settle` dùng `onlySolver`; manager/proxy quản lý authenticator allow-list. Settlement và vault-relayer được docs ghi non-upgradeable, authenticator upgradeable. Học signed-limit enforcement/atomicity; không copy nhãn permissionless/privacy. [C1–C6]
6. **UniswapX paper tách fill deadline, proof deadline và settlement oracle.** Đây cross-chain extension design, không live Ironwood/Solana support. Source payment đã xảy ra khác proof chưa đến; copy refund timer/bond không sửa native paid-but-unproven race. [U1–U3]
7. **Strict GD2 không waived.** Exact price/fill hoặc actual assets mà trader thông đồng thấy có thể tiết lộ protected honest orders. MPC/hidden receipts/shielded notes không sửa output channel. Bilateral signed terms làm settlement deterministic, không giải strict matcher/trader noninference. [N2]
8. **Operator independence không phải censorship/data/issuer immunity.** Chain consensus, issuer freeze, code upgrades, source/history availability, local proving resources, gas và backups còn là assumptions. Company biến mất không được tước existing rights; không hứa luôn được mine hay có đối ứng. [Z8–Z11, H1–H8, S1–S5]

## 2. Phân loại route theo quyền tài sản

| Lane | Ai thật sự có quyền chuyển? | Manual/self-hosted path cần có | Không được suy ra / trạng thái |
|---|---|---|---|
| **Same-chain proof-authorized asset notes — Proposed mới** | Program/contract giữ backing, owner proof hoặc mutually authorized terms mới cho chuyển. | Direct owner withdraw/cancel/fill với available public state và user-held opening; no company signer/allow-list cho exit. | Chưa có relation/program/circuit; không native ZEC, cross-chain atomicity hoặc GD2 solution. |
| **Native outbound Ironwood→EVM** | U giữ ZEC SpendAuth; S prefund destination; verifier/escrow phân bổ theo authenticated source fact. | U independent payout witness; S complete local-proved Q không U FVK/spend key; direct proof submission. | Full history/classification/terminal recovery/excess return/hiding uniqueness/actual escrow còn Blocked. [N1] |
| **Inherited Solana↔Zcash custody market** | Solana program giữ SPL; threshold set có ZEC custody SpendAuth. | Solana exit trực tiếp nếu construction cho phép; native recovery phải có independent authorized shares/capability/data. | Entitlement/DB/MPC/Solana proof không force FROST signatures. Company-only threshold không operator-independent. |
| **Hyperliquid asset trong P2P** | Phụ thuộc exact Core account, EVM contract/native balance hoặc custody. | Qualified programmable-domain asset có thể nghiên cứu same-chain primitive; cross-chain cần route riêng. | Core/EVM/Solana balances không tự fungible; chưa chọn/qualify cặp/link/custody/bridge. |
| **External HyperCore spot** | User/master hoặc exact delegated signer; Core khớp. | Local per-action signing và alternative acquisition/API/node reconciliation. | Public external venue, không P2P allocation/native ZEC delivery; venue/issuer/bridge restrictions còn nguyên. |
| **Public LP/swap, provider/1Click** | Pool/issuer/provider/custodian theo exact route. | Direct interaction/exit chỉ khi actual underlying route cho phép. | Không default native ZEC backing, shielded end-to-end hoặc forced refund; scope retained/deferred. |
| **Agent/autopilot, ZSA venue** | Explicit enforced user authority; ZSA theo activation/client/asset rules. | Không company-only signer; same-chain exit không cần mới xin service certificate. | Deferred; current NU6.3 v6 không ZSA; ZIP228 Draft/future không LP share. [Z12] |

Không tạo **unified fungible cross-chain balance** mặc định. Credit là liability backed bởi controlled unallocated spendable inventory, không tự là native coin/cưỡng chế chi trên chain khác. Inventory Core/EVM/Solana/Ironwood, fees và change không được dùng backing hai obligations/venues.

## 3. Zcash NU6.3/Ironwood/v6: authoring và chứng minh nguồn

### 3.1 Trạng thái nguồn và publication mismatch

**P:** ZIP index hiện nói NU6.3 settled Mainnet tại **3,428,143**. ZIP258 định nghĩa branch `0x37A5165B`, Mainnet height đó, Testnet **4,134,000**; ZIP229 định nghĩa v6. Cả hai trang vẫn label **Draft**. Pinned Zebra6.4.2 source có Ironwood/v6; release2026-09-25 sửa malformed-v6 DoS. [Z1–Z2, Z7, Z10]

**Mâu thuẫn cần giữ:** PDF từ `protocol.pdf` lần đọc này có header **v2026.7.0-236-ga735ca [NU6.2]**, ngày2026-09-30, §3.3 còn nói NU6.2 most recent settled. ZIP258 dẫn version2026.8.0 [NU6.3] hoặc mới hơn. Không giả PDF là complete current NU6.3 specification. Dùng PDF cho chain-selection/crypto foundations có scope rõ; ZIP258/229 và pinned compatible source cho deltas. Acceptance phải reconcile exact spec/code/activation hash/network; không live tip query hay network run được làm ở đây. [Z1–Z3]

### 3.2 Ironwood không chỉ đổi tên Orchard

**P:** Ironwood reuse Orchard protocol/Pallas/Vesta/Halo2 nhưng là **pool riêng**: note tree, anchor, value balance và digest personalizations riêng. Key/address structures chung không làm notes/pools tương đương. Sau NU6.3 không có new value vào Orchard, cross-address Orchard transfer disabled; value vẫn đi ra/turnstile sang Ironwood. [Z2]

Pinned code có IronwoodDomain nhận V3/lead byte`0x03`, OrchardDomain nhận V2/`0x02`; compact note plaintext không có memo. ZIP326 phân biệt wallet scanning/restore/use_qsk/receiver scopes và không expose internal receivers/viewing keys ngoài wallet trust boundary. ZIP2005 quantum-recoverable notes chuẩn bị cho **potential future Recovery Protocol**, chưa detailed/current refund protocol. [Z4]

**D:** Bind network, pool, branch, tx version, circuit/VK, exact ciphertext/effects và history policy. Không port Orchard/v5 bằng một branch-ID change; không dùng quantum “recovery” làm swap refund/counterparty-loss primitive.

### 3.3 Preauthorization/reanchor: lợi ích và giới hạn

**P:** V6 shielded anchors chuyển từ effecting sang authorizing data; reanchor không đổi effect txid/signatures, nhưng proof vẫn bind anchor. ZIP374 PCZT v2 cho ký trước anchors/witnesses/proofs, roles independent và durable intermediate states. [Z2, Z5]

- **P:** Prover code cần note/FVK/witness/alpha/rcv/matching key; `AnchorDeferred` bị reject. Extractor cần every-action SpendAuth, proof và binding material. [Z6]
- **I:** Extracted Q không tự reanchor/reprove. Fixed effects/recipient/value/fee/expiry/branch không mutate nhờ anchor update. Một real input không đồng nghĩa chỉ một action/dummy signature.
- **P:** Delegated prover không spend key nhưng PCZT có private addresses/value/randomness/FVK; delegation reveals transaction contents. **No spend authority ≠ no viewing disclosure.** Selected native vẫn local-prove Q, không U FVK/spend key cho S. [Z5–Z6; N1]
- **D:** Complete packet/certificate phải authenticate same real input, actual ciphertext và mọi nonzero Q output U-owned, fee/lifetime; server flag/partial signature không đủ.

### 3.4 Halo2 bundle proof không phải financial certificate

**P:** Action statement chứng minh private old/new notes, net value commitment, nullifier derivation, randomized spend validating key và Merkle path tới **given anchor** cho real nonzero input; zero dummy có exception. SpendAuth và binding signatures là separate checks. [Z3, Z6]

**I:** Nó không tự chứng minh anchor thuộc valid accepted history; input/nullifier chưa spent; all transaction authorizations/all-era consensus đúng; recipient/value/ciphertext là agreed consideration; no S-funded gross fake payment; đúng beneficiary/asset/deployment; hay note không backing obligations khác. Statement proof nói prover biết witness, không disclose hidden inputs cho một independent DEX classifier.

**D:** Compose source-validity + accepted-history + tx auth/effects + ownership/net-consideration + context + stable financial uniqueness, rồi target verifier mới xuất financial fact. `SourceObservation`/quorum/PCZT/Zcash proof không cast thành `VerifiedSettlementFact`.

### 3.5 Node history/canonicality/data assumptions

**P:** Protocol§3.3 chọn valid chain có greatest total work **trong view của node**, khuyến nghị multiple sources, và activation-block hash của most recent settled upgrade. ZIP221 MMR/FlyClient verification **probabilistic**, hỗ trợ history/block/metadata inclusion; không automatically receiving-chain app verifier. [Z3, Z9]

**D:** Native đã chọn **full validating source proofs, no SPV fallback**. Connected all-era history và actual prior state phải authenticated; hard-coded recent header/trusted prior state không âm thầm thay mục tiêu. State gồm note roots, spent sets/UTXOs, monetary/pool balances và consensus context; không chỉ header/work. Bound early P/T không bị mất vì artificial post-funding scan cutoff. [N1]

**P:** Pinned Zebra source nói không fully validate pre-Canopy và dùng mandatory checkpoint; zcashd6.11.0 PHGR branch trả true vì post-Sapling checkpoint. “Chạy node” không tự chứng minh original genesis replay. Đây limits của inspected versions, không theorem mọi implementation/history impossible. [Z11]

**I:** Full-validity proof của candidate không chứng minh không có heavier valid chain withheld/eclipsed. Competing-head availability, fresh/authenticated checkpoint, anti-eclipse/challenge policy là **safety assumptions** khi payout/refund irreversible, không chỉ UX. PoW depth/node rollback limit không absolute finality; best submitted work không globally canonical oracle.

**D:** Alternative public block/auth/history sources/cache và reconstructible valid raw bodies/leaf structure cần tồn tại. Hash/root chỉ authenticate bytes khi có, không data availability. Private note/input-owner/output witnesses vẫn actor-owned. Missing data fail closed, nhưng pending vô hạn không completed terminal recovery.

### 3.6 FROST spending: quyền hạn, privacy, liveness

**P:** ZIP312 re-randomized FROST chia `ask`; threshold signature tương thích SpendAuth. Coordinator/share holders trusted với transaction privacy; ZIP không ngăn họ link signing với chain. SIGHASH không đủ consent: signers phải kiểm transaction/openings và hash. [Z7]

**P:** Official frost-tools PR593 merged2026-08-12, commit`06c0dbdbb1bac9b99cd255e74ba2f387c295e660`: v6 hash, separate Orchard/Ironwood signature injection. Tác giả kể mined testnet transactions nhưng nói Orchard-spend-in-v6 migration chưa trực tiếp exercise. Source exists; mining claims là **V**, không Ziquid run/audit. [Z7]

**P:** RFC9591 requires threshold cooperation, corrupt fewer-than-threshold assumption, one-use nonces và abort khi invalid/transport fail. Official README partial NCC v0.6.0 audit **excludes rerandomized FROST**. [Z8]

**I/D:** Threshold custody có thể block khi mất shares/cooperation; N-of-M không tự permissionless/company-independent. Self-hosted replacement transport không phục hồi shares/witness hoặc ép signer ký. Preauthorization chỉ đúng fixed inputs/effects/lifetime, không arbitrary future change/refund. Durable nonce/spend-intent/input locks survives restart/rollback. Ordinary/re-randomized FROST không tự là adaptor/cross-curve binding/atomic swap; business ACK không SpendAuth/mined payout.

## 4. HTLC và atomic-swap constraints

**P:** ZIP300 Proposed Informational “only supports transparent cross-chain swaps”, Bitcoin-inherited P2SH scripts. Secret-revelation leg timeout phải ngắn hơn redemption leg và đủ relative block-time margin; 24h/48h là examples. [A1]

**I:** Shared hash/preimage/key/amount/timing có thể nối legs; atomic HTLC đúng vẫn cần data, chain progress/inclusion/finality và monitoring. Shielded note không arbitrary P2SH script: hash/timeout trong memo không consensus enforcement.

**P:** ZIP203 expiry chặn **unmined** tx mine sau N; included tại N hợp lệ, N+1 quá muộn. Nó không undo mined transfer. Pinned Zebra `lock_time()` chỉ enable khi transparent-input sequence khác`u32::MAX`; pure-shielded future locktime không enforce delayed Q. [A3]

**D:** S cầm executable Q có thể broadcast sớm; disclose fee/cancellation grief. Delayed construction dùng transparent timing input hay cơ chế khác cần proof về input control, privacy, timing off-by-one, fees/finality/lifetime; chưa chọn.

**P:** BlockstreamResearch scriptless note basic construction giả định same group và Schnorr, nêu different-curve discrete-log obstacle. [A2] **I:** Không biến specific recipe obstacle thành theorem mọi cross-curve swap impossible; cũng không coi generic Schnorr/FROST là audited RedPallas adaptor/EVM verifier. Signature/secret public trong mempool/calldata transaction revert vẫn lộ; reveal không chứng minh payout thành công/fair exchange. Current direct P/Q không thay bằng custom crypto chưa approved.

## 5. CoW: settlement tốt không đồng nghĩa permissionless/private

### 5.1 Authority

**P:** Docs có independent bonded solvers/open development. Nhưng `settle(... onlySolver)` gọi authenticator; manager add/remove, proxy owner/manager đổi manager, authentication upgradeable. Onboarding có bonding/whitelisting; KYC passages riêng CoW DAO bonding pool, không apply mọi private pool. Settlement/vault-relayer non-upgradeable theo docs. [C1–C3]

**I:** Open optimizer code không cho user tự trở thành authorized deployed settler. Immutable settlement không xóa mutable authority ở dependency. Ziquid owner exit của operator-independent route không được copy company allow-list dependency.

### 5.2 Enforced terms và cancellation

**P:** Signed order bind tokens/receiver/amounts/validTo/fee/kind/partial flag. Contract kiểm signature/expiry/limit/filled amount; successful same-chain transaction chuyển proceeds. Vault-relayer firewall tách allowances khỏi arbitrary solver interaction. [C4–C5]

**I:** Signed minimum enforcement không prove global best price/fair admission/optimal solver/liveness; buffers và user balances khác authority. Token behavior, ERC1271 wallet, vault approvals và chain remain assumptions. Official core còn ghi zero amounts, ERC1271 replay, cached-domain fork replay/appData issues; invariant không unconditional theorem. [C2]

**P:** API cancellation **best effort**, có thể không stop in-flight settle; onchain invalidation checks order owner và sets max filled. [C6, C4] **I/D:** Cancel request/HTTP200 không cancel đã thắng authoritative race; fill trước cancel không rollback. Đừng release credit/reuse funds vì cancel đã gửi. Expired filled-storage có thể freed, latest mapping không historical occurrence oracle. [C4]

### 5.3 Privacy

**P:** Solver input chứa orders, sell/buy/full signed amounts, owner/receiver/signature; Trade event có owner/tokens/amounts/fee/UID. [C7, C4]

**I:** Inspected ordinary route không cung strict hidden-content/accepted-identity privacy trước solver/public observer. MEV protection/private submission không GD2 noninference. Không claim mọi possible CoW service đều public; không import private roadmap extension chưa đọc.

**D:** Học principle authorization → exact checks → one-time consume → actual transfers atomically, không copy entire architecture/trust label. App-data/context hash phải có actual semantic enforcement; không universal `verified` bool.

## 6. UniswapX: fill deadline khác proof deadline

**P:** July2023 paper§4.1 có settlement oracle, fill deadline, filler bond và proof deadline riêng; destination records fill-before-deadline rồi oracle relays origin. §4.2 thêm challenge bond/deadline trước proof deadline; parameterization ngoài paper scope. [U1]

Paper nói “can be extended”; current overview/architecture mô tả signed publicly broadcast orders, permissionless fillers và reactors kiểm received outputs. Deployment list không chứng minh live Ironwood/Solana crosschain reactor/oracle hoặc pair. Không inspected deployed crosschain route/latency/cost ở đây. [U2–U3]

**I/D cho native:**

- Tách source consensus expiry/inclusion cutoff, entitlement, proof preparation/submission, target acceptance/transfer và ETA. Source height khác destination timestamp.
- Accepted timely source payment không mất payout entitlement vì relayer/prover chậm. Timer/status không authorize S refund sau U trả.
- Paper's proof-deadline forfeiture/bond là economic design riêng, không đáp ứng native all-hostile/excess requirements tự động. “No proof by timer” không no-payment proof.
- Oracle/bridge/challenger availability/authority phải disclose; bond không cryptographic nonpayment evidence hay quyền cưỡng chế ZEC return.
- Proof blob/callback khác actual transferred asset. Copy whitepaper không close receiving-chain source validity/privacy/financial gates.

## 7. Hyperliquid: asset domains và signer control

### 7.1 Core/EVM

**P/V:** Một L1, hai execution components Core/EVM; vendor mô tả transparent Core orders/cancels/trades và one-block HyperBFT finality. Đây provider claim, không independent Ziquid validation/censorship theorem. [H1]

**P:** Core spot↔EVM spot cần token link; HYPE links native EVM balance, không ERC20. Docs cảnh báo fungibility, arbitrary linked bytecode, no sufficient-supply/ERC20 checks, rounding. Token ID khác spot market ID, Mainnet/Testnet khác. [H2–H3]

**D:** Qualify exact network/domain/token ID/native-or-contract/decimals/lot/account control/backing/issuer/upgrade/transfer rights. Core/EVM/Solana/Ironwood inventory không gộp theo ticker. Chưa qualify HYPE/ZEC hay HYPE/Solana-USDC; không selected provider/bridge.

**P:** Core→EVM queued next EVM block; EVM→Core và CoreWriter actions xử lý sau EVM block; Core account phải tồn tại trước block, initialize qua transfer cùng block có thể vẫn reject action. Orders có delayed enqueue và execution riêng; read-precompile passage nói **testnet**, không infer all-mainnet readiness. [H4]

**I/D:** EVM success/read balance/CoreWriter log không Core fill/cancel hoặc custody quyền chi. Reconcile exact action/order/partial/fill/transfer; Unknown giữ reservation. Cùng L1 không automatically synchronous atomicity giữa domains, càng không Zcash/Solana atomicity.

### 7.2 API wallet không spot-only mặc định

**P:** Master approve API/agent wallet để sign master/subaccounts; queries dùng actual account. Nonce per signer, reuse address sau pruning có thể replay old signed actions. Hai signing schemes L1/user-signed, exact payload/env/vault/nonce/expiresAfter; user-signed transfers không universally support expiry. [H5–H6]

**Exact current primary endpoint quote:** `agentSendAsset`: **“Similar to send asset, but can be signed by an agent. Destination must match the source address.”** Endpoint còn có **“Set User Abstraction (agent)”**, `agentSetAbstraction` choices **“[\"i\", \"u\", \"p\"] where \"i\" is \"disabled\", \"u\" is \"unifiedAccount\", and \"p\" is \"portfolioMargin\"”**. [H7]

**I:** Generic agent không inherent place/cancel-spot-only, no balance movements hoặc no leverage. Đó là documented permission surface, chưa runtime qualification một account. **D:** Product vẫn spot only/no perps/leverage/no automatic residual fallback. Conservative direct per-action user signer là research option; delegated automation cần **chain/signer-enforced exact restrictions** đã qualify. Backend server policy hoặc chữ “agent wallet” không security guarantee. Broad API approval còn blocker nếu không bound desired scope; no capability đã chọn ở đây. Separate approveAgent/order/cancel/withdraw/builder-fee authority; revocation không undo mined fills.

### 7.3 External service/data assumptions

**P:** Official docs dẫn self-running nodes; Foundation non-validator endpoint best-effort, no availability/completeness guarantees, không sole authoritative source, có riêng eligibility/discretion. Permissionless running không cùng nghĩa guaranteed access endpoint này. [H8]

**D:** UI mất thì user cần local signing/direct account tooling và alternative source/API. Ziquid không control venue consensus/software/issuer/withdrawal bridge. Core fills là external venue, không native financial fact/market funding credit. Không quảng cáo public Core như strict-private P2P fallback.

## 8. Solana atomicity, upgrades, issuer controls

**P:** Solana all transaction instructions succeed hoặc revert state; failure vẫn charge fees. Đây cùng-chain atomicity, không hai-chain commit. Loader-v3 upgrade authority có thể thay bytecode tại same program ID; `None` makes immutable. Verifiable build không ngăn future upgrade. [S1–S2]

**P:** Mint có mint/freeze authorities; freeze giữ balance/owner nhưng blocks receive/transfer/burn. Native token accounts không freeze theo source doc; không generalize mọi representation. Token2022 optional extensions có fees/hooks/pausable/permanent delegate; delegate có thể transfer/burn any account, owner không revoke; hook có custom rejection/allow-list logic. [S3–S5]

**D:** Immutable app không làm issuer/token/bridge immutable. Qualify exact mint/token program/extensions/backing/admin và net delivered amount, không ticker. Proof valid nhưng frozen token/hook reject không actual transfer; verify/consume/transfer atomic hoặc retry entitlement rõ ràng. Upgrade/pause ở app/verifier/asset/hook khác roots. Solana cryptographic primitive không automatically new note ledger/verifier; cần actual relation/program/resources/DA/review.

## 9. Proposed full product shape

### 9.1 Nhỏ nhất giữ đúng ownership

**Recommended research shape:** wallet-owned secrets/local proofs + immutable **per-domain** asset ledger/verifier + replaceable discovery/matching/relay. Không new rollup/chain/proving primitive, omnibus universal balance hay mandatory shared daemon.

Hosted omnibus custody có thể operational với explicit signer authority nhưng không company-disappearance native recovery nếu company giữ đủ shares. Universal private bridge/rollup thêm consensus/DA/custody roots, không giải GD2/missing witnesses bằng abstraction. Per-domain shape giữ differences và full lanes, không tuyên bố tất cả operator-independent.

| Behavior/artifacts cần xây | Existing package seam | Authority boundary |
|---|---|---|
| Canonical route-qualified terms/units/nonce/portion/obligation/allocation | `crates/protocol` | Pure rules, không network/storage/key. Different lanes không cast schema/fact. |
| P/Q authoring, wallet reservations/independent payout witness; proposed owner note client | `crates/zcash` + user-owned consumer | U keys/private data; same-chain recipient/owner prepares exact receive/change/successor outputs, locally checks/decrypts/backs up before fresh per-fill authorization; no long-term FVK/spend key cho matcher/S. |
| Separate same-chain relation; native valid-history/effects/owner/net/hiding/uniqueness composition | `crates/proofs` | Pinned statement/program/VK, prover không chọn trust level. |
| Funding/root/nullifier/portion state và atomic verify/consume/transfer/owner exit | Qualified `contracts/<target>` | Exact program-controlled backing; no company-only signer/allow-list cho trustless-class exit. |
| Exact ABI/accounts/code/admin/finality/asset calls; Core actions riêng | `crates/chains` | Chain-specific acceptance, không source classification. |
| Solver custody/funding/physical locks/reconciliation/retry | `crates/runtime` | Operator inventory/liability, không sole user-rights database. |
| Quotes/proposals/encrypted transport/task relay, optional UI | Replaceable processes/consumers | May withhold discovery, không mutate terms/recipient/fees/fabricate funds. |
| Actual common acquisition/parsing/client plumbing | Optional pinned Zoss library reuse | Observation/message/quorum non-money, không credit/settlement/SpendAuth. |

Roles không tự tạo crates/processes/repos mới; namespaces/code không đổi. Same-chain owner withdrawal không cần mandatory matching result/epoch certificate mới; vẫn phải có owner-authorization/membership proof theo asset relation. If company must publish root hoặc authorize exit, server chưa optional.

### 9.2 Concrete same-chain proposed relation

**D, chưa implementation:** Qualified asset deposit vào exact contract/program; note commitment là backed right trên **chính domain đó**, không synthetic native ZEC. User giữ owner secret/opening. Proof relation authenticate input membership tại accepted ledger root, ownership, asset/units/value, conservation, exact outputs/fees và nullifier domain. Program kiểm unspent rồi consume/update/transfer **atomically**.

**Selected documentation construction, chưa implementation:** recipient/owner prepares exact receipt/change/unused-successor notes khi fill quantity đã biết; owner giữ opening và local backup, tự decrypt/check ciphertext→note/commitment/value trước ký. A/B fresh-authorize từng fill trên cùng common terms/digest, bind exact commitments/ciphertexts/fees/recipients. Per-owner proof composition vẫn phải construct actual checked ownership/conservation proofs và atomic target validation; chữ ký hoặc local check không tự thành implemented proof. Relayer tự động hóa **sau** đủ authorizations, không rewrite outputs/fees. Không một bên/matcher extract chỉ fee hoặc một leg; same-chain transition không crosschain atomicity.

Cancel/owner exit và fill tranh cùng consumed capability/nullifier; only one winner. Partial fill vẫn retained: consume parent một lần rồi tạo disjoint filled/unused successor rights với exact values/openings và fresh owner authorization; original/successor không cùng chi. Output availability/recoverability đến từ recipient/owner preparation, local ciphertext/decryption/commitment check và backup theo common authorized digest, **không giả generic ciphertext-correctness ZK đã có**. Circuit-enforced encryption là unselected alternative cho future truly unattended partial fills. Backing actual asset balances/conservation/fees/issuer effects vẫn phải verified bằng actual relation.

**Liveness trade-off được công bố:** extra authorization roundtrip; owner offline ngăn **new** fills cần exact quantity/output mới. Existing owner exit và settlement packet đã fully authorized vẫn phải usable không company server/counterparty signature mới, subject state validity/data/chain inclusion. Không offline-matching/fresh-fill liveness promise; consent refinement không waived strict GD2.

Spendable in-ledger note/entitlement khác external withdrawal đã tới address. Nếu acceptance yêu cầu actual payout, credit/commitment vẫn nonterminal tới withdrawal. Failure/revert giữ original right retry; token freeze/network failure không “paid”.

Root/DA policy không company-signed root-only assertion. Commitments/ciphertexts/history updates reconstructible independent; verifier/VK/governance không retire funded rule/path. New deployment version không reset consumed rights hay migrate old liabilities ngầm.

### 9.3 Native outbound vẫn load-bearing, không substitute

Theo current requirements [N1]: one real valid U note; locally complete Q với same-input/all U-owned nonzero outputs/agreed fees; unsigned P redacted; U independent payout witness; S irrevocable prefunding và U independent finality/code/config check **trước** P release. Quote/bilateral signature không P SpendAuth. Accepted source P/Q/general T cần full validity, actual effects/auth và classification; same effect/new auth vẫn P; `T!=P` không nonpayment.

Ký hiệu: `A>0` là agreed source consideration, `C` là authenticated actual net source consideration, `D` là funded destination amount; `U`/`S` là destination shares của fixed beneficiaries. Supported `0<=C<=A`: `U=floor(D*C/A)`, `S=D-U`, dust fixed S, both destination transfers atomic. `C>A` cần actual **S-authorized source excess return executed/proven**; no gift/clamp/full destination refund substitute. Complete = actual correct transfers và source consideration/finality, không credit/event.

**Information/authority blockers:** raw hostile mixed-positive-input T + S IVK không reveal all owners/debits/dummy/output openings. Halo2 chứng minh prover có witnesses, không export them cho independent arbitrary classifier; full-chain zkVM không recover hidden facts. Wallet one-input policy không constrain malicious U. Additional sound availability/source-authority construction required; user không approved relaxing requirement. Fail-closed pending không complete all-hostile terminal recovery.

Sau S nhận native ZEC note, destination contract không ký thay S. Q spends original U note, không note S đã nhận. Before arming cần independently usable actual source-return authorization/input/lifetime/data construction cho excess; quote promise không SpendAuth. Không âm thầm chuyển custody để che gap rồi giữ trustless label.

### 9.4 Bidirectional/custody needs separate construction

**I/D:** Reverse smart-contract source có thể hold programmable asset và verify ZEC payout evidence, nhưng S phải thật sự have/authorize ZEC và U independent witness. Source refund by proof timer sau ZEC delivered làm S loss; source release before ZEC delivered làm U nonpayment exposure. Reverse cần explicit prefunding/arming order, source/destination finality, spend/recovery authority, privacy/DA/no-payment proof và lifetime riêng; không đảo forward recipe.

Inherited custody market giữ full funding credit→symmetric hold→complete authenticated allocation→disjoint entitlement→native signing/broadcast→actual payout/reconciliation/input-change locks. Solana proof không ép threshold set chi ZEC. Nếu company exclusive signer/data thì route không thỏa operator-independent class; ghi Blocked/incompatible, không xóa bidirectional lane hoặc declare demo complete.

## 10. Deterministic settlement sau mutually signed terms

**D:** Matching/negotiation trả proposal, không payout entitlement. Selected same-chain construction chờ exact fill quantity, recipient/owner-prepared outputs đã locally checked/backed up, rồi fresh A/B authorizations trên cùng canonical terms/digest. Per-owner proofs authenticate ownership/conservation/committed terms, actual atomic validation còn phải xây; same valid state/evidence/terms cho same allocation/outputs. Bind:

- route class, network/domain/deployment namespace, exact native/mint/contract/token ID và integer units;
- each owner sell/debit cap, desired receipt/limit, fill/partial policy, exact receiver/change, fee cap và fixed fee recipient;
- notes/credit portions/obligations, counterparties/capability scope, nonce, original/successor consumption;
- proof program/VK/schema/code, accepted history/finality/source expiry, recovery authority và original funded lifetime;
- public/private output/disclosure policy; terms authorization khác admission, custody ACK hay SpendAuth.

Fixed negotiated amounts không cần thêm price oracle. Existing proportional rule bind exact arithmetic/rounding. Relayer copying packet không redirect recipient/fees; replacement fee destination cần explicit fresh authorization hoặc keep originally authorized exact fee. Invalid spent/cancelled/expired state reject dù chữ ký đúng; cancellation không reverse delivered fill.

Deterministic không guaranteed match/inclusion/fair optimal price/private outputs. Direct bilateral RFQ có thể giảm central economic discretion, nhưng thay batch market là mechanism/product decision riêng; không silent GD2 closure.

## 11. Strict privacy và realistic alternatives

[N2] giữ unchanged adversary: matcher control/collude legitimate trader, thấy own asset outcomes. Existing buyer q2/limit12 với Alice ask6 vs10 và second genuine seller unknown ask1/2/3 gives midpoint own price9 vs11, certainty distinguishes worlds dù perfect MPC. Hiding receipts không hide actual own balances/refunds/delivery.

No-cross trace: adversarial buyer limit8, honest ask6 vs10, no independently funded cover dealer. Ask10 legally gives delivery0; perfect noninference requires same distribution ask6, so also0. Never settle useful crossing để “privacy” không requested full market. Đây reasoned incompatibility **specific threat model/corpus**, không mọi privacy-preserving trading impossible. No fresh runtime/experiment được chạy ở đây.

| Alternative | Guarantee/trade-off thực tế | Under current strict GD2 |
|---|---|---|
| MPC/encryption privacy modulo disclosed outputs | Hide raw/intermediate inputs, output inference permitted trong khác definition. | Requirement change, chưa approved. |
| Bilateral RFQ + mutually signed exact terms | Counterparty biết negotiated data; matcher có thể bớt view; deterministic settlement. | Trader collusion/output channel vẫn; không toàn strict market. |
| Fixed price/denominations/genuine cohort/batching | May reduce price/detail/timing channels; fill/no-fill still depends hidden limits. | Không Pass; không invent genuine unknown traders/cover. |
| Noisy/differential-private outcomes | Quantified bounded inference, limits/economic/composition constraints. | Khác perfect noninference, requires decision/proof. |
| Independently prefunded dealer/cover inventory | Input-independent delivered outcome nếu actual backing/economics thỏa. | Adds capital/counterparty/exposure, không bilateral crossing; chưa approved. |
| Exclude matcher-controlled/colluding traders | Thay adversary/governance; proxy enforcement khó. | Không user choice; public identity membership vẫn separate leakage. |

Same-chain shielded notes hoặc Zcash shielded source có thể hide public observer, không hide corrupt owner's own outputs. Source linkage privacy và admission/matcher content/accepted-identity privacy tách riêng. **GD2 structural FAIL, replacement Open, no waiver.** Không claim live private matching/anonymity hoặc ZK solves all.

## 12. Safety, liveness và roots of trust

| Boundary | Safety requirement | Liveness/data/censorship limitation | Required proof/capability |
|---|---|---|---|
| Company/UI/relayer/matcher disappears/malicious | Không redirect/fabricate/consume rồi bỏ tiền/false timer refund. | New discovery/quote có thể dừng; old rights cần packets/resources/data independent. | Direct self-submit/exit cho funded states, no company-only root/signature. |
| Same-chain verifier/admin | Ownership/conservation/replay, cancel/fill atomic winner. | Gas/resources/DA/root access/original rule lifetime. | Actual relation/code/VK/transfer failure checks; chưa implementation. |
| Source mining/eclipse/reorg | All facts same valid accepted history, no false nonpayment/multi-obligation. | Honest competing heads/PoW/activation/prior state/progress. | All-era full validity + head/finality policy, no SPV fallback. |
| Hostile mixed T | Correct net consideration/proportional allocation. | Missing independently available concealed owner/debit witnesses. | **Missing capability**, all-hostile terminal Blocked. |
| S received excess `C>A` | Actual authorized native return, not gift/clamp. | Offline/malicious S and source-input lifetime/data. | **Missing return authority construction**. |
| FROST threshold | No unauthorized sign/nonce reuse, exact effects consent. | Enough shares/cooperation/privacy-trusted participants/transport. | Native DKG/intent/nonce/input/recovery, not DB/quorum. |
| Proof setup/program/resources | Intended complete relation, not only valid bundle/bytes. | Fetchable authenticated artifacts and local private proving capacity. | Pinned artifacts/assurance/actual target acceptance, existing gaps retained. |
| HyperCore/EVM authority | Correct asset/account/action, no cross-domain double backing. | Venue consensus/API/data/CoreWriter/issuer/link/bridge. | Exact qualification + enforced spot-only delegation or direct signing. |
| Solana/token issuer | No false amount/consumed withdrawal without delivery/right. | Freeze/hook/pause/delegate/upgrades may block/take assets. | Exact asset authority audit/disclosure or exclude incompatible class. |
| Matcher/trader collusion | Strict protected content/identity including own assets. | Useful exact outputs incompatible candidate. | GD2 redesign decision, not MPC wiring. |
| Restart/reorg/cleanup/version changes | Preserve terminal consumption/live liability/input/change exclusivity. | Original authenticated state/history/artifacts retained. | Stable deployment/pool/network identity + durable disjoint partitions. |

Safety = không chi sai/đúp/false refund theo assumptions. Liveness = eventually actual settlement hoặc usable terminal recovery. Unknown/locked escrow safer than theft có thể cần nhưng **không complete all-hostile acceptance**. Data availability ảnh hưởng safety và liveness: hidden heavier chain có thể wrong refund, missing secret witness có thể indefinite lock. No finite recovery promise dưới arbitrary chain halt/censorship/secret loss. Operator independence removes company dependency, không mọi môi trường assumption.

## 13. Server-off matrix và open decisions

### 13.1 Proposed acceptance, không commands có sẵn

| State | Manual/self-hosted right cần có | Không được suy ra |
|---|---|---|
| Draft/unfunded | Local discard/reconstruct; no P export; source wallet rights intact. | No quote không funds lock/S obligation. |
| Funded same-chain note | Direct owner proof withdraw/transfer từ original deployment và reconstructible data. | API login/new FAA certificate không cần cho exit; issuer freeze còn. |
| Quoted, chưa authorized | Reject proposal, alternative discovery hoặc owner exit. | Terms/quote signature không source spending. |
| Open order/proposal | Direct owner cancel/exit trên unconsumed capability; new fill cần exact owner-prepared outputs + fresh authorization khi quantity known. Fully authorized fill có thể self-submit trong validity. | Cancel request không overwrite mined fill; generic open order không offline permission to invent new outputs/fill quantities. |
| Partial | Filled/unused successors riêng, exact values/openings/ciphertexts locally prepared/checked/backed up và fresh per-fill auth; unused owner exit independent. | Parent reuse/partial chunk release full hold; owner offline không new partial fill, không silently disable partial semantics. |
| Native Q ready, chưa armed | U wallet intact, disclosed S Q-only cancel capability, local reservation cancel nếu no chain funding. | Q no guaranteed delayed broadcast/payment window. |
| Native armed/outcome unclear | Saved packets/direct source/proof/target path; verified Q/general conflict classification. | Timer/missing callback không S escrow withdrawal. |
| Source submitted/included | U independent history/payout witness/prover/direct submission. | Proof deadline không erase valid included payment. |
| Proof/entitlement ready | Retry same immutable context/right, actual transfers. | Blob/credit/event không paid; revert/OOG không abandon right. |
| Hostile mixed T/excess unresolved | Preserve liability/evidence, show exact prerequisite; capability required before release. | Pending không terminal; chain proof no hidden fact, Q no excess return. |
| Custody ZEC payout pending | Native independent authorized shares/capability/data nếu construction exists. | Company-only set lost không automatic refund. |
| External Core open/partial/cancel/Unknown | Direct user signing + exact authoritative reconciliation. | HTTP200/enqueue/revoke không undo fill/crosschain delivery. |
| Submission failed | Determine exact effects; same authorization retry if valid/unspent. | Timeout/restart không zero-effect/free funds. |
| Terminal | Independently verify actual transfers/recipients/amounts/source policy, retain replay history. | ACK/receipt/DB status không money proof. |

### 13.2 Recovery package/data lifetime

**D:** Before funding/arming user backs up private secrets/openings, immutable terms/context/policy và actual usable recovery packet. Public manifest identifies exact code/circuit/program/proving key/VK/ABI/deployment/network/policy/cohort artifacts. Private package encrypted with user-owned capability, not sole company copy/public upload.

Public commitments/ciphertexts/state updates/history/full bodies must be independently obtainable or sufficiently backed up để reconstruct witnesses. Hash/content addressing ≠ availability. Stored witness ages; pins không useful nếu binaries/proving resources mất. Gas/fees/finality/resource policy real; replacement relay cannot mutate fee/beneficiary. Public data không recreate lost secret. Matching epoch/Zoss roster/API revocation/library upgrade/company shutdown không retire funded original consumption/proof/recovery path.

### 13.3 Decisions/blockers không giảm scope

- **Native all-hostile net witnesses:** independent construction còn missing; wallet policy/genesis proof không recover encrypted owner/debit facts. No witness-qualified indefinite-pending completion.
- **Source excess return:** actual S authority/capability/input/proof/lifetime missing; destination bond/refund không substitute native return.
- **Strict matching:** mechanism/security contract compatible unchanged GD2 còn Open; bilateral/public Core not waiver.
- **Same-chain new relation:** exact domain/asset chưa qualify; selected recipient/owner-prepared exact outputs + local backup/decrypt/commitment checks + fresh per-fill common-digest authorization. Actual per-owner ownership/conservation composition/atomic validation/cancel-exit/data/resources còn cần xây. Circuit-enforced encryption/unattended fresh partial filling unselected; no offline new-fill promise hoặc support claim.
- **History/canonicality:** no-SPV full-validation giữ nguyên; reconcile PDF/ZIP/source/version/activation và authenticated prior state/data.
- **Reverse/custody:** separate authority/refund/privacy/data design; preserve native bidirectional target, label company-exclusive routes incompatible thay quảng cáo independent.
- **Hyperliquid delegation:** exact asset/action/account qualification, enforced spot-only/no-leverage hoặc direct per-action signing; no server-policy guarantee.
- **Governance/lifetime/setup/issuer:** immutable funded rights versus token/control dependencies, independent artifacts/proving/data.

Nguồn trong file xác nhận passages/code existence, không live privacy/market, GD2 fix, full terminal recovery, excess capability, audit pass, benchmark/gas/latency, approved mainnet support hoặc implementation. Assignment này không chạy build/tests/lint/formatter/checks, transactions, deployment, funds hay git actions.

## 14. Claim–source ledger

**Mọi nguồn dưới đây truy xuất 2026-10-02.** Quotes giữ nguyên language nguồn; source docs/provider claims không independent validation. Internal references là current requirements/inherited reasoning, không experiments/audits mới của research này.

### 14.1 Zcash authoring và node history

| ID | Primary URL / version | Exact passage/section đã đọc | Scope và limitation |
|---|---|---|---|
| **Z1** | [ZIP index](https://zips.z.cash/) | “The most recent settled Network Upgrade on Mainnet is NU6.3, which activated at Mainnet block height 3428143.” | Official index assertion, không live-tip query. ZIP labels/PDF publication mismatch giữ nguyên. |
| **Z2** | [ZIP258](https://zips.z.cash/zip-0258), [ZIP229](https://zips.z.cash/zip-0229) — pages label Draft | ZIP258 `ACTIVATION_HEIGHT`: Testnet4134000/Mainnet3428143; “No new value may enter the Orchard pool”; ZIP229 Ironwood: “its own note commitment tree, anchor, and chain value pool balance”; §Anchor commitment: “without changing the transaction ID, while the proofs still bind to the specific anchor used.” | Consensus/format deltas, không wallet/target network run. Draft label không tự quyết định activation; index và source được đối chiếu, exact operational acceptance còn cần. |
| **Z3** | [Protocol PDF](https://zips.z.cash/protocol/protocol.pdf) — retrieved v2026.7.0-236-ga735ca [NU6.2], dated2026-09-30 | §3.3 “valid block chain with greatest total work”; full validator “SHOULD attempt to obtain candidate blocks from multiple sources”; §4.18.4 “Merkle path validity”; §4.15 separate SpendAuth; §4.20 mempool decrypted information “provisional, and private”. | PDF chưa tự nhận complete NU6.3 revision; chỉ foundational chain/crypto claims có scope. Không independent Ziquid proof/canonicality theorem. |
| **Z4** | [ZIP2005](https://zips.z.cash/zip-2005), [ZIP326](https://zips.z.cash/zip-0326), [pinned Orchard encryption](https://github.com/zcash/orchard/blob/e000e9f8e236edc0c4f25c1be475e69039fa5551/src/note_encryption.rs) | ZIP2005 Recovery Protocol “in outline but not in detail: many of its design decisions are intentionally left open”; “not required to add support for the Recovery Protocol to consensus rules now.” ZIP326 “A light wallet is a wallet that does not validate the consensus rules itself.” Encryption: IronwoodDomain “accepts only NoteVersion::V3”; compact prefix “covers every field except the memo.” | Quantum recovery preparation ≠ swap refund. Scanning/key/domain scope only, no wallet runtime or note validity proof. |
| **Z5** | [ZIP374](https://zips.z.cash/zip-0374) — Revision0 Draft | Abstract v2 supports “fully signed before its anchors, Merkle witnesses, and proofs are known”; privacy: “Delegating the Prover role reveals the private data”; PCZT includes “full viewing key”. | Durable role-separation format, không automatic proving/recovery/confidential delegate. |
| **Z6** | [pinned prover](https://github.com/zcash/orchard/blob/e000e9f8e236edc0c4f25c1be475e69039fa5551/src/pczt/prover.rs), [extractor](https://github.com/zcash/orchard/blob/e000e9f8e236edc0c4f25c1be475e69039fa5551/src/pczt/tx_extractor.rs), [Note API0.15.5](https://docs.rs/orchard/0.15.5/orchard/note/struct.Note.html) | Prover uses `MissingFullViewingKey`, `MissingWitness`, `AnchorDeferred`; extractor uses `MissingSpendAuthSig`, `MissingProof`, `MissingBindingSignatureSigningKey`; `apply_binding_signature` verifies every rk/signature. Note API: “Derives the nullifier for this note.” | Static source/API prerequisites, not chain-admissible anchor/note or independent arbitrary-T classifier. Compatibility requires full coherent upstream cohort. |
| **Z7** | [ZIP312](https://zips.z.cash/zip-0312), [frost-tools PR593](https://github.com/ZcashFoundation/frost-tools/pull/593), [merge metadata](https://api.github.com/repos/ZcashFoundation/frost-tools/pulls/593), [pinned signer](https://github.com/ZcashFoundation/frost-tools/blob/06c0dbdbb1bac9b99cd255e74ba2f387c295e660/zcash-sign/src/sign.rs), [pinned Zebra nullifiers](https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-state/src/service/check/nullifier.rs) | ZIP312 “Coordinator is trusted with the privacy”; “All key share holders are also trusted”; “signers MUST check that the given SIGHASH matches the data”. API `merged_at=2026-08-12T16:46:44Z`; signer uses `v6_signature_hash` and separate pool passes. Nullifiers “MUST NOT repeat”; pools “considered disjoint, even if they have the same bit pattern.” | RedPallas threshold source exists; PR mining/end-to-end narratives là V, migration direct-test limitation retained. Nullifier conflict identifies spent input, không net-payment/refund fact. No ordinary-FROST-adaptor equivalence. |
| **Z8** | [RFC9591](https://www.rfc-editor.org/rfc/rfc9591), [ZF FROST README](https://github.com/ZcashFoundation/frost), [FROST server](https://frost.zfnd.org/zcash/server.html) | RFC§1 adversary corrupts “strictly fewer than a threshold”; §5.2 “MUST NOT use the nonce as input more than once”; §7.4 protocol abort on failure. README audit “does not include frost-secp256k1-tr and rerandomized FROST.” Server E2E messages exchanged through JSON-HTTP sessions. | Threshold cooperation/security/nonce and partial audit scope; replaceable transport không recover key shares/witness hoặc compel signers. No full current custody/re-randomized audit claimed. |
| **Z9** | [ZIP221](https://zips.z.cash/zip-0221) — Final | Abstract “probabilistic verification FlyClient”; Motivation “correct with high probability”, block/history metadata inclusion. | History commitment/possible light-client design, not selected full validating app proof or canonical oracle. |
| **Z10** | [Zebra6.4.2 release](https://github.com/ZcashFoundation/zebra/releases/tag/v6.4.2), [metadata](https://api.github.com/repos/ZcashFoundation/zebra/releases/tags/v6.4.2) | Published2026-09-25; target `e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291`; “Fix a remotely triggerable denial of service when processing malformed V6 transactions.” | Specific released source/version, not a live-node run/full financial proof. |
| **Z11** | [pinned Zebra network](https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-chain/src/parameters/network.rs), [zcashd6.11.0 proof verifier](https://github.com/zcash/zcash/blob/v6.11.0/src/proof_verifier.cpp) | `mandatory_checkpoint_height`: “Zebra can't fully validate the blocks prior to Canopy.” PHGR branch: “We checkpoint after Sapling activation, so we can skip verification” and `return true`. | Pinned historical validation gaps, không every version/node incapable hoặc authorization to weaken full-validity requirement. |
| **Z12** | [ZIP229](https://zips.z.cash/zip-0229), [ZIP228](https://zips.z.cash/zip-0228) | V6 Non-requirements “need not support ZSAs”; ZIP228 Draft, Deployment “future Network Upgrade”; limitation “we do not support partial fills.” | ZSA venue future, not LP share/live support. ZIP228 refers withdrawn ZIP230/246, not current NU6.3 v6 specification. |

### 14.2 Atomic swaps, CoW và UniswapX

| ID | Primary URL / pin | Exact passage/section đã đọc | Scope và limitation |
|---|---|---|---|
| **A1** | [ZIP300](https://zips.z.cash/zip-0300) — Proposed Informational | “only supports transparent cross-chain swaps”; Timeout Duration “significantly shorter”; Block times must account relative chain block times. | Transparent P2SH/HTLC, không Ironwood shielded script/refund. Suggested24h/48h không parameters chọn cho Ziquid. |
| **A2** | [BlockstreamResearch scriptless note](https://github.com/BlockstreamResearch/scriptless-scripts/blob/master/md/atomic-swap.md) | Basic construction assumes “same group” và “support Schnorr signatures”; Motivation describes different-curve discrete-log problem. | Specific research recipe, không global impossibility/RedPallas integration/audit/selected implementation. |
| **A3** | [ZIP203](https://zips.z.cash/zip-0203), [pinned Zebra transaction](https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-chain/src/transaction.rs) | “transaction must be included in block N or earlier”; `lock_time()` uses `.any(|seq| seq != u32::MAX)` trên transparent inputs. | Expiry inclusion, không undo/refund; future pure-shielded Q field insufficient. No source/destination clock conversion assumed. |
| **C1** | [CoW solvers](https://docs.cow.fi/cow-protocol/concepts/introduction/solvers), [onboarding](https://docs.cow.fi/cow-protocol/tutorials/solvers/onboard) | “independent, bonded participants”; “Anyone ... can create a solver”; onboarding “whitelist your solver's address”; KYC specifically CoW DAO bonding pool. | Open development vs authorized settlement. Không universalize KYC to every pool hoặc claim permissionless settle. |
| **C2** | [CoW core](https://docs.cow.fi/cow-protocol/reference/contracts/core) | Deployment entries Settlement “Upgradeable: No”, AllowListAuthentication “Upgradeable: Yes”; known issues zero amounts/ERC1271 replay/cached domain fork replay/appData. | Docs deployment architecture, not independently matched bytecode/admin snapshot; guarantees conditional exact wallet/token behavior. |
| **C3** | [CoW authentication docs](https://docs.cow.fi/cow-protocol/reference/contracts/core/allowlist), [pinned code](https://github.com/cowprotocol/contracts/blob/c07a93e3596194c5e3cf331c755a3f9f0e4a17d8/src/contracts/GPv2AllowListAuthentication.sol) | “Only the manager can add or remove solvers”; proxy-upgrade warning; source `onlyManager`, `onlyManagerOrOwner`, `solvers`. | Mutable permissioned dependency. Không nói admin bypass immutable user-fund enforcement; protocol buffers khác user assets. |
| **C4** | [CoW settlement docs](https://docs.cow.fi/cow-protocol/reference/contracts/core/settlement), [pinned settlement](https://github.com/cowprotocol/contracts/blob/c07a93e3596194c5e3cf331c755a3f9f0e4a17d8/src/contracts/GPv2Settlement.sol), [pinned signing](https://github.com/cowprotocol/contracts/blob/c07a93e3596194c5e3cf331c755a3f9f0e4a17d8/src/contracts/mixins/GPv2Signing.sol) | `settle` `onlySolver`; compute checks expiry/limit/filled; `invalidateOrder` owner check/max amount; `Trade` owner/token/amount/fee/UID. Docs historical filled storage may be freed. | Atomic authorized same-chain example, not crosschain/privacy/best-execution/liveness proof. Pin resolved from official tree during retrieval. |
| **C5** | [CoW vault relayer](https://docs.cow.fi/cow-protocol/reference/contracts/core/vault-relayer) | “only able to transfer ERC-20 tokens to the GPv2Settlement contract”; allowances to relayer; external vault transfer requires governance/user approvals. | User-fund firewall, not absence token/vault/chain risks or unrestricted solver custody. |
| **C6** | [pinned CoW OpenAPI](https://github.com/cowprotocol/services/blob/8e49a227456f08483a7dea78aefc7ab164ed5f7f/crates/orderbook/openapi.yml) | DELETE orders “best effort cancellation ... might not prevent solvers from settling ... in-flight settlement transaction”; creation schema has deny-listed403. | Off-chain request ≠ consensus invalidation; schema read, not API call. API replacement atomic operation không irreversibly wins on-chain fill race. |
| **C7** | [CoW solver input schema](https://docs.cow.fi/cow-protocol/reference/core/auctions/schema) | `orders` includes `sellAmount`, `buyAmount`, `fullSellAmount`, `fullBuyAmount`, `owner`, `receiver`, `signature`. | Ordinary route exposes these values to solvers, no strict GD2 privacy. Không infer all potential extensions from one schema. |
| **U1** | [UniswapX whitepaper](https://uniswap.org/whitepaper-uniswapx.pdf) — July2023 | Abstract “can be extended”; §4.1 settlement oracle/fill deadline/bond/proof deadline; parameterization “outside the scope”; §4.2 challenge deadline before proof deadline. | Proposed crosschain/economic construction, không current Zcash/Solana deployment/safety evidence. Oracle/bond/challenger assumptions remain; deadlines không adopted native policy. |
| **U2** | [UniswapX overview](https://developers.uniswap.org/docs/liquidity/uniswapx/overview), [architecture](https://developers.uniswap.org/docs/liquidity/uniswapx/concepts/architecture) | Orders “broadcast publicly”; “Anyone can fill”; reactors validate/resolve/pull via Permit2/callback/verify received outputs. | Current documented same-chain mechanics, not hidden orders, guaranteed fill or requested crosschain support. |
| **U3** | [UniswapX deployments](https://developers.uniswap.org/docs/liquidity/uniswapx/deployments) | Chain-specific reactor/quoter/Permit2 tables. | Docs list only, not exercise a crosschain oracle/asset route or assign rollout dates. Không fabricated market-absence theorem. |

### 14.3 Hyperliquid và Solana

| ID | Primary official URL | Exact passage/section đã đọc | Scope và limitation |
|---|---|---|---|
| **H1** | [About Hyperliquid](https://hyperliquid.gitbook.io/hyperliquid-docs/about-hyperliquid.md) | “split into ... HyperCore and the HyperEVM”; “Every order, cancel, trade, and liquidation happens transparently with one-block finality inherited from HyperBFT.” | Provider-described architecture/finality, không independent validation/censorship theorem; no throughput benchmark adopted. |
| **H2** | [Core↔EVM transfers](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/hypercore-less-than-greater-than-hyperevm-transfers.md) | HYPE links native EVM balance; “Do not blindly assume accurate fungibility”; “no checks ... sufficient supply ... valid ERC20”; “arbitrary bytecode”. | Exact link/contract/supply/decimals required. Future-enabled mainnet passages không readiness evidence; no Solana/ZEC bridge selected. |
| **H3** | [Asset IDs](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/asset-ids.md), [HIP1](https://hyperliquid.gitbook.io/hyperliquid-docs/hyperliquid-improvement-proposals-hips/hip-1-native-token-standard.md) | “spot ID is different from token ID”; network IDs differ; HIP1 “capped supply fungible token standard”, name has “no uniqueness constraints”. | Identity/lot/supply-domain distinction, not qualification/liquidity/backing of candidate pairs. |
| **H4** | [Core interaction](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/interacting-with-hypercore.md), [timings](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/interaction-timings.md) | Read precompiles “testnet”; delayed actions “first as an enqueuing and second as a HyperCore execution”; Core→EVM queued; account “must exist on HyperCore before the EVM block is built”. | Domain-specific execution order/enqueue distinction. Không actual network run/mainnet availability/atomicity/asset control claim. |
| **H5** | [Nonces/API wallets](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets.md) | “A master account can approve API wallets to sign on behalf”; “only used to sign”; “previously signed actions can be replayed once the nonce set is pruned.” | Delegation/account identity/nonce replay, không blanket spot-only or unrestricted-withdrawal permission inference. |
| **H6** | [Signing docs](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing.md), [official SDK signing](https://github.com/hyperliquid-dex/hyperliquid-python-sdk/blob/master/hyperliquid/utils/signing.py), [SDK exchange](https://github.com/hyperliquid-dex/hyperliquid-python-sdk/blob/master/hyperliquid/exchange.py) | “two signing schemes ... sign_l1_action vs sign_user_signed_action”; `action_hash` binds msgpack action/nonce/vault/expiry; `bulk_orders` L1 path; user-signed scheme sets `hyperliquidChain`. | Static official encoding/action dispatch, not network acceptance or full permission enforcement. Master branch unpinned/live; direct per-action consent conservative, no SDK installation/signing. |
| **H7** | [Exchange endpoint](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/exchange-endpoint.md) — sections Agent Send Asset, Set User Abstraction (agent), Expires After, Initiate withdrawal | “can be signed by an agent. Destination must match the source address”; `agentSetAbstraction` choices i/u/p where p “portfolioMargin”; user-signed Core USDC transfer does not support expiresAfter; withdrawal says “L1 validators will sign and send the withdrawal request to the bridge contract.” | Direct evidence generic agent not inherently spot-only/only order+cancel. Specific account enforcement and full action matrix unqualified. Withdrawal bridge distinct root, no fee/time benchmark promises copied. |
| **H8** | [Nodes](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/nodes.md), [Foundation non-validating node](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/nodes/foundation-non-validating-node.md) | Node instructions linked; Foundation “No guarantees ... data completeness”; “should not be relied upon as a sole or authoritative source”; running non-validator “permissionless”; endpoint access may be discontinued. | Self-running vs particular Foundation service access policy. No independent consensus verification/DA/availability guarantee. |
| **S1** | [Solana transactions](https://solana.com/docs/core/transactions) | “If any instruction fails, the entire transaction fails and all state changes are reverted”; “Fees are still charged on failure.” | Same-chain atomic instruction boundary, không crosschain atomicity; no compute/size/performance feasibility inferred. |
| **S2** | [Solana deployment](https://solana.com/docs/core/programs/program-deployment), [Agave3.1.8 loader](https://github.com/anza-xyz/agave/blob/v3.1.8/programs/bpf_loader/src/lib.rs) | “Setting the upgrade authority to None makes the program immutable”; same Program account pointer does not change upgrade; loader Upgrade validates signed authority and ProgramData. | Exact upgrade root, no existing Ziquid deployed authority audit. Verified source/binary không guarantee future immutable. |
| **S3** | [Solana tokens](https://solana.com/docs/tokens), [freeze account](https://solana.com/docs/tokens/basics/freeze-account), [token program9.0.0 processor](https://github.com/solana-program/token/blob/program%40v9.0.0/program/src/processor.rs) | Mint freeze authority; frozen account prevents “receiving, transferring, or burning”; native-token accounts do not support freezing; `process_toggle_freeze_account` validates authority and sets Frozen. | Token control independent app immutability. Không inspected a specific USDC/stock/bridge mint's live authorities. |
| **S4** | [Token2022 extensions](https://solana.com/docs/tokens/extensions), [permanent delegate](https://solana.com/docs/tokens/extensions/permanent-delegate) | Optional `Pausable`, fee/hook/delegate types; delegate can authorize transfer/burn “for any token account”; owner “cannot revoke” delegate. | Must inspect exact mint/extension. Không mọi SPL asset has delegate/pause/confidential support. |
| **S5** | [Transfer hook](https://solana.com/docs/tokens/extensions/transfer-hook) | “custom instruction logic on every token transfer”; use cases “Black or white list wallets”; CPI hook example can fail transfer. | Issuer/hook policy and code/admin risk, not claim hooks obtain sender's unrestricted signer privileges; docs explicitly restrict those privileges. |

### 14.4 Current project requirements và inherited reasoning

| ID | Internal source | Passage/section dùng | Scope và limitation |
|---|---|---|---|
| **N1** | [Native status — concrete blockers](../NATIVE-IMPLEMENTATION-STATUS.md#concrete-blockers-to-the-entire-protocol), [ARCHITECTURE](../ARCHITECTURE.md), [MODULES](../MODULES.md) | Independently obtainable terminal recovery for every hostile spend, actual S-authorized excess source return `C>A`, no U FVK/spend key to S, full validating no-SPV, one-real-note/one-obligation, proportional allocation và actual transfer completion. | Current user requirements/status authority, no fresh run/new audit by file này. Upstream capabilities/current subrelations không full protocol. |
| **N2** | [Imported strict-privacy feasibility](../imports/kerb/docs/reviews/2026-10-02-strict-privacy-feasibility.md) | User retained strict privacy/no output waiver; §§1–2 midpoint price9/11 and legal common-delivery0 traces; remedies require changed requirement. | Inherited reasoned mechanism analysis với source-reported arithmetic checks, không new runtime privacy experiment/general theorem every exchange. GD2 remains FAIL, not enabled by redesign. |

### 14.5 Claim-audit disposition

Primary URLs/passages được đọc, official index/spec/code và live provider descriptions được phân biệt; no citation/release/audit/experiment/benchmark fabricated. Every recommended behavior ghi Proposed hoặc requirement, no support/status promotion. Counterexamples/authority deductions là reasoning with boundaries, không observed exploits. Mâu thuẫn PDF/ZIP, PR author test limits, permissioned CoW, broad Core agent permission và unavailable native witness/return capabilities được giữ thay vì chọn source thuận tiện. Các live/default branches có thể đổi; deployment bytecode/admin state/network exercises và integrated documentation checks thuộc separate acceptance, không được claimed tại đây.

