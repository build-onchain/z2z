# Server-independent workflows — Ziquid / future Z2Z

**Design basis 2026-10-02; scope consolidation 2026-10-06, not yet release-qualified.** The first passing journey requires an owner-local `z2z-node` P2P/CLI, a samechain bilateral testnet (Base Sepolia is the engineering default), and full company-off recovery. It requires no mandatory hosted UI/API/matcher/indexer/relayer/database. **These are active parallel obligations for project completion, not V2:**

- native ZEC (L-ZEC, M1–M5/S1–S7)
- L-HEVM, L-SOL and L-NEAR
- X.CROSSCHAIN (HTLC first, which is not atomic and claims no privacy)

Each carries the same company-off requirements. V2 keeps only GUI, standing maker, Intents/1Click, mainnet and full privacy. Strict GD2 is an active Blocked gate, not a waiver. [ARCHITECTURE](ARCHITECTURE.md) owns behavior; the [V1 matrix](V1-DELIVERY-MATRIX.md) and [micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md) own acceptance and task mapping; [BLOCKERS](BLOCKERS.md) owns readiness; [status](NATIVE-IMPLEMENTATION-STATUS.md) owns observed evidence, which is not funded recovery completion. [Server](research/SERVER-INDEPENDENCE-RESEARCH.md), [cross-chain](research/CROSSCHAIN-MARKET-RESEARCH.md) and [network/cross-chain 2026-10-06](research/2026-10-06-phase0-private-discovery-network.md) research remain construction inputs.

## 1. Điều được bảo đảm phải cụ thể

**Company-offline autonomy** nghĩa là một owner có keys/witnesses và môi trường chain/prover cần thiết có thể kiểm trạng thái và thực hiện **quyền đã được protocol cấp**, không cần domain/API/database hoặc chữ ký mới của công ty. Không có nghĩa:

- User có thể tạo đối ứng/thanh khoản khi không ai muốn giao dịch.
- User có quyền đảo ngược chân thanh toán đã final hoặc thu hồi tiền đã trả bên khác.
- Không cần gas, node/data/history, phần cứng tạo proof hoặc chain inclusion.
- Issuer không thể freeze/deny transfer, validators không thể censor, sequencer/provider không thể ngừng hoạt động.
- Công khai contract/verifier đồng nghĩa circuit source, proving keys, note secrets, ciphertext và history đều onchain/còn tải được.

Release claims tách **funds safety**, **authorization independence**, **data/prover availability**, **transaction inclusion** và **liquidity/matching liveness**. Chỉ lớp đầu/permission có thể kiểm bởi relation/contract; lớp khác có assumptions và drills riêng.

### 1.1 V1 company-off milestone — full recovery, không observation-only

V1 covers qualified samechain Native/one vanilla ERC20 rights on **one selected EVM public testnet**: unfilled backed orders, partial remainder, received/proceeds/change/ordinary notes và pending/Unknown operations. Hai owners phải online và fresh authorize mỗi **new** bilateral fill; owner không cần counterparty/company permission để cancel live remainder hoặc withdraw eligible owned note. Base Sepolia proposed, selection/pins pending; public-testnet acceptance không local Anvil hoặc mainnet support.

Required chain: **encrypted owner backup + usable pinned artifact kit → cold restore in clean owner process → independent complete authenticated history/current roots/NFs/outcomes → local decrypt/recompute openings + witness → genuine local proof → exact owner review/sign → independent direct/alternate-relay submit → actual correct asset arrival/finality/reconcile**. Proof/artifact/capability dry restore qualification (P4.01–P4.05) must precede irreversible funding. Final funded clean-process unfilled/partial/proceeds/Unknown/retry drills (P4.14–P4.18) remain required, not fulfilled by decrypt, inspection, CPU execution, unsigned calls or simulation.

Durable storage remains UNRESOLVED; no mandatory shared company DB, but PostgreSQL-only active SQL/no-local-SQL/approved-private-URI hold still binding. No SQLite substitution or operational reset/migration. Proving system/resource targets unqualified: measure genuine owner-local wrapping, no remote witness upload. Production-secret-bearing recovery, resource runs, networking, signing/submission/funds/deployment (including Anvil) require separate approval; docs/plans authorize none.

### 1.2 P2P discovery and relay independence

Company bootstrap supplies discovery only and is optional. `z2z-node` must accept independently selected peers, alternate bootstrap and direct connections. Neutral availability beacons are rebuildable. Order terms go only to the selected bilateral counterparty over a direct session, and exact bilateral public packets are coordinated without company DNS/API/login/DB. An optional independent relay is used for introduction and hole punching only. Independent RPC/history replacement, and an arbitrary submitter of the **unchanged authorized** call, must preserve domain/asset/recipient/fees. Missing peers may stop new price discovery but cannot veto an existing eligible exit. No replacement peer creates liquidity or a concealed witness.

A peer signature is not backing or current-spentness proof. Backing requires the dedicated non-executable `BackingClaim` relation (proposed, P0.05), never a financial certificate. Keys, openings, recovery capabilities and private proving witnesses never enter peer frames, not even as encrypted witness exchange. **Strict GD2 is an unmet gate:** exact terms reach the counterparty, public NF/order locators identify the accepted maker, and own results distinguish adjacent worlds. The bilateral-only audience is minimization, not a waiver. Losing the discovery cache or hitting a negotiation timeout cannot release exported/submitted rights or clear `Unknown`.

Company-off drill disables company bootstrap/API/indexer/prover/relay and uses independent peers/RPC/artifact copies. Demonstrate direct/alternate-relay cancel/withdraw/eligible authorized submission and actual asset arrival. Peer discovery, chain data availability/finality, local compute/gas and issuer behavior remain explicit dependencies, not company permission.

**Active parallel lanes, not closed by the first journey:** native P/Q/source history/net classification/hostile-T terminal/excess recovery (L-ZEC) remains first-class and keeps its unchanged S1–S7/M1–M5 meaning. Old funded, signed and artifact identities stay intact. **X.CROSSCHAIN company-off requirement:** the backup holds the preimage (initiator), the hash, both conditional lock openings and the session envelope **before the first lock**, behind a durable preimage-release fence. A cold-restored owner must be able to claim or refund on each lane with company services off. Refunds are enforced only by the on-chain deadline under finalized lane time; a local timeout unlocks nothing. Claims are permissionless with a fixed recipient, so any owner node may act as watcher. The asymmetric outcome (one leg claimed, the other refunded after the responder misses its deadline) is a disclosed exposure, not atomicity. **V2 retained:** one maker opening signature permitting new standing fills while the maker is offline, and sound full privacy.


## 2. Default lựa chọn và quyền nâng cấp

Đề xuất default cho **new qualifying proof-controlled deployments**: rules/verifier/asset adapter/consumption domain không thay sau funding, không admin sweep, không company allowlist cho settle/withdraw/cancel; arbitrary submitter được mang exact authorized payload. Registry/UI có thể ngừng discovery nhưng không khóa existing funded rights. Native actual implementation lựa chọn immutable version vẫn cần kiểm code/target; tài liệu không deploy gì.

- New version = deployment/immutable rule identity mới; user chọn và ký migrate, không admin rewrite old obligations.
- Không chọn emergency pause chặn indefinitely existing exit/settlement. Nếu future deployment cần pause/upgrade, phải disclose governance, exit điều kiện và phân loại không còn default immutable-autonomous, cần duyệt riêng.
- Retain funded verifier artifacts và recovery lifetime; source consensus upgrades và state root changes vẫn có thể cần **new proof** đúng pinned statement, không chứng minh packet cũ luôn executable.
- Solana upgrade authority, contract proxy/delegatecall, mutable verification-key registry, ERC/SPL issuer authorities và external venue đều phải audit. Một ABI/version string hay code hash của proxy không pin tất cả behavior.

Không đưa custody route nguồn Kerb vào lớp này. Threshold committee mất toàn bộ signer có thể khóa ZEC; relayer replacement không thay native spend authority.

## 3. Recovery bundle và dữ liệu công khai

### 3.1 Trước khi giao quyền hoặc funding

Client phải kiểm recovery readiness, lưu encrypted owner-local bundle và chứng minh có thể đọc lại. Không gửi secret cho relayer/matcher, không giả storage path = dữ liệu đã lưu.

| Phần | Nội dung bắt buộc và owner |
|---|---|
| Private capability | Owner keys/reference ví, note secrets/openings, spend/view capability đúng scope; không export seed/key vào public bundle. Backup key policy và loss ceiling phải rõ. |
| Authorized transaction | Exact domain/network/deployment/code/verifier/schema, asset identity/raw units, intent/quote/order, recipient/refund, amounts/limit, fees, nonce/consumption tag, expiry/finality/source policy và authorization riêng từng chain. |
| Proof resources | Source/circuit/prover/verifier identity, build/toolchain/source revision, public proving-key hashes và ceremony/provenance, actual artifact bytes ở owner/mirrors, practical resource qualification. Hash không đảm bảo artifact tải được hoặc setup sound. |
| Samechain recovery — V1 | Actual private owner/recovery capabilities, every owned note/order/proceeds/change opening and exact packet/consents, pending signed bytes, admitted output descriptors/ciphertexts/tree/index/context and artifact version. Restore from backup+independent chain history; reconcile current NF/generation/Unknown before proving. Not native P/Q custody format or secrets stored in SQL. |
| Source recovery — V2 | Native P/Q complete allowed payloads, independent U payout witness, effect/openings và privately needed relations; Q anchor/fee/branch/expiry/lifetime. All-hostile terminal/excess return capabilities must block native arming before enablement; not a V1 samechain substitute. |
| Chain access | Target ABI/account layout/deployment descriptors, source raw/history acquisition formats/policies, independently reconstructible commitments/ciphertexts và node/archive prerequisites. Explorer website không dependency bắt buộc. |
| Durable record | Atomic transition intent, funding/arming/authorization release, submission Unknown, immutable raw bytes/signatures/receipts, exact recipient/change identities và proof version. Chain reconcile owns effects; local record không tạo money permission. |

Bundle có public descriptor được content-addressed/mirrored và private owner phần encrypted, disjoint stores giữa wallet/solver/market. Không phục hồi secret đã mất bằng public ciphertext/hash hoặc server backup không có user-controlled key.

### 3.2 Data availability là protocol requirement

V1 programmable-chain note ledger phải publish ordered commitments/nullifiers và **complete authenticated encrypted output recovery data** trong independently retrievable actual chain data/events. Proof/authorization binds ciphertext/version/output order/deployment to commitment. **V1 bilateral strategy:** each recipient locally creates/checks exact opening/ciphertext/value/commitment and backs it up before both owners sign common terms/exact outputs and input consumption. Contract verifies bindings; do not pretend circuit proves encryption correctness. **V2 new maker-offline fills** need circuit-enforced recovery or another reviewed standing template construction, not current fresh-consent dependency. With independent chain history, user can recover without app DB/indexer/new company certificate.

User sở hữu receive/decrypt capability; client phải tự scan/cập nhật tree, không server exclusive branch. **Selected samechain retained-root policy is now implemented in authority source:** every successful intermediate append retains `(treeId, root) → count` immutably; initialized/rollover empty roots are never spend-admitted, input index must be below retained count, and every spend checks deployment-global current N. Common generation N makes included cancel invalidate all F1/F2; program semantics govern successor capacity. Unrelated appends/rollover alone do not expire an exact authorized root; consumed backing, unadmitted/fork state and signed expiry still reject. Storage/gas/retention/full-tree behavior and real offline-owner submission are unqualified, not a funded liveness claim. Native Zcash anchors/Q/lifetime do not inherit this policy.

**Mathematical replay and authority source implemented, not authentic cold recovery:** canonical Rust `NoteTree/root_from_path` and Solidity `SamechainTree` share depth-32 domain-separated SHA256 deployment/tree/index/commitment leaves, exact empty defaults, `u64` count through `2^32`, full-only rollover and checked ID exhaustion. Historical insertion paths remain against retained roots. Authority now stores every intermediate root/count, global NF/seen-C and emits ordered complete ciphertext/version/recovery commitment/insertion metadata in the same atomic manifest as payments. [Status](NATIVE-IMPLEMENTATION-STATUS.md) owns counts/evidence; mathematical/codec/differential positives are not financial certificates. Chain-authenticated scanning/history retention, real admitted wrapped proofs/transfers, clean-device restore and funded company-off/root-churn/receiver-failure drills remain NOT RUN.

Append events chỉ hữu ích nếu chain history truy xuất được. Chuỗi chỉ giữ state root hoặc short-lived blobs cần owner archival backups/mirrors và explicit retention; unavailable hash-addressed file vẫn unavailable. Native Zcash history/witness acquisition không được substitute từ target log.

## 4. Thao tác cùng chain — authority source implemented, funded qualification pending

Đây là **separate deployment-scoped asset-authority relation**. Native semantics/shared guest and four-mutator Solidity authority/Codec/Tree implement receipt/roots/NF/atomic manifests under fixed token/program/chain/internally new real SP1. Arbitrary constructor VKey is not independent financial trust. Genuine certificate/admitted-right/rollback/cold-restore/company-off qualification remains NOT RUN pending resources/pins. Scoped independent source review reports no actionable findings, not full audit/program/setup/funded support. Not native ZEC/bridge/GD2 solution; original source financial validator/armed escrow absent.

### 4.1 Nạp và rút tự chủ

1. Owner tạo note commitment và recovery bundle trước nạp. Token adapter đo exact received amount; asset có fee/rebase/hook/freeze không được mặc định vanilla.
2. Chain transition nhận asset thật và ghi commitment/complete recovery data atomically. Credit chỉ từ chain-controlled asset, không committee promise hoặc imported source observation.
3. Owner sync trusted chain history/check root và local note; tạo proof quyền tiêu note/amount/destination/fee/domain.
4. Owner tự gửi hoặc chọn relayer. Contract kiểm proof, eligible root/context, unspent tag, authorization và conservation; consume+transfer atomically. Revert không consume quyền.
5. Client kiểm actual final asset effect, không gọi log/credit/tx submitted là paid.

**Native ordinary-note slice implemented/exercised — 2026-10-04:** distinct withdrawal packet/journal/terms/consent, `order=None` input/change, actual commitment/N/path, strict consent and same-asset U512 Exit/Fee plus complete AEAD-recovered change without fake order. Scoped native/CPU receipt/change/cancel-return cases belong to [status](NATIVE-IMPLEMENTATION-STATUS.md), not funded withdrawals. `SamechainAuthority.withdraw` now checks retained root-count/index/global NF, verifies the canonical expected ordinary journal under the fixed program and atomically consumes/applies exact note/payment outputs. Genuine admitted spend and receiver/token-failure rollback remain NOT RUN; authentic client/cold restore/proof/asset qualification still required.

**Exact samechain note creation native slice implemented — 2026-10-04:** before deposit, `ziquid samechain review-note-creation --packet FILE --witness-stdin` checks an independently selected public deployment/payer/creation nonce and the exact private owner/opening, Native or fixed-token amount/asset, commitment, blinded terms and complete AEAD recovery; it returns consent bytes without signing. `check-note-creation --witness-stdin` additionally checks strict owner consent and emits only public packet/journal. Ordinary notes require no order; initial orders bind matching identity, generation 1, positive bounded remaining capacity and role-valid opposite-asset policy. Native ordinary Native/token and initial-order A/B CPU journal matches plus actual native CLI review/signed verification/decryption and fresh-consent amount-inflation rejection are owned by [status](NATIVE-IMPLEMENTATION-STATUS.md).

Creation journal alone is not a receipt. `SamechainAuthority.create` now authenticates actual payer, exact Native value or token payer-decrease/authority-increase deltas, verifies expected journal under fixed program before token receipt, reserves payer nonce/optional initial ID and atomically appends complete recovery bytes/root-count/seen-C state. Initial IDs stay reserved after cancel/exit. Negative creations reach actual pairing rejection without token invocation/state changes; no genuine positive deposit/admitted spend is claimed. Resources/independently trusted program/asset profile, cold restore and company-off lifecycle remain unqualified. Native source authoring/history/hostile-T/excess/privacy/SQL holds unchanged.

Nếu withdraw public asset, recipient/value/time có thể lộ; samechain ZK không private-chain guarantee. Asset issuer freeze vẫn có thể chặn transfer hợp lệ.

### 4.2 Giao dịch P2P cùng chain

**V1:** discovery/gossip proposes candidates, two online owners independently inspect/prepare/prove and freshly consent to each exact full/partial packet. Each retains private witness/output recovery material; peers exchange public certificates/consents only. Target verifies both canonical journals before either consumption/effect and performs both legs atomically or reverts. P2P is not chain consensus, backing proof or strict-private matching.

Current [reviewed Fill2](superpowers/specs/2026-10-06-independent-owner-fill-design.md) and [actual witness/guest contract](modules/zcash-proofs.md#samechain-relation-and-authority-source--no-native-source-proof-substitution) assemble identical public B/E/ordered opaque A+B leaves into C/frozen packet, with each authenticated policy and independent own_salt owner-local. `review-fill --packet FILE --execution FILE --role a|b --witness-stdin` requires independently approved canonical E frame2 and exact embedded packet equality; no counterparty policy/common blind. Guest mode0 is byte0 + one OwnerWitness frame2; non-fill/note/policy/tree/schema/outer journal/ciphertext/blinds remain1. Retain original fill1 bytes/ELF/binary identities without reinterpretation/fallback/migration; new ELF/program needs authorized new immutable authority and genuine all-mode proof/target/clean-recovery qualification. [Status](NATIVE-IMPLEMENTATION-STATUS.md) owns current native/CPU/correspondence and completed source reviews; independent source/setup/program qualification remains UNVERIFIED. E quantities are counterparty-visible, not GD2-secret; native independent opening availability does not qualify durable backup, advertised backing, wrapping or funded company-off recovery.

**V2 standing-maker requirement retained:** maker signs exactly once at backed opening; eligible takers create new fills within signed asset/quantity/net-price/fee limits while maker offline. Existing known-fill source requires fresh maker consent/witnesses, so it can be reused for V1 but does not deliver V2. Standing input authority and maker-only recoverable receipts/successors need reviewed construction without maker secret sharing; retain original signed/artifact identities and independent exits. V1 genuine funded/company-off and V2 standing drills remain NOT RUN.

Không bắt toàn bộ secrets của hai bên vào một server prover. Proof chỉ binding hash không đủ semantic agreement/output amounts. Onchain verification có thể loại operator gian lận settlement, **không** chứng minh giá tối ưu/công bằng auction hoặc giấu inference từ trader own results.

### 4.3 Cancel, partial fill và race

Owner withdrawal/cancel và fill phải tiêu cùng single-use backing capability/intent identity; partial fill tạo successor state/notes chứa **remaining exact liability + remaining allowed amount** và owner recovery data. Replay old capability không fill lại; partial fill count không được reset quote capacity bằng random fresh note.

- Cancel trước included fill: **consume/invalidate atomically shared backing capability generation** và chuyển thành owner successor note/actual withdrawal theo relation; mọi outstanding fill digest F1/F2 trên generation cũ đều reject, kể cả khác relayer/fee/proof bytes. Chỉ revoke một packet không order cancellation, không release backing và không làm packet khác vô hiệu. API ACK không invalidation onchain.
- Fill included trước cancel: chỉ unfilled successor được cancel, không đảo asset delivered.
- Pending signed fill không tự bị hủy do API trả success; chain canonical consumption quyết định.
- No company-owned escrow state bắt buộc phải có matcher-signed epoch kết thúc để rút unfilled principal. Nếu chọn future batch auction, phải có protocol-state exclusive force-close/exit và state/data independently available; chưa chọn sequencer/rollup/batch protocol.

The native armed crosschain obligation (L-ZEC, active) **does not use** the cancel/timeout of a samechain order; see §5. X.CROSSCHAIN HTLC legs use their own on-chain deadline refund, which is not the native armed contract. Standing-maker new-fill execution is V2, while samechain partial successor/cancel/recovery is required.

## 5. Native ZEC-outbound (L-ZEC, active) — original financial contract unchanged

| Stage | Owner/manual action khi company off | Không được làm |
|---|---|---|
| Draft / RecoveryPrepared, chưa arm | Dùng own wallet giữ hoặc self-spend note; giữ P unsigned; independently verify Q packet. | Không coi local reservation canceled là refund chain; Q complete không tự valid qua anchor/upgrade. |
| DestinationArmed, chưa release P | Tự verify immutable obligation/finality và chọn source action theo exact authorization; prove valid conflict/self-return mới có destination refund predicate. | Không solver cancel/timeout hoặc coi user bỏ UI là nonpayment. |
| Source P/T/Q submitted/Unknown | Acquire complete accepted valid history + exact effects/classification; giữ raw authorized bytes. | Không resend competing economic intents vì missing response; T khác P không nonpayment. |
| Source payment valid | U giữ independent payout witness, local prove và submit allocation; retry exact authorized transfer. | Không expiry tước payout; không đòi solver mới gửi private IVK/debit witness. |
| Source conflict/nonpayment proved | S tự generate eligible proof, submit allocated refund; verify Q/self-return ownership nếu branch đó. | Không root/receipt/operator signature substitute full source validity/classifier. |
| Mixed/hostile T hoặc excess C>A | Phải có independently obtainable terminal classification/recovery và actual S-authorized excess-return capability **trước route enablement**. | Hiện capability thiếu; không declare manual path complete, no gift/clamp/timeout/seizure invention. |
| Transfer revert / OOG / receiver reject | Proof/entitlement còn retry theo pinned version; funded fee/prover/lifetime constraints giữ. | Không redirect recipient silently hoặc consume rồi chỉ credit mà label paid. |

Native Q chỉ self-return khi agreed input chưa bị accepted spend khác tiêu. Destination contract không tự ký ZEC từ source receiver; proof không tiết lộ concealed openings vốn không được cung cấp. Best-submitted-work selection không global canonicality: honest history/anti-eclipse assumptions cần independent access. Nếu chain halt/censor/witness unavailable thì có thể pending; điều đó **không đạt** owner yêu cầu independently terminal completion cho mọi hostile T. Không count safety-only pending là delivered product.

## 6. V2/later custody market, HyperCore và lanes còn lại

### Custody Kerb market

Có thể manual query/export/reconcile ledger khi retained data/certificates còn, nhưng credit/ACK/business signatures không spend authority. Không đủ native threshold signer hoặc signer từ chối thì không unilateral ZEC payout. Không thêm company-signed "escape" tạo bảo đảm giả; muốn chuyển route sang operator-independent cần construction nguồn/target mới và approved migration. Legacy local safety nằm nguồn, không implementation shared wallet.

### HyperCore external spot

User dùng own account/main signer để xem/hủy/giao dịch qua venue-native tools/API; delegated signer có quyền trade không mặc nhiên quyền rút hoặc chỉ spot. Research ghi official agent actions còn có `agentSendAsset` và `agentSetAbstraction`/`portfolioMargin`: **default conservative là per-action user signing**, không company-held broad API wallet dưới nhãn spot-only. Delegation sau này cần enforceable action restrictions được qualify, không backend promise. UI-off autonomy là đối với Ziquid, vẫn phụ thuộc Hyperliquid venue/network/account rules và state/data access. Cancel races và Unknown yêu cầu actual fills/positions/số dư reconcile; không tự route vốn P2P. HyperEVM transfer/escrow và Core spot không một atomic target transaction.

Đã có native offline exact order/cancel proposals từ selected metadata và explicit account/nonce/expiry/cloid/TIF/requested cap, normalized U256 price/size và local digest; ordered `action_json` giữ dạng string. Đây chỉ preparation/inspection: signer/submit readiness false, không reservation/execution/durable nonce fences/reconciliation, requested cap chưa venue-enforced. Không financial/manual completion hoặc spot-only delegated authority từ proposal.

### Public LP/provider/agent/ZSA

User-owned LP positions có thể dùng protocol-native tools theo pool rules; issuer/pool/executable depth và program authority risks còn. 1Click custody/provider route cần provider-specific recovery, không automatic trustless exit. Agent cần enforce cap/recipient/expiry/revoke tại signer/onchain, revoke không undo completed action. Future ZSA venue đòi source consensus/client/liquidity mechanisms, không kế thừa EVM proof authority.

## 7. Native consumer surface — scoped commands, lifecycle goals

V1 manual consumer is core, not deferred GUI/TS. Existing native samechain unsigned review/signed checks, four call builders, trusted-node hash-pinned inspection/simulation and four-mutator authority source have scoped evidence; they do not deliver complete private restore/scanner/witness/genuine wrapping/owner sign/submit/outcome/retry/funded company-off flow. Reuse these stages, do not relabel implemented inspection/simulation absent or promote them to recovery. V2 native source financial validator/armed escrow/manual lifecycle remains missing. [Status](NATIVE-IMPLEMENTATION-STATUS.md) owns exercised results/counts.

The **offline public call-builder stage is implemented:** four `chains::samechain` builders and runtime `build-note-creation-call`, `build-fill-call`, `build-cancel-exit-call`, `build-note-withdrawal-call` emit exact unsigned calls before private stdin dispatch, preserving all seven private commands. [Destination spec](modules/destination-settlement.md#public-offline-samechain-call-builder) owns independent Deployment selection, current 356-byte framing/ABI/value/journals/effects and UNVERIFIED/false labels. Framing/call construction supplies no genuine certificate, sign/submit, restore/finality or funded acceptance; separate implemented observation/simulation below retains its trusted-node limits. [Status](NATIVE-IMPLEMENTATION-STATUS.md) owns scoped evidence, not company-off closure.


V1 prover must work owner-locally from retained usable artifacts without company endpoint/license, paid or shared remote prover, witness upload or new viewer. Measure genuine whole-prover wrapping/resources/target admission; do not claim laptop support from CPU journals. V2 full-history proving has its own resource/witness prerequisites; more hardware cannot supply unavailable private facts.

**Implemented inspection, not authentic financial recovery:** `ziquid samechain inspect-authority` now performs actual bounded block-pinned HTTP RPC, requiring independently selected canonical Deployment, fixed token/runtime hash, block hash, policy ID and secret endpoint-env; optional public packet kind adds root-count/current N/Note C/creation nonce/initial-ID observations. [Exact contract](modules/destination-settlement.md#block-pinned-trusted-node-samechain-inspection) owns all arguments, three runtime Keccak/full getter checks, EIP-1898 requireCanonical/no-latest behavior and strict duplicate/null/ABI/bounds/error handling. Private acquired scope is TRUSTED_NODE_AT_SELECTED_BLOCK: a coherently lying node can answer consistently. Pins/source hashes do not qualify program/token issuer/prover/finality/backing; UNVERIFIED/false financial output stays. [Status](NATIVE-IMPLEMENTATION-STATUS.md) owns synthetic public RPC standalone identity/creation/fill and real HTTP negative evidence/counts, not deployed profile/certificate/funded acceptance. Independent consensus/profile, sign/submit/outcome, authentic scanner/cold restore and funded manual/company-off drills still missing; PostgreSQL NOT RUN.

Native public `simulate-call` now performs fresh inspection followed by exact bounded hash-pinned `eth_call` without overrides/signing/submission. It returns node-reported void execution only with financial/proof/finality/backing assurances unverified; malformed/Unknown/provider rejection never releases an existing right. [Exact native contract](modules/destination-settlement.md#public-samechain-hash-pinned-void-call-simulation) is shared by hosted/manual consumers. This stage does not close genuine proof-backed manual/company-off recovery.


### 7.1 Manual lifecycle theo stage, không chỉ withdrawal

| Stage | Owner có thể làm khi company offline | Ràng buộc |
|---|---|---|
| Cold restore | Khôi phục private bundle và actual pinned tool/artifact copies; kiểm exact deployment/asset/rule trước quyền chi. | Không company login/DNS/license/approval, không recreate secret từ hash. |
| Draft / quote | Kiểm điều kiện, giữ self-controlled asset; tìm đối ứng trực tiếp hoặc bằng service khác. | New price discovery có thể ngừng; không giữ quyền trade của người khác. |
| Samechain funded/unfilled | Sync current spent/intent state, owner prove và direct withdraw/cancel exact backing. | Fill và cancel consume cùng right; response API không thắng included fill. |
| Samechain partial — V1 | Recover actual proceeds and exact live remainder, independently cancel/exit eligible remainder; new fill needs both owners online and fresh exact consent. | Old generation cannot reset quantity; settled portions remain successful; fresh-consent V1 does not claim V2 standing-maker execution. |
| Already fully authorized samechain fill | Submit exact immutable packet hoặc nhờ arbitrary sender dưới retained accepted historical membership root; observe atomic state/asset effects. | Không cần regenerate offline owner's private proof do unrelated appends/rollover. Explicit signed expiry, counterparty shared cancel/spend trước hoặc invalid root vẫn reject; không guaranteed execution/MEV immunity. |
| Submitted / Unknown | Query authentic current state/outcome, retain original bytes và fee/recipient; rebroadcast/regenerate only permitted action. | Không assume no-effect từ timeout, không cạnh tranh double funds. |
| V2 native armed/source stages | Theo matrix §5, independently verify source history/classification và exact payouts/refunds. | Native S1–S7 remain; do not apply V1 samechain timeout/cancel to irrevocably armed obligation or claim missing hostile/excess capability closed. |
| Failed proof/transfer | Reconcile failure và retry unchanged financial right; samechain valid historical proof không cần refresh chỉ vì root-window churn. Native source proof renewal có prerequisites riêng. | Revert không consumed right; invalid/fork proof không trở thành valid vì retain roots. Recipient vĩnh viễn reject/issuer freeze vẫn liveness limit, không silent redirect. |
| Terminal / restart / new version | Kiểm actual final transfer/spent tags; restore/reconcile durable state và migration consent. | Cache/backup rollback không resurrect rights; new deployment không reset old obligation hoặc tự retire verifier. |

Matrix là design acceptance. Không operation nào trong matrix được claim đã chạy tiền thật chỉ từ ví dụ hoặc throwaway model.

## 8. Verification trước claim autonomous/trustless-class

Each selected route must exercise its actual implementation; state diagrams/source/VM negatives do not self-certify. V1 requires genuine authorized **public-testnet** asset and cold-recovery results plus adverse-path evidence; local Anvil/CPU/simulation is no substitute. Items labeled V2 below preserve later obligations, not V1 closure criteria.

1. Disable authorized company bootstrap/UI/API/indexer/prover/relay/signers for the drill. Start clean owner nodes using cached artifacts, alternate/direct peers and independent chain access, without hidden company hostname/login/bootstrap secret.
2. Restore encrypted bundle vào clean user-controlled process, scan complete commitments/ciphertexts, recompute authenticated roots/state; fresh tree witness và unknown outcome reconcile.
3. Exact user withdraw/cancel và approved settlement; relayer substitution không sửa recipient/asset/terms/fees, duplicate/replay atomically rejected.
4. Onchain fill/cancel race, **hai outstanding packets F1/F2 khác fees/relayers cùng backing generation → cancel → reject cả hai**, partial→successor/cancel/replay, malicious missing/wrong output ciphertext; **fully authorize → một owner offline → unrelated root turnover/tree rollover → bên kia submit exact packet** dưới retained root, vẫn current unspent/expiry checks; full tree/reorg/finality, transfer failure/reentrancy/OOG.
   **V2 confirmed standing-order drill retained, not V1 gate:** maker opens/backs/signs exactly once → goes offline → unrelated tree appends/rollover → multiple independent takers create/settle **new** eligible partial fills without maker proof/signature renewal → maker returns and independently recovers all proceeds/exact remainder → cancels remainder; outstanding packets reject. Quantity/net price/fees, wrong/missing maker recovery output and races reject atomically. Current V1 dual-consent source does not satisfy this V2 requirement.
5. **Native source drill (L-ZEC, active):** U offline/S action and S offline/U payout; conflict/mixed/earlier/same-effect/excess/arbitrary hostile-spend terminal capability. Never emulate an unavailable witness with caller owner labels; samechain success does not close native S1–S7.
6. **X.CROSSCHAIN drill (active):** for each selected pair, run a company-off cold restore after the first lock, at reveal, and after a missed deadline. Claim or refund each leg on its own lane, and observe the actual assets. A refund and a late claim must be mutually exclusive on each authority.
7. Mutable registry/admin/factory removal does not retire funded rules. A new version needs a new namespace and migration consent. Issuer freeze and validator/history outage are classified as dependencies, not silent refunds.
8. Measured local proving resources, artifact availability and recovery data limits. Permanently unavailable artifacts or private openings block enablement; an author-signed checklist is no substitute.

Current evidence includes native process/CPU semantics, mathematical/codec differential vectors, fail-closed actual authority VM/offline-script paths and scoped independent financial source review reporting no actionable findings, **not full audit or funded release drills**. Samechain control source exists, but genuine positive certificate/real admitted spend/valid-first-invalid-second rollback/receiver failure/cold restore/company-off remain NOT RUN pending independent pins/resources. Original native source financial validator/armed escrow/full manual lifecycle remain missing. Strict GD2, native hostile-T/excess, issuer/prover/lifetime/action holds and PostgreSQL verification NOT RUN pending private URI remain; no SQL/network/mainnet/funds or whole-goal closure.

**Scope/evidence/permission boundary:** V1 acceptance additionally maps company-bootstrap-off P2P discovery/coordination/replacement to P2.27/P5.07–P5.09 and complete cold recovery to P4.01–P4.18. [Micro-plan](V1-MICRO-IMPLEMENTATION-PLAN.md) expands 122 tasks, not authorization or readiness. SQL pending approved private URI/no-local-SQL, genuine wrapping/resource qualification, production-secret recovery approval, public-gossip/privacy review and testnet selection/action holds remain. No implementation/deployment/signing/broadcast/funds/migration/mainnet/push authorization follows from this documentation consolidation.
