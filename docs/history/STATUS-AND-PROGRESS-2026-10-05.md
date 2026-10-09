# Z2Z — status và progress report, 2026-10-05

## 1. Kết luận trước

**Chưa có giao dịch end-to-end để người dùng thực hiện trong app và nhận tài sản thật.** Native code, cryptographic relations, target authority và client tools đã tiến, nhưng chưa ghép thành funded user journey. Không dùng số test hoặc source review để che điều đó. Full project, private matching, native Zcash financial construction và company-off recovery chưa complete.

User yêu cầu status/progress ngay và lưu brainstorm; [context mới](BRAINSTORM-2026-10-05-ORDERBOOK-AND-ONCHAIN-RIGHTS.md) đã được lưu vào repo, không chỉ session memory. [Frontend handoff](PRODUCT-OVERVIEW-AND-FRONTEND-HANDOFF.md) có71 stories. User owns sibling frontend; agent owns native/backend/secure transport/qualification. Discussion mở rộng orderbook/rights không đổi thành implementation perps/tokenization hoặc thêm support giả.

## 2. Status theo hành vi người dùng

| Workstream | Đã có / đã chạy | Còn thiếu để đạt yêu cầu |
|---|---|---|
| Consolidation | Native protocol/zcash/proofs/chains/runtime và migrated market/custody/Solana source thuộc base Ziquid; một CLI; PostgreSQL-only cutover | Complete merged SQL/network/financial lifecycle chưa verified; old source/stores/artifacts bảo toàn |
| Frontend | Existing sibling landing; current generated route tree chỉ `/`; product handoff71stories | Trading routes, wallet/native integration, asset/rights queries/mutations, actual outcome/recovery UI chưa có. Chưa có link app giao dịch usable |
| Own P2P market | Exact known-fill terms/consent, backing-generation/successor/cancel rules, native bilateral semantics | Owner confirmed maker ký một lần lúc mở order, nhiều takers fill khi maker offline; current fresh-per-fill maker consent chưa đáp ứng. Standing authority/recoverable-output construction, admission/private matching/full backed settlement còn thiếu; strict GD2 không waived |
| Samechain asset authority | Actual immutable EVM authority/codecs/tree: create/fill/cancelOrExit/withdraw, real SP1 verifier, actual codec/negative VM checks | No genuine wrapped certificate admitted-positive deposit/fill/withdraw; receiver-failure retry/cold restore/company-off lifecycle NOT RUN |
| Samechain owner crypto/proof host | Real signatures/AEAD, four-mode host framing/native preflight, actual CPU owner guest, compiled ELF/program-pinned Groth16 producer và SHA-only verifier | Independent program/setup qualification, sufficient owner-controlled proving capacity, actual successful wrapping/target acceptance chưa có |
| Public native client | Exact unsigned ABI calls, actual pinned trusted-node inspection, fresh identity→same-block eth_call simulation; actual standalone CLI exercised | Signing/submission/finality/reconcile/scanner/portfolio/manual driver chưa complete. Simulation không actual financial execution |
| Owner proof CLI | Permanent `execute-owner` consumes user canonical witness/full deployment/ELF pin;10 subprocess checks and10 actual CLI CPU cases exercised, complete journals matched with empty diagnostics | `prove-owner` isolated SDK worker implementation still pending; genuine wrapped certificate/program/setup/backed acceptance chưa qualified. CPU output không chứng minh financial execution |
| Runnable backend/server + owner-local software | Existing reusable Rust native/runtime/CLI primitives; product boundary now explicit | Final product must run as software/server consumed by frontend, not CLI-only. Public backend/API may handle permitted public/non-sensitive order data and user-authorized public payloads, submit unchanged transactions and reconcile outcomes; wallet/local companion keeps keys/witnesses and signs/proves. No HTTP listener, public API, owner-local transport or app-to-runtime lifecycle/restart/outcome integration is implemented; server-only signing and private-witness hosting are not selected |
| Native ZEC outbound | Real local P/Q authoring/preparation/recovery/source/era relations; finite era-aware validating ledger source | Connected authentic Ironwood/history/witness qualification, composed financial proof, hostile-T independent terminal classifier/recovery, actual S-authorized excess return và armed escrow/client còn thiếu |
| Solana↔Zcash custody | Migrated safety/core and actual local SBF/ELF synthetic SPL effects/rollback | Native custody source signer/network/private-market/SQL combined lifecycle chưa qualified; no unilateral ZEC exit inherited |
| Hyperliquid | Real testnet info reads, exact offline spot order/cancel proposals | Actual signer/send/nonce/capital/fee/reconciliation chưa có. Hyperliquid P2P assets chưa qualified; positions/perps chưa tokenized/selected |
| PostgreSQL | Active SQLx PostgreSQL schemas/journals; SQL targets compile | Runtime migrations/concurrency/restart/accounting tests NOT RUN pending authorized nonlocal URI/schema scope; không local SQL |
| Manual owner recovery | Local private custody, owner consent/output recovery và some client steps | Full authenticated scan/restore/prove/submit/retry với company off chưa exercised end-to-end |
| Expansion | Saved orderbook/rights/storage/LayerZero brainstorm; possible phased path | New instrument/controller/valuation/redemption/demand design chưa selected. Không bổ sung universal wrapper/chain/ledger |

## 3. Progress thực trong các wave gần nhất

### Wave A — product/frontend handoff

- Đối chiếu canonical product/runtime/sibling frontend.
- Viết71 unique user stories across8 families và proposed screen/state/error contract.
- Independent review bổ sung bidirectional Solana↔Zcash, direct Raydium swaps, early-Q export risk, independent U/S offline actions và explicit frontend ownership.
- Current report/readiness không claim app ready; local doc file links đã kiểm.

### Wave B — RPC trust-boundary repair

- Review tìm remote-HTTP query-host bypass và positional JSON struct acceptance.
- Regression failed-before, sửa leading actual scheme/parsed literal loopback identity và raw map-only decoding retaining duplicate/presence checks.
-19HTTP +10CLI passed; scoped rereview no new finding. SQL-off permanent workspace checkpoint943 checks/71 suites.
- Một bare workspace attempt fail do thiếu documented real Solana harness environment; chạy đúng actual harness/ELF/fixture paths mới qua. Không ignore test hoặc giả target.

### Wave C — actual pinned public simulation

- Actual simulate API và native simulate-call implemented; independent declared pins, fresh inspection rồi exact from/to/U256/value/data/gas cùng hash; không overrides/latest fallback/sign/send.
-35 chains checks (builders8, inspection19, simulation8),61 CLI checks/6 suites passed.
- Standalone creation/fill/numeric-rejected withdrawal mỗi case11 actual loopback HTTP requests; private stdin giữ mở, credential/private sentinel không lộ.
- Permanent workspace964/73, Clippy1.03s, EVM47/7 passed. Scoped source reviews không finding actionable.
- Node-reported void only, deliberate invalid proof/public synthetic node runtime; **không certificate/backing/asset arrival**.

### Wave D — permanent owner proof host

- OwnerInput actual4mode borrow/nativepreflight/guarded frame + realCPU execute_owner + actual pinned SDK CPU/Groth16 producer và SHA-only certificate verifier.
- Native3 and feature5 checks passed; local producer feature compiled. Pin/context/header/scalar negatives reject trước heavy setup.
- Actual CPU11positive journeys matched full journals, gồm FillA/B, Cancel/Exit, recovered withdrawal/change/full và4creationforms. Fresh correctly consented amount inflation bypass native preflight → actual guest exit1/empty journal.
- Design review tìm scalar canonicality mismatch: lower native Fr decoder reduces modR còn Solidity rejects >=R. Explicit program/nonce<R checks added before release.
- Source review không production defect; found malformed-length regression masked by invalid header. Corrected header-preserving truncation/append; rereview no issue.
- Final permanent SQL-off workspace967/74 passed; default Clippy5.95s và sp1-local all-target Clippy37.25s passed. Corrected feature5 + Clippy0.80s passed afterward. Upstream proc-macro-error2 future-Rust-compatibility warning remains disclosed.
- CPU smoke caller removed. **No valid-pin heavy setup/Groth16 owner wrap or genuine pairing positive was run.**

Các checkpoint không cộng lại thành progress percentage hoặc số test mới. Latest permanent default SQL-off workspace967/76 passed2390 after direct-output suppression and permanent execution CLI; default release all-target Clippy7.49s và runtime sp1-execute all-target Clippy29.49s passed. Default tests do not run feature-gated owner CLI; its10 subprocess rejection checks2385 và10 actual standalone CPU CLI journeys2387 are separate evidence. EVM latest fresh offline bg68 passed47 checks across7 suites, including one actual Rust-call ABI decoder; this remains VM/math/negative evidence, not genuine certificate/standing-maker/server acceptance. Upstream proc-macro-error2 future-Rust warning remains. SP1 source review additionally confirms POSIX shared-memory sinks outside TMPDIR; producer storage privacy is not erasure-complete after abnormal worker death.

Evidence owning docs: [native status](../NATIVE-IMPLEMENTATION-STATUS.md), [destination contract](../modules/destination-settlement.md), [SQL hold](../SQL-VERIFICATION.md). Session outputs:2350 simulation checkpoint;2359 actual ownerCPU/feature negatives;2363 permanent workspace/lints;2366 corrected feature regression/lint;2375 failed-before private guest diagnostics;2381 shared sink checks/lint;2385 execution CLI negatives;2387 actual execution CLI CPU smoke;2390 final permanent default workspace and default/execute-feature lints. These IDs are session-local evidence pointers, not durable publication URLs; report preserves their actual result/scope.

## 4. Vì sao chậm và lâu?

### Phần do cách thực thi — trách nhiệm của assistant

1. **Đi quá sâu vào primitives trước khi đóng user journey.** Có nhiều helpers/relations/checks chạy được, nhưng chưa có một owner accountable cho frontend→native→proof→execution→receipt/remainder→recovery hoàn chỉnh.
2. **Mục todo quá lớn, trong khi slice quá nhỏ.** Cùng một mục “complete samechain” chứa nhiều bước chưa đạt; nhiều wave pass không khiến user thấy sản phẩm dùng được. Cần báo stage/observable acceptance, không cứ nói “đang tiến”.
3. **Review/check/rebuild lặp nhiều.** Một số phát hiện bảo mật thật cần sửa; nhưng không phải mọi lượt đọc/review/build đều là phần phức tạp bắt buộc. Có regression test chưa isolate, missing command match arm và thiếu documented test environment; đó là rework tránh được.
4. **Chưa đưa blocker quan trọng lên đầu đủ sớm.** Genuine wrapping/resources/program/setup là prerequisite thực của funded path. Tiếp tục phát triển helper mà không báo điểm này khiến lượng code tăng nhưng khoảng cách tới trade success không rõ.
5. **Chuyển ngữ cảnh engineering/product nhiều lần mà tracking chưa tốt.** Đây không phải lỗi của user hỏi về sản phẩm; agent phải giữ plan/evidence gọn và trả report ngay, thay vì kéo dài cuộc điều tra chỉ để giải thích.

### Phần thực sự khó hoặc thiếu prerequisite

- Current owner Groth16 chưa thành công; trước đây **sender** proving trial bị OOM ở4GiB, không phải một benchmark samechain. Existing16GB loaded host không qualified cho full wrap.64GiB chỉ conservative UNMEASURED guidance, không tested minimum/success guarantee. Không launch thêm heavy trial hoặc remote private prover để giả vượt gate.
- Program/setup/source→ELF mapping và target genuine positive chưa qualified. Existing setup byte hashes matching TOFU không ceremony proof.
- Strict privacy/GD2 và native all-hostile concealed facts/source excess return có construction gaps, không đơn thuần thêm endpoint là xong.
- SQL runtime checks chưa được phép; deployment/sign/send/fund cũng cần action-specific authorization. Những holds này không cản mọi coding, nhưng cản verified end-to-end completion.

**Không có ETA đáng tin cho toàn bộ project hiện nay.** Hứa thêm một ngày hoặc completion percentage sẽ không dựa trên evidence. Tài nguyên mạnh hơn cũng không tự giải privacy/custody/witness gaps.

## 5. Thứ tự giao hàng và cách báo tiến độ từ đây

**Ưu tiên user giữ nguyên: current real usable journey trước, expansion sau, full production vẫn tiếp tục.** Không ra một landing/clickable screen rồi gọi financial demo xong.

| Stage tiếp theo | Acceptance phải quan sát được | Trạng thái / dependency |
|---|---|---|
| Owner-native permanent proof/CPU commands | User canonical witness+independent scope/ELF pin → exact public journal or actual final certificate; errors redacted; no private leak | Code slice tiếp theo, test-source/design now; library/CPU already real. Not whole trading delivery |
| Genuine certificate qualification | Independent program/setup/resource profile → actual owner wrapped proof → actual SHA target acceptance/mutations | Resources/program/setup still prerequisite; không fake/verifier bypass |
| Actual target lifecycle | Real deposit/admitted rights → bilateral partial fill → actual proceeds withdrawal → residual cancel/exit | Requires genuine cert and exact action authorization. Known counterparties not private matching solution |
| Backend/manual integration | Recovery kit/state scan/pending intent/outcome/restart, exact rights; actual native API consumable by frontend | Missing implementation/qualification; owner secrets remain local |
| User-owned frontend integration | Actual network/wallet/operation screens wired to actual native/backend; truthful balances/Unknown/remainders | User frontend, engineering native/backend contracts; no takeover sibling UI |
| Usable product checkpoint | User completes advertised trade, assets arrive and rights reconstruct after refresh/restart | NOT ACHIEVED; no public trading URL yet |
| Own market + retained native work | Admission/discovery/privacy/full native proof/recovery/venue/SQL/company-off acceptance | Full project obligation intact, construction/permissions not waived |
| Broader assets/vault/position rights | Exact control/backing/liabilities/redeem/recovery + real demand | Later design/activation, not current unapproved feature expansion |

Report sau mỗi meaningful user-path acceptance hoặc blocker mới, với: **đã chạy gì → kết quả gì → còn thiếu gì → next action rõ**. Không dùng helper count/tests count làm thước đo sản phẩm. Nếu stage bị external prerequisite chặn, finish reachable integration và nói chính xác requirement thay vì vòng lặp primitive vô hạn.

## 6. Cần từ owner khi thật sự tới gate

- Nonlocal PostgreSQL test URI qua secure config + isolated schema permission; không paste credentials vào chat.
- Sufficient owner-controlled proving resources và independently qualified program/setup; chưa tự thuê/chuyển private witness.
- Exact network/deployment/signing/funding/submission approval với signer/fee payer/recipients/assets/amounts/fees/simulation trước action.
- Frontend phối hợp theo existing design và71-story handoff; chọn active qualified route khi prerequisites đủ.

Đây là danh sách prerequisites, không yêu cầu cung cấp secret hoặc quyền chung ngay. Toàn bộ code/docs/tests reachably independent vẫn thực hiện trong quyền hiện hành. Không marks full samechain/task/project complete.

### Latest source finding before native proof CLI implementation

**Historical pre-fix finding:** independent design review identified a guest diagnostic privacy gap: direct pinned SP1 executor forwarded guest stdout/stderr to host stderr, bypassing returned-error redaction. At that checkpoint the new CLI was test-source/design-only. The subsequent correction below and actual CLI checkpoint above supersede that execution status; they do not establish safe asynchronous proving.

**Subsequent correction:** a genuine regression guest printed a synthetic input sentinel on both descriptors/cycle-tracker lines and panic; both tests failed before the shared executor fix (2375). Scoped live-receiver TLS sinks now suppress both diagnostic streams while preserving exact successful journal and actual panic exit1/empty journal; sp1-execute6 and sp1-local8 checks plus feature Clippy5.17s passed2381, scoped source review no finding. Profiling-disabled feature graph was observed. This protects direct synchronous execution only; installed SDK asynchronous proving has no propagated sink and still requires isolated worker design before permanent proving CLI exposure. No genuine wrapping/financial acceptance is implied.

**Isolated proving continuation:** scoped design review found two additional concrete SDK worker hazards: `Child::try_wait` reaps the leader before group cleanup, and real Gnark wrapping writes a private `NamedTempFile` witness. Reviewed design uses nonreaping waitid observation then owned-group termination/reap, explicit owner-selected trusted0700 private scratch with per-run child TMPDIR, and categorical failure/deadline handling. Parent crash/power loss can retain private scratch; upstream allocations, swap/core/storage erasure are not guaranteed. Source implementation and process checks remain pending; no heavy valid proof/setup run or new financial permission follows. Venue work is no longer blocked merely by the already-delivered product report; its actual signer/capital/fee/reconciliation prerequisites remain open.
