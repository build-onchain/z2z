# Kerb Zolana — nghiên cứu blocker giao thức và custody

**Truy xuất mọi nguồn ngoài: 2026-09-30.** Read-only investigation, không phải approved design/security certification. Không sửa project files; không build/test/lint/formatter, chạy node, RPC mainnet, ký/gửi hay funding. Chỉ viết artifact này. **P** = nguồn gốc định nghĩa/ship/tuyên bố; **P-report** = contributor báo thực nghiệm, không chúng tôi tái lập; **[INFERENCE]** = đề xuất; **U** = chứng cứ thiếu. Source publication/status dưới đây; rolling docs không visible publication date được ghi “rolling”.

**Current-authority banner 2026-10-01:** retained Sep30 source investigation; path aliases/file:line citations below refer to the then-read snapshots, not current locations/line numbers. [Kerb current authority](../docs/00-CANONICAL.md#0-current-documentation-authority) adopts shared Zoss source/context/domain/Solana libraries inside Kerb-controlled processes **docs only**, without new mandatory viewer/key/private-cache/witness daemon or messages/watchers/receipt/quorum. Kerb still owns funding-owner/canonical/inventory/dedup, FAA/MPC/journals/FROST/payout/refund/recovery; optional messages OFF/non-money. Oct1 financial/private candidate remains unapproved and **GD2 structural FAIL**, no runtime/privacy/custody pass. Original source evidence below is not rewritten or re-certified.

Repo prefix **S**=`/home/harry-riddle/dev/github.com/kerb/zolana-review-2026-09-29`; **D**=`/home/harry-riddle/dev/github.com/kerb/docs`. File:line ranges exact. D0/R1a/R1b/R2/R3 theo `S/product/16-ROADMAP-AND-DECISIONS.md:19–26`.

Short file references in remaining text are exact aliases: `S/04`=`S/architecture/04-ONCHAIN-PROGRAM-DESIGN.md`; `S/05`=`S/architecture/05-TOKEN-2022-ISSUER-INTEGRATION.md`; `S/06`=`S/architecture/06-OFFCHAIN-SERVICES.md`; `S/07`=`S/security/07-THREAT-MODEL.md`; `S/08`=`S/security/08-TEST-AND-VERIFICATION-PLAN.md`; `S/16`=`S/product/16-ROADMAP-AND-DECISIONS.md`. They are citation abbreviations, not guessed filesystem names.

## 1. Kết luận

- **Ironwood không phải “unavailable vì Draft”.** Stable node/native libraries đã ship và first-party report nói activated. Blocker là exact Kerb stack chưa pin/operational proof, không owner vote một upgrade future.
- **FROST native Ironwood signing có merged support**, nhưng tool vẫn demo và dùng experimental key constructor explicitly incompatible with quantum recovery/future wallet conformance. R2/R3 cần maintained conformant derivation+recovery review, không production claim từ testnet report.
- **IVK receipt ≠ unspent ≠ claimant ownership ≠ spendability.** Cần separate FVK/nullifier/wallet inventory, witnesses, keys/quorum, durable reservations; change backing old liabilities không tạo buyer credit mới.
- **No leg order makes atomicity.** ZEC-first: buyer risks SPL failure; SPL-first: seller risks ZEC nonpayment. Timeout không reclaim mined note. Chọn thứ tự chỉ cùng loss/reserves/caps.
- **Refund theo encumbrance/entitlement**, không cutoff hay original-note-unspent. Accepted epoch giữ SPL trước Fill; unused ZEC portions remain owed after partial payout/change.
- **Issuer freeze/pause/delegate không bị PDA/attestation vô hiệu hóa.** USDC issuer address có; xStock chưa qualified. Same-chain atomic RFQ/Jito không chứng minh Ironwood swap.
- **Owner không vote-away** privacy/funded binding, complete accepted-set, effect-checking signer, concurrent spend/refund serialization, solvency, exact token conditions, actual control-domain independence, chain observations, recovery and explicit transaction permission (`S/04:78`; `S/06:73`; `S/08:69`; `S/16:23–26,95–101`).

## 2. Ironwood / NU6.3 — primary evidence

| Source / date,status | Passage và giới hạn |
|---|---|
| [ZIP258](https://zips.z.cash/zip-0258), Created2026-06-19, **Draft** | Branch`0x37A5165B`; testnet4,134,000/mainnet3,428,143; post-activation no new Orchard value, cross-address disabled. “Expected only Zebra” proposal wording, không runtime inventory. |
| [Zebra6.0.0](https://github.com/ZcashFoundation/zebra/releases/tag/v6.0.0), published2026-07-10, stable | Ships mainnet height3,428,143; testnet4,134,000 “active since v6.0.0-rc.0”; released NU6.3 crates. Not Kerb node sync proof. |
| [Zodl activation](https://zodl.com/ironwood-is-live-on-zcash/), published2026-07-28 | Explicit activated mainnet at3,428,143; Zodl3.8.0 migration, same receiver. **P operator/wallet report**, no worker consensus-node observation. |
| [Zebra6.4.2](https://github.com/ZcashFoundation/zebra/releases/tag/v6.4.2), published2026-09-25, latest fetched | Patches malformed-v6 remote DoS. [Advisory](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-h5rr-8pqv-grp9), published2026-09-25: affected6.4.0/6.4.1, patched6.4.2; earlier releases unaffected by **this issue**, not every risk. |
| [Zebra6.4.0](https://github.com/ZcashFoundation/zebra/releases/tag/v6.4.0), published2026-09-23, withdrawn binaries/images | Explicit do not run6.4.0/6.4.1. Experimental direct lightwallet gRPC; sidecar rollback99→1000; end-of-support early Nov2026; NU7 **tentative**, not activated. |
| [ZF Zebra/Zakura](https://zfnd.org/zebra-zakura-and-the-road-through-nu6-3/), published2026-07-16 | Both migration paths; recommends Zebra alongside for independent check. Draft ZIP “only Zebra” cannot establish current absence; forks not automatically independent implementation. |
| [Ironwood concepts](https://zcash.github.io/ironwood/concepts.html), rolling | Shared Orchard **protocol/receiver/keys**, distinct **pool tree/nullifier/value balance**; v6 can contain both bundles. Address alone cannot identify pool. |
| [librustzcash#2539](https://github.com/zcash/librustzcash/pull/2539), merged2026-07-08 | Scanning, poolcode4, separate note-encryption domain, received notes/nullifiers/tree/balance. Historical body “send/change not implemented” not current-state proof. |
| [backend0.24.0](https://docs.rs/crate/zcash_client_backend/0.24.0), published2026-08-19; [PCZT0.9.3](https://docs.rs/crate/pczt/0.9.3), published2026-08-07 | Stable APIs: [WalletRead](https://docs.rs/zcash_client_backend/0.24.0/zcash_client_backend/data_api/trait.WalletRead.html)`get_ironwood_nullifiers`; [Signer](https://docs.rs/pczt/0.9.3/pczt/roles/signer/struct.Signer.html)`sign_ironwood/apply_ironwood_signature`; [low-level](https://docs.rs/pczt/0.9.3/pczt/roles/low_level_signer/struct.Signer.html)`sign_ironwood_with`. API≠Kerb custody exercised. |
| [ZIP229](https://zips.z.cash/zip-0229), Created2026-06-13,Draft; [ZIP326](https://zips.z.cash/zip-0326), Created2026-06-30,Draft | v6 sighash includes Ironwood; correct external/internal and`use_qsk` scan, strict testnet/mainnet key segregation. Receiver protocol-scoped not pool-scoped. |
| [librustzcash README](https://github.com/zcash/librustzcash), rolling | Only consensus node checks consensus validity; parsing insufficient meaningful user-level constraints. PCZT apply-signature≠consensus validation. |

**[INFERENCE] Recommend** native Ironwood target unchanged, D0 non-settling. R1a pin binary/lockfile/features, network/branch/pool, receiver derivation/birthday, treestate, health/deprecation and independent observers. Patched maintained Zebra6.4.2 is candidate not certification. **R1b/R2/R3 stop** pending exact operational evidence. **U:** no Kerb synced tip/hash, note/witness, quorum transcript, recipient decryption or restart/reorg trace.

### Alternative nếu exact native Ironwood stack chưa established

| Option | Giữ pair owner? | Trade-off / đề nghị [INFERENCE] |
|---|---|---|
| A — giữ Ironwood, D0/R1a non-settling đến native proof | **Có** | **Recommend hiện tại**. Native APIs/report đã có; investigate exact integration, không wrapper hay false credit. |
| B — auxiliary native **Sapling testnet** scanner/PCZT/spend comparator | Không nếu thay settlement; được làm experiment riêng sau scope/transaction approval | ZIP229 v6 giữ Sapling; PCZT có`sign_sapling/sign_sapling_with`, ZIP312 RedJubjub. Có ích inventory/change/coordinator comparator, nhưng không Ironwood tree/version/sighash/derivation proof. Sapling không ZIP2005 recovery. Không gọi “R1 Ironwood”. |
| C — transparent HTLC [ZIP300](https://zips.z.cash/zip-0300), Created2017-03-08, Proposed/Informational | **Không** | Source explicit transparent/Bitcoin-derived scripting, chưa Solana SPL mechanism. Đổi privacy/settlement product, không ready atomic Kerb. |
| D — wrapped ZEC/SPL receipt/bridge balance | **Không** | Asset/redemption/trust model khác; không silent substitute. |

Nếu deadline không chờ gate: honest **non-settling demonstrator**, giữ pair làm research target. Không alternative cho claim “native Ironwood settlement tested” khi chưa quan sát nó.

## 3. FROST — support và experimental key boundary

- **P [ZIP312](https://zips.z.cash/zip-0312), Draft, Created`2022-08-dd` như source.** Rerandomized spend-auth compatible Sapling/Orchard. Coordinator **và mỗi share holder** trusted with payment privacy; network privacy/key generation ngoài scope. Signers MUST check/recompute sighash từ transaction/effect data; exact effect-sharing format ngoài scope. Không note covenant/forced refund.
- **P [#591](https://github.com/ZcashFoundation/frost-tools/issues/591), opened2026-07-15, now Closed; [#592](https://github.com/ZcashFoundation/frost-tools/pull/592), [#593](https://github.com/ZcashFoundation/frost-tools/pull/593), merged2026-08-12.** Native v6 sighash và both-bundle signing. #593 contributor báo end-to-end 2-of-3 testnet tx`c5a1c4a11706d2c0083390c9220e2729aba024045030d24854ed38eca7d7410e` at4,246,513, multi-input tx`23ec9a37dc58e0317f10a51be9b0254766c5ef59cc812f3c140a1c1165fc7740` at4,246,606. **P-report**, không Kerb result. Contributor không tạo được real migration để test Orchard-spend-in-v6 trực tiếp; only version-dispatch local pass có thể sai sighash khi broadcast.
- **P [pinned generate.rs](https://raw.githubusercontent.com/ZcashFoundation/frost-tools/06c0dbdbb1bac9b99cd255e74ba2f387c295e660/zcash-sign/src/generate.rs), commit06c0dbd merged2026-08-12:** explicit “Quantum recoverability is deferred”, dùng`from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed`.
- **P [orchard#475/files](https://github.com/zcash/orchard/pull/475/files), PR created2025-12-12, still Draft; constructorrev42015f1:** “ONLY FOR EXPERIMENTAL USE”, “DOES NOT SUPPORT QUANTUM RECOVERABILITY”; future mandatory conformance/future wallets may reject, possibly funds inaccessible. Wording cũ về hash chưa chosen không override ZIP2005 hiện hành, nhưng explicit constructor incompatibility vẫn là caveat.
- **P [ZIP2005 §Usage with FROST](https://zips.z.cash/zip-2005#usagewithfrost), Created2025-03-31, Proposed:** DKG group`ak`; privately agreed`sk`, use`use_qsk=true` deriving`nk/qsk/qk/rivk_ext`; retain`qsk` securely/reliably. Recovery protocol future/incomplete, không backup thoát custody hiện tại. Recoverable note format≠custom demo-key recovery conformance.
- **P [pinned Cargo.lock](https://raw.githubusercontent.com/ZcashFoundation/frost-tools/06c0dbdbb1bac9b99cd255e74ba2f387c295e660/Cargo.lock):** resolves **frost-rerandomized2.1.0 stable**, PCZT0.8.0-rc.1/backend0.24.0-rc.1, orchard0.15.5 forkrev42015f1. Manifest RC lower-bound constraint không chứng minh actual FROST resolution RC. Stable native library mới≠demo old pin qualified.
- **P [frost-tools README](https://github.com/ZcashFoundation/frost-tools), rolling:** demos “should not be used in production”. [ZF FROST Book](https://frost.zfnd.org/), rolling: generic crates stable, NCC v0.6.0 audit **không rerandomized FROST**. Không audit inheritance cho whole native custody/interface.
- **P [RFC9591](https://www.rfc-editor.org/rfc/rfc9591),2024-06, Informational/IRTF, §§7.3,7.7:** fresh uniform nonce; reuse may key-recovery; validate permitted transaction content, không signing oracle. [FROST server](https://frost.zfnd.org/zcash/server.html), rolling: authenticated end-to-end encrypted messages/TLS; session authentication≠trade authorization.

**[INFERENCE] Recommend:** native maintained source starting point cho isolated capped R1 candidate, không tự viết cryptography hay opaque-hash signer. Nếu experimental constructor được nghiên cứu: disclose, testnet-only ephemeral material, no carryover to production. R1 needs full effects/network/recipient/amount/change/fee/expiry/sighash checks, crash-safe nonce lifecycle, independent recipient observation, restart accounting. **R2/R3 stop** until maintained conformant derivation/recovery independently reviewed. Owner accepting custody cannot make incompatible constructor conformant.

### Threshold / roster choices — không invent independent operators

Unselected repo: `S/architecture/06-OFFCHAIN-SERVICES.md:16,19,41–45,67,73`; `S/security/07-THREAT-MODEL.md:38,98,103`; `S/product/16-ROADMAP-AND-DECISIONS.md:11,51–53,97`.

| Option | Actual trade-off | Conditional recommendation [INFERENCE] |
|---|---|---|
| 2-of-3 real custody domains | Theft requires2;1 unavailable tolerated;2 lost/offline strands. Any2 collusion can steal all funds. | **Bounded R1 candidate only**, if3 actual willing independently controlled operators exist, effect-check/journal proven. No roster→unfunded. |
| 3-of-5 real domains | Theft requires3, can tolerate2 unavailable; more operations/log/privacy/supply-chain surface. | Consider real assets only after roster/availability/collusion economics evidence; not “more signers=certified safer”. |
| n-of-n | Every signer can veto; one loss/outage blocks. Lower collusion combinations, severe liveness. | Useful unfunded consent/abort comparator, not default production. |
| Multiple shares under one controller | Machines/keys may differ but common admin/cloud/backups can reach threshold. | Does **not** prove independence; disclose as one domain; cannot satisfy claimed distributed governance. |
| Separate spend vs Solana attestation roster | Separate keys/scopes isolate ciphersuites/powers; distinct actual operators may add truth-check and liveness boundary. Same operators less operational overhead but correlate trust. | Keep **keys/domain separated**; choose human overlap only after access/collusion review. FROST RedPallas sig is not Solana Ed25519 authorization. No external roster has been verified. |

For k-of-n: forgery/theft threshold k, honest availability at least k, liveness tolerates n−k unavailable. This arithmetic is not probability/security certification. **Quorum intersection≠durable two-ledger serialization:** with2-of3, maliciousB can sign payout withA and refund withC; FROST does not remember business reservations. Signer journals/common state, immutable effect approvals, replay/domain checks and honest-intersection/ordering assumptions require proof; raising k alone is no fix. Signer refresh/backup cannot undo leaked secrets or final transactions. Need named public operator roster, legal/admin/hosting/log access graph, DKG/dealer choice, share restore/rotation/nonces, service and loss terms; missing→**R1b/R2/R3 blocked**.

## 4. IVK / FVK / nullifier / inventory / change

**P:** [ZIP316](https://zips.z.cash/zip-0316), Created2021-04-07, Rev0Active/Rev1Withdrawn/Rev2Draft, separates incoming/full viewing. Maintained orchard0.15.5 [IVK](https://docs.rs/orchard/0.15.5/orchard/keys/struct.IncomingViewingKey.html) explicitly cannot spend **or detect spent**, unsuitable alone for accurate wallet balance. [FVK](https://docs.rs/orchard/0.15.5/orchard/keys/struct.FullViewingKey.html) gives incoming/outgoing view and nullifier capability; [Note](https://docs.rs/orchard/0.15.5/orchard/note/struct.Note.html)`nullifier(fvk)` derives nullifier. [OVK](https://docs.rs/orchard/0.15.5/orchard/keys/struct.OutgoingViewingKey.html) alone cannot maintain balance. [Builder](https://docs.rs/orchard/0.15.5/orchard/builder/struct.Builder.html) permits optional OVK and wallet-controlled change. Versioned API documentation, not observed wallet operation.

**[INFERENCE]:** IVK receipt cannot prove claimant ownership. FVK canonical nullifier tracking does not sign, certify usable quorum/witnesses, or prove liability completeness. Outgoing recipient evidence needs committed effects/openings, deliberate sender-recoverable OVK policy or recipient decryption; do not assume any constructor preserves audit view. Test external deposits **and internal change**, correct pool/keys/birthday.

| Option | Trade-off | Recommendation [INFERENCE] |
|---|---|---|
| IVK-only scanner ledger | Least outgoing visibility; cannot see spent or internal change with only external scope. | **Insufficient funded path**; positive receipt only. |
| Separate inbound IVK scanner + independent custody FVK/wallet inventory | Scanner less privileged; extra synchronization/access boundary. | **Recommend candidate** matching `S/06:13,25–27`; shared controlled-value checks before credit/admission and spend. No matcher access to either mapping. |
| One FVK-backed scanner/custody observer | Fewer sync seams; sees more payment history and concentrated false-credit control. | Explicit trust alternative, only separate from matchers and with independent reconciliation; process labels not independence proof. |
| Two independently governed FVK observers | Can cross-check spent/change/chain; duplicates privileged view and operating cost. | Conditional for real assets where governance/privacy/cost justify; no independent operators assumed. |

Repo: `S/architecture/06-OFFCHAIN-SERVICES.md:13,25–27,49–56`; `S/security/08-TEST-AND-VERIFICATION-PLAN.md:39,44` (T05/T09). **U blocking R1b:** atomic reservation versus concurrent spends, canonical nullifier inventory, witnesses and quorum-ready funds, restore/reorg journal, correct claimant binding, fee policy and audit-access independence. Change never issues new buyer credit. Per-pair receiver separation should be actual key/inventory authorization boundary: different diversified addresses under one FVK/spend root still share control, so address namespace alone does not prove pair isolation.

## 5. Scanner / reorg / finality policy

**P conflict:** old [Zebra RFC State Updates](https://zebra.zfnd.org/dev/rfcs/0005-state-updates.html), start2020-08-14, says100-block reorg/finalized state. Current [zebra-chain13.0.0 source](https://docs.rs/crate/zebra-chain/13.0.0/source/src/parameters/constants.rs) says`MAX_BLOCK_REORG_HEIGHT=1000`, **“local-only node policy; not part of consensus”**; current Zebra6.4 release sidecar aligns1000. Do not select100 or1000 customer confirmation count from these. [ZIP200](https://zips.z.cash/zip-0200), Created2018-01-08,Final, describes upgrade/reorg branch validation, not service-specific risk assurance.

**P:** [Solana commitment docs](https://solana.com/docs/rpc), rolling: processed rollbackable, confirmed supermajority vote, finalized maximum-lockout strongest state. [getAccountInfo](https://solana.com/docs/rpc/http/getaccountinfo), rolling, carries context.slot/base64 bytes/owner; default cannot replace explicit consistent commitment. **P [ZIP203](https://zips.z.cash/zip-0203), Created2018-01-09,Final:** nExpiryHeight governs unmined inclusion, UI must not rely zero-confirmation. Neither chain's Sent/Authorized is Final.

| Scanner option | Trade-off | Recommendation [INFERENCE] |
|---|---|---|
| Single hosted compact-block/RPC source | Operationally easiest, relies on provider correctness/currentness; same endpoint accounts not independent. | D0 fixtures only / disclosed research source; not independent inventory/finality evidence. |
| Self-validated maintained node + separate observer/source | Validation and disagreement detection; extra sync/ops cost, common cloud/admin still possible. | **R1 candidate**: source hashes/height/branch/pool, stale-tip checks, explicit disagreement pause. |
| Independently governed validator implementations | Greater differential checking; duplicated complexity and correlated-code ancestry remain. | Consider after genuine providers available; not named partners presumed or proof from two process names. |

**Recommend no arbitrary depth.** Owner selects risk objective/worst accepted loss/latency, reviewers derive deposit and payout policies separately against actual network/work/censorship, software rollback/witness retention and experiments. Record count convention, canonical hashes/cursor/checkpoints, rewind/rescan horizon, source agreement/staleness, replay/idempotent credit, mempool/expiry and persistent pending-spend treatment. On reorg invalidate/quarantine—not recreate credit. A post-first-leg reorg leaves Disputed/exposure, never pretend opposite leg reversible. Solana strongest finalized observation for irreversible-leg research candidate, but no certification or guaranteed wait bound. Need empirical measurements and offline fork/restart traces `S/08:45,48,50,63,69`; none observed. Blocks **R1b/R2/R3**, not D0.

## 6. Exact Solana assets / issuer powers

**P sources, retrieval2026-09-30:**

- [Circle official addresses](https://developers.circle.com/stablecoins/usdc-contract-addresses), rolling: canonical Solana mainnet`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`; devnet`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`, expressly no financial value/no USD backing. Address list not on-chain account-owner/freeze proof. [USDC Terms](https://www.circle.com/legal/usdc-terms), LastUpdated2025-12-12, §§8,9,13: copies/wrappers not supported; chain/blocklisting risks; third parties **can support USDC without Circle authorization**, support not endorsement/legal approval. Avoid blanket “every USDC integration must have Circle agreement”; counsel determines exact service scope and contractual requirements.
- Solana rolling first-party docs: [Freeze](https://solana.com/docs/tokens/basics/freeze-account) blocks receiving/transferring/burning until issuer thaws; [Pausable](https://solana.com/docs/tokens/extensions/pausable) mint-wide transfer/mint/burn rejection; [PermanentDelegate](https://solana.com/docs/tokens/extensions/permanent-delegate) can transfer/burn any account, holder cannot revoke; [TransferHook](https://solana.com/docs/tokens/extensions/transfer-hook), metadata date2023-02-01, custom CPI every transfer; [DefaultAccountState source](https://github.com/solana-program/token-2022/blob/program%40v10.0.0/interface/src/extension/default_account_state/mod.rs) default account state initialization. These are feature semantics, **not** evidence every xStock has them.
- [Scaled UI docs](https://solana.com/docs/tokens/extensions/scaled-ui-amount), rolling: raw balance unchanged, configurable current/next multiplier/effective timestamp, immediate/scheduled updates, UI conversions floating-point/non-round-tripping. [Issuer corporate actions](https://docs.xstocks.fi/docs/dividends-and-stock-splits.md), rolling: Solana raw constant, multiplier; advises pause around00:30UTC after ex-date. [Issuer Solana xChange guide](https://docs.xstocks.fi/developers/xchange-solana-market-maker-guide.md), rolling: raw transfers, registered maker wallet/ATAs, multiplier pause advice, finalized before settled, **uncled-block rebroadcast caveat**. These windows are issuer recommendations for its flow, not measured sufficient Kerb two-chain horizon.
- Issuer public API documentation [Get Asset](https://docs.xstocks.fi/apis/openapi/assets/get_public_assets_by_symbol.md), v2.0.0, rolling; primary GET snapshot [TSLAx](https://api.backed.fi/api/v2/public/assets/TSLAx) lists ISIN`CH1436219252`, Solana mint`XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB`; [SPYx](https://api.backed.fi/api/v2/public/assets/SPYx) ISIN`CH1436219716`, Solana mint`XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W`. **Examples for research, not owner selection/qualification**. Response lists USDC decimals6/`solanaTokenProgram:TokenProgram`; xStock mint's own owner/extensions not established from that field. `supportsAtomicSwaps:true` refers issuer service, does **not** say Ironwood cross-chain atomic or matcher-private.

**Repo gate:** `S/architecture/05-TOKEN-2022-ISSUER-INTEGRATION.md:13–19,25–37,41–51`; no live mint qualified; no exact account bytes or transfer exercise reported. `S/04:72–74` dynamic spendability checks; `S/08:49` T14; `S/16:25–26` distinct real-asset phases.

| Choice | Trade-off | Recommendation [INFERENCE] |
|---|---|---|
| Synthetic legacy SPL research mint | Minimal extension surface; chosen authority/freeze can be disclosed, issuer failures emulated. | First candidate **R1 only**, after explicit setup/funding authorization; does not qualify USDC/xStocks. |
| Canonical USDC/ZEC next | Less corporate-action complexity; real issuer freeze/blocklist/redemption and legal gates. | **R2 after R1 evidence**, exact address owner/state/decimals/authorities/source/return/buyer accounts read and transfer-path qualified. No switch to devnet or wrapper as equivalence. |
| One exact xStock/ZEC | Extra denomination, eligibility/corporate-action/authority and liquidity constraints. | **R3 later**, mint selected only with evidence/owner decision; read raw TLV bytes/authorities and terms, actual account transfer/thaw route. No ticker whitelist. |
| Refuse freeze entirely | Simplifies custody reversibility assumptions but may exclude selected real instruments. | Owner can choose risk appetite; cannot say existing mint changes powers. Current staged first proposal conditionally allows freeze, refuses hook/delegate/fee extensions. Exceptions require explicit spec/review, not silent “qualified”. |

**U:** no RPC mainnet queried, no exact live USDC owner/freeze account or xStock extensions/authority snapshot, no issuer consent/counsel/safe transfer results. Chain-state read would be non-transaction evidence but was not performed; any future on-chain tests need authorization. Policy simulation/account fingerprint cannot stop issuer exercising already-existing authority. **R2/R3 blocked**; no protected outcome guaranteed even after preflight.

## 7. Settlement order, loss allocation, reserves và caps

Repo unresolved: `S/architecture/04-ONCHAIN-PROGRAM-DESIGN.md:48–68`; `S/06:41–45,58–67`; `S/security/07-THREAT-MODEL.md:90,98–100`; `S/08:45–50,57–63`; `S/product/16-ROADMAP-AND-DECISIONS.md:69–74,97–98`. Signed authorization proves keys, not payout effect; receiver/decryption/canonical spend evidence stays private. No Solana light-client/effect verifier exists in Kerb.

| Option | First-leg loss window | Conditional recommendation [INFERENCE] |
|---|---|---|
| **SPL-first**, then observed ZEC payout | Seller SPL gone if custody withholds/diverts/reorgs payout. Buyer avoids paying before failed SPL transfer. | **R1 synthetic baseline candidate** if custody holds confirmed reserved credit, verifies final SPL transfer, has accepted seller-loss rule and bounded exposure. Avoids honest ZEC-first paying then issuer freeze. Not safe production/atomic. |
| **ZEC-first**, then SPL release | Buyer ZEC paid seller, SPL may freeze/fail/refund. | Only where buyer expressly accepts and compensation/liquidity source demonstrably covers; preflight cannot eliminate subsequent issuer freeze. Not default real-assets recommendation. |
| Custodian advances own prefunded inventory / guarantees shortfall | Can shift economic loss from users to provider, but adds capital/credit/insolvency risk and privileged views. | Meaningful real-asset option only after independently verified capital, enforceable terms, scope limits. **Not atomicity**, no provider/insurance assumed. |
| Parallel broadcast | Reduces nominal latency but both uncertain/in-flight, harder disputes/cancel. | Do not use first research baseline; no atomicity benefit. |
| Native cryptographic atomic/effect-proof design | Different mechanism, absent implementation and proof. | Research separately if required; cannot label custody-attestation ordering atomic. |

**Recommendation now:** choose policy hypotheses and loss bearer, not authorize money. Rehearse **both leg orders** offline with freeze/withholding/wrong destination/reorg/expiry; after evidence and independent review decide production leg order. Owner cannot promise third-party operator compensates without operator/capital/contract evidence. If reserves/consent missing, stay D0/R1a.

### Encumbrance, partial fills và reserves

**Required accounting [INFERENCE, not implementation]:**

1. **SPL encumbrance begins at accepted executable set**, not first Fill. `refund_unreserved_spl` only never accepted, final unfilled portion, or atomically irrevocably invalidated epoch before payout. Stale epoch/replay rejects. Cutoff/expiry alone not eligible. `S/04:42–43,50–68`; T06b `S/08:41`.
2. CreditC splits disjoint final seller payouts + final buyer refunds + final explicitly-approved fees + outstanding seller entitlement + outstanding unused-buyer entitlement. Pending broadcast remains outstanding/reserved, not free/final. Original note spent→change inventory backs obligations; paid filled portion does not bar unused refund. `S/06:25–27`; T09 `S/08:44`.
3. Private credit/order-use nullifier or nonce **distinct from Zcash chain note nullifier**: accounting entitlement≠note. Chain nullifier prevents duplicate note spend; business ledger prevents duplicate claims across notes/change/fills/epochs. Need both.
4. Consistent canonical inventory snapshot must cover **all outstanding per-pair ZEC liabilities + disclosed fee obligations**; account input reservations/change/in-flight once. Never original input+pending change double counting. SPL vault spendable raw balance covers exact outstanding release/refund. Frozen tokens/broken witnesses/unavailable quorum≠liquid reserves. No cross-pair subsidy/unspecified netting. Unclaimed deposits/surplus quarantine.
5. **1:1 liability backing≠loss capital.** Non-atomic exposure/reorg/threshold theft/issuer freeze need distinct identified risk capital. Reserve under same corrupt quorum may be stolen together. Confirmations cannot cure theft/freeze/offline keys; no external capital/provider/insurance assumed.
6. **Fees/dust:** D0 credits24+10→25seller+9unused zero-fee, not viable funded amounts. [ZIP317](https://zips.z.cash/zip-0317), Created2022-08-15/Updated2026-06-26, Rev0Active/NU6.3Rev1Draft, formula5,000zats/action; Zebra6.4 release says implemented standardfee1,000/action; [ZIPPR1352](https://github.com/zcash/zips/pull/1352), created2026-08-17, still Open, proposes reduction without consensus upgrade. Conflict→**pin actual wallet/node fee policy**, not guarantee either fee/mining. User-paid vs operator-funded fees explicit respecting max/fee cap; no consuming unused claims silently.

| Reserve/cap option | Trade-off / recommendation [INFERENCE] |
|---|---|
| Exactly backed liabilities/no compensation | Accounting minimum, users still bear disclosed custody/non-atomic loss; cannot market protected execution. |
| Liabilities + segregated first-loss capital | Better economic protection only if actually spendable/accessible under incident, legally owed, independently controlled from failed authority. No evidence now. |
| Credit/insurance promise | Enforceability/exclusions/provider solvency/timing dependencies, **U**; do not say insured. |
| Per-fill cap only | Does not bound cumulative pair/epoch/custody/in-flight liability. Also bound total/concurrency/incident exposure. |

**Research hypotheses, not production parameters:** D0≤8 synthetic orders for bounded logic/leakage, not throughput;2-of3 if real roster; first explicitly authorized R1b could use **one concurrent fill** for inspectable traces. Actual zatoshi/raw-SPL budget remains U until fee/dust, tolerable test loss and transaction approval. **No arbitrary $cap/depth/safe threshold chosen.** Real-asset exposure caps derived from independently available loss reserve in liable asset, conservative inventory and incident capacity; cannot eliminate issuer/colluding-quorum tail risk. All-user custody exposure matters even with one active fill.

Need consistent liability audit; restart/rescan reservations; partial payout+unused refund after note→change; pending cancel/rebroadcast/expiry; equivocation; compromised reserve/freeze; restoration without double credit/payout; actually observed recipient effects. `S/06:49–67`; `S/08:39–50,57–63,69`; **blocks R1b/R2/R3**.

## 8. Contradictions — revision work, không owner waiver

| Location / conflict | Correct disposition |
|---|---|
| ZIP258Draft vs shipped Zebra/July28 activation | State exact status **và** implementation/operator chronology; neither future-only nor Kerb verified. |
| ZIP258 expected-only-Zebra vs ZF July16 Zebra/Zakura | Draft expectation not market absence; inspect actual node/source independence. |
| FROST#591 old open blocker vs Closed/#593mergedAug12 | Update evidence pointer to #593+commit/lockfile and retain demo/key/recovery caveats; do not repeat “nobody working” as current. `S/06:43`, `S/07:38`, `S/16:50–53,112` need richer current evidence. |
| ZIP312 reference implementation “reddsa” vs current reddsa README defers support to FROST repo | Pin concrete compatible ciphersuite/version, not follow stale pointer or generic audit; docs references differ. |
| ZIP2005 Proposed key recovery requirements vs demo constructor incompatible | Explicit R1 experimental / R2-R3 conformant-maintained review gate. Recovery future≠present user exit. Cannot solve by renaming constructor. |
| Old Zebra2020 RFC100/finality vs current source1000 local policy | Explain dated implementation conflict. No100/1000 confirmation default or guarantee. |
| Published ZIP3175,000 vs current Zebra implemented1,000 and still-open fee ZIP | Versioned fees/relay/solver actual behavior; no fixed fee claim before pin/measure. |
| **Old proposed spec** `D/docs/superpowers/specs/2026-09-29-kerb-zolana-design.md:70` “expired unexecuted SPL escrow can refund”; :111 credits from inbound checks; :113 “verified custody note” refund | Ambiguous relative to strengthened staged `S/04:42,68`, `S/06:25–27`. Explicit accepted-epoch encumbrance, separate spendable inventory/FVK check, disjoint unused refund backed by controlled inventory/change. Owner should review revised spec; not waiver or destructive old-doc cutover. |
| Staged system03 historical stale refund sentence | Fresh read `S/architecture/03-SYSTEM-ARCHITECTURE.md:88` now explicitly accepted-epoch encumbrance and inventory/change-backed disjoint unused refunds. **Do not report as still open.** Parent revised it; worker made no project edit. |
| xStock family “freely transferable” vs actual issuer/extensions/account conditions | Qualification per exact mint/runtime, not presume all have freeze or all permissionless. `supportsAtomicSwaps` on issuer API≠cross-chain Ironwood atomic. |

## 9. What choose now vs hard prerequisites

| Domain | Choose now / conditional recommendation [INFERENCE] | Cannot vote away / proof still U | Phase blocked |
|---|---|---|---|
| Native Zcash target | Keep Ironwood; D0/R1a; Sapling comparator separate explicit scope | Pinned maintained node/libraries/receiver derivation; consensus-valid spend and actual inventory/change | R1b+ |
| Spend keys/recovery | Research native external signing, reviewed DKG/dealer plan | Actual constructor compatibility, key-share/nonces restore, no hidden full-key bypass; future recovery conformant retained material | R1b exact test config; especially R2/R3 maintained support |
| Threshold/roster | 2-of3 bounded R1 hypothesis only when3 real domains; assess3-of5 later | Named independently controlled operators, keys/admin/log access, availability/loss terms; no invented partners | R1b+ |
| Viewing/scanning | Separate IVK + custody FVK/inventory candidate | Spent/change/witness/quorum-ready evidence, claimant-bound credit and race-free reserve | R1b+ |
| Finality | Explicit source-agreement/staleness/reorg pause; strongest Solana observation candidate | Derive deposit/payout depths from actual risk/work/latency; measured reorg/restart; no arbitrary safe number | R1b+ |
| Release order | SPL-first synthetic baseline vs ZEC-first/advance inventory, both faults | Durable effect/nonce/state, observed recipients, liable loss bearer and reserves; no atomic/unilateral refunds | R1b+ |
| Refund/accounting | Accepted-epoch encumbrance + per-portion disjoint entitlement | Implement irreversible invalidation, serial concurrent claims, note/change conservation, fee/dust policy | R1b+ |
| Assets | Synthetic first; USDC next; one exact xStock last | Exact chain bytes/program/authorities/account states/transfer paths and independent legal/eligibility evidence | R2/R3; synthetic path R1b |
| Caps/compensation | D0≤8 fixtures, R1 single-fill/2of3 hypotheses | Actual amount/fees/capital/custody exposure and incident ability; no claimed insurance/provider guarantee | R1b+ |
| Protocol privacy & output | Preserve no-single-matcher content **and accepted-order identity** | Actual unlinkable funding/admission/control graph, accepted-set availability, rules/inclusion/correct output; sibling privacy report covers mechanism | All funded matching, including synthetic |
| Authorization | Review choices/spec only | Explicit later cluster/signers/fee payer/recipient/assets/amount/fees/simulation then signing approval; no implicit funding | Any on-chain setup/transfer/deployment |

**Hard technical tasks, not user opinion:** implement complete exact ledger/escrow/state/wallet flow, replay/expiry/roster-version checks, scanner credit and spendable inventory, crash-safe nonce and journal serialization, actual circuit/input-set/rules proof, chain observations, live token CPI behavior, and observer-specific privacy attack evidence. `S/04:3,13,25,31,46,78`; `S/06:19,25,33,41,73`; `S/07:96–103`; `S/08:13–15,69`; `S/16:23–26`. Repo is documentation-only; sources reduce uncertainty but cannot supply runtime proof. No arithmetic/mock/docs approval clears gates.

## 10. Unavailable proof / research limits

- GitHub unauthenticated API returned403; fetched primary repository/PR/release HTML and raw source instead. No auth/secret requested.
- ZcashExplorer linked testnet tx returned403. Alternate CipherScan showed public page metadata/block4,246,513 but dynamic body loading; **not primary signer-quorum verification**, no raw consensus/receipt rerun. Contributor PR is labeled P-report; public signature alone cannot disclose which shares signed, who controlled them, or shielded recipient effect.
- FROST releases feed had no useful entries; no maintained binary-release warranty inferred. Source commit/lockfile captured; only partial library audit scope stated, no exact Kerb audit exists.
- No exact on-chain USDC/xStock state fetched; issuer API examples are canonical-deployment **vendor records**, not chain-byte/control/eligibility qualification. No statement all xStocks default-frozen or permanent-delegated.
- No live operator willingness, independent roster, reserves, insurance, quorum recovery, scanner/access graph, effect inspector, wallet construction or recipient/payment trace established. No build/test/node/transaction evidence manufactured.
- Primary source statuses and native APIs checked manually; this report's evidence **does not certify soundness/security/atomicity/privacy or release readiness**. Documentation/source-conflict fixes belong a reviewable spec revision, not silent scope reduction.
