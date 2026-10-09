# Z2Z product overview and frontend handoff

> **Archived — 2026-10-05:** complete dated 71-story/frontend handoff retained as historical integration detail. Current product authority is [PRODUCT](../PRODUCT.md); V1 follows the [V1 prompt](../Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md) with P2P CLI trading, online bilateral consent and full company-off recovery. GUI/standing-maker stories are retained later-production scope, not current V1 instructions or readiness evidence.

Current-state report, 2026-10-04. This is an implementation/first-user-delivery report, not final production completion or deployment authorization. The product must expose real successful user journeys; no presentation-only product mode, invented balances, canned trades, fake proofs or artificial success states.

## 1. Product definition and first delivery gate

Z2Z is a DEX with its own P2P order market: users choose an exact asset, quantity and limit; discover a counterparty; approve exact trade terms; settle through a qualified route; and control their remaining rights. RFQ is another way to find a price/counterparty inside this DEX. Samechain and crosschain are settlement constructions, not separate competing matching products. External HyperCore spot is an explicit separate venue choice, never an automatic fallback. Zoss provides shared infrastructure and optional non-money messages, not settlement authority.

First delivery must be usable by a person, not just presentable: frontend input → actual backend/native operation → exact owner authorization → actual execution → independently checked result → correct portfolio/remaining rights after refresh. A trade is successful only when the advertised asset actually arrives. Creating a note claim is not an external wallet transfer; if the flow promises wallet delivery, it must include actual withdrawal. Prepared calldata, signatures, CPU journals, simulation, server acknowledgements and transaction inclusion alone do not prove completed settlement.

Production continues after the first usable journey. No native financial, privacy, recovery, SQL, security or deferred activation requirement is silently removed. The latest priority activates frontend integration for that journey rather than waiting for every protocol workstream to finish.

## 2. What exists, and why users cannot trade yet

| Layer | Current actual implementation | Missing user-facing acceptance |
|---|---|---|
| Web | `../z2z-protocol`: React19/TanStack Start/Router/Query, Vite8, Tailwind4, Nitro; implemented landing with theme/menu/FAQ/art | Generated route tree has only `/`; no trading app, wallet connection, financial queries/mutations or native bridge |
| Protocol | Canonical deployment/assets/orders/fees/packets/journals; exact allocation; partial-successor and shared-generation rules | Rules/shape/hashes do not create owned or backed rights |
| Owner cryptography | Native samechain creation/Fill/Cancel/Exit/ordinary withdrawal, strict consent, real AEAD recovery; shared CPU guest executes | Complete owner journey/key lifecycle, independently qualified wrapped certificates and funded positives |
| EVM | Real immutable `SamechainAuthority`, strict Rust-compatible codec/tree, internally constructed actual SP1 verifier, four mutators | No qualified genuine-certificate deposit/fill/withdraw lifecycle, financial failure/retry or actual network deployment |
| Owner proof host | Permanent borrowed four-mode framing/signed preflight, real CPU execution and compiled independently ELF/program-pinned local Groth16 producer/SHA-only verifier | No successfully wrapped owner certificate or qualified program/setup/funded target acceptance; insufficient local proving resources remain explicit |
| Native client | Four unsigned ABI builders; block-pinned trusted-node inspection and actual bounded hash-pinned void-call simulation; private review/check CLI | No signing/send/receipt/finality/scanner/portfolio/cold-restore orchestration or web transport; simulation is not financial success |
| Zcash | Real local P/Q authoring/proof/signatures/redaction/recovery, source validation components and finite era-aware ledger | Connected qualified Ironwood history/owner witnesses, composed financial proofs, independently terminal hostile-spend classification and actual source excess return |
| Persistence | PostgreSQL-only scoped inventory/market journals and encrypted owner-local preparation custody | PostgreSQL lifecycle/concurrency/restart tests NOT RUN; no authorized nonlocal URI/scope supplied |
| External venue | Actual HyperCore testnet information reads and exact unsigned spot order/cancel proposals | Venue signer/submission/nonce/capital fences, enforceable fee policy and complete reconciliation |
| SDK | `packages/sdk/src/index.ts` exports nothing | No usable browser SDK/FFI/WASM or local-companion integration |
| Zoss | Actual `zoss-zcash::NodeRpc` reuse for supported-era raw acquisition; separately maintained | Does not supply DEX proofs, custody, entitlement, payouts/refunds or an EVM messaging route |

Observed verification is not product readiness. The corrected endpoint and map-only RPC decoders passed 19 actual HTTP regressions and 10 native inspection CLI checks after independently demonstrated failures; scoped rereview found no remaining issue in those fixes. Final all-target release Clippy passed in 0.83s and EVM 47 tests/7 suites passed. The initial bare post-fix workspace attempt failed because the required real Solana harness environment was absent; rerunning with the existing documented harness/ELF/native-fixture paths passed **943 checks across 71 suites** (artifact 2329), SQL features disabled. This is the completed inspection checkpoint, before the subsequent simulation feature. None of these counts establishes successful trading, independent chain finality, complete audit or SQL verification.

Subsequent simulation checkpoint: exact public API/CLI and standalone loopback acquisition were exercised, then permanent SQL-off workspace **964 checks/73 suites**, Clippy1.03s and EVM47/7 suites passed (artifact2350); scoped source reviews found no actionable issue. These are runtime/transport checks with explicitly synthetic public node responses and invalid-pairing frames, never successful trading evidence. The actual financial first-user gate remains unmet.

Why the schedule did not produce a usable app: engineering prioritized breadth of consensus/cryptographic primitives and repeated finite checks, while the first user vertical slice had no single acceptance gate. The frontend remained a landing; no browser-to-owner-native bridge, usable certificate pipeline, funded execution or result reconstruction was finished. The corrected priority is a real complete user journey, not more isolated primitives presented as product completion.

## 3. Recommended first real trading journey

Recommended construction: one separately qualified samechain deployment, its native/fixed vanilla-token pair, two known owners, one exact partial bilateral fill, actual proceeds withdrawal, and cancellation/withdrawal of the remaining order. This reuses real existing owner relations and authority, not a new exchange backend.

This is exact known-counterparty settlement inside the P2P product, not solved strict-private discovery/matching. Full P2P discovery/privacy remains required and blocked; no privacy waiver is implied. Native shielded ZEC crosschain and external venues retain separate workstreams.

Acceptance:
1. User connects an actual wallet; chooses the explicitly identified network/asset/deployment; app reads real scoped state.
2. Owner creates and restores local recovery material, reviews exact deposit and generates a genuine target-verifiable creation certificate.
3. Owner authorizes allowance/value/gas and actual submission. Target receives actual asset units, admits the note and publishes complete recoverable data. App reconciles the exact receipt and state.
4. Maker reviews and signs exact standing order limits/recovery policy once after eligible backing; maker goes offline. Multiple independent takers review/authorize their own exact fill and construct qualifying proofs/recoverable maker receipts and successors without maker input secrets or new maker signatures.
5. Actual target enforces opening maker policy plus exact taker authorization and atomically applies each eligible full/partial fill. App shows every settled fill as successful and remaining order open. Distinguish received note rights from external wallet assets; demonstrate actual withdrawal when wallet delivery is advertised. Current two-fresh-consent known-fill code alone does not satisfy this acceptance.
6. Partial remainder remains spendable with exact capacity. Owner cancels/exits it; all old packets for that generation and replay attempts reject.
7. Refresh/restart reconstructs actual outcomes. Failed execution leaves rights retryable. An ambiguous send stays unresolved rather than manufacturing failure or releasing funds.
8. User independently restores and exercises an existing right without company APIs/signers; artifacts/data/compute/gas remain explicit dependencies.

Until those steps run successfully through the application, the first trading delivery gate is NOT achieved. Read-only data integration is useful interim work, but does not satisfy this trading gate.

## 4. Actors and frontend information architecture

Actors: trader/order owner; counterparty; RFQ requester; solver/liquidity maker; external-venue account owner; recovery owner; separately authorized relayer; legacy custody/operator roles. A relayer carries an authorized payload, never gets permission to rewrite recipients/fees. Operators are not ordinary user wallet signers.

Use the existing frontend design, not a generic bridge dashboard:

| Proposed route | User purpose | Primary panels |
|---|---|---|
| `/` | Understand product and availability | Existing landing, honest route scope |
| `/app/p2p` | Own market orders/proposals | Own orders, asset/quantity/limit form, counterparty proposals, remaining quantity |
| `/app/rfq` | Request/compare DEX quotes | Exact request, solver offers, net receipt/fees, quote/recovery conditions |
| `/app/assets` | Actual wallet assets and protocol rights | Domain-specific balances, ordinary notes, order backing, reserved/unknown capital; never universal crosschain balance |
| `/app/activity` | Track actual actions | Owner-local activity, stage/source evidence, pending/unknown/final outcomes |
| `/app/activity/:localId` | Inspect a specific right/action | Exact immutable terms, authorized bytes, transaction/effects, remaining rights, safe next action |
| `/app/recovery` | Restore and exercise owned rights | Local recovery kit, authenticated state sync, permitted cancel/withdraw/claim/retry |
| `/app/external/hypercore` | Explicit public external venue | Account/market/order/cancel/fills, original request and coverage caveats |
| `/app/settings` | Exact environment/security choices | Wallet/companion, selected node policy, artifact/profile versions, backup status and permissions |
| Maker/operator workspace | Quote and capital management | Exact quote validation, inventory reservations, funding/unknown operations; separate from user wallet |

These are frontend route recommendations consistent with current design; only `/` currently exists. Deferred LP/provider/agent/ZSA/NEAR lanes should not become live navigation merely because their stories are listed below.

## 5. Complete user-story catalogue

Status: **Primitive** = real supporting native code/checks, not end-to-end app; **Missing** = product flow not implemented; **Blocked** = construction/qualification unresolved; **Deferred** = retained lane not activated. Each story needs normal, loading, empty, rejected, unavailable and recovery states where applicable.

| ID | Actor and story | Flow / frontend acceptance | Current boundary |
|---|---|---|---|
| A01 | Trader: understand what I can trade before connecting | Show exact network/asset/route availability and dependencies; unavailable is not zero liquidity | Landing exists; live route qualification missing |
| A02 | Trader: connect my own wallet without handing over secrets | Wallet account/network shown; reject wrong chain; no seed/FVK upload | Wallet integration missing |
| A03 | Owner: connect local private preparation/proving tools | Explicit local companion consent, version/profile and progress; no hosted witness upload | Companion transport/orchestration missing |
| A04 | Trader: choose exact assets and raw units | Chain/address or token ID/decimals/domain, not ticker alone; exact decimal input/rounding rejection | Typed primitives; web adapter missing |
| A05 | Owner: inspect deployment/program/issuer assumptions | Show runtime/program/token/source policy and whether independently qualified | Trusted-node inspector exists; qualification and UI missing |
| A06 | Owner: back up and restore recovery material before funding | Local encrypted kit and actual clean-process restore; cannot skip required restore | Preparation custody exists; full samechain kit/restore missing |
| B01 | Trader: see actual available, committed and unresolved capital | Separate wallet assets, ordinary note rights, order capacity and uncertain sends; no aggregate spendable fiction | Portfolio scanner/account integration missing |
| B02 | Owner: deposit native asset into a recoverable right | Exact amount/value/recipient/program review; genuine certificate and reconciled admission | Native creation/authority/builders; funded positive blocked |
| B03 | Owner: deposit the selected eligible token | Explicit bounded allowance, exact receipt units and token caveats | Target delta enforcement; wallet/qualified positive missing |
| B04 | Owner: create an initial order together with backing | Generation1, exact ID/policy/quantity/fee limits and encrypted recovery | Native initial-order predicate; real admission missing |
| B05 | Owner: receive proceeds or ordinary change | Decrypt/recompute actual output, authenticate admission, preserve ordinary-note identity | Native AEAD/relation; scanner/funded flow missing |
| B06 | Owner: withdraw part and keep recoverable change | Exact Exit/Fee/change sum, recipient review, actual wallet asset arrival | Native withdrawal/authority; genuine funded execution missing |
| B07 | Owner: withdraw an entire ordinary note | No fake order/capacity; consume once, actual transfer and history | Same qualification gap |
| B08 | Owner/recipient: use a route-permitted internal successor or transfer | Exact recipient-prepared recoverable outputs conserve actual backing; authenticate new notes before spendable display; not a generic payment/bridge API | Output predicates exist; general customer transfer contract and funded lifecycle not qualified |
| C01 | Trader: draft a buy/sell limit order | Exact asset pair/quantity/limit/fee cap/partial policy; unfunded draft discard | Policy primitives; customer order API missing |
| C02 | Trader: submit a backed order to my DEX market | Admission actually checks exclusive rights and authority; receipt not merely server ACK | Admission/discovery/API missing; strict GD2 blocked |
| C03 | Trader: find a counterparty without fabricated liquidity | Genuine eligible proposals; distinguish no counterparty from service unavailable | Matching construction/API blocked |
| C04 | Maker: inspect and sign standing order terms once | Exact assets/deployment/quantity/net-price/fee beneficiaries and recovery policy; no per-fill maker approvals | Current preconsent review is exact-fill only; standing construction missing |
| C05 | Taker: authorize an exact fill against the standing order | Taker terms/recovery review; maker opening authorization enforced without maker online | Current native relation requires both fresh consents; standing successor/proof construction missing |
| C06 | Trader: settle a full fill and see actual receipt | Standing maker authority plus exact taker authority and atomic effects; external delivery distinct from note receipt | Existing authority source is dual-consent; standing and genuine positive execution unqualified |
| C07 | Trader: settle a partial fill and keep exact remainder | Each settled fill successful; disjoint conserved remainder stays open under original maker limits | Current successor rules exist; offline standing fills and admitted lifecycle missing |
| C08 | Maker: leave remaining order available while offline | Other takers fill without new maker signature; authenticate recoverable receipts/remainder on return; capacity never resets | Standing authorization/input/output construction and funded scanner/prover flow missing |
| C09 | Owner: cancel all outstanding proposals for one generation | Cancel consumes shared backing N, not one digest; race shows actual winner | Native/target rules; genuine race acceptance missing |
| C10 | Owner: exit remaining backing after cancel | Ordinary returned right or exact authorized external effect; no reversal of completed fills | Funded recovery/withdrawal missing |
| C11 | Taker: create and submit an eligible new fill while maker offline | Enforce one opening authorization, live residual backing and recoverable maker outputs; no fresh maker consent | New standing construction missing; current old fully-authorized-packet offline submission is a narrower separate capability |
| C12 | Trader: update terms without changing funded rules silently | Unfunded draft edit; funded change only through supported cancel/new authorization | No customer update mechanism selected; avoid invented mutable order API |
| C13 | Relayer: carry an authorized payload unchanged | No recipient/fee rewrite/owner secrets; actual receipt reconciliation | Call builders; send/outcome driver missing |
| D01 | Trader: request a DEX RFQ for exact asset/quantity | Selected route/receiver/net terms and expiry; quotes are not guaranteed liquidity | Quote backend missing |
| D02 | Trader: compare genuine solver quotes | Net receive/all fees/dependencies, never invented best-price claim | Quote authentication/funding missing |
| D03 | Solver: inspect P/Q and exact quote before funding | Real Q crypto/capsule correspondence and recovery/lifetime; no user FVK/spend key | Native primitives exist; qualified certificate/funding missing |
| D04 | Solver: reserve owned capital without double use | Exact scoped inventory; Prepared/Unknown/Armed remain fenced | PostgreSQL source; SQL runtime NOT RUN |
| D05 | Solver: irrevocably fund exact destination obligation | Actual funds/beneficiaries/context/note reservation verified atomically | Native armed financial escrow missing |
| D06 | Trader: authorize ZEC only after authentic arming | Inspect real target/finality and retain independent payout witness before P release | Full wallet/arming/source execution missing |
| D07 | Trader: receive full or proportional payout from actual source result | Full accepted history/net predicate; actual U/S transfers, fixed dust | Financial composition/classifier/escrow blocked |
| D08 | Owner: recover after replacement/conflicting source spend | T!=P is insufficient; qualified nonpaying conflict, independent witnesses | All-hostile terminal construction blocked |
| D09 | Trader/solver: handle excess source payment correctly | Actual S-authorized source excess return, never clamp/gift/full-refund substitute | Source return capability missing |
| D10 | Owner: handle expired/unusable Q or unavailable evidence honestly | Prepared lifetime and specific recovery predicate; Pending not terminal | Full independently terminal recovery unresolved |
| D11 | U: prepare and export complete Q without exporting executable P or keys | Locally prove/sign exact same-real-input Q; verify every nonzero output is U-owned and retain independent payout witness; export review discloses S can broadcast Q early, even before prefunding, causing cancellation/source-fee/option grief | Real local P/Q crypto and capsule primitives; authentic note/history and qualified certificate pipeline incomplete; no delayed-Q/payment-window promise |
| D12 | U: discard an unfunded preparation without pretending to refund an armed obligation | Before arming, keep P unsigned and cancel only eligible local reservations; already exported Q retains its broadcast capability. After irrevocable arming, closing UI/rejecting P does not cancel or trigger timer refund | Local fences exist; complete wallet/arming flow missing; pre-arm and post-arm controls must be separate |
| D13 | S: broadcast agreed Q and exercise eligible recovery while U is offline | Use only complete exact authorized Q under valid anchor/branch/expiry/fee; independently acquire/prove valid conflict/nonpayment and reconcile actual U source return/S destination refund | No U FVK/spend key/re-sign rescue or automatic reanchor; actual offline-source/funded recovery and all-hostile terminal capability unqualified |
| D14 | U: claim an eligible payout while S is offline or withholding information | Retained independent witness plus accepted valid finalized history enables exact allocation/transfer/retry without new S cooperation; payout eligibility survives quote/source expiry after valid inclusion | Complete financial relation/escrow/witness availability remain blocked; unavailable witness is not recoverable from public proof bytes |
| D15 | U/S: see truthful recovery estimates without granting timer money rights | Show Unmeasured/Estimated/EvidencePending, reason/as-of/provenance, distinct source inclusion/proving/target submission/finality/transfer stages; clocks are not added into a refund deadline | Estimates unmeasured unless actual observations supplied; no countdown implying entitlement |
| E01 | Venue owner: explicitly choose HyperCore spot | External/public venue disclosure and exact account/network/domain | Info/proposal primitives; app execution missing |
| E02 | Venue owner: read actual market/account/orders/fees | Original request/source/as-of; mixed market and incomplete history retained | Actual testnet info reads; web bridge missing |
| E03 | Venue owner: prepare an exact spot limit order | Exact lot/tick/decimal/TIF/cloid/nonce/expiry; fee cap marked unenforced | Real unsigned proposals exist |
| E04 | Venue owner: sign and submit only that action | Actual venue signing scheme/account permissions; no blanket agent/perps rights | Signer/submission/fences missing |
| E05 | Venue owner: track partial/filled/open/unknown outcomes | Correlate account/order/cloid/fills; incomplete fills not complete accounting | Reconciliation missing |
| E06 | Venue owner: cancel residual by OID/cloid | Exact cancellation action; races preserve completed fills; request not cancellation | Proposal exists; executed outcome missing |
| E07 | Venue owner: reconcile after restart or unknown response | Original bytes/nonce/capital fences retained, no competing order retry | Durable venue state missing |
| E08 | Trader: trade eligible Hyperliquid assets in Z2Z P2P | Separate backing/control/asset route; not external spot by another name | Distinct retained lane unqualified |
| E09 | Venue owner: separately withdraw or transfer reconciled external-venue capital | Choose exact domain/asset/recipient/fees; review fresh transfer authorization, then actual source/destination outcome; Core spot fill/CoreWriter enqueue is not EVM/Solana arrival | No selected qualified transfer/bridge or withdrawal implementation; order/agent/builder-fee permissions do not authorize this action |
| F01 | Owner: inspect actual activity and immutable terms | Separate own records, source observations, authorized actions and actual effects | Web/history/receipt scanner missing |
| F02 | Owner: distinguish unavailable from no activity/balance | Missing provider/data never zero/unspent/failed/refunded | Native strict observation primitives; UI integration missing |
| F03 | Owner: reconcile Unknown before retry | Same payload/context and real chain disposition; keep holds until known | Complete outcome driver missing |
| F04 | Owner: see reorg/finality changes | Pending/included/final separately, reorg rolls back derived view not retained rights | Actual finality/scanner missing |
| F05 | Owner: restore on another clean local process/device | Verify encrypted bundle/artifacts/current consumption, not resurrect old backing | Partial custody primitives; full route restore missing |
| F06 | Owner: use an existing right without company services | Own node/tool/prover/gas; same target rules, no new company permission | End-to-end company-off funded workflow missing |
| F07 | Owner: reject changed fee/recipient/asset/program bytes | Review exact authorized digest; changed terms require new consent | Real native/target predicates; app orchestration missing |
| F08 | Owner: choose future version without retiring old rights | Immutable old funded rules/artifacts retained; explicit migration | Product lifetime contract; migration execution not selected |
| G01 | User: submit a funding/settlement proof as evidence | Exact claimant/relation/program/context/backing/dedup verification | Self-service proof intake product API missing |
| G02 | Legacy custody customer: understand custody and settlement rights | SPL escrow vs designated ZEC signers/ACKs disclosed; no unilateral source promise | Local safety core; combined SQL/network route unqualified |
| G03 | Maker/operator: inspect/reconcile liability partitions safely | Available/held/unused/payout/refund/inventory disjoint; privileges not user funds API | Ledger source; authorized SQL tests pending |
| G04 | SPL seller: exchange exact Solana assets for ZEC through a separately qualified retained P2P route | Own eligible SPL backing/admission → exact authorized allocation → actual SPL effect and designated native ZEC custody payout → reconcile partial/residual/recovery; credit or ACK is not ZEC delivery | Retained Solana→Zcash direction; local safety/SPL VM evidence only, SQL/native custody/network/private matching/company-off source capability unqualified |
| G05 | ZEC seller: exchange ZEC for exact Solana assets through a separately qualified retained P2P route | Authentic source funding/claimant/admission and exclusive backing → authorized fill → actual SPL payout; unused ZEC requires actual eligible source disposition and source signer, not SQL refund label | Retained Zcash→Solana direction; one-way native EVM construction does not supply this route or its bidirectional recovery; no unilateral custody-source exit claim |
| H01 | LP owner: enter/manage/exit a qualified public pool | Exact pool/program/range/fees/minimums and real position outcomes | Deferred; not live tab |
| H02 | Provider user: choose a qualified provider route/refund policy | Provider custody/fees/failure/refund distinctions; no unilateral claim | Deferred 1Click/provider lane |
| H03 | Agent owner: grant/revoke enforceable bounded actions | Actual recipient/asset/amount/expiry/domain limits, no broad key called spot-only | Deferred automation; no permission assumption |
| H04 | ZSA user: trade eligible new assets through a qualified route | Exact identity/issuer/proof/consensus and exit control | Deferred |
| H05 | NEAR/other-chain user: select only an actually qualified route | Separate authority/custody/finality and recovery, no empty-slot support | NEAR empty; future routes deferred |
| H06 | Public-pool trader: explicitly choose a qualified Raydium swap | Exact pool/program/mints/token programs/backing/controller and actual-size quote → instruction-specific slippage/fees → owner signing → actual final balances; wrapped SPL ZEC is not native shielded ZEC | Deferred, separate from LP position management/native P/Q/P2P; pool metadata is not executable depth, and issuer/hook/freeze/bridge risks must qualify |
| H07 | Historical liquidity maker: inspect retained own-funded residual ladder role | If separately selected, maker funds its own exact quotes, residual user opts in within limits, immutable eligible entitlements settle with unused return; distinguish maker wallet from custody signer/solver/agent | Historical/unselected mechanism only, not current launch requirement, fee schedule or fabricated fallback liquidity |

## 6. Frontend data and state contracts

Common exact review data: operation/local ID; chain/domain/network; full asset identity and raw amount strings; selected deployment/program/schema; owner/sender/recipient; maximum debit/minimum net receive; every fee asset/payer/beneficiary; expiry meaning/clock; immutable terms and packet digest; proof state; source policy/block; privacy/custody/issuer dependencies; actual transaction/effect evidence; remaining right; safe next action.

Never use JavaScript floating point for money. U256 atom values use decimal strings. Several existing native JSON fields use u64 integers (nonces/counters/timestamps); browser integration needs lossless handling above Number.MAX_SAFE_INTEGER, not blind JSON→Number coercion. Asset ticker/logo is display only. Native byte arrays and hex fields require a versioned adapter preserving exact bytes.

Privacy and support boundaries: no plaintext keys/private P/Q/PCZT/witnesses/quote↔source mapping in URLs, WebStorage, SSR hydration, analytics, diagnostics or automatic support uploads. Owner-local encrypted recovery remains separate from public operation records. Source shielding does not hide destination/address/amount/time/API linkage; external venue/pool effects are public. GD2 own-result noninference remains blocked, even with correct bilateral consent. Minimal financial accessibility: full exact terms accessible at small viewport/200% zoom, keyboard/focus/error labels, no accidental signing/cancel from navigation, and no artwork masking money controls. Existing frontend design §§6, 8, 10 owns these requirements; this report does not replace its visual/interaction contract.

Do not collapse these into a single `success` boolean:

| Stage | Truth that may be displayed | Insufficient evidence |
|---|---|---|
| Draft | Owner entered terms | Order accepted/backed |
| Reviewed | Local semantic preflight accepted exact terms | Signed/proved/traded |
| Authorized | Owner signed exact operation | Network inclusion or asset arrival |
| Certificate ready | Actual qualified proof produced/verified under correct profile | Framed proof bytes/CPU journal |
| Prepared | Exact unsigned call/venue proposal exists | Sent/filled |
| Submitted | Wallet/node accepted transmission; record exact hash/bytes | Finalized/payment |
| Unknown | Actual disposition unavailable | Failed/no effect/unlock/refund |
| Included | Exact transaction/receipt observed under policy | Independent finality/correct asset effects |
| Settled | Qualified final evidence of advertised asset effect | SQL ACK/event name or source observation |
| Partially settled | Actual fill plus live successor/right | Requested quantity minus incomplete fill list |
| Cancellation pending | Request/sign/send exists | All offers invalidated/capital released |
| Canceled/exited | Actual generation consumption and authorized remaining disposition | Packet digest locally revoked |
| Recovery available | Complete usable secrets/data/artifacts/compute plus eligible right | Root/hash/verifier present alone |

Errors: wallet rejection; wrong network/pins; malformed amounts/precision; insufficient actual funds/allowance/gas; no counterparty; service unavailable; mismatched/expired terms; missing/wrong recovery material; proving resources unavailable; invalid certificate; consumed capability; cancellation/fill race; receiver/token rejection; RPC malformed/pruned/reorg; Unknown disposition; incomplete venue history. Each must preserve prior financial state, explain what is known and offer only a genuinely permitted retry/action.

## 7. Existing callable interfaces and the missing web bridge

Current native APIs are CLI/Rust library interfaces, not a public web backend:
- Seven private samechain commands: review/check Fill, check Cancel/Exit, review/check ordinary withdrawal, review/check creation. Private witnesses arrive only through bounded erasing stdin. Reviews return unsigned consent bytes; checks return native public journals, not certificates.
- Four public samechain call builders: exact create/fill/cancelOrExit/withdraw ABI with public packet/deployment/proof files; from/to/data hex, value decimal, exact payment effects and descriptive journals. All assurance flags remain UNVERIFIED/false.
- Public block-pinned inspector: independently declared deployment/token/code/block/policy, endpoint through private environment, optional public packet; node-reported tree/root/N/C/nonce/order state. Source is TRUSTED_NODE_AT_SELECTED_BLOCK, not financial/finality proof. Security corrections require current verified evidence before release.
- Public `simulate-call`: exact creation/fill/cancel/exit/withdrawal from public files, mandatory independently selected pins and explicit bounded gas, fresh identity inspection then one same-block `eth_call` without overrides. Only empty void result becomes node-reported observation; all money/finality/proof assurances remain UNVERIFIED/false. No signing/submission or asset effects.
- HyperCore testnet info plus exact unsigned order/OID/cloid cancel proposals. `action_json` is an ordered string; do not reserialize it for signing. Requested fee caps are not venue-enforced, fill history remains incomplete.
- Market journal/migration/replica/PCZT tools are operator/native safety utilities, not customer order APIs. SQL commands must not run locally.

**Required software delivery, not CLI-only:** provide a long-running public backend/server API for supported orders/discovery/qualified matching, public state/outcome orchestration and unchanged authorized relay, and a reviewed owner-local companion for private authoring/review/signing/proving/recovery. Both consume the same native protocol/runtime rules; CLI remains operator/manual recovery access when company app/server disappears. This is not an implemented HTTP/IPC contract yet. The server may receive public/non-sensitive order data and user-authorized public payloads, then send the unchanged transaction and track/reconcile it. It must not receive owner witnesses/FVK/keys/recovery openings, sign instead of the wallet, mutate terms or create money authority from a database row. No broad SDK framework is required, but actual authenticated transport, process/job lifecycle, lossless statuses and frontend→runtime→actual outcome checks cannot be omitted. User owns sibling frontend; engineering owns native/backend/secure local integration.

**Authority model for the frontend:** browser/backend/server is coordination, public-data transport and execution relay; the owner-local companion or wallet is the secret-bearing signer/prover; the target blockchain/contract is the final authority. The local companion does not run a separate blockchain consensus. It must verify exact state and protect keys/witnesses, while local locks/journals prevent duplicate submissions only. Backend failure must not erase already authorized rights; app-visible status must distinguish server observation, transaction submission, chain inclusion and actual transfer state.

## 8. What must happen next

1. The two demonstrated RPC safety defects are corrected with failing-before/passing-after evidence and scoped rereview; preserve that boundary in subsequent client work. This closes those defects only, not financial/finality qualification.
2. Qualify a genuine samechain certificate/program/setup pipeline using authorized owner-controlled resources. The previous 4GiB wrapping attempt OOMed; CPU success is not a certificate and repeated under-resourced attempts are not progress.
3. Define the concrete first-route environment/assets and user wallet/companion contract; preserve samechain authority and local-secret boundaries.
4. **User owns the sibling frontend implementation**: build its app routes/screens using this handoff and the existing design. **Engineering agent owns native/backend integration, owner-local secure transport, genuine certificate/execution and exact outcome qualification**. Agree on lossless public data/error/status contracts and jointly exercise deposit→partial-fill→withdraw/remainder. This handoff does not authorize the agent to take over the frontend repository; no fixture-data financial fallback is allowed.
5. Obtain explicit approvals for exact deployment/sign/fund/send actions when ready; show network, signer/fee payer, recipients/assets/amounts/fees and simulation before signing approval. Read secret configuration through secure user-controlled channels only.
6. Exercise user refresh/restart/Unknown/cancel race/transfer failure/retry and local recovery. Supply a usable URL/local launch path only after real journey acceptance.
7. Continue native Zcash full-history/financial/classifier/uniqueness/terminal recovery/excess, strict private-market construction, selected external venues, SQL and production security/manual/DA/resource/lifetime gates in parallel. First journey is not whole-product completion.

External prerequisites: authorized proving capacity/artifacts; selected chain/asset/program qualification; explicit deployment/signing/funding/submission scope; owner-controlled wallet/capabilities; authorized data source/finality policy; securely supplied nonlocal PostgreSQL URI and isolated-schema permission where used. No private keys/seeds/FVK/API tokens should be requested in chat or committed. SQL URI alone does not grant destructive migrations/server restart.

## 9. Source owners and evidence

Product scope: [PRODUCT](../PRODUCT.md), [ARCHITECTURE](../ARCHITECTURE.md). Readiness/evidence: [BLOCKERS](../BLOCKERS.md), [NATIVE-IMPLEMENTATION-STATUS](../NATIVE-IMPLEMENTATION-STATUS.md), [PROGRESS](PROGRESS-2026-10-04.md). Modules/recovery: [MODULES](../MODULES.md), [SERVER-INDEPENDENCE](../SERVER-INDEPENDENCE.md), [destination contract](../modules/destination-settlement.md), [SQL hold](../SQL-VERIFICATION.md). Frontend: [existing design](../../../z2z-protocol/docs/design.md), [frontend README](../../../z2z-protocol/README.md), actual `src/routeTree.gen.ts` and `package.json`. Actual authority: [SamechainAuthority](../../contracts/evm/src/SamechainAuthority.sol), [contract README](../../contracts/evm/README.md). Native public client: [samechain builders](../../crates/chains/src/samechain.rs), [runtime](../../crates/runtime/src/samechain.rs). Zoss: [shared architecture](../../../zoss/docs/ARCHITECTURE.md).

This report intentionally distinguishes current runnable primitives, required product stories, recommendation and unverified financial delivery. It authorizes no blockchain/SQL action and marks no full-goal completion.

## Owner clarification — resting orders, multiple takers and settled partial success

The product is not a simultaneous two-party deposit session. One maker creates a Buy/Sell order with exact price/quantity/fee policy, supplies eligible backing, then leaves its live remainder available. Many takers may independently fill portions of the same logical order over time. Each settled fill is successful immediately; aggregate PartiallyFilled/Open displays settled quantity and the live remainder separately. Filled/Complete requires requested quantity fully settled. Cancel affects only the remaining unconsumed right; prior final fills remain successful. Submitted/Unknown portions keep exclusive reservations and must not count as settled or be offered twice. The buyer funds the payment asset, not the asset being bought; all fees/debit limits must be authorized.

Example: sell100 units → takerB settles20 → takerC settles30: settled50, remaining50, both fills successful, orderPartiallyFilled/Open. Later takerD settles50 → aggregateFilled/Complete. A fill failing/reverting does not count; a not-yet-known disposition retains its fence. The UI must not call the whole partly settled order Pending or hide realized proceeds until full fill.

**Owner confirmed: maker signs exactly once when opening the order.** After eligible backing is established, arbitrary eligible takers may fill within signed asset/quantity/net-price/fee limits while maker is offline; no per-fill maker confirmation or signature step. Frontend must not present fresh maker approvals as the intended resting-order flow. Owner cancellation/amendment, if requested, is a distinct authorized action affecting live remainder rather than a required fill approval. Current recipient-prepared per-known-fill code still requires fresh maker consent and does not satisfy this requirement. A reviewed standing-authorization, executable proof and maker-recoverable output/successor construction is required; an open database row is insufficient. This confirmation preserves strict privacy, backing, actual settlement and company-off requirements, and grants no money-action permission.
