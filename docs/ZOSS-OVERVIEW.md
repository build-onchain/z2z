# Zoss × Ziquid — architecture overview

> **Authority/supersession update — 2026-10-02.** This is the retained **2026-10-01 read/CLI snapshot**. Its docs-only Zoss, four empty libraries/binary-only runtime, no-import/empty EVM and exact CLI/source-layout observations are historical—not today's inventory or compatibility evidence. [Native status](NATIVE-IMPLEMENTATION-STATUS.md) now records real limited runtime store/custody library primitives, proof/guest/allocation primitives and the approved read-only `zoss-zcash` acquisition seam; none establishes financial source validity, funded escrow or a complete manual consumer. Reinspect actual sibling source/exports and its [sole Zoss register](../../zoss/docs/BLOCKERS.md); do not copy the old statuses below.
>
> Active Ziquid behavior/ownership: [ARCHITECTURE](ARCHITECTURE.md), [MODULES](MODULES.md); DEX readiness: [BLOCKERS](BLOCKERS.md); manual rights/recovery data/resources: [SERVER-INDEPENDENCE](SERVER-INDEPENDENCE.md); future expanded direction: [redesign spec](superpowers/specs/2026-10-02-z2z-server-independent-architecture-design.md). Manual native operation is core acceptance, while TS/UI/bindings stay deferred. Full validating history/no SPV, proportional actual transfers, all-hostile independent terminal recovery, actual excess source return and strict-GD2 failure remain load-bearing. Optional messaging never grants money authority; new samechain bilateral rights and legacy custody/venue lanes have separate unqualified constructions. This docs-only update does not refresh the three historical CLI runs, source queries, action permissions or gate results.
>
> **Lane status — 2026-10-06.** Native ZEC is an ACTIVE first-class lane (L-ZEC) in the whole pipeline, not V2, with pairs ZEC↔{Base, HyperEVM, Solana, NEAR}; wrapped/bridged ZEC never substitutes. HyperEVM (L-HEVM), Solana devnet (L-SOL), NEAR testnet (L-NEAR) and cross-chain HTLC (X.CROSSCHAIN, HTLC first, all pairs in parallel, **no atomicity/privacy claim**) are active parallel lanes. The body's "NEAR is a layout slot" and any Solana/ZEC-deferred phrasing are superseded by this line; no other body text changes.

**Retained overview and evidence follow; “current” below refers to the 2026-10-01 review unless current authorities establish otherwise.**

Review snapshot: 2026-10-01. Research report, not an architecture authority, implementation approval, or gate-status register. Canonical documents are unchanged. The user's subsequent intent to implement Ziquid while building Zoss independently is addressed by the [implementation system prompt](history/ZIQUID-IMPLEMENTATION-SYSTEM-PROMPT.md); it does not retroactively change this snapshot's evidence.

## Conclusion and coverage

**Zoss is proposed shared native infrastructure, not Ziquid's settlement layer.** Optional quorum messaging cannot establish our financial facts or solve our recovery/privacy obligations. Current canonical documents agree on this separation.

Fully read all seven files under sibling `zoss/docs/`: [README](../../zoss/docs/README.md), [ARCHITECTURE](../../zoss/docs/ARCHITECTURE.md), [BLOCKERS](../../zoss/docs/BLOCKERS.md), [private_dex](../../zoss/docs/private_dex.md), [kerb](../../zoss/docs/kerb.md), [HTML brief](../../zoss/docs/reviews/2026-10-01-zoss-readiness-review.html), and [implementation prompt](../../zoss/docs/reviews/2026-10-01-implementation-system-prompt.txt). Also read both root READMEs, all Ziquid architecture/blocker/research/module/historical-plan documents, and relevant Rust/SDK/contract sources and manifests. Truncated long lines were reread raw.

Evidence classes: canonical designs are Proposed; upstream observations in existing research are historical source evidence; code maturity below was inspected directly; CLI results were executed in this review. Except for the pinned RPC declarations below, upstream claims were not comprehensively refreshed. No protocol test, proof, source/target route, signing, deployment, or transaction was exercised.

## 1. Maturity

| Area | Direction | Inspected maturity |
|---|---|---|
| Zoss common libraries | Context/authentication, source acquisition and reusable clients | Docs-only; no manifests/source/library exports found |
| Optional Zoss messaging | Ironwood testnet → Solana devnet non-money callback | Proposed; runtime gates Open |
| Ziquid native core | Five Rust packages | Four comment-only libraries and help/version binary |
| Ziquid SDK/contracts | TS SDK and independent target slots | Empty SDK export; no verifier/escrow/program implementation |
| Shared-library adoption | Future dependencies below existing Ziquid modules | No Zoss dependency/import/API |
| Financial/privacy readiness | Application-owned acceptance | M1–M5/S1–S7/P1–P2 Open/Blocked |

Sources: [Zoss architecture](../../zoss/docs/ARCHITECTURE.md), [Zoss register](../../zoss/docs/BLOCKERS.md), [local README](../README.md), [MODULES](MODULES.md), [DEX register](BLOCKERS.md).

The Zoss HTML is currently a **Build and Ship Brief**, despite its readiness-review filename. It describes future implementation and preserves canonical status/action boundaries; it is not completed readiness evidence.

## 2. Shared libraries first; messaging optional

Applications can reuse Zoss inside caller-owned processes without mandatory memo/inbox/watchers/IVK/quorum/receipt/runtime/shared daemon. Schemas, proofs, private witnesses, keys, economics and custody remain application-owned.

| Proposed package | Responsibility | Limits |
|---|---|---|
| `protocol` | Canonical context/domain/encoding and explicit-algorithm authorization | No sibling I/O, private keys, app economics or generic financial verified result |
| `zcash` | Actual acquisition, parse/full decrypt, stable occurrence, separately labelled provenance | Observation is not complete history/ownership/payment proof |
| `chains` | Concrete reusable submission/inclusion/finality/uncertain-outcome mechanics | Caller retains signer, exact calls/accounts and business policy |
| `runtime` | Optional watcher persistence/attestation and relay | No credit/custody/payout/refund authority |
| Independent Solana contract | Exact message verification, replay, authorized non-money callback | Target-safe separate build |

Intended graph: `protocol` below independent `zcash` and `chains`; `runtime` composes them. SDK/bindings are deferred. Module, package, process and repository are distinct decisions. Public raw-data sharing requires matching network/branch/version/policy; private keys/witnesses/mappings/proving jobs remain isolated. [Zoss §§3–4](../../zoss/docs/ARCHITECTURE.md)

Three non-interchangeable conceptual artifacts:

- `SourceObservation`: acquired/decrypted data and policy-labelled provenance.
- `QuorumAcceptedMessage`: exact route/quorum/context/app authorization for a non-money callback.
- DEX `VerifiedSettlementFact`: actual target verification of app history/effect/classification/uniqueness predicates.

Parser/RPC/decryption/signature/quorum success cannot promote observation into a financial fact. Ordinary Ed25519, Arcis SHA3-512 certificates and native spend authorization are separate schemes/roles. [Zoss §3.1](../../zoss/docs/ARCHITECTURE.md)

## 3. Ziquid integration and current flow

| Consumer | Potential reuse | Ziquid retains |
|---|---|---|
| `protocol` | Common encoding/domain/authentication | StatementContext and allocation rules |
| `zcash` | Acquisition/parse/full decrypt/provenance | P/Q authoring, note relations, wallet integration |
| `proofs` | Common encoding/source inputs | History/authentication/classification/hiding/uniqueness circuits |
| `chains` | Genuinely identical client mechanics | Exact financial calls, policy and transfers |
| `runtime` | Primitives through native modules | Inventory, funding records, Q custody, jobs and reconciliation |

Financial proofs submit **directly to the DEX target verifier**. Local native EVM is the first financial target, not Zoss EVM messaging support. Solana is separately gated; NEAR is a layout slot. [Consumer seam](../../zoss/docs/private_dex.md), [MODULES §1.3](MODULES.md)

With U selling ZEC and S supplying destination liquidity:

1. U creates unsigned P and locally complete proved/signed self-spend Q on the same authenticated real Ironwood input. All Q nonzero outputs are U-owned, less agreed fee. U durably retains independent `PayoutWitnessU`.
2. S validates executable Q without U FVK/spend key, then irrevocably prefunds the exact destination obligation.
3. U independently verifies code/verifier/context/amount/beneficiaries/finality before releasing executable P authorization.
4. On the same accepted valid finalized source history, supported payment satisfying the obligation permits U payout; proven nonpaying real-input conflict permits S refund; unknown evidence remains pending.
5. Actual fixed-beneficiary native transfer and consumption are atomic. Failed transfer rolls back attempted consumption; valid entitlement remains retryable.

Q can be broadcast early: cancellation/fee/option grief, not guaranteed delayed recovery. Final Q cannot autonomously reanchor/reprove. Missing evidence, unusable artifacts or chain halt can cause indefinite pending. ETA changes status, not allocation. [Architecture §§7.2–7.3](ARCHITECTURE.md), [destination spec](modules/destination-settlement.md)

## 4. Main remaining protocol risks

These are design prerequisites, not deployed Ziquid vulnerabilities.

| Risk | Required work/evidence |
|---|---|
| Accepted-history validity | Authenticate checkpoint **state**, actual transaction/auth-body validity, inclusion structure, consensus/history and competing-history/finality assumptions. Header hash or best submitted work alone is insufficient. |
| Conflict versus nonpayment | T≠P can pay S; same-effect new authorization remains P. Classify complete transactions and earlier admissible P/T; no artificial activation-height cutoff. |
| Gross versus net consideration | Authenticate complete real-input ownership/zero-dummy scope. S-owned input returned to S can yield sufficient gross receipts with zero user consideration. Unsupported mixed/partial cases remain pending. |
| Hidden-payment reuse | New order IDs/random commitments cannot let one payment claim several escrows. Receipt replay is a separate ledger. |
| Independent witnesses | U proves payout without post-payment S IVK/witness release; S has usable recovery artifacts while U is offline. |
| Lifetime/privacy/resources | Original usable prover/VK/history/private witnesses survive until terminal. Measure linkage and proof/gas/data costs. Expiry/upgrades do not retire included-payment entitlements. |

Sources: [proof spec](modules/zcash-proofs.md), [wallet spec](modules/wallet-authoring.md), [solver spec](modules/solver-operations.md), [DEX blockers](BLOCKERS.md), [audit](research/ARCHITECTURE-AUDIT.md).

## 5. Optional messaging and Kerb

Proposed flow: shielded memo → full-decrypt watcher → private signed observation → public opaque receipt → distinct authorized quorum verification → atomic non-money callback. Default public receipts omit source locators/height/value/private-record hashes. Callback failure rolls back state; same immutable receipt retry requires still-valid authorization. Quorum can lie/censor; opaque IDs do not prove privacy; destination atomicity is not cross-chain atomicity. Memo budget is 511 app bytes after the binary prefix. Cross-route namespace and epoch/revocation/retry policies remain unresolved. [Zoss §§5–7](../../zoss/docs/ARCHITECTURE.md)

Kerb uses libraries in its own scanner and retains credit/holds/FAA/MPC/custody/recovery. Diagnostics default OFF. Its separate private-demo candidate has a known GD2 structural failure: public seller membership plus attacker-owned fill results can reveal a seller's limit. Shared libraries/encryption/padding/opaque receipts do not repair that inference. [Kerb assessment](../../zoss/docs/kerb.md)

All seven Zoss named shared-library readiness rows remain Open, separate from optional message G/Z and rejected-escrow B records. Applications do not inherit acceptance from library/message success. [Sole register §7](../../zoss/docs/BLOCKERS.md)

## 6. Documentation cautions

1. **Full-block path:** ZE5 wording is ambiguous. Independently fetched pinned [service.proto](https://github.com/zcash/lightwallet-protocol/blob/12b892541bbf14d8e485a13e63ccfac85382fc21/walletrpc/service.proto#L224-L276) declares GetBlock/GetBlockRange returning compact blocks and GetTransaction returning raw transactions. The latest brief correctly requires identifying actual full-block acquisition. No endpoint was exercised.
2. **Historical alternatives:** exclusion-only refunds, [L,H] eligibility and delegated-FVK constructions remain historical audit/research evidence. Current canonical flow selects classified conflict/local Q and handles earlier bound payments. Approval supersedes direction, not underlying safety findings.
3. **Runtime shape:** prose mentions an empty runtime library, but [manifest](../crates/runtime/Cargo.toml) and [source](../crates/runtime/src/main.rs) contain only a binary: four libraries plus one binary.
4. **Coverage provenance:** the Zoss prompt mentions “the review's 80% goal”; current HTML provides no numeric policy. This is not a canonical acceptance gate.

## 7. Recommended sequence and observed verification

Assessment: preserve ownership. Zoss should implement context/authentication and actual source integration with two isolated consumers; optional messaging is a separately selected path. Ziquid should follow M1 definitions → M2 actual offline Q → M3 complete classifier/independent witness → M4 source verifier and actual local EVM transfers → M5 privacy/uniqueness/resources/lifetime. Public LP/1Click/autopilot/ZSA remain deferred, not substitutes or settlement fallbacks. [Acceptance order](MODULES.md), [SDK spec](modules/client-sdk.md)

Commands executed from repository root during the review:

| Command | Observed result |
|---|---|
| `cargo run -p ziquid-runtime --bin ziquid -- --help` | Exit 0; settlement/solver/server explicitly unimplemented |
| `cargo run -p ziquid-runtime --bin ziquid -- --version` | Exit 0; `ziquid 0.1.0` |
| `cargo run -p ziquid-runtime --bin ziquid -- swap` | Exit 2; unsupported command |

No protocol test, deployment, signing, transaction, or money movement was performed. This saved report adds no gate closure. Zoss reduces duplicated infrastructure work; it does not discharge the financial proof obligations of a safe, private, executable swap.
