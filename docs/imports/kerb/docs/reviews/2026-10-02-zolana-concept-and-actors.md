# Zolana dossiers, Kerb architecture and actors

Date: 2026-10-02. Scope: local-document/source comparison requested by the owner; no new protocol implementation, network action, privacy experiment or external-source recertification.

## Decision: retain both Zolana directories

`zolana-review-2026-09-29/` contains 18 proposed cross-chain documents. `zolana-research-2026-09-30/` contains six dated evidence/research documents. Both describe the same native Solana↔Ironwood end-goal as the [approved safety-core objective](../docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md#1-intent-decisions-and-full-objective): isolated synthetic-SPL/ZEC, USDC/ZEC and exact qualified xStock/ZEC profiles; matcher content/accepted-identity protection; threshold ZEC custody; non-atomic settlement.

**No Zolana file was identified for deletion under the owner's condition “delete if it describes a different concept.”** Older alternatives, dated implementation gaps and rejected mechanisms are not a separate product thesis. No files were deleted. The research supplies nonduplicated source evidence and is explicitly consumed by [the integrated candidate §12](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md#12-source-evidence-and-decision-trace) and [the strict-privacy feasibility record](2026-10-02-strict-privacy-feasibility.md).

The genuinely different concept is the **historical public-Solana tokenized-stock/USDC auction with optional residual maker**, retained below current-authority prefixes in `docs/`. In particular, the maker diagrams in [architecture03](../architecture/03-SYSTEM-ARCHITECTURE.md) and maker/crank runbooks in [operations06](../architecture/06-OFFCHAIN-SERVICES.md) are not the current cross-chain architecture. Retention of that historical material does not approve or implement it; deleting that separate dossier was not the conditional Zolana deletion requested here.

Sources: [review identity and mapping](../../zolana-review-2026-09-29/README.md), [research index](../../zolana-research-2026-09-30/README.md), [current authority §0](../00-CANONICAL.md#0-current-documentation-authority).

## Differences that matter without changing the concept

| Topic | Earlier research/review | Later candidate or approved increment |
|---|---|---|
| Admission | Blind-token/private-proof alternatives explored | Oct1 proposes independent FAA with disclosed order+identity view; not an implemented anonymous credential |
| Matching | D0 integer reference, exploratory bounds/ties | Oct1 proposes fixed eight-slot zero-fee uniform-price matching and private results; Oct2 does not implement this failing mechanism as approved private matching |
| Custody decisions | Threshold and ordering alternatives researched | Oct1 proposes 2-of-3 native spending, separate unanimous three-domain business decisions, SPL-first and one concurrent fill |
| Funding/refunds | Earlier requirements and discovered accounting conflicts | Full buyer max debit and seller quantity held from prepare; complete canonical allocation plus full journal activation required; payout and refund have distinct predicates |
| Zoss | Historical optional receive-notification discussion | Adopted direction is in-process source/context/domain/Solana library reuse; messaging OFF/non-money; no required watcher or daemon |
| Implementation | Sep29/Sep30 preimplementation snapshots | Oct2 approved local Rust/PostgreSQL/Solana/unsigned-native safety increment; not complete network settlement |
| Privacy | Risks and singleton/public-membership probe | Known GD2 failure; Oct2 own-price/asset-disposition argument survives a genuine second seller and hidden membership |

Sources: [research admission/output evidence](../../zolana-research-2026-09-30/privacy-admission.md), [custody/source evidence](../../zolana-research-2026-09-30/protocol-custody.md), [candidate decisions §2](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md#2-one-selected-architecture-not-unresolved-menu), [safety scope](../docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md), [privacy prerequisite](2026-10-02-strict-privacy-feasibility.md).

Retain all six research files: README is the dated decision index; protocol-custody carries native/version/recovery/history evidence; privacy-admission carries transport/control/output evidence; business-legal carries dated issuer/legal/contest/demand evidence; inventory is the historical discovery trace, not today's backlog; evidence-scope preserves the limits on all those claims. External facts need refreshing before public or operational use. Old “no executable” statements are historical, not descriptions of today's local safety code.

## Intended system architecture, not a working private exchange

1. **Trader clients:** seller signs its exact SPL funding and order; buyer signs its own native ZEC deposit and order. Each funds its own leg, not both sides.
2. **Source/inventory checks:** Kerb scanner acquires/decrypts source data, using shared libraries where integrated. Kerb separately checks claimant rights, receiver/value/occurrence, canonical history, controlled unallocated inventory and durable credit dedup. Observation alone is not credit.
3. **Independent FAA:** validates eligibility, exact signed order and durable funding hold; certifies the same tuple encrypted for MPC. FAA deliberately sees identity and terms and must be outside matcher control/access.
4. **Separate intake and MPC:** intake batches encrypted certified tuples; proposed independently controlled MPC domains compute authenticated sealed allocations. Matching does not expose plaintext orders to a single matcher, but results/public settlement can still leak them.
5. **Ledger and coordinator:** PostgreSQL holds liabilities, inventory, input locks, immutable intents and recovery history. A privileged coordinator validates complete allocation/conservation and proposes exact operations. Three durable business domains must acknowledge the same decision before applicable monetary authority is exported.
6. **Solana escrow:** public program state anchors epoch/release/cancellation and transfers exact SPL to fixed recipients. A relayer submits transactions; signatures and program state, not relayer choice, authorize them.
7. **Native custody:** intended native transaction construction/proving and 2-of-3 FROST spending use reserved buyer backing after exact effect/policy checks. Native keys are separate from ordinary Solana/business authorizer keys. Both chains must be observed under explicit finality policy.

**Settlement is not atomic.** Under the proposed SPL-first ordering, seller SPL can be delivered while native ZEC payout is withheld, lost or unresolved. A corrupt spend threshold can steal; unavailable custody can strand refunds. Neither Solana nor a timeout forces a native refund.

The full candidate remains unapproved and fails the retained strict privacy requirement. Local safety implementation does not establish FAA/MPC, actual source history, native proving/signing/broadcast, independent operator governance or funded-network settlement. See [current implemented scope](../README.md#implemented-local-safety-cores-2026-10-02), [candidate roles §3](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md#3-components-and-actual-trustcontrol-boundaries), [workflow §7](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md#7-complete-usersystem-workflow).

## User stories

- **Seller:** select an eligible exact pair; escrow SPL; authorize quantity, minimum price and ZEC recipient; prepare/admit encrypted order; obtain own result; matched SPL is delivered first, then custody pays ZEC. Eligible unused SPL returns separately. Native withholding after SPL delivery is a disclosed loss risk.
- **Buyer:** deposit native ZEC to the exact pair receiver; receive one claimant-bound controlled-inventory-backed credit; authorize maximum debit, quantity, price limit and fixed destinations; prepare/admit encrypted order; receive matched SPL. Unused credit becomes a disjoint native-refund claim after complete allocation activation.
- **Partial fill illustration:** held maximum34 splits into seller liability25 and buyer-unused9. The9 is not available during unresolved matching, partial activation or ambiguous send. Network fee capital is separate from user backing.
- **No cross/exclusion/abort:** use canonical irreversible disposition and retained authority history to release backing. BuyerRefund does not require an SPL delivery. Expiry, missing callback or elapsed time alone never proves funds may be freed.
- **Restart/outage:** retain holds and live input/nonce/intent history; reconcile independently retained heads and exact chain observations. Unknown is not failed/no-effect. Completion requires both final legs, not a signature or broadcast.

These are intended funded requirements, not enabled product capabilities. Sources: [candidate accounting §§5–7](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md), [typed native predicates in safety spec §7](../docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md#7-custody-effect-checks-and-native-intents).

## Maker signer and other signatures

**Maker signer is a historical liquidity-provider wallet role, not an AI-agent requirement or current custody service.** In the old public-Solana concept, the inventory owner signs a fully funded quote ladder for residual orders. A human wallet or authorized automated client can exercise that authority [INFERENCE from the signature contract]; the contract cares about the key and funded terms, not who clicks. Maker cannot sign for users or choose primary clearing price. The current cross-chain candidate explicitly has **no residual maker or price oracle**, and the current Solana dispatch has no maker-ladder operation.

Do not conflate:

| Role | Signs/authorizes |
|---|---|
| Trader wallet | Own funding, order and destinations |
| Historical maker wallet | Its own funded residual quotes, only in the historical concept |
| Proposed FAA certificate key | Admission certificate for the exact held tuple; vendor Arcis scheme distinct from ordinary wallet Ed25519 |
| Business/Solana authorizers | Exact durable journal/state-transition decisions, ordinary Ed25519; current policy needs all three |
| Intended native FROST shareholders | Native ZEC spend, intended threshold2-of-3; not implemented by ordinary business signatures |
| Relayer/fee payer | Submits/pays for a transaction; cannot replace required monetary authority |

Sources: [historical ladder contract](../00-CANONICAL.md#34-residual-phase-separate-cannot-change-primary-outcome), [candidate no-maker decision](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md#2-one-selected-architecture-not-unresolved-menu), [signature schemes §4](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md#4-records-domains-and-certificateinput-consistency), current `contracts/solana/program/src/lib.rs` dispatch and `crates/protocol/src/records.rs` SignatureRole comments. A `NativeIntent` business-record signature is not a native FROST spend signature.

## Actors beyond users and external calls

**Beyond users: yes. Mandatory random third-party keeper/maker service: no.**

- Outside the **smart contract**, a wallet or process must submit lifecycle transactions: the program has no autonomous scheduler. Kerb coordinator/relayer workers can do this. Caller/fee payer is not financial authority.
- Inside the **protocol**, FAA, intake, MPC, scanner/inventory, privileged coordinator and custody business/spend functions are required by the proposed full workflow. Independent control/access domains are security requirements, not merely separate containers. Independence does not require a particular SaaS vendor, but one shared administrator cannot honestly be labelled independent.
- Outside the **deployment**, actual chain access/consensus and actual chosen MPC execution are needed for funded integration. RPC can be self-hosted or outsourced. Blockchain reads/submission/observation are dependencies, not an external market-price oracle.
- Zoss **libraries** are in-process reuse, not required calls to a Zoss watcher/receipt/daemon service. Optional message diagnosis stays OFF/non-money.
- Jupiter, NEAR, xChange, price-feed and residual-maker integrations are not required current execution paths. A reference integer “oracle” used to check allocations means a validation algorithm, not an external feed.

Sources: [candidate role/flow tables](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md), [current private operations](../architecture/06-OFFCHAIN-SERVICES.md), [local safety module contract](../docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md).

## Review coverage and limits

Read-only delegates inventoried all18 review files and compared relevant sections of every file; another read all six research files through EOF, including long raw lines. All compared against the Oct1 candidate/review, Oct2 approved safety scope and strict-privacy record. Actor investigation traced current Rust/Solana source and historical maker terminology. Parent reread authority, architecture, workflow and custody boundaries. No current live external source facts, legal conclusions, privacy proof or funded deployment is asserted. No Zolana file deletion or protocol-code edit was made for this clarification.
