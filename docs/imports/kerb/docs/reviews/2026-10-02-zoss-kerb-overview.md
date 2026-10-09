# Zoss and Kerb — architecture overview

Review date: 2026-10-02. Source architecture/design records are dated 2026-10-01. This is a non-authoritative documentation synthesis, not a code/security audit, implementation approval, or readiness register. Zoss's ARCHITECTURE owns its engineering contract; BLOCKERS alone owns its core acceptance/status. Kerb's current authority separates adopted library reuse from its unapproved financial/private candidate and retained historical public-Solana design.

## Executive assessment

**Zoss is a reusable native cross-chain library core, not Kerb's bridge, custodian, funding authority, or settlement engine.** Its optional authenticated Ironwood-testnet → Solana-devnet messaging profile is non-money. Kerb can use its source/context/client code inside Kerb-controlled processes without a Zoss daemon, receipt, watcher quorum, memo, or extra viewing party. Kerb retains all financial state, keys, policy, matching, settlement and recovery. [Zoss ARCHITECTURE lines 13–59, 88–134; Kerb 00-CANONICAL lines 7–17]

**The documents describe a direction and build contract, not running software.** All canonical shared-library acceptance rows and optional G/Z/B gates remain Open. The workspace inventories inspected contained no Cargo.toml, package.json, Anchor.toml or go.mod in either Zoss or Kerb. This is limited repository evidence, not proof that no implementation exists elsewhere. [Zoss BLOCKERS lines 1–6, 89–103; local inventory check]

**Kerb's private funded-demo candidate has a known structural privacy failure.** Zoss improvements cannot close that failure. Public seller participation plus an attacker's legitimate own-fill output can expose both the accepted seller identity and a private limit without breaking encryption or MPC. [Kerb design review lines 7–11; production-demo design lines 149–157, 249–257]

**Newer Zoss build-design and implementation-plan documents appeared during this reading.** The design records local implementation authorization and concrete wire/namespace/epoch choices in a separate session; its header still says Proposed/awaiting written-spec review, while the newer plan says that spec was reviewed and user-approved. Older canonical text still calls these choices unresolved and its adoption docs-only. This is a freshness/authority synchronization issue: choices and a separate-session approval record exist; canonical statuses and runtime evidence have not changed. This review request authorizes no implementation or external action. [Zoss product-build design lines 1–16; product-build plan lines 1–21; ARCHITECTURE lines 338–354]

## 1. Coverage and evidence limits

All nine files present under Zoss/docs at the final coverage check were read completely, including unabridged long lines and the HTML/script, implementation-prompt and plan text as data:

| Zoss file | Logical lines read | Role |
|---|---:|---|
| README.md | 1–36 | Scope and reading order |
| ARCHITECTURE.md | 1–354 | Canonical module, package, process, authority and message contract |
| BLOCKERS.md | 1–103 | Sole source evidence and gate/closure register |
| kerb.md | 1–167 | Kerb consumer workflow and obligations |
| private_dex.md | 1–95 | Ziquid consumer and rejected escrow record |
| reviews/2026-10-01-zoss-readiness-review.html | 1–79 | Build/ship guidance, not gate authority |
| reviews/2026-10-01-implementation-system-prompt.txt | 1–43 | Guidance for a separately authorized implementation session |
| superpowers/specs/2026-10-01-zoss-product-build-design.md | 1–122 | Newer proposed detailed implementation choices |
| superpowers/plans/2026-10-01-zoss-product-build.md | 1–129 | Newer implementation plan and separate-session spec-approval record |

Zoss's repository-level README was also read. Relevant Kerb sources are its docs README; 00-CANONICAL; Oct1 integrated proposal and adversarial review; architecture 03/06; security 07/08; roadmap 16. Historical dossiers were used only where needed to distinguish prior designs, not re-certified as current architecture.

Primary evidence here means the local project documents. External ZIP/API/release references and the new build design's reported read-only network observations were not independently re-fetched or reproduced. Their claims remain attributed to their source documents. No program/runtime/deployment/funding/privacy experiment was run by this review.

## 2. What Zoss owns

### Shared native modules

| Proposed package/artifact | Responsibility | Authority limit |
|---|---|---|
| protocol | Canonical context, encoding, explicit signature algorithms, role domains and digests | Does not define app economics or produce a generic financial verified result |
| zcash | Actual upstream full transaction/block acquisition, parsing, full memo decrypt, stable occurrence, separately labelled canonical policy; optional unsigned message construction | Caller owns viewing capability/process/private state and wallet signing; observation is not complete accepted-history, ownership or payment proof |
| chains | Concrete target-client request construction, submission/inclusion/finality observation and unknown-outcome reconciliation | Caller owns signer/fee payer; app owns method/accounts and financial finality |
| runtime | Optional persistent watcher/private observation/attestation and isolated public relay | No spend, credit, payout or refund authority; not a library-consumer prerequisite |
| Independent Solana build | Exact message verification, durable replay/nonce consumption and fixed non-money callback | Target-safe protocol subset only; no token/custody vault capability |

Intended dependency direction: protocol has no sibling I/O dependencies; zcash and chains each depend on protocol, not each other or runtime; runtime composes them. The Solana contract is independently built. Kerb and Ziquid keep their own repositories and releases. An SDK remains deferred until actual client operations justify one. [Zoss ARCHITECTURE lines 84–134]

### Three deliberately different artifacts

- **SourceObservation:** acquired/decrypted data with stable occurrence and policy-labelled provenance. It does not confer funding ownership, complete source validity/history or credit.
- **QuorumAcceptedMessage:** exact public receipt accepted under route/context/app authorization by distinct authorized quorum keys. It is trusted message-policy acceptance, not independent source proof.
- **VerifiedSettlementFact:** Ziquid-owned output only after its actual target proof verifier checks the app's history/effects/classification/context/uniqueness relation. Neither observation nor signatures construct it.

These are not a trust-level ladder or interchangeable wrappers. Kerb must not import the DEX fact or use any generic verified boolean to bypass its funding predicates. [Zoss ARCHITECTURE lines 49–59; Kerb 00-CANONICAL lines 9–15]

## 3. Optional messaging: what it guarantees and does not

Proposed flow:

```text
Actual shielded note + authenticated memo
  → full decrypt and source-context checks
  → persistent private observation/source→receipt mapping
  → opaque public receipt + distinct authorized destination signatures
  → unprivileged public relay
  → Solana verify + consume replay/nonce + authorized non-money CPI
  → Delivered only after destination transaction commit
```

Private provenance contains source occurrence, commitment, block context, value and full memo, and privately binds the exact public receipt digest. Default public receipt omits cmx/txid/action/block/height/value/raw memo/private-record digest. It still exposes route/epoch/app key/nonce/ciphertext/signers and destination actions/timing. Removing a deterministic locator is not proof of anonymity or unlinkability. Watchers retain privileged source visibility. [Zoss ARCHITECTURE lines 169–179, 237–258]

Replay is consumed before authorized CPI in the same destination transaction. Callback failure rolls back app/endpoint/replay/nonce state; every retry re-verifies the same immutable receipt while its epoch and app authorization remain valid. At most one committed callback is not eventual delivery. Source reorg does not automatically undo a destination callback. Destination atomicity does not recover source funds or create cross-chain atomicity. [Zoss ARCHITECTURE lines 195–233]

Stable source occurrence is (network, pool, txid, action_index). Block inclusion is separate context; re-inclusion does not create a new occurrence. cmx is not a global payment occurrence key. Messaging source→receipt projection, destination replay/app nonces, Kerb credit/hold/intent uniqueness and app terminal entitlement consumption remain distinct ledgers. [Zoss ARCHITECTURE lines 224–233]

## 4. New detailed build choices and remaining synchronization

The new product-build design narrows several older Open decisions without claiming code exists:

| Topic | New proposed choice | What remains unproved |
|---|---|---|
| Wire/signatures | Fixed-width 288-byte body; separate ordinary Ed25519 role domains over SHA-256 body digest; canonical prime-subgroup registered keys and host/target rejection vectors | Actual codecs, strict/native verifier equivalence and independent vectors |
| Payload | Inline XChaCha20-Poly1305; 511 app bytes minus body288, signature64, nonce24 and tag16 leaves maximum plaintext119 | Actual wallet/full-memo round trip, schema compatibility and complete Solana transaction fit |
| Source→receipt namespace | One occurrence→one receipt across all enrolled routes/profiles/consumers/deployments in one explicitly owned registry | Durable implementation, migration and canonical contract adoption; separate registries do not imply universal financial uniqueness |
| Epoch/retry | Immutable snapshots survive new epochs until explicit revocation; same body/ID/epoch on retry; consumed state never reset | Actual replay, revocation and delayed-retry execution |
| Source cohort/path | Candidate encryption0.4.2 cohort; real full-block node JSON-RPC path, compact gRPC discovery/full transactions remain distinct | Dependency compilation and full parse/decrypt/context compatibility |
| Persistence | Watcher-private SQLite and separate public-only relay store/process; registry projection reserves mappings before signature export | Crash/restart/equivocation/OS-capability isolation evidence |
| Solana/client | Native precompile instruction-sysvar inspection; exact account/template validation; persisted Unknown submission and state/history reconciliation | Compiled target execution, CU and serialized transaction size, deployed route evidence |

[Zoss product-build design lines 9–16, 18–71, 73–99]

The payload arithmetic was independently checked during this review: body288 and plaintext119. This proves arithmetic only, not serialization/security/transaction fit. The design explicitly requires complete transaction-size proof within the chosen supported format; 511-byte memo capacity does not establish Solana transaction capacity. [Product-build design lines 36–60, 85–87]

The design reports fresh Tatum/full-block and Solana version observations. These are source-reported read-only observations; this review did not reproduce them. It explicitly says acquired raw bytes had not yet been Rust-parsed/decrypted and a public coinbase memo cannot substitute for G1's caller-wallet app memo/IVK round trip. [Product-build design lines 61–71, 73–75]

**Documentation discrepancies:** BLOCKERS ZE5 uses “full transaction/block” RPC shorthand, while the brief/new build design explicitly distinguish compact gRPC blocks from full node JSON-RPC blocks. The prompt's “review's 80% goal” has no matching target in the current HTML brief or canonical register; it is not a canonical readiness gate. The plan says the spec is reviewed/approved while the spec header still awaits review. These are wording/provenance synchronization issues, not evidence of failed runtime or passed gates. [BLOCKERS line 33; implementation prompt lines 22,41; product-build design lines 3,63; product-build plan line 11]

**Recommendation [INFERENCE]:** reconcile the written-spec approval record and synchronize accepted namespace/epoch/wire/cohort choices into canonical architecture and decision wording, preserving Open statuses until exact evidence closes them. Do not describe these choices as wholly absent, or mistake selected design for runtime closure.

## 5. What this means for Kerb

### Adopted reuse, not adopted financial architecture

Kerb's adopted direction is library reuse in its own scanner/coordinator/client processes. Its financial/private Oct1 candidate remains unapproved. The older public-Solana same-mint/USDC auction is a retained historical proposal, not a second approved implementation or automatic replacement. [Kerb 00-CANONICAL lines 3–17; docs README lines 3–16]

```text
Ironwood source data
  → Zoss source library inside Kerb-owned scanner
  → KERB claimant + receiver/occurrence + canonical history
       + controlled unallocated inventory + durable credit-dedup checks
  → private credit and symmetric holds
  → independent FAA admission + encrypted MPC
  → canonical Solana epoch decision + fenced private journal
  → Kerb SPL authorization and Ironwood FROST custody
  → Kerb payout/refund/reconciliation/recovery

Optional Zoss receipt → diagnostic only [OFF]; no arrow to money authority
```

[Kerb system architecture lines 9–24; Zoss kerb.md lines 7–29, 31–59]

Kerb owns per-pair schemas/units, claimant ownership, full maximum-debit/seller holds, FAA certificates, MPC relation/results, custody inventory, Solana escrow/epoch transitions, journals, FROST nonces/intents, payout/refund and recovery. A shared library neither adds an IVK/FVK holder nor authorizes shared private caches/witnesses/logs. Control/admin/backup/support access—not actor names—determines whether a matcher can obtain protected data. [Kerb operations lines 9–19; security07 lines 11–26]

Ordinary wallet/Solana Ed25519, Arcis SHA3-512 certificate signatures and native FROST spending remain separate schemes/roles. Source parsing and IVK detection do not replace FVK/nullifier/witness inventory or complete claimant/history checks. [Zoss kerb.md lines 25–29, 61; Kerb operations lines 11–15]

### Unapproved funded-demo candidate

Candidate target: exact synthetic legacy-SPL mint on Solana devnet against native shielded Ironwood testnet ZEC; fixed eight-slot maximum-volume uniform-price auction, half-even plateau midpoint, price priority/marginal pro-rata, no oracle/residual/amendment/min-fill, zero protocol fee and operator-sponsored network fees. Arcium Cerberus/distributed preprocessing is the proposed three-domain matcher; privileged FAA and coordinator must be outside matcher control. [Kerb production-demo design lines 11–35]

Three-domain unanimous business acknowledgements plus a canonical Solana anchor and fenced private writer serialize honest policy. Native custody remains 2-of-3 FROST. One missing business acknowledgement halts; a corrupt spend threshold can still steal. This is not Byzantine ledger consensus. Settlement is SPL-first, one concurrent fill, followed by ZEC payout; seller bears disclosed second-leg withholding/reorg loss. No trustless/atomic swap or unilateral ZEC-refund claim exists. [Zoss kerb.md lines 14–17, 75–85]

Seller quantity and buyer full max debit remain held through delayed MPC/unknown decisions. Refund/release requires exact finalized allocation plus complete authenticated chunks, unanimous matching acknowledgement and fully activated journal. Typed SellerPayout and BuyerRefund have different predicates; timeout or missing Zoss receipt releases neither backing. Restore must preserve non-rollback intent/nonce history, including potentially live signed effects. [Zoss kerb.md lines 75–85; Kerb review lines 13–47]

### The blocking privacy counterexample

Alice is the only natural seller; public epoch-bound escrow reveals her participation. Other slots are padding or attacker-owned orders whose values/results the attacker knows. Alice's ask is either6 or10. Attacker bids8: a fill means ask6; no fill means ask10. This reveals protected content and accepted identity without breaking MPC. Padding, hidden certificates, no public clearing price, opaque receipts and library isolation do not remove this information. [Kerb review lines 7–11]

**Recommendation [INFERENCE]:** validate a redesign of collateral/membership AND compositional active-probe/output leakage before a funded-private release. Hiding membership alone is insufficient. Any reduced privacy requirement or deliberately non-private settlement experiment is an explicit owner decision, not an engineering shortcut.

## 6. Why Ziquid matters, and why its design must not be imported into Kerb

Ziquid is another prospective caller of common source/context libraries. It owns unsigned P, complete locally authorized/proved competing Q on the same real input, independent durable user payout witness, complete source/history/effect/classifier/hidden-payment uniqueness proofs and actual local native-EVM transfers. Direct app proofs bypass Zoss receipts. Its documented approved frame is not implemented settlement and its local-EVM research is not Zoss EVM support. [Zoss private_dex lines 3–45, 89–95]

The reusable lesson is authority separation, not Kerb adopting P/Q/solver escrow. The rejected receive-only money escrow illustrates why callback rollback/timeout cannot recover already-paid source funds or prove nonpayment. Zoss's B1–B5 retain that failure record, not a launch backlog. [Zoss private_dex lines 67–83; BLOCKERS lines 67–80]

## 7. Readiness and recommended sequence

Authoritative current status stays in the original registers, not this overview:

- Zoss's seven named shared-library acceptance rows are Open: context/authorization, real source integration, trust-result separation, caller capability isolation, target-safe packaging/clients, replay/policy authority and usable pinned artifact lifetime. [BLOCKERS lines 89–103]
- Optional messaging G1–G6 and Z1–Z8 remain Open. G4 is deferred beyond non-money scope, not a privacy pass; Z7 reverse direction is outside scope. B1–B5 are rejected-escrow/app-impact history, not mandatory core launch milestones. [BLOCKERS lines 41–80]
- Kerb GD1–GD7 are not passed; GD2 is a known design FAIL, not merely unrun. GD7 applies only if diagnostics are enabled; library reuse does not require it. [Production-demo design lines 243–257]
- Exact real-asset qualification, independent operators, legal/eligibility, demand and net savings remain separate obligations. No qualified xStock mint, measured bilateral advantage or named demand cohort is established by these architecture docs. [Kerb docs README lines 48–53; roadmap16 lines 20–35]

Recommended sequence [INFERENCE], consistent with Zoss's build brief:

1. Review/synchronize the newer concrete shared encoding/namespace/epoch/cohort choices without changing gate statuses by prose alone.
2. Exercise real context/source integration and two isolated caller-owned consumers; build the independent local Solana non-money path after shared contracts settle. These are separable workstreams.
3. Complete persistent optional watcher/relay faults and actual testnet→devnet route only when selected and separately authorized; never make them Kerb funding prerequisites.
4. In parallel at the design/research level, resolve Kerb's GD2 mechanism failure. Then pursue separately approved FAA/MPC/holds/custody/settlement/recovery evidence. Zoss readiness cannot waive these gates.
5. Keep real-asset, legal, issuer, operator and demand validation independent of synthetic integration success.

## Sources

All sources were retrieved locally for this review on 2026-10-02; source line references above refer to that read snapshot. Source documents may change concurrently. External claims retain their documents' original retrieval/version scope.

- [Zoss overview](../../../../../../zoss/docs/README.md)
- [Zoss canonical architecture](../../../../../../zoss/docs/ARCHITECTURE.md)
- [Zoss sole readiness register](../../../../../../zoss/docs/BLOCKERS.md)
- [Zoss Kerb consumer contract](../../../../../../zoss/docs/kerb.md)
- [Zoss private DEX consumer contract](../../../../../../zoss/docs/private_dex.md)
- [Zoss build/ship brief](../../../../../../zoss/docs/reviews/2026-10-01-zoss-readiness-review.html)
- [Zoss implementation-session prompt](../../../../../../zoss/docs/reviews/2026-10-01-implementation-system-prompt.txt)
- [New Zoss product build design](../../../../../../zoss/docs/superpowers/specs/2026-10-01-zoss-product-build-design.md)
- [New Zoss implementation plan](../../../../../../zoss/docs/superpowers/plans/2026-10-01-zoss-product-build.md)
- [Kerb reading order](../README.md)
- [Kerb current authority](../00-CANONICAL.md)
- [Kerb integrated candidate](../docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md)
- [Kerb adversarial findings](../docs/superpowers/specs/2026-10-01-kerb-design-review.md)
- [Kerb system architecture](../architecture/03-SYSTEM-ARCHITECTURE.md)
- [Kerb off-chain operations](../architecture/06-OFFCHAIN-SERVICES.md)
- [Kerb threat model](../security/07-THREAT-MODEL.md)
- [Kerb verification obligations](../security/08-TEST-AND-VERIFICATION-PLAN.md)
- [Kerb roadmap/decisions](../product/16-ROADMAP-AND-DECISIONS.md)

## Checks performed by this review

- Enumerated the Zoss docs tree and read all nine documents, including the build design and implementation plan added during the review.
- Inspected repository entries and searched for the four named implementation-manifest types in both repositories; none found at the inventory check.
- Independently recomputed proposed public-body and inline-plaintext sizes:288 and119 bytes respectively.
- No runtime, privacy, upstream compatibility, transaction-size or deployment verification is claimed.
