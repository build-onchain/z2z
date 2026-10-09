# Architecture review — expanded Ziquid / future Z2Z

**2026-10-02; full documentation audit and design review, not runtime/security certification.** User requests server/relayer optional with manual existing rights. Read-only scouts inspected every pre-redesign current/native doc plus all 53 Kerb imports and relevant source exports. Primary research in [server independence](SERVER-INDEPENDENCE-RESEARCH.md) and [crosschain/market](CROSSCHAIN-MARKET-RESEARCH.md) records source URLs/pins/quotes/retrieval and limits. Current [architecture](../ARCHITECTURE.md), [product](../PRODUCT.md), [independence workflow](../SERVER-INDEPENDENCE.md), [modules](../MODULES.md) and [blockers](../BLOCKERS.md) own proposed cutover; [status](../NATIVE-IMPLEMENTATION-STATUS.md) owns observed code.

## Decision and rejected shortcuts

Recommended shape is owner-local authorization/witness/proof, route-specific immutable onchain asset authority, and replaceable discovery/matching/relay. Retain native route independently; no custody-ledger merge presented as trustless, no new rollup/global chain/omnibus credit built to avoid source facts. A deployment-scoped programmable-chain note ledger and atomic mutually authorized exchange can be researched separately; it does not solve inherited strict matcher-output privacy or source ZEC control.

Highest-priority blockers remain: complete accepted Zcash history; arbitrary-hostile private ownership/net witness availability; actual S-authorized source excess-return capability; DEX composed financial proof/verifier/escrow/client; strict GD2 incompatibility; actual proof resources/assurance and data/secret recovery; issuer/chain/venue/admin permissions. No safe pending is counted independently terminal completion. No privacy waiver, FVK disclosure, source custody override or economics change selected.

## Cutover dispositions

- Refactor live owners and five module contracts into system/route/data/manual lifecycle rather than future-lane append-only prose.
- Prior research/audit/overview/design/plan headers identify date and superseded live assumptions; retain all actual evidence, source caveats, model findings and approval scope.
- Preserve old architecture/module snapshots with hashes/link-only relocation under `history/`; preserve imported source records against MANIFEST byte hashes.
- Target/SDK README clarify absent full verifier/escrow/client/manual consumer, current native role versus deferred product UI.
- Research sources are reviewed source/vendor statements, not deployed behavior or new measurements. Independent claim/architecture review and documentation verification are recorded below only after observed output.

## Design smoke and evidence ceiling

A throwaway dependency-free state/quantity model was executed in this documentation task. **44 reachable-state visits** checked conservation, rejected stale/replayed capability generations, rollback on simulated failed transfer, partial successor remainder and a single cancel/fill winner. A two-world privacy trace (buyer limit8, honest seller limit6/10) checked different feasible outcomes. These are **model checks only**, not real contracts/circuits, crypto, chain/finality, liquidity, atomic crosschain exchange or company-off runtime tests. The actual drills in SERVER-INDEPENDENCE remain Unrun until implementation and relevant action authorization.

## Coverage sources and editorial treatment

Original native audit lists **26 pre-redesign non-import Markdown files**, including root README, all canonical/modules/history plans and target/SDK READMEs; it additionally read new redesign/independence drafts and research. Kerb audit lists **all 53 source-relative imported Markdown files**, plus wrapper/manifest/link report and targeted sibling source. The complete tables/findings follow so no historical business/legal/pitch/mechanism scope is silently discarded.

### Native audit (attributed read-only inspection)

# Native docs audit — exhaustive compressed coverage

## Scope and evidence

Read completely: every original non-import Markdown document (26), root README included; plus new parent drafts `SERVER-INDEPENDENCE.md` and Oct2 redesign spec, and newly landed `SERVER-INDEPENDENCE-RESEARCH.md` (29 total). Long lines reread raw. Inspected actual Rust/Solidity/TypeScript exports, manifests, critical implementations and relevant test scenarios. Imported Kerb archive excluded from this assignment; preserve its bytes/history. No builds, tests, lint, formatting, smoke commands, Git, transactions or repo changes performed. Existing run/review results are attributed to NATIVE-IMPLEMENTATION-STATUS, not independently rerun.


## Verdict / blockers

Canonical financial safeguards are mostly honest and load-bearing. Active module bodies still reopen superseded choices and carry stale permission/import/maturity prose. Code has genuine primitives, not complete settlement or full manual consumer. Parent samechain note/control proposal is a **new proposed relation**, not replacement for full native scope, custody escape or private-matcher feasibility.

- **P0 Hostile-T witness availability:** arbitrary valid T can consume agreed U input plus concealed other-party inputs; S IVK/raw bytes do not reveal complete input values/owners/zero-dummy openings. zkVM cannot recover missing facts. Status blocker2 explicitly requires independently terminal every hostile spend. Unknown is safe but **not completed protocol**; wallet input restriction cannot exclude hostile T.
- **P0 Excess C>A:** original Q cannot spend funds already received by S. Target proof cannot sign ZEC return. Status blocker3 requires actual independently usable S-authorized return, exact value/recipient/fees/effect/history proof. No gift/clamp/full-destination-refund/cooperation promise substitute.
- **P0 Full source proof:** body parsing/header ancestry/pre-Overwinter ledger do not implement all-era genesis→Ironwood consensus, accepted fork/finality or complete historical acquisition. Every pool/unrelated transaction/predecessor state matters. Best submitted work is not globally canonical; honest competing-history/freshness/anti-eclipse is **safety**, not just liveness.
- **P0 App proof/escrow/client absent:** nonzero context fields and general SP1 base verifier do not authenticate financial policy, receiver/net relation, stable hidden note tag or irrevocable arming. No real DEX escrow/fund/settle/transfer/client/full manual driver.
- **P0 Strict GD2:** inherited attacker-controlled trader own result/price/assets/refund inference remains structural FAIL. Samechain atomicity and owner consent do not establish noninference. No waiver/collusion narrowing/MPC-or-HyperCore remedy approved.
- **P1 Prover/resources/assurance:** real guest execution is not wrapped certificate; existing status records 4GiB OOM/no certificate, PK/circuit/archive TOFU, setup ceremony unqualified, independent program pin and actual target positive/mutation acceptance missing. 64GiB recommendation unmeasured, not normal-laptop capability.
- **P1 Q lifetime:** S may broadcast before funding, causing disclosed fee/option cancellation. Final Q cannot auto-reanchor; branch/expiry/fee/anchor failure can strand armed capital. No timer/admin refund or guaranteed window.
- **P1 Artifacts/data/governance:** public verifier/hash/root is not retained circuit/PK/secret/ciphertext/history availability. Default autonomous rights need no company allowlist/signer/pause/sweep/latest-registry veto over funded claims; issuer freeze/chain censorship/gas/secret loss remain separate limits.
- **P1 Custody:** source Kerb ZEC still needs native custody signers. Funding proof/credit/Solana verifier does not confer ZEC spend authority if committee disappears/refuses. Relayer replacement is not signer replacement.
- **P1 Durable lifecycle:** current encrypted preparation custody lacks wallet note reservation and P-release journal; SQLite funding fence lacks signed payload reconciliation and terminal financial release. Restore artifact/DB is not authorization. Backup rollback/tombstones/same-UID/root/private backup risks remain explicit.
- **P1 Actions:** no authorized real-note/source action, broadcasts, deployment/funding/mainnet or new private-view/prover delegation established. Docs task cannot close network gates. Distinguish missing code/capability from missing action permission.

## Every-file inventory and disposition

R=refactor active requirements/navigation; H=retain dated history, correct only misleading live pointers; K=keep factual checkpoint/disclaimer. References describe inspected pre-parent-rewrite text.

|#|File|Read and disposition|
|---|---|---|
|1|`README.md`|All. R/K: accurate primitives/no-swap/generated-fixture/direct-proof/Zoss/storage warnings. Add manual-core and route authority limits; no proposed note ledger as implemented; keep action/naming limits.|
|2|`docs/README.md`|§§1–6. R: canonical navigation, independence/research/review owners and manual-native≠deferred SDK. Retain every lane/archive boundary.|
|3|`docs/PRODUCT.md`|§§1–8. R: preserve RFQ/P2P/external spot/GD2/custody; strengthen company-off existing rights by route. Samechain proposed, not silent native/Solana↔Zcash replacement.|
|4|`docs/CONSOLIDATION.md`|§§1–5. R/K: preserve source hashes/provenance/no code migration or rename; dated redesign/authority supplement without rewriting source approval scopes.|
|5|`docs/ARCHITECTURE.md`|All §§1–11/E1–E21/diagrams. R: retain native §7 financial rules, every lane/GD2; reorganize authority/data/manual path, link policy/status owners rather than delete requirements.|
|6|`docs/MODULES.md`|All §§1–7.3/16 repo precedents. R/K: existing acyclic role/path intent, module≠crate/process/repo, private owner isolation. Map manual reconstruction/bundles/proposed relation to existing roles, no new scaffolding/package migration. Survey dated source, not compatibility.|
|7|`docs/BLOCKERS.md`|All S/P/U/A/F/D/expanded requirements/decisions/evidence. R/K: preserve IDs/all-hostile/excess/GD2; add company-off authorization/data/artifact/manual evidence per route. No inherited gate closure.|
|8|`docs/NATIVE-IMPLEMENTATION-STATUS.md`|Entire inventory/run ledger/commands/6 blockers. K: strongest current checkpoint; add absent consumer operations. Retain generated/native/guest/local-VM/source-network boundaries and OOM/TOFU limits; no aggregate sibling results.|
|9|`docs/modules/wallet-authoring.md`|§§1–5. R/K: actual P/Q top, stale “libraries/circuit encoding not selected” body. Distinguish private preparation relation from missing wrapped/composed no-FVK S certificate; add native durable note/release/bundle lifecycle.|
|10|`docs/modules/zcash-proofs.md`|§§1–6. R: full-validation header versus SPV/Open strategy body; proportional rounding called unresolved; “current classifier” although none implemented. Retain complete inputs/net/output/history/privacy witness requirements.|
|11|`docs/modules/destination-settlement.md`|§§1–6. R/K: retain irrevocable arm/fixed U/S/atomic transfers/retry/lifetime; binary diagram and blanket pro-rata unresolved conflict with approved formula. Explicit missing actual escrow/client. Samechain cancel ≠ armed native cancel.|
|12|`docs/modules/solver-operations.md`|§§1–6. R/K: real SQLite/file fences; stale no imports/Zoss exports. Capacity must be TOTAL including active reservations. Keep signer/prover/Q capabilities and absent terminal reconciliation clear.|
|13|`docs/modules/client-sdk.md`|§§1–7. R: SDK empty/deferred correct; frame-only native approval/no Zoss integration stale. Native essentials owned by core/independence, not TS acceptance; retain ETA/privacy/errors.|
|14|`docs/SETTLEMENT-RESEARCH.md`|§§1–6/R1–R10/graphs/models. H: preserve reverted-claim/absence/conflict/FVK research; header current frame/no integration stale. Delegated reanchor/FVK and activation cutoff historic alternatives, not current requirements.|
|15|`docs/ARCHITECTURE-AUDIT.md`|§§1–9/A1–A17/models. H: retain all counterexamples, not deployed vulnerabilities; exclusion-only flow/L cutoffs/frame/SPV/transfer-choice reopening dated. Add supersession map/current pointer without rewriting model claims.|
|16|`docs/ZOSS-OVERVIEW.md`|§§1–7. H: Oct1 explicitly dated maturity/CLI snapshot. Docs-only Zoss/four libs/runtime binary/no imports not current; keep full-block caution/separate authority/GD2 and current status pointer.|
|17|`docs/ZIQUID-IMPLEMENTATION-SYSTEM-PROMPT.md`|Entire mission/graph/M1–M5/runtime/verify/completion. R: runtime binary stale; encode selected full validation/proportional/one-deployment, all-hostile actual excess/manual acceptance. Copied prompt not code/action authority.|
|18|`docs/superpowers/specs/2026-10-01-native-protocol-implementation-design.md`|§§1–8. H/K: owner choices retained; starting point/docs-only/no guest/candidate0.16 prerelease dated, not current. Point to actual selected cohort/status.|
|19|`docs/superpowers/plans/2026-10-01-native-protocol-implementation.md`|All constraints/contracts/bootstrap/10 tasks/self-review. H/K: unchecked boxes not current inventory; candidate0.10.6 superseded by0.10.5; original proposed review wording not later choice authority. No fabricated completion ticks. Manual Task8/10, not SDK.|
|20|`docs/superpowers/plans/2026-10-01-ziquid-workspace-frame.md`|Full four-step frame plan. H: frame approval historical; no Git/empty slot meaning retained; stale live future-only imports pointer corrected, not current permission ceiling.|
|21|`docs/superpowers/plans/2026-09-28-architecture-doc.md`|Full scope/items/checklist. H: public LP/attested/source-refund-first/old G4/contest evidence dated; current frame/no integration pointer stale.|
|22|`docs/superpowers/specs/2026-09-28-global-docs-design.md`|§§1–6. H: one-engineering-doc/Attested/public-first record not ban on current module docs; stale current frame/import pointers only.|
|23|`contracts/evm/README.md`|All. K: general base verifier/allocation, no real certificate/app escrow/deployment. Immutable base ≠ immutable app policy; independently pinned program/certificate target acceptance still needed.|
|24|`contracts/solana/README.md`|All. K: independent empty target, no program/ID/escrow/route; no inherited Kerb network support.|
|25|`contracts/near/README.md`|All. K: empty target, no ID/NEAR settlement/1Click approval.|
|26|`packages/sdk/README.md`|All. K: private ESM frame/export nothing, no wallet/manual bindings; build not financial readiness.|
|27|`docs/SERVER-INDEPENDENCE.md`|New parent §§1–8. R/proposed: good authority/data/bundle/native matrix and custody/venue limits; add complete open/partial/terminal stages/fee binding/root policy; no current code or GD2 solution.|
|28|`docs/superpowers/specs/2026-10-02-z2z-server-independent-architecture-design.md`|New parent §§1–7. R/proposed: smallest onchain-rights pattern, not rollup/custody merge; native all-hostile/excess/GD2 intact; design only, not implementation/waiver.|
|29|`docs/SERVER-INDEPENDENCE-RESEARCH.md`|New sibling §§1–11/T1–T8/E1–E6/Z1–Z6/R1–R8/CI1–CI13, fully read after landing. K/proposed: strong source/caveat ledger, source versus deployed/matching distinction, bind-bytes≠recoverability, immutable≠DA, relayer fee and partial successor limits. Independently re-fetched only native sources listed below, not every new research citation. Retain Unrun drills and company-off kit.|

## Active contradictions / precise correction

1. **High:** proof spec `:24,55,60` reopens SPV/source-consensus strategy, contradicting own header, native design§3/plan constraint19/BLOCKERS supplement. Full validation selected; exact bootstrap/forks/all-era/backend qualification remains Open, no SPV fallback.
2. **High:** proof§3 `:103`, destination§4 `:80`, SDK partial blanket wording call pro-rata/rounding unresolved, versus architecture§7.1/destination§3/plan approved floor/dust. Economics chosen for authenticated0≤C≤A; circuits/hostile witnesses/transfers/excess still missing. Correct binary diagrams.
3. **High:** unbounded delay disclosure versus all-hostile independent terminal requirement: missing witness/capability is admission/release blocker, not supported completion. Temporary chain delay differs from permanent information absence; no arbitrary-halt finite guarantee.
4. **Medium:** wallet§1/proof§1/solver header§1§5/SDK header stale no installed source/imports/only-frame. Actual zcash manifest/source and runtime manifests/libs prove limited NodeRpc/current imports; broader reuse still Proposed, financial gates unchanged. zcash currently has no protocol dependency despite intended map: label intended versus actual.
5. **Medium:** handoff`:44` current runtime binary obsolete; actual library exports store/custody, imports protocol/zcash/proofs. No chains/full orchestration.
6. **Medium:** wallet`:30` circuit/encoding unchosen versus complete private deterministic relation/codec/guest. Missing wrapped independently pinned S certificate/history/tag semantic openings/Q Halo2 guest checks remain—not no local relation.
7. **Medium:** native plan candidate0.10.6/design0.16 prerelease versus current0.10.5/0.15.5/0.30.1. Dated candidates/supplements, not silent pin changes/repeated approvals.
8. **Medium:** research/audit/Sep28 live “current” pointers and exclusion-only/L-cutoff flows stale. Retain dated body/source/model counters untouched, concise superseding choices.
9. **Medium:** solver§3 post-obligation “spendable” cap versus ActorStore TOTAL cap including all active reservations. Passing net remaining balance double counts holds. Caller-selected actor/asset/deployment cap is not verified chain balance.
10. **Medium:** manual prepare/restore/prove/arm/sign/submit/reconcile not deferred SDK feature; native contract owns safety, SDK future consumer. Current CLI no full lifecycle.
11. **Trust decision:** official SP1 approved-prover recommendation includes whitelisted oracles. Mandatory company approver would violate default independence and is unapproved; record assurance gap, don't invent whitelist or claim vendor advice proves permissionless financial safety.
12. **Scope:** samechain note rights new proposed relation, not private matching, ZEC custody, native witness fix, bidirectional bridge or replacement workstream.

## Exact native transition/invariant contract

1. **Draft→RecoveryPrepared:** exact context/quote, one genuine valid available U Ironwood note; nonexecutable unsigned P; complete local Q same authenticated real input, every dummy/action/signature/binding, every nonzero self-output/ciphertext/fee. Durable independent U payout witness before export. S no U FVK/spend key and independent certificate before funding; certificate remains missing. Q grants early cancellation only.
2. **Reservation/funding intent:** persist exact operation before export/sign/send. Actual Reserved→Cancelled only pre-prepare; FundingPrepared/Unknown/Armed fence capacity even before tx hash. Proven-no-effect release needs real reconciliation, not TTL/no response.
3. **RecoveryPrepared→DestinationArmed:** exact D/fixed U,S/deployment/code/verifier/program/policy/statement; fund+arm+stable note reservation atomic, deployment-wide across supported versions. No S withdraw/cancel/rewrite/sweep. U independently observes authentic finalized immutable state before P authorization; API/event/quote insufficient.
4. **Armed→SourceResolutionPending:** persist exact release then sign/complete/release/send P; same-effects rebroadcast, no fee/input/output/expiry/branch replacement. Early P/T by another wallet remains reachable; earlier bound accepted history admitted if funded, but S not compelled to fund user who self-paid early.
5. **Resolution SAME accepted valid finalized history:** same-effect/new auth/anchor remains P; real same-pool/network conflict excludes exact P only. Process complete inputs/outputs/receiver/ciphertext and net consideration, not T≠P or IVK gross. S debitA/creditA gives net0, not U full payout. Equal bytes other pool/dummy not conflict. Unknown nonterminal, no nonpayment implication.
6. **Authenticated0≤C≤A:** A,D>0, U=floor(D*C/A), S=D−U, dust fixed S, no hidden fee. C0 requires actual nonpaying same-real-input conflict; partial irreversible source resolution/net proof. C>A actual authorized/proven source return before completion, no gift/clamp/refund shortcut.
7. **Ready→terminal:** full proof/context/history/classification/uniqueness verification, once-only consumption and both fixed native transfers atomic rollback; zero share no call. Failed/reentrant/OOG/recipient reject retains valid retry, no beneficiary/opposite-allocation change. Completed actual destination effects/finality+source consideration; Refunded actual S refund+nonpayment conflict (Q actual U self-return too). Proof flag/log/credit/tx hash/QBroadcast/Zoss Delivered not paid.
8. **Pending/lifetime:** valid evidence resumes; expiry stops late mining, not earlier payment claim. No timer/admin/quorum/claim deadline/latest-registry rewrite or expiry-based verifier retirement. Original usable proof/data/witness/resources until terminal; competing history safety, censorship/halt/gas/permanent refusal limits explicit.
9. **Uniqueness:** one authenticated real note arms one obligation within selected deployment across versions, stable secret-derived relation not free nonce/salt/tag. Fund failure rollback; terminal consumption retained. Other targets/deployments unsupported, not invented global guarantee. Zoss receipt/replay independent.

## Actual export/manual consumer map

- `protocol` exports StatementContext/ValidatedContext/amounts/allocate: 474-byte BE DEX testnet/Ironwood/native-EVM wire SHA256, shape checks any nonzero branch/policy/program/code. No semantic opening/checkpoint/financial fact/tag derivation/state machine; not ABI/Zoss encoding.
- `zcash` OwnedInput/SourceParameters/OutputPlan/prepare: genuine local V3 ownership/path and P/Q construction, explicit conservation; no note-chain admission/unspentness, wallet durable reservation/P release/destination arm check.
- PreparedPair unsigned_payment/payout_witness/private_recovery_pczt_bytes/finish_recovery: redaction, private sender openings, all-action local Q proof/sign/extraction with borrowed ask. No S wrapped certificate/autonomous reanchor/funded authorization/P finish-submit interface. Private Q PCZT U-only.
- IronwoodTransaction parse/verify_authorization: canonical Ironwood-only v6 and full local SpendAuth/Halo2/binding; not anchor/spentness/fee/U ownership/finality/consideration.
- PayoutWitness restore/recover outputs: exact requested output-action mapping/full ciphertext without S IVK; not inclusion/net arbitrary-T proof or release approval.
- source::acquire_historical_block + runtime acquire_source example: real sibling NodeRpc NU6.3 testnet raw bytes, DEX structure, UNVERIFIED/Unknown. No genesis-era/raw all-history/financial proof/submission. Sibling source needed; Ziquid clone alone not self-contained offline build.
- proofs preparation+guest: one authentic local note/FVK/path, zero dummies, exact effects/ciphertext/Q signatures/fees, blinded context/packet journal. Explicitly no guest Q Halo2, source-history/admissibility, semantic commitment/tag opening, classifier/uniqueness or successful wrapped S certificate.
- artifacts execution/local: actual CPU guest and explicit qualified local wrapping APIs/preflight, independent ELF/program pin required. Existing run records no certificate; no composed history/financial prover.
- genesis/header/history/sprout/legacy crypto/ledger: authentic subrelations; pre-Overwinter testnet heights1..207499, rejects207500 onward. Recorded connected0..10 only; no all-era forks/finality/full history SNARK. Historical equations don't repair old soundness.
- runtime custody save/load: Linux immutable encrypted complete P/Q/mapping, independent namespace/context, full local Q/restore/durable barriers. No wallet P-release journal/approval/terminal/return. Same-UID/root/backups outside guarantee, parsed allocations not fully erased claim.
- ActorStore: transactional total-cap U256 reservations; immutable prepared→Unknown/Armed observations and reserved-only cancel. IDs/digests only, no signed payload validation/send/finality/reconcile/terminal release/source note reservation.
- ziquid CLI: help/version/allocation only. Examples generated P/Q, journal fence and raw structure. No all-stage prepare/fund/arm/P release/classify/prove/settle/retry/bundle/status workflow.
- EVM only Allocation/general pinned base verifier: caller programVKey, SHA256 journal/fixed recursion root; no DEX app policy/tag/funded escrow/ABI/transfer. chains empty, Solana/NEAR empty, SDK export{}.

## Durable bundle and full manual lifecycle

**U private:** canonical funded context, exact private P/all note+dummy+output openings/FVK/path/anchor/action mapping, sender recovery material, complete allowed Q, original policies/programs; durable reservation/export/consent/sign/release/signed bytes; separate user-controlled encryption/backup. No public secret/PCZT/argv/log/relayer witness.

**S private:** unsigned P identity/openings, verified preparation/composition certificates, final Q/own receiver binding/view data, independently obtainable classifier/recovery witnesses without U, actual authorized excess-return capability, private quote/source mapping, inventory/sign/funding/Unknown/terminal journal. Existing SQLite ID fence not this full bundle.

**Public retained bytes:** source/circuit/prover/VK/PK/program/toolchain/upstream/Zoss pins and source, ABI/code/network/policy descriptors, setup assurance, full relevant authentic history/predecessor proofs and target commitments/ciphertexts/nullifiers. Hash/CID/root isn't availability/soundness. Independent archives/mirrors/cold local copies and actual restore required; old witness may need valid update, accepted roots/rollover/full-tree exit/reorg/branch/expiry/fee rules concrete. Backup rollback must not resurrect consumed rights or funding.

|Stage|Required independent action|Restriction/current gap|
|---|---|---|
|Cold company-off install|Pinned tool/source/artifact/ABI copies; independently authenticated chain/history access|No company hostname/login/license/bootstrap signer; packaging/manual driver not qualified|
|Draft/prepared/quote|Local prepare/restore/check exact terms/Q and retain source note control|Discovery/liquidity may stop; shared Q early cancellation persists|
|Open/unfilled samechain (new)|Owner exit/cancel consumes same backing/intent as fill|No company epoch ACK; no implementation or native armed cancel|
|Partial samechain (new)|Recover filled proceeds+disjoint residual note/quantity/rights; cancel/fill residual|Chain race one winner, old capability replay/fresh random note capacity reset reject; GD2 still blocker|
|Prepared/Unknown funding|Reconcile exact original operation before retry/release|No RPC-absence/no effect; current journal no financial reconciler|
|Native armed|Independently verify final code/context/amount/rules and source lifetime; exact P or valid resolution|No S timer/cancel, user leaving UI not nonpayment|
|P/Q/T submitted Unknown|Retain exact bytes/acquire complete accepted history/classify|No competing intent on timeout/effect-only auth substitution/T≠P refund|
|Payment/proof ready|U local prove without S IVK/new company signature, self-submit/arbitrary relay fixed shares|Composed wrapped proof/target client absent|
|Nonpaying conflict|S independent eligible proof, Q self-output relation|Final Q doesn't manufacture missing private/history facts/reanchor|
|Mixed/excess|Independent terminal classifier and actual authorized source return|Capability missing; pending not delivery|
|Failed transfer|Same valid pinned entitlement/proof/beneficiary retry with gas or alternative submitter|No redirect/consume-credit-as-paid/opposite refund; permanent refusal limit|
|Terminal/restart/new version|Observe actual final effects; retained consumption/tombstone/backup reconcile|No double funds/payout on rollback/cache loss/new salt/version; no old rule retirement|
|Custody/venue/provider|Expose actual remaining signer/provider/venue rights, direct native tools where allowed|No unilateral ZEC custody/issuer unfreeze/censorship immunity/new liquidity/crosschain atomicity|

## Refreshed primary-source claims (retrieved 2026-10-02)

Other E/R citations/past evidence and newly landed research ledger remain attributed, not a fully refreshed bibliography.

- [ZIP203](https://zips.z.cash/zip-0203), Motivation: “transaction must be included in block N or earlier. Block N+1 will be too late”; Specification zero disables expiry. Supports inclusive consensus expiry, not refund/asset reversal or guaranteed time.
- [ZIP229](https://zips.z.cash/zip-0229), Terminology: Ironwood “its own note commitment tree, anchor, and chain value pool balance, distinct from the Orchard pool”; Motivation anchors “authorizing data rather than effecting data.” Supports separate pool/reanchor proof capability, not app recovery/network acceptance. Retrieved Draft; pinned raw .rst URL404, official page alternate, no inference from failure.
- [ZIP374](https://zips.z.cash/zip-0374), Proof delegation: prover “requires the note's private data and full viewing key, but does not require any spending key material”; Privacy PCZT receiver learns all present data. Supports local scope/private custody/permissionless submit≠witness discovery, not app proof. Official revision0 Draft.
- [ZIP244](https://zips.z.cash/zip-0244), Abstract IDs “commit to all transaction data except for attestations to transaction validity”; Motivation stable despite proof/signature recomputation. Supports effect≠auth and same-effect identity; v6 extensions still ZIP229, no root-only validity.
- [Zebra v6.4.2 nullifier source](https://raw.githubusercontent.com/ZcashFoundation/zebra/v6.4.2/zebra-state/src/service/check/nullifier.rs), Consensus: “A nullifier MUST NOT repeat ... across transactions in a valid blockchain”; pools “disjoint, even if ... same bit pattern.” Supports same-pool conflict, not nonpayment/canonicality.
- [Immutable Zebra network source](https://raw.githubusercontent.com/ZcashFoundation/zebra/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-chain/src/parameters/network.rs), mandatory checkpoint comment: “Zebra can't fully validate the blocks prior to Canopy.” Supports reuse limitation, not impossibility of all other strategies.
- [Immutable SP1 v6.1.0 verifier](https://raw.githubusercontent.com/succinctlabs/sp1-contracts/d3629729c3216eb51bd4859d027a8eb729399fa4/contracts/src/v6.1.0/SP1VerifierGroth16.sol), verifyProof caller programVKey/journal, hashPublicValues sha256, fixed recursion root/exitCode0. Supports actual base relation, not allowed app policy/financial acceptance. No hash comparison/target execution performed.
- [SP1 security model](https://docs.succinct.xyz/docs/sp1/security/security-model), Program Safety: “proof of correct execution for the user-provided program”; ZK: individual STARK proofs “do not currently satisfy the zero-knowledge property”; Trusted Setup toxic-waste assumption; Approved Prover whitelisted provers/oracles additional sanity check. Mutable vendor advice/general model, not independent/version-specific audit; do not add company veto or infer readiness.
- [ECC CVE-2019-7167](https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/) now redirects [Zodl archived article](https://zodl.com/zcash-counterfeiting-vulnerability-successfully-remediated/), Counterfeiting details: bypass elements “allow a cheating prover to circumvent a consistency check ... This breaks the soundness of the proving system.” Supports historical acceptance≠retroactive soundness; not a current-counterfeiting or no-counterfeiting assertion.

## Minimal coherent cutover

Existing PRODUCT/ARCHITECTURE/MODULES/BLOCKERS/status owners remain; independence detailed requirements not second gate register. Each module: active contract, actual exported primitive, missing acceptance. One native state/economic contract in architecture, one observed checkpoint in status, one gate/permission register. Historical research/audit/spec/plan/overview retain findings/source/approval scope, no live contradictory rules. New samechain note relations proposed; native entire scope/all-hostile/excess unchanged; custody operator-dependent/GD2 blocking; all external/public/deferred lanes retained. Manual native consumer/data/artifact company-off drill is core acceptance, not deferred UI. Parent owns integrated doc/link/provenance verification; no readiness gate changed here.

## Imported Kerb audit (attributed read-only inspection)

# Kerb whole-document audit for expanded Ziquid / future Z2Z

Read-only research/design audit, 2026-10-02. Reviewed ALL53 imported Markdown docs:29 docs/,18 zolana-review-2026-09-29/,6 zolana-research-2026-09-30/, plus wrapper, complete manifest and link report. Ranged/raw reads reached document endings. Targeted sibling implementation reads corroborated interfaces, not a whole-code security audit. Selected official primary sources were freshly fetched. No build/test/lint/format/runtime/Git/network transaction/deployment checks ran; historical results are source-reported, not rerun.

Archive-relative paths below are under docs/imports/kerb/. Sibling source paths are under ../kerb/. Current unified authority remains docs/PRODUCT.md, CONSOLIDATION.md, ARCHITECTURE.md, MODULES.md, BLOCKERS.md and NATIVE-IMPLEMENTATION-STATUS.md. Parent docs/SERVER-INDEPENDENCE.md proposes new company-independent samechain chain-controlled notes; it is unimplemented and does not replace the original Kerb strict matcher requirement.

## 1. Conclusions and preserved product scope

Two distinct unresolved conflicts: (a) exact private auction fails strict noninference when matcher controls/colludes with a legitimate trader and sees its own result/assets; (b) threshold-custodied native ZEC has no unilateral user exit if spend quorum refuses/disappears. MPC/encryption/commitments/proofs/replicas/arbitrary Solana fee payer solve neither by themselves.

Source local safety code exists. Its protocol/Postgres/compiled local legacy-SPL/unsigned Ironwood PCZT modules implement useful safety responsibilities. Actual source/history acquisition, FAA/MPC matching, native proving/FROST signing/broadcast/payment, independent operators and strict privacy remain unestablished. No implementation imported into Ziquid and no test evidence combined across repos.

Signed bilateral samechain settlement is a distinct feasible design question: both owners consent to semantic exact terms and a contract controlling both qualified assets performs one atomic transition or reverts. It changes price discovery/auction guarantee and accepts the information inherent in consent/own assets; NOT a GD2 solution. Hidden commitment, signature or proof bytes alone do not establish backing, custody/control, semantic agreement, witness availability or recoverable outputs. Parent proposal correctly leaves construction open.

Preserve ALL targets: first native one-way Ironwood ZEC→local EVM with complete validating source proofs, proportional allocation, one-note/one-obligation, independent recovery/payout and actual excess return; private P2P with distinct synthetic SPL/testnet ZEC, canonical USDC/native ZEC and exact-qualified xStock/native ZEC profiles; eligible Hyperliquid-asset P2P; separate external HyperCore spot; user proof submission; Solana destination candidate; Base Sepolia staging; public LP/swap; optional 1Click; agent; future ZSA. Deferred/blocked/different guarantees are not deleted. Historical public-Solana xStock/USDC + residual-maker mechanism remains provenance, not approved substitute.

## 2. Exhaustive coverage and classifications

C=current source direction/constraint or attributed local checkpoint, not unified approval. M=current dated prefix plus historical body. F=unapproved financial/private candidate, known privacy failure. H=historical proposal/research/plan, still relevant evidence. P=provenance capture, author assertion/opinion rather than demand/permission.

### 2.1 All29 files under docs/

| # | Exact reviewed archive-relative path | Class | Key finding |
|---|---|---|---|
|1|docs/00-CANONICAL.md|M|§0 current library/financial separation and GD2; §§1–6 old public exact-mint/USDC auction, fees/residual/issuer exits, not crosschain contract.|
|2|docs/README.md|C/M|Current source local safety evidence and explicit missing source/FAA/MPC/FROST/network/privacy; fixture native payout not mined, refund unsigned/Unknown. Historical reading order retained.|
|3|docs/architecture/03-SYSTEM-ARCHITECTURE.md|M|Current caller-private Zoss reuse and two Hyperliquid paths; old crank/maker/two-vault diagram not current custody topology.|
|4|docs/architecture/04-ONCHAIN-PROGRAM-DESIGN.md|H|Proposed program recomputes price, exact token programs, isolated epoch vaults/fixed entitlements/no sweep; unimplemented old market, upgrade risk persists.|
|5|docs/architecture/05-TOKEN-2022-ISSUER-INTEGRATION.md|H|Raw exact mint/TLV/authority/account qualification; hooks/delegates/fees/unsupported confidential flows refused; issuer freeze/pause defeats transfer; no mint qualified.|
|6|docs/architecture/06-OFFCHAIN-SERVICES.md|M|Current private source/inventory/ACL/Unknown obligations; old gateway/indexer/crank replaceability only where program already grants rights.|
|7|docs/business/10-MARKET-AND-COMPETITION.md|H|Same-mint/window dealer-spread advantage unverified; actual alternatives and counterevidence; volume≠natural paired intent.|
|8|docs/business/11-BUSINESS-MODEL.md|H|Old CROSS two5bps user sides vs RESIDUAL one/zero maker, fee6:3:1; illustrative revenue/costs not expanded fee contract.|
|9|docs/business/12-GTM-AND-VALIDATION.md|H|Unrun old preregistration ≥10 interviews/≥3 flow/≥2 tickets/one maker/≥3 both-side executable windows; thresholds not results.|
|10|docs/docs/superpowers/plans/2026-10-02-kerb-safety-core-build.md|C/H|Approved independent safety increment; successive reported81/83/99 tests/restart/physical identity, plus still-unchecked acceptance for overlap/sponsor/cancelled-return defects. Do not promote closure from README alone.|
|11|docs/docs/superpowers/specs/2026-09-29-kerb-zolana-design.md|H|Three isolated native pairs/strict goal/accepted custody research trust; broad expiry/refund/IVK statements superseded by stronger holds/inventory; old Zoss locator payload rejected history.|
|12|docs/docs/superpowers/specs/2026-10-01-kerb-design-review.md|C/F|F1 structural fail; F2 typed refund, F3 output owner, F4 nonrollback history, F5 activation, F6 roots, F7 IDs/expiry durable requirements; policy correction not runtime proof.|
|13|docs/docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md|F|FAA/private intake/MPC/coordinator/3of3 business/2of3 native/SPL-first full candidate; no public exact price; complete workflow still fails strict privacy. Arithmetic smoke not integration.|
|14|docs/docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md|C|Approved local records/journals/inventory/SPL/unsigned-native increment; real fact producers/private mechanism still separately required.|
|15|docs/legal/09-REGULATORY-AND-LEGAL.md|H|22 old public-securities-venue counsel questions: classification/distribution/custody/fees/governance/sanctions/data/routing; no opinion; frontend geofence not direct-use enforcement.|
|16|docs/mechanism/01-MECHANISM-SPEC.md|H|Max-volume plateau/half-even/proration, separate residual, aggregate fee, conserved entitlements; public input/result semantics not strict privacy.|
|17|docs/mechanism/02-MARKET-DESIGN-RATIONALE.md|H|RFQ/CLOB/AMM/oracle/solver tradeoffs; strategic limits/split/self-cross/sniping remain; no fairness/truthfulness/savings/privacy guarantee.|
|18|docs/pitch/13-PITCH-NARRATIVE.md|H|Hypothetical synthetic public-auction script/deck, not observed demo or current expanded capabilities.|
|19|docs/pitch/14-JUDGE-RED-FLAG-AUDIT.md|H|25team+25deck flags/roleplay scores, not actual judging; founder facts unknown; overtime/language/job heuristics not rules.|
|20|docs/product/15-HACKATHON-PLAN.md|H|Old public-auction calendar/demo/residual requirements; no action authorization; old scope cuts must not shrink present native/full lanes.|
|21|docs/product/16-ROADMAP-AND-DECISIONS.md|M|Current library/both Hyperliquid directions; old no-crosschain/no-privacy/Solana-only/fees ADRs historical, not present prohibitions. Fallback second authorized action after returned funds.|
|22|docs/product/17-HYPERLIQUID-EXPANSION.md|C|A eligible-asset P2P vs B external public spot, exact assets/authority/Unknown reconciliation; no perps/leverage/residual automatic fallback/proof implementation.|
|23|docs/reviews/2026-10-02-strict-privacy-feasibility.md|C|Own-price trace with genuine second seller; own-asset disposition contradiction; no output waiver; remedies change economics/guarantee or fail.|
|24|docs/reviews/2026-10-02-zolana-concept-and-actors.md|C|Both Zolana folders same native-market thesis, retained not duplicate disposal; actor/signature distinctions; local safety supersedes old empty-repo observations.|
|25|docs/reviews/2026-10-02-zoss-kerb-overview.md|H/C|Useful authority separation; no-manifests/no-code/current-gates inventory preimplementation snapshot, not present readiness.|
|26|docs/security/07-THREAT-MODEL.md|M|Current library/privacy boundary atop old public I01–I12/T01–T21; historical zero-tests applies that design, not all sibling code.|
|27|docs/security/08-TEST-AND-VERIFICATION-PLAN.md|M|Current consumer obligations + unrun old Q01–Q22; observable compiled token/account deltas, not self-agreement/text checks.|
|28|docs/sources/notion/idea-bank-row-5.md|P|T2 Verify first capture, missing exact row block ID; SG/HK/Brazil/TEE/BAM feasibility author hypotheses, no customers/clearance.|
|29|docs/sources/x/status-2038643299221729462.md|P|Archive/opinion, authenticity/pasted-original comparison unavailable; not official Colosseum rubric or100M/1B threshold.|

### 2.2 All18 files under zolana-review-2026-09-29/

Every file is historical unapproved owner-review material; some have Oct1 synchronization/authority prefixes. They preserve current native-market end goal, not current implementation approval. Known GD2 notices remain relevant.

|#|Exact reviewed archive-relative path|Class|Key finding|
|---|---|---|---|
|30|zolana-review-2026-09-29/00-CANONICAL.md|H/F|Three-pair/custody/privacy consistency, later holds/activation/GD2; no public-price/old-fee inheritance.|
|31|zolana-review-2026-09-29/README.md|H/F|18-file non-destructive review-copy mapping; later selections≠approval; known public-seller/own-fill failure.|
|32|zolana-review-2026-09-29/architecture/03-SYSTEM-ARCHITECTURE.md|H/F|Full FAA/intake/MPC/custody access graph, held acceptance, trusted signatures≠ZEC effect; message branch disabled.|
|33|zolana-review-2026-09-29/architecture/04-ONCHAIN-PROGRAM-DESIGN.md|H/F|Solana controls SPL only; exact accounts/replay/3of3 testimony/full activation/cancel-release fence; no forced native refund.|
|34|zolana-review-2026-09-29/architecture/05-TOKEN-2022-ISSUER-INTEGRATION.md|H|Exact mint/program/raw units/issuer qualification; public-balance vs confidential semantics; actual release and return required.|
|35|zolana-review-2026-09-29/architecture/06-OFFCHAIN-SERVICES.md|H/F|Receipt+claimant+inventory, portions/input→change, nonrollback unanimous journals/typed native intents; still quorum authority.|
|36|zolana-review-2026-09-29/business/10-MARKET-AND-COMPETITION.md|H|USDC/ZEC vs exact-xStock/ZEC jobs and alternatives; source gaps not market absence; synthetic research not paying demand.|
|37|zolana-review-2026-09-29/business/11-BUSINESS-MODEL.md|H|Symbolic contribution/unknown tail losses/providers/fees, unique completed notional; X marked P conflicts with capture's S/authenticity caveat.|
|38|zolana-review-2026-09-29/business/12-GTM-AND-VALIDATION.md|H|Unrun draft B/C≥2/10 paper behavior +≥2 historical paired windows; differs from old thresholds; qualified C cohort prerequisite.|
|39|zolana-review-2026-09-29/legal/09-REGULATORY-AND-LEGAL.md|H|17 pair/role/jurisdiction/title/loss/privacy-audit/data questions; D0/testnet/USDC/xStock separate; custody preference not customer consent.|
|40|zolana-review-2026-09-29/mechanism/01-MECHANISM-SPEC.md|H/F|D0 integer reference/own-leg funding; no inherited residual/60s/5bps/public owner tie; later FAA/permutation doesn't cure leakage.|
|41|zolana-review-2026-09-29/mechanism/02-MARKET-DESIGN-RATIONALE.md|H|RFQ/TEE/CLOB/transparent HTLC change guarantees; no automatic residual; custody/wait/freeze/loss economic costs.|
|42|zolana-review-2026-09-29/pitch/13-PITCH-NARRATIVE.md|H|Research-toward narrative, planning vs actual D0, no atomic/unilateral exit/qualified support claim.|
|43|zolana-review-2026-09-29/pitch/14-JUDGE-RED-FLAG-AUDIT.md|H|Claim ledger privacy/admission/custody/assets/absence/traction evidence; X provenance P-vs-S drift.|
|44|zolana-review-2026-09-29/product/15-HACKATHON-PLAN.md|H|Nonsettling D0/real MPC only if available, honest plaintext baseline; no fake funded UI; not current approved code ceiling.|
|45|zolana-review-2026-09-29/product/16-ROADMAP-AND-DECISIONS.md|H|ADR-Z01–08 constraints/research/action gates; old unselected threshold/ordering menu not current approval.|
|46|zolana-review-2026-09-29/security/07-THREAT-MODEL.md|H/F|Observer/access matrix/I01–I08/R01–R06; strict GD2 and non-atomic loss; secrecy not transitive across actors.|
|47|zolana-review-2026-09-29/security/08-TEST-AND-VERIFICATION-PLAN.md|H/F|T01–T17 plus T06b/c full collateral/debit/full activation/physical vs business replay/typed refund; specified failure not runtime result.|

### 2.3 All6 files under zolana-research-2026-09-30/

Nonduplicated historical source research. Old file:line aliases/no-code snapshots are not live locations/status. Current banners preserve later corrections, not fresh recertification.

|#|Exact reviewed archive-relative path|Class|Key finding|
|---|---|---|---|
|48|zolana-research-2026-09-30/README.md|H|B01–B30 grouped choices/gates,65 underlying groups, choice≠evidence; B20 stronger holds/activation; old menus not approvals.|
|49|zolana-research-2026-09-30/business-legal.md|H|Contest vs advice, Zecathon placeholder/conflicts, issuer package/omnibus, Circle scope, conditional MiCA/FinCEN/OFAC/data questions and unknown costs/demand.|
|50|zolana-research-2026-09-30/evidence-scope.md|H|Separates source/contributor/structural checks/failed-worker messages from runtime/legal/privacy proof.|
|51|zolana-research-2026-09-30/inventory.md|H|65 historical groups/17 then-unrun labels/path aliases/accounting/provenance conflicts; discovery trace not present backlog.|
|52|zolana-research-2026-09-30/privacy-admission.md|H|Cerberus trust/preprocessing/recovery, public payer→ciphertext, PrivacyPass/Semaphore/AnonCreds primitive gaps, output inference.|
|53|zolana-research-2026-09-30/protocol-custody.md|H|Ironwood availability vs Draft; FROST contributor support vs experimental key/recovery; IVK/inventory, fee/reorg drift, assets, reserves/ordering/non-atomic loss.|

### 2.4 Wrapper/manifest/supporting current material

- docs/imports/kerb/README.md:29+18+6, source code/stores/manifests/fixtures/builds excluded; current/historical/known failure;79 external-relative rewrites; order/status conflicts.
- docs/imports/kerb/MANIFEST.json: complete schema/date/three roots/all53 source/import records/hashes/bytes/rewrites read. Source/import hashes intentionally differ where rebased; no hash recalculation here.
- docs/imports/kerb/LINK-REPORT.json: prior53 source unchanged/manifest match and zero new missing targets; one inherited Sep29 Zoss #5-interface-proposed broken fragment. Prior76docs/1093links not rerun.
- docs/PRODUCT.md and CONSOLIDATION.md read: unified authority, all lanes, future name only, no migrated implementation or inherited permission.
- Relevant ARCHITECTURE/BLOCKERS/NATIVE-IMPLEMENTATION-STATUS read: approved native full validating proofs/proportional/one-note/independent witness/recovery; code vs missing verifier/escrow/actual transfer.
- SERVER-INDEPENDENCE.md read: parent new samechain notes/bilateral proposal distinct from original Kerb custody/GD2 and native crosschain; construction/data/resource/exit proof missing, no launch claim.

## 3. Durable credit/hold/claim/custody requirements

### Authority types

SourceObservation≠QuorumAcceptedMessage≠FundingCredit≠AdmissionHold≠Allocation≠NativeIntent≠native VerifiedSettlementFact≠actual transferred assets. Source decryption/ordinary signatures/receipt/credit/event/callback cannot substitute for full source truth, rightful claimant, controlled backing or payout.

Funding needs exact network/genesis/pool/receiver/value/stable occurrence and canonical history; claimant authorization bound to issuance; controlled unallocated spendable notes/witnesses/key authority; durable one-time issuance. IVK detects inbound only. Stable occurrence network/pool/txid/action-index separate from block inclusion; actual commitment/nullifier/genesis also bind. Reinclusion/reindex/restart/copied memo/proof/new label cannot create credit. Change backs old liabilities, not new deposits.

### Holds/allocations

Buyer C=Available+AdmissionPrepared+EpochEncumbered+SellerPayoutOutstanding+BuyerUnusedOutstanding+FinalSellerPayout+FinalBuyerRefund, all disjoint. Pending/Unknown is substate of outstanding, not free/additional value. Seller atoms similarly available/prepared/encumbered/filled/unused/released/returned.

FULL signed buyer max debit including selected bounded fees and seller quantity held at PREPARE, before certificate/root—not after Fill. Each trader funds own leg. Delay/expiry/zero fills/no callback/restart/HTTP error cannot unlock. Preallocation release needs irreversible canonical abort/exclusion plus stale commit/auth fences. Final unused and first-leg release BOTH require complete authenticated result and fully activated ALL accepted holds: exact canonical Final+all chunks+same-decision ACKs+complete private application. Disjoint final-unused refunds may coexist with different filled obligations; portion exclusivity, not whole-credit exclusivity.

Rct exact sealed ciphertext provenance, Cholds private-opening hiding held-membership commitment, Corder certified plaintext commitment are distinct. Hiding hash does not prove private ledger/backing true or remove public membership.

### Physical backing/fees

Separate controlled spendable inputs, exclusively locked live inputs, provisional recipient effects, provisional owned change and usable confirmed change. Canonical input consumption replaces original with exact approved attributed effects; never original+change/pending recipient+available/new+old balances counted twice. Recipient effect backs its own pending obligation only. Change binds real tx/action/commitment/nullifier/owning view/value; equal-value note labels insufficient. Future change reserved before materialization. Globally scoped physical claims prevent relabeling across user/sponsor/pairs within that retained store; separate registries require explicit uniqueness design.

Sponsor fee capital separate; no silent user debit. Impairment/Unknown/reorg fences new sends/activation while preserving claims and existing locks. Not first-come payout, socialization, compensation or proof spendability. Unclaimed/unsolicited assets quarantined.

### Durable authority/recovery

Operation identity deployment/pair/epoch/stable entity/portion/intent/generation/prior-version/transition. Persist immutable exact bytes/recipient/effects/input locks BEFORE ACK/signature handoff. Same ID/different bytes conflict; identical replay idempotent. Credit/portion/business replay, native note nullifiers and signer nonces distinct: same liability could be paid twice from different notes despite no nullifier repeat.

Serializable DB/CAS/one fenced writer/three exact persisted business ACKs is fail-stop trusted policy, not BFT. Native2of3 shares separate; bad threshold can steal. One missing business signer halts even if two native shares available.

Restore needs independently retained fresh signed heads, pending bytes, used intents, every potentially live tx/input lock and never-reused signing nonce/tombstone. All pre-intent backups with no retained anchor cannot prove later authority never existed: halt, no reset/new writer. DB+chain not atomic. Unknown not failed/no-effect. Version/roster/message/library updates cannot erase consumed identities, private evidence or funded rights.

### Typed payout/refund/asset transfer

SellerPayout requires exact active seller liability and observed finalized corresponding SPL recipient/atoms in candidate SPL-first policy. BuyerRefund requires its OWN final-unused/excluded/fenced-abort/safely-cancelled disjoint portion+fixed destination+usable inventory+no live competing intent, NOT SPL delivery. SponsorFee isolated. No original-note-unspent requirement: controlled change may back unused liability.

Native signer inspects actual PCZT all recipients/value/change/fee/network/pool/expiry and recomputes sighash; opaque coordinator digest insufficient. Inspection not native signature/proof/history/payment. Whole-book coordinator key/version pinned every extraction; client own result key exact certified slot—not caller override.

ReserveFill not live Release. FirstLegPrepared persists before signatures. Cancel/Release share monotonic target disposition. Filled return needs finalized unreleased target cancellation and retained no-live-native-intent custody history; Solana cannot independently prove native absence. SPL collateral return and native buyer refund distinct and may safely proceed in either order without rewriting each other.

Verification+consumption+actual token transfer atomic locally; unexpected CPI revert restores state. Complete means both actual final effects/reconciled liabilities, not signed/broadcast/queued/credited. Transfer failure leaves retry rights/fixed beneficiaries. Issuer freeze/dead native quorum may strand claims indefinitely.

## 4. Sibling implementation paths/status preserved

Source reads only; no new execution:

- ../kerb/crates/protocol/src/lib.rs/domain.rs/policy.rs: no_std records, checked units/typed intents, data predicate≠authenticated fact. Domain currently Ironwood TESTNET/v6/NU6.3/legacy Tokenkeg/ordinary Ed25519—not generic Token-2022/mainnet/HyperEVM/Core support.
- ../kerb/crates/ledger/src/lib.rs: PairPolicy enrolled source/inventory/target producer keys and3business authorizers. SignedSourceFacts/SignedInventoryFacts/SignedNativeFacts; IssueCredit/PrepareHold/ObserveEpoch/ActivateAllocation/PrepareNative/NativeUnknown. SIGNED TRUSTED TESTIMONY, not trustless chain proof.
- ../kerb/crates/ledger/src/store.rs: serializable immutable prepare/commit/head/generation, claimant/source/inventory validation, global full activation, exact user/sponsor inputs/typed native plans; recovery needs3fresh signed retained heads. Database not onchain asset authority or native spend key.
- ../kerb/crates/ledger/src/replica.rs: financial validation replay and exact journal/intent/head COMMIT before ordinary ACK export. Three processes not independent control or FROST/payment.
- ../kerb/crates/ledger/migrations/0008_physical_inventory.sql: append-only occurrence/commitment/nullifier scoped network/pool/genesis, immutable identity projections; nonempty old enrollment/history migration rejects. Never reset/re-enrol operational data or synthesize missing identities; authenticated migration separate.
- ../kerb/crates/custody/src/lib.rs and Cargo.toml: inspect_pczt→UnsignedNativeInspection, exact metadata/inputs/outputs/change/txid/sighash/byte digest; pinned pczt0.9.3/primitives0.30.1/protocol0.10.5/orchard0.15.5/encryption0.4.2. Inspection permits deferred v6 anchor/witness state; not proof/signatures/source history/signing/payment.
- ../kerb/crates/runtime/src/native.rs/coordinator.rs/facts.rs/local.rs/process.rs: exact plan binding before reservation/export, diagnostics signatures/proofs/history/signing/broadcast=false, LocalFixture testimony/three stores/Unknown. Inspected replica CLI path requires fixture key bootstrap+LocalFixture; not deployed general custody signer.
- ../kerb/contracts/solana/program/src/lib.rs/authorization.rs/accounts.rs: local legacy-SPL escrow/global decisions/activation/fill/release/cancel/return; exact accounts and3distinct enrolled Ed25519 precompiles. Comment: testimony not MPC/source/history/native-spend-absence/finality proofs. Even ReturnUnused needs3authorizer decision; owner/arbitrary fee payer alone cannot exit.

Important source-order mismatch: spec says CPI before paid state; actual release/return deliberately writes NON-PAID consumption/version/head before CPI, then paid marker after successful CPI. Correctness relies on atomic Solana rollback. Source reports compiled freeze rollback checks, not rerun here. Do not claim all source writes occur after CPI.

Freshness: old overview/no-code/staged zero-implementation statements historical. Safety plan has successive81/83/99 reports plus unchecked overlap/sponsor/cancel-return acceptance; newer README describes corrections. Unavailable session artifactNNN records not inspected as fresh proof. Code presence/README description alone cannot close old acceptance; parent owner verification needed if claiming readiness, no new failure alleged.

## 5. Strict matcher infeasibility and materially different alternatives

Retained guarantee: protected honest order/accepted-identity changes must not change adversary view, including matcher-reachable services/public data and legitimate colluding trader own result/assets/balances/refunds. Stronger than normal crypto input privacy modulo explicit outputs. User retains strict guarantee, no own-output exclusion/waiver. FAA/coordinator privileged separation doesn't cure trader output.

Three documented distinguishing traces:
1. Singleton Alice/public epoch escrow, other slots known attacker/padding. Ask6 vs10, attacker bid8→fill vs none exposes secret+membership.
2. Genuine extra seller does not help exact price: attacker q2/limit12, Alice q1/ask6 vs10, independent seller q1/askU∈{1,2,3}. Both fill2 but plateaus[6,12]/[10,12], own price9/11. Eventprice9 probability1 vs0. Perfect MPC/hiding/private permutation/cohort still distinguish.
3. Suppressing receipt doesn't hide own assets. Buyer limit8, seller limit6 vs10, no independently prefunded substitute: legal delivery in high ask world0; equal distributions force delivery0 in low world. Randomization cannot create legal trade in high world. Never settling to conceal output is not useful exchange.

These are reasoned mechanism arguments plus attributed arithmetic checks, NOT a new privacy/MPC/network test. Scope is retained definition/economics/permitted corpus, not all privacy/exchange/recovery impossible.

Alternatives require explicit new contract:
- Hidden custody/chain notes/private ingress/recovery ciphertext may reduce direct membership joins; own outputs remain. Needs real contract-controlled backing/ownership/auth/conservation/nullifiers/ciphertext recoverability/data/exit, NOT solved by Cholds/root.
- Privacy modulo explicitly declassified exact fills/prices/balances: defensible crypto target but CHANGES original guarantee, not approved; metadata/admin privacy still separate.
- Fixed external price removes plateau-price channel but execution/quantity probes remain; adds oracle/session/corporate-action price actor.
- Differential privacy/random prices/allocations permits bounded inference, changes execution/limits/economics and maybe cover capital; not exact noninference, no selected epsilon/construction.
- Minimum genuine cohort/batch/delayed publish increases wait and can reduce particular joins, not exact-price trace; wallet count not unknown independent owners.
- Forbid matcher traders/collusion CHANGES threat model, needs enforceable proxy/governance assumptions, not selected.
- Input-independent funded cover dealer shifts P2P to principal inventory/risk/liquidity model. Actual finite independently controlled capital/adverse selection/loss/solvency terms missing; no universal guarantee from cover name.
- Signed bilateral samechain: local dual consent/backed asset atomic target transition, arbitrary relay; DIFFERENT settlement/price discovery, counterparty knows terms/own asset result; no GD2 closure. Per-owner proof/composition/custody/partial-successor/DA unimplemented parent proposal.
- Native maker RFQ, public CLOB, old public auction, HyperCore spot preserve separate lanes/different disclosure. Cannot be fallback branded strict private.
- Robust common legal output across all protected worlds: zero in documented trace, not complete nontrading substitute.

Maintain GD2 structural FAIL; viable trading replacement/security contract unresolved. New optional bilateral lane doesn't waive original target.

## 6. Company-offline reuse versus incompatible authority

Separate company-UI-off, backend-off with surviving independent quorum, owner-unilateral funded rights, samechain dual-asset atomicity and crosschain source-proof settlement. None implies data/prover availability, chain inclusion/noncensorship, issuer thaw, price fairness/liquidity.

Reusable:
- exact consent/unsigned clients/permissionless submission, independent reads, real paid-state evidence;
- isolated vault/immutable entitlement/retry/no-sweep targets from old public mechanism;
- symmetric holds/portions/physical backing/Unknown/replay/nonrollback requirements across venues;
- typed PCZT effect checks and signature/domain/key separation;
- app ownership of real source-proof predicates, no receipt-as-funding;
- publicly reconstructible data and local recovery capabilities as acceptance criteria.

Cannot alone deliver target:
- mandatory FAA issuer/approval still gates new admissions; anonymous credentials don't self-fund;
- MPC shares/preprocessing/keys/migration/availability cannot be recreated by installing code; own-output contradiction remains;
- private3of3 journal/target authorizers require signatures; a replacement relayer cannot manufacture them;
- native threshold spend quorums can steal/refuse/lose shares. FROST no mined-note refund covenant, business unanimity liveness stricter than2of3 spend;
- proof of receipt doesn't authorize native ZEC transfer or recover missing note openings;
- hiding commitment/nullifier only binds defined record/spend within correctly implemented scope, not physical custody/backing/data;
- self-hosted old code cannot recover erased journals, secrets or exclusive witness;
- immutable contract/VK root/hash alone not actual proof/ciphertext/artifact availability.

Parent samechain proposal: qualify real received exact assets under program control, semantic two-party consent, conserved disjoint inputs, authorized recoverable output ciphertext, atomic consume/transfer, root rebuilding and concurrent partial fill successor retaining remaining quote capacity. Per-owner proof composition OPEN; don't hand full secrets to one server prover or call commitment binding proof of semantic economics. Not native ZEC pool/bridge/control and not strict private auction.

Manual operation specification must enumerate authorizer/surviving actor, owner-retained keys/witness/rules/VK/code/assets/beneficiaries/fees/consumption IDs, source/history/target reconstruction, local proving resources, exact submit/retry and actual terminal transfer. No hidden company DNS/license/key/export approval. Publish complete authenticated recovery ciphertext bound to commitment and intended recipient, not arbitrary blob/hash; tree branches/root histories rebuilt without company indexer. Missing unknown openings cannot be derived from chain root. Retain rules/artifacts/evidence through funded lifetime; gas/archives/prover resources/chain progress/issuer remain assumptions.

Native Ziquid stays DIFFERENT: locally complete Q and independent U payout witness, solver prefund/irreversible arming BEFORE P authorization release, general source T payment classification/full accepted validity/history, proportional/uniqueness/recovery and actual excess return. Do not substitute Kerb custody credit/ACK/SPV/timeouts. Existing missing full proofs/hostile T witnesses/excess capability/financial escrow means manual end-to-end autonomy not established. Honest safe indefinite Pending is not full independently terminal product.

## 7. HyperCore autonomy limits

Retain A eligible Hyperliquid assets in P2P vs B explicit external spot. HYPE/ZEC and HYPE/USDC-Solana examples unqualified; no assets/domain/custody/bridge chosen; no perps/leverage/automatic remainder.

A: HyperEVM contract custody separate from user Core balances; exact native HYPE/ERC20/wrapped/link/token ID/decimals/admin/supply/return path qualify. Same L1 doesn't grant Ziquid spend authority or Core liquidity to P2P. Source proof doesn't pull assets into escrow or resolve GD2.

B: user own actual master/account signer+venue-native tools may replace Ziquid UI/API; conditional independence FROM ZIQUID, not Hyperliquid network/venue/consensus/account/transport/authority, not guaranteed liveness. Agent/API wallet signs, not account address/AI/unlimited withdrawals; action permissions/revoke/expiry checked. Company-held sole signer fails user-unilateral target.

Core public orders/cancels/trades not private through UI/MPC. Exact action/account/order/cloid/nonce/limits/fees/open/partial/fill/cancel/Unknown retained. Cancel races with fills, queued/HTTP/EVM success≠fill, fill≠Solana/ZEC delivery. Unknown reservations cannot reroute/reuse. Revoking delegate doesn't undo completed action. Nonce pruning/address reuse can replay old signed actions.

CoreWriter queues contract-address actions, delayed order execution; read latest Core state at EVM block construction not spending permission. Account must preexist before EVM block—sameblock initialization transfer insufficient. Core→EVM queued next EVM block; EVM→Core and CoreWriter later processing. Linked ERC20 arbitrary bytecode/supply/decimals caveats: no synchronous Core+EVM atomic fill/return assumption or crosschain guarantee. Exact environment/feature availability/runtime unobserved.

## 8. Economics/legal/product hypotheses

No committed users/makers/distributors/custodians/independent operators, qualified exact xStock, measured bilateral savings, live route, actual budgets/cover capital/insurance, approved entity/licensing or expanded fees. Source absence isn't market absence.

Old public fee5bps each side/6:3:1 differs from Oct1 zero demo protocol fee with sponsor network capital; real private/native/Core fee unselected. CROSS notional count once, residual one paying user, no blended10bps residual. Hypothetical revenue costs/100M/1B not forecast/official threshold; residual rebate can make direct maker better. Escrow liability not revenue; unresolved legs not collectible fee by assumption. Independent manual operation still pays gas/data/proving/security/legal/availability. Cover/dealer alternatives need NEW principal-capital model, not minor fee switch.

Demand: exact pair/network/pool/mint/program/size/window/compatible limit/economic-owner/time/eligibility-matched EXECUTABLE quotes, natural contra intents, failures/no-quote/partial/blocked and risk-informed refusals denominator. Executed turnover lacks omitted/abandoned intents/custody willingness. Old≥10/3/2/maker/3 vs staged≥2/10 +≥2 windows are distinct historical unrun experiments, not unified results. Keep past behavior/consent/denominator/preregistration/two-party all-in benefit lessons; no outreach conducted.

Legal issue map per actual entities/control/activity/territory: securities classification/exchange/ATS/MTF/broker/router; crypto custody/exchange/transmission; issuer Final Terms/eligible holders; title/segregation/insolvency/client-asset duties/loss; AML/sanctions/history/audit/data/retention; upgrade/VK/governance and fee conflicts. Company-offline/open source/proof-control/testnet/synthetic/nonprofit not exemptions. Geofenced host not direct program restriction; no administrative bypass invented under compliance. SG/HK/Brazil author hypothesis/Jersey issuer/absent restricted list not permission.

MiCA Art2 financial-instrument exclusion means don't classify every xStock blindly under MiCA. If platform rules apply, archived Art76 holder+transaction-history/public disclosures may conflict with exact privacy/service role; confidential separate channel candidate not proven lawful separation. These are counsel questions, NOT blanket illegal/permitted verdict. Fresh ESMA Art2 read succeeded. EUR-Lex HTML/PDF returned WAF; tried ESMA Art76 URLs404, so Art76 wording remains attributed Sep30 research, NOT freshly verified legislation.

Issuer overview1:1/no commingling vs archived later supplement pooled omnibus subcustody preserve version/structure caveat; no absolute bankruptcy/insurance guarantee. Exact latest Final Terms/mint/account/holder eligibility unknown. USDC nonEEA third-party support doesn't require blanket Circle partnership, but no endorsement/legality, EEA consent/reporting scope separate. Issuer freeze remains despite permissionless software.

World's Fair official current-at-Sep30 FAQ vs2024 guide vsX opinion differ (separate pitch/demo/private repo reviewer access/optional accelerator). Overtime/quit-job/native language not official eligibility. Zecathon domain-served15k/PrivateMarkets data had explicit placeholder prize split/forms conflicts—not final guarantee. Brand/domain/handle/team/IP/work-window facts unknown. No registration/submission/publication authorized.

## 9. Fresh primary-source ledger

ALL retrieved2026-10-02. Quotes/section delimit claim; vendor/issuer source statement≠independent deployment/runtime/legal certification. Publication dates only if stated.

|ID|URL and section|Quoted supporting passage|Scope/limits|
|---|---|---|---|
|S1|https://hyperliquid.gitbook.io/hyperliquid-docs/about-hyperliquid.md Technical overview|“state execution is split into two broad components: HyperCore and the HyperEVM”; orders/cancels/trades happen “transparently”|Vendor L1/public/finality statement, no independent speed/finality/asset integration.|
|S2|https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/interacting-with-hypercore.md CoreWriter|actions “delayed onchain for a few seconds”; explorer “first… enqueuing… second… HyperCore execution”; acts for own contract address|Enqueue/execution/authority distinct; read section says testnet; no target feature/gas qualification.|
|S3|https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/interaction-timings.md|Core→EVM “queued… next HyperEVM block”; account “must exist… before”; sameblock init “rejected”|Timing/preexistence vendor rule, no new runtime test/crosschain atomicity.|
|S4|https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/hypercore-less-than-greater-than-hyperevm-transfers.md Introduction/Caveats|HYPE native EVM notERC20; “Do not blindly assume accurate fungibility”; “no checks… sufficient supply… valid ERC20”; “arbitrary bytecode”|Qualify actual link/supply/code/decimals. Contains future mainnet wording; don't claim universal availability.|
|S5|https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets.md|API wallets “only used to sign”; “previously signed actions can be replayed once the nonce set is pruned”; “tracked per signer”|Signer vs account and replay, not all action permissions/withdrawal safety or AI.|
|S6|https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing.md|“two signing schemes… sign_l1_action vs sign_user_signed_action”|Encoding/action domain distinct; no signature attempted.|
|S7|https://zips.z.cash/zip-0203 Abstract/Specification|expiry after tx “cannot be mined”, removed if “have not been mined”|Final ZIP unmined expiry, NOT mined-note reversal/refund covenant; future NU7 not assumed active.|
|S8|https://zips.z.cash/zip-0312 Threat Model/Nonrequirements/Round2|coordinator and holders “trusted with… privacy”; signers “MUST check” or compute sighash; “Network privacy is not in scope”|Draft threshold authorization/privacy model not turnkey native custody/ledger/unilateral refund.|
|S9|https://docs.rs/orchard/0.15.5/orchard/keys/struct.IncomingViewingKey.html Description|cannot “spend… or detect when… spent”; “cannot maintain accurate balance”|Versioned capability, not history/inventory truth.|
|S10|https://www.rfc-editor.org/rfc/rfc9576 §§6.1,6.3,7.1|metadata partitions anonymity; timing reduces set; “tokens are not intrinsically bound to Clients”|Informational PrivacyPass primitive/deployment, not funded asset relation or output privacy.|
|S11|https://docs.arcium.com/multi-party-execution-environments-mxes/mpc-protocols|Cerberus “dishonest-majority, detect-and-abort”, “at least one… honest”; MPC interaction/availability liveness|Vendor assumptions not actual Kerb independence/outputs/inventory proof; own-output leak survives perfect computation.|
|S12|https://docs.arcium.com/developers/node-setup Preprocessing backend|trusted dealer default; misspelled optional keys “dropped silently”; inspect resolved startup backend|Config gate, no node run/setup actions followed.|
|S13|https://solana.com/docs/tokens/basics/freeze-account|prevents “receiving, transferring, or burning… until… thawed”|Token semantics, not exact mint/account query; program can't bypass issuer.|
|S14|https://docs.xstocks.fi/docs/product-legal-overview.md Classification/Distribution|“bearer debt… tracker certificate”; no shareholder voting; own Final Terms/jurisdiction restrictions|Issuer claim, no counsel/qualification/consent; preserve later-supplement segregation caveat.|
|S15|https://www.circle.com/legal/usdc-terms §§2,8,13 updated2025-12-12|third parties support “without any authorization”; not endorsement “valid, legal, stable”; block transfer onchain|NonEEA issuer terms, no blanket partnership or exemption/forced thaw/thirdparty peg promise; EEA separate.|
|S16|https://www.esma.europa.eu/publications-and-data/interactive-single-rulebook/mica/article-2-scope Art2|activities “in the Union”; excludes “financial instruments”|Official scope, not actual classification/exemption/counsel verdict; Art76 not refreshed.|
|S17|https://raw.githubusercontent.com/ZcashFoundation/frost-tools/06c0dbdbb1bac9b99cd255e74ba2f387c295e660/zcash-sign/src/generate.rs|“Quantum recoverability is deferred”; invokes incompatible_with_quantum_recoverability_and_will_be_removed constructor|Pinned experimental derivation, not maintained production solution; not all threshold custody impossible; no keys/signing generated.|

Other Sep29/30 activation/releases/final terms/prizes/NEAR/paper/SPV claims remain attributed archive evidence, not re-certified. No market absence/current supply/liquidity/legal permission/experiment invented. Historical source aliases/artifact IDs not live paths.

## 10. Refactor recommendations/open decisions [INFERENCE]

1. Archive bytes/tree/manifest remain provenance, no mass rename/delete/fact rewrite. Current unified docs synthesize exact path/section/date/grade. No duplicate readiness registers, source results not native evidence.
2. Every lane: user job, exact assets/domain, price discovery, custody/authorizers, observer privacy definition, lifecycle/recovery, manual/data prerequisites, status/evidence. No umbrella autonomous/private/trustless guarantee borrowed across lanes.
3. Preserve native full validating history/payment classification, prefund-before-P, independent Q/U witnesses, proportional/one-note/actual excess-return and hostile completion. No SPV/receipt/credit/timeouts easier substitute; existing missing capabilities remain blockers.
4. Private P2P retains strict own-output-inclusive requirement/known contradiction. New bilateral samechain proposal explicitly different assurance, not waiver or solved control. Any changed threat/economics/output semantics user decision.
5. Reuse safety responsibilities/actual interfaces only when semantics align; no generic verified/bridge/signature wrapper that grants money rights. Code migration/package scope not decided by docs import.
6. Manual rights enumerate enforceable predicates, independently available capabilities/data/proving assets and actual transfer, not company export approval. Safe Pending honest but not completed independently terminal product. Parent integrated verification only; no drills run here.
7. Preserve conflicts: old5bps vs zero demo/unknown expanded fees; plan unchecked defects vs newer README/source; old overview status; X capture grade; issuer overview/omnibus; official contest/advice. Don't silently resolve evidence by optimistic prose.

Open: strict viable private trading/security/economics; custody-independent native ZEC construction; concrete samechain proof/semantic consent/ciphertext recovery/partial composition; exact qualified domains/assets/venues; authority/governance/independent operators/recovery; Core delegation/order/fees/signing path; fees/distribution/cover-loss capital; real legal entity/cohort/jurisdictions/counsel; any code migration/name/action/network approvals.

## 11. Evidence boundary

Coverage53 distinct paths29+18+6 plus full wrapper/manifest/link report. Targeted source investigation, not security certification. Fresh sources support bounded §9 claims. No project/archive/source modification, no checks/retests/runtime/funds/deploy/Git. Parent persisted this report and owns integrated documentation verification.

## Addendum — selected exact-output construction, superseding generic-encryption alternatives

Fresh current-repo evidence: `docs/SERVER-INDEPENDENCE.md` §§3.2,4.2–4.3, read2026-10-02 after the parent's refinement. This is a selected **documentation/design construction**, not available implementation or runtime qualification.

### Selected behavior

1. Once exact fill quantity is known, each recipient/owner prepares the exact opening and ciphertext for assets it will receive, including its own change/remainder and partial-fill successor rights.
2. Before consuming input rights, it saves a local recovery backup, decrypts its ciphertext locally, recomputes/checks the output commitment and verifies exact asset/value/recipient/quantity/remaining capacity/fees/domain.
3. Both owners authorize the SAME immutable fill terms/digest, semantically binding exact outputs, quantities, recipients, fees, deployment/rules and disjoint backed inputs. Hash binding alone is not proof that a consumer has checked these meanings.
4. Per-owner locally generated proofs, composition/ABI/circuit, replay/cancel/remaining-capacity conservation and atomic contract/program validation must still be implemented and qualified. No full-secrets handoff to a server prover or fake existing checked-proof interface.
5. Relayer automates only AFTER sufficient exact authorizations; cannot alter ciphertext/output/recipient/value/fee/terms. Changed bytes require the corresponding fresh authorization and proof, not a relayer rewrite.
6. Extra owner roundtrip means owner offline prevents NEW arbitrary fills requiring consent. Existing owner exits and already fully authorized pending settlement remain company-independent subject to retained data/proofs/chain/asset assumptions. No owner-offline matching-liveness claim.
7. Partial fill is retained: each known fill produces fresh exact remaining-value/capacity successor rights/openings/recovery data and authorization. Old capability cannot revive consumed capacity; cancel affects unfilled successor only. Do not silently disable partial fills or invent unlimited preauthorized templates.

### What is NOT selected or solved

- A generic ciphertext-correctness ZK relation is **not assumed** for this construction. Contract verifies exact signature/proof/output binding; recipient recoverability relies on the owner-prepared/local-decrypt/commitment check and retained data before authorization.
- Circuit-enforced encryption/recovery or other reviewed template/capability design remains **unselected alternative** for future truly unattended arbitrary partial fills. Do not present it as the selected implementation requirement or completed mechanism.
- Malformed null/wrong-key ciphertext must not be authorized just because its hash matches; local exact output validation precedes consent. That requirement is not a current runtime pass.
- Actual assets must be held under qualified chain-controlled transfer authority and backed/conserved; commitment/output signature/proof does not establish that custody by itself.
- This is signed bilateral samechain settlement, not hidden maximum-volume auction or native ZEC custody. It does not close GD2, weaken the matcher-controlled legitimate-trader adversary, grant unilateral spending of committee ZEC, or shrink native P/Q/full-history/payment-class/proportional/one-note/independent-recovery/excess-return obligations.

### Integration into the whole audit

Replace the earlier §5 alternative-table and §6 generic samechain recoverability wording with: **Selected recipient/owner-prepared exact outputs and fresh per-fill consent; checked proof composition/atomic validation remains Open; owner-offline new fills not guaranteed.** Preserve all prior credit/hold/claim/custody/source-code status findings and every53-file classification. Native P/Q ciphertext/source proof relations have their own requirements and are NOT modified by this samechain choice. No archive bytes edited, no runtime checks performed.


## Independent security/claim review and corrections

Read-only specialist review spot-checked load-bearing primary-source passages and found **two medium design defects**, not observed implementation exploits: (1) canceling one exact digest would leave another signed packet over the same backing live; (2) a sliding membership-root window could strand an already fully authorized bilateral fill after one owner goes offline. No privacy waiver, source-witness creation, fee redirection or claimed unilateral ZEC custody was established elsewhere.

**Corrected proposed design:** shared-generation cancel/consume rejects every outstanding digest, not only F1; samechain deployment retains every authenticated membership root/tree generation with current deployment-wide unspent/cancel/capacity and explicit expiry checks. Retained roots have growing state/storage/gas costs to qualify; they are not a new native Zcash anchor rule. Exact recipient-prepared outputs/fresh consent remain selected. Detailed acceptance in SERVER-INDEPENDENCE/spec, with source research CI-5/CI-8 aligned.

Throwaway model additionally observed F1/F2 reject after shared cancel, and signed authenticated membership root retained across120 appended entries/three tree generations while canceled/unaccepted state rejects. This checks specified model only, not actual circuits/contracts/proof renewal/finality/company-off funds. Whole native and strict GD2 blockers remain open. **Targeted specialist rereview confirmed both conceptual findings resolved** in SERVER-INDEPENDENCE, Oct2 spec and research CI-5/CI-8, with no new actionable finding. That rereview did not exercise implementation or rerun the model; cross-owner propagation is checked by integrated documentation verification.

## Integrated documentation verification

[ARCHITECTURE-VERIFICATION.json](../ARCHITECTURE-VERIFICATION.json) records final local paths/fragments, complete Kerb source/import SHA-256 preservation, dated snapshot/native evidence-register integrity, navigation smoke and model scope. No new broken local links or source archive edits were found; one historical Zoss proposed-interface fragment already broken in the source is retained/reported. Full manual consumer, circuits/contracts/network company-off drills remain **Unrun**; no gate Passed from this documentation task.
