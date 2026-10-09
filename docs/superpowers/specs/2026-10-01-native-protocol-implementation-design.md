# Ziquid native protocol — implementation design and prerequisite review

> **Status — 2026-10-06:** this design is the **ACTIVE L-ZEC objective**. Native ZEC is an active first-class lane in the whole pipeline, not V2, with pairs ZEC↔{Base, HyperEVM, Solana, NEAR}; S1–S7/M1–M5 obligations are unchanged. The 2026-10-02 header below still governs which parts are dated investigation.

> **Authority/supersession update — 2026-10-02.** The owner-approved native goal and choices in this design remain provenance; the observed starting workspace, tool lookup, sibling exports and candidate `0.16.0`/prerelease cohort below are **dated investigation**, not present state or selected dependencies. [Native status](../../NATIVE-IMPLEMENTATION-STATUS.md) owns actual code/coherent `0.10.5` cohort/proof/setup/resource evidence; [ARCHITECTURE](../../ARCHITECTURE.md) and [MODULES](../../MODULES.md) own active behavior/packaging; [BLOCKERS](../../BLOCKERS.md) is the sole readiness register. See [SERVER-INDEPENDENCE](../../SERVER-INDEPENDENCE.md) for manual rights/data/artifacts and the [redesign spec](2026-10-02-z2z-server-independent-architecture-design.md) for proposed future expanded architecture. A fresh implementation session must establish active scope; these records grant no new money/Git/deployment/viewing actions.
>
> **Current native contract clarifications:** full validating history/no SPV and one-real-note/one-obligation across supported versions in the selected deployment are retained. Proportional `U=floor(D*C/A)`, `S=D-U`, dust fixed S for authenticated `0<=C<=A` is selected, not an unresolved rounding menu; all-hostile independent terminal recovery and actual S-authorized `C>A` excess return still lack required capabilities. Safe Pending is interim, not delivery. Runtime library/limited guest/source primitives now exist but complete financial proofs/escrow/reconciliation do not. Standalone manual/company-off consumer, cold recovery restore, independently usable artifacts/history/witnesses/prover resources are native acceptance, not deferred TS/UI. Proposed samechain recipient-prepared bilateral relation is separate/unimplemented and neither replaces native scope nor fixes strict GD2 or legacy ZEC custody. This header preserves original approvals/source/date/results; it does not recertify them.

**Retained design and prerequisite review follow.**

Status: **owner approved the written design**, selected full validating source proofs, proportional settlement, and one real note per obligation in one EVM deployment. Exact allocation/excess, proof/bootstrap/finality and artifact contracts must be reviewed in the implementation plan before production edits. User requested starting the [core implementation brief](../../history/ZIQUID-IMPLEMENTATION-SYSTEM-PROMPT.md). The entire goal remains all five native roles, actual source proofs, EVM verification/transfers, durable execution, privacy/uniqueness and usable recovery. SDK/UI/bindings/additional targets are deferred. No gate passed; no transaction/deployment/new-viewer/Git/publication permission follows.

## 1. Observed starting point

Current workspace has four comment-only Rust libraries plus a help/version binary, no dependencies or native protocol APIs. `cargo test --workspace --all-targets` passes one CLI argument-rejection test; that proves only frame behavior. `cargo run -p ziquid-runtime --bin ziquid -- --help` states settlement/solver/server commands unimplemented. Rust/Cargo 1.98.1, Foundry 1.3.6-dev and solc 0.8.34 are installed. No source node or proving binary was found in the named executable lookup. This does not establish unavailable libraries or network infrastructure; primary-source/API investigation continues before cohort selection.

`git rev-parse` reports not a Git repository. The [historical frame plan](../../history/plans/2026-10-01-ziquid-workspace-frame.md) explicitly prohibited Git initialization/commits. Preserve that constraint: work in the existing directory, no worktree/init/commit/push operation without changed authorization. Sibling Zoss currently contains README/docs only; no exports may be assumed. Source/private stores and Zoss remain user-owned.

## 2. Product and security contract

U sells shielded Ironwood ZEC; S supplies one local-EVM native asset obligation. U prepares unsigned P, complete locally proved/signed Q consuming the same authenticated real U-owned note, and independent durable sender payout witnesses. All nonzero Q outputs are U-owned with agreed fee. S independently verifies Q's ownership/effect/ciphertext relations without receiving U spending key or FVK. S irrevocably arms exact destination amount/fixed beneficiaries before U releases P authorization.

Payment and nonpaying conflict predicates use the **same accepted valid finalized source history**. Paying P or a supported paying replacement T creates fixed U entitlement; proven nonpaying real-input conflict creates fixed S refund. T≠P does not establish nonpayment; same-effect/new-authorization P stays P. Unknown history/input ownership/debits/classification leaves nonterminal pending. Earlier admissible bound P/T cannot be excluded by an activation-height cutoff. Included valid payments retain payout after source expiry.

Native transfer and once-only consumption are atomic. Failed proof/transfer/reentrancy attempts leave valid entitlement retryable and never redirect beneficiary or switch allocation. Completed/Refunded require correct source allocation and actual destination transfer/finality. Q can cancel early and is not autonomously reanchor-capable. Conditional unbounded pending is disclosed, not replaced by timer/admin/quorum recovery.

Authority: [architecture §7](../../ARCHITECTURE.md), [module map](../../MODULES.md), [DEX gate register](../../BLOCKERS.md), [proof spec](../../modules/zcash-proofs.md), [wallet spec](../../modules/wallet-authoring.md), [destination spec](../../modules/destination-settlement.md), [solver spec](../../modules/solver-operations.md).

## 3. Alternatives requiring an explicit security choice

### Source accepted-history strategy

**Owner selected full validating transaction/state/history proofs with authenticated checkpoint state.** This preserves the strongest validity target; implementation/proving/target compatibility must be demonstrated, not inferred from upstream Halo2 spend proofs. Full validity still needs declared bootstrap, competing-history availability/freshness/anti-eclipse and finality policy. No globally canonical chain claim follows from best submitted work.

Header/inclusion verification with an honest-valid-source SPV assumption was offered but **not selected**. It is not an automatic fallback if full validation is difficult.

Rejected: signatures/quorum/RPC assertions promoted to financial verified facts. This violates the approved app-proof separation and is not an alternative implementation.

### Partial and excess consideration

**Owner selected proportional settlement**, changing the initial full-U-or-full-S-only allocation direction. Exact partial/excess/rounding/fee/source-return rules still require a concrete contract, not an implicit implementation default. A complete hostile-wallet protocol cannot exclude these cases by wallet guard.

Until the proportional/excess relation is reviewed and cryptographically supported, unknown consideration remains EvidencePending without full payout or inferred full refund. The plan must define conservation and both fixed-beneficiary transfers, exact integer rounding, supported net user consideration and excess-source disposition. Selecting proportional settlement does not itself give U or S source-refund authority or reveal arbitrary hidden inputs.

These decisions are not routine coding details. Produce a concrete source-backed recommendation and owner approval before compiling them into funded-state rules. Independent mechanical/library feasibility work remains actionable.

## 4. Implementation map

| Responsibility | Existing path | Consumes → produces | Authority and observable completion |
|---|---|---|---|
| Pure rules/encoding | `crates/protocol` | Exact versioned context/rules → canonical bytes, validated statement, typed classification/allocation/transitions | No network/storage/signing. Independent vectors; wrong context/units/overflow fail. Raw observation cannot construct a financial verified fact. |
| Source authoring | `crates/zcash` | Caller-owned real note/upstream capabilities/context → unsigned P, full Q, private sender witnesses and separately labelled acquired source data | User keys stay local; S offline validation/U-offline Q executed in authorized environment. Every action/dummy/binding/output proof covered. |
| Settlement proof relations | `crates/proofs` | Context + granted transaction/history/ownership/encryption witnesses → real proof artifacts and matching target verifier material | No economic signer or RPC-to-proof shortcut. Exact/full-T/net-consideration/history/auth/hiding/uniqueness relations verified. |
| Destination | `contracts/evm`, `crates/chains` | Pinned actual proof/context + exact funded obligation → once-only fixed native transfer, observed/reconciled outcomes | Irrevocable arming, no cancel/timer. Full proof reaches actual verifier; balances/state confirm payout/refund and rollback/retry. |
| Durable orchestration | `crates/runtime` | Validated packets/reservations/signer intents/granted proof jobs → durable execution/reconciliation and thin native driver | Transactional inventory; persist before export/sign/send; ambiguous operations reconcile. Cache rebuild/expiry cannot release armed value. |

Intended acyclic imports: protocol at bottom; zcash/proofs/chains each depend on protocol and necessary maintained upstream libraries, never each other/runtime; runtime or user-local caller composes. EVM consumes equivalent canonical encoding and pinned proof artifacts, not native worker stack. No new wallet product, UI, generic plugin/queue framework or SDK work.

## 5. Shared Zoss handoff

Zoss common encoding/authorization is below DEX-specific context; source acquisition is below DEX authoring/proof witnesses; truly identical client mechanics are below DEX financial calls. Published export names/revisions and encoding/domain/cohort conformance must be agreed with the user as owner. Use real upstream APIs for independent work, not fake Zoss packages or duplicate permanent standards. Final selected integration uses actual published exports, removes superseded callers and proves two caller-owned private-state domains remain isolated.

`SourceObservation` ≠ `QuorumAcceptedMessage` ≠ target-owned `VerifiedSettlementFact`. App financial proofs bypass optional receipts. No mandatory watcher/new IVK holder/runtime/daemon. Public raw blocks may share only under matching context; keys/private witnesses/payment mappings/proving jobs cannot.

## 6. Load-bearing unresolved relations

The implementation plan must resolve rather than conceal these prerequisites:

1. Compatible actual Ironwood/v6 builder/prover/extractor cohort; every action/signature/binding and valid note/tree/anchor capability.
2. Independent same-real-input and all-Q-output ownership/ciphertext validation without user FVK handoff. Valid upstream spend proofs alone do not certify app beneficiary ownership.
3. Actual complete input/output/auth-body and accepted-history proof strategy, checkpoint state and competing-history policy.
4. Independent sender payout proof sharing receiver classifier semantics; no S IVK/debit-witness withholding dependency.
5. Complete net consideration and owner-selected partial/excess allocation; mixed S-owned input gross-sufficient/net-zero adversarial case.
6. Hiding-compatible global-within-selected-domain payment consumption across new order IDs/random commitments; no public locator privacy shortcut.
7. Usable artifact/private-witness/data lifetime, actual proof cost and target verification feasibility.

Dependency pins, backend names and wire algorithms will be selected only from actual APIs and exercised compatibility, not copied from role diagrams. A missing cryptographic relation is not filled by a trusted certificate or mock true flag.

### Primary-source feasibility findings

Read-only investigation found concrete primitives, not completed app relations:

- [Orchard 0.16.0 public proof inputs](https://github.com/zcash/orchard/blob/8190e4d9b7e9c0140964e88b71f95276d2b50470/src/circuit.rs#L1170-L1299) bind anchor/value commitment/nullifier/randomized authorization key/note commitment/flags, not EVM order, all-input ownership, recoverable ciphertext or solver consideration. App certificates/circuits are required; accepted source proof is not an ownership/payment certificate.
- [Sender output recovery](https://github.com/zcash/zcash_note_encryption/blob/b646773328bf97cbbeeb92f7affaeb91541119ea/src/lib.rs#L788-L842) can validate full ciphertext/commitment/ephemeral-key relation from sender material without S IVK. This is a real candidate for independent U payout witnesses, not a complete settlement proof.
- **Arbitrary hostile T witness availability:** public raw T and S IVK do not reveal every other input's value/ownership or zero-dummy opening. If U authors T elsewhere and disappears, S may not possess the complete no-other-real-input witnesses; a zkVM cannot recover information hidden by Zcash proofs. Independent supported-T capabilities remain a separate security prerequisite even after amount/allocation policy is selected.
- Published candidate cohort: Orchard `0.16.0`, zcash_primitives `0.31.0-pre.0`, zcash_protocol `0.11.0-pre.0`, note_encryption `0.5.1`; newer PCZT source still has an old package version label. Existing audit Git pins and their root patches differ from same-named published packages. These candidates require real lockfile/build/proof compatibility checks before selection. [New primitives release](https://github.com/zcash/librustzcash/tree/52456edcda0350ca9b904ff381f021a4ba97223d), [audited root patches](https://github.com/zcash/librustzcash/blob/f7b1cfb0b5bb1bdb10564079ac51b54aa18b07a1/Cargo.toml)
- SP1 and RISC Zero have actual EVM-verifiable proof paths, but no Ironwood guest compilation/proving was exercised. Backend proof wrapping does not authenticate an arbitrary state snapshot or node assertion. Non-ZK intermediate/fake dev receipts must not cross private/financial interfaces; setup/verifier governance and indefinite old-artifact support need review. [SP1 security model](https://docs.succinct.xyz/docs/sp1/security/security-model), [RISC Zero verifier](https://github.com/risc0/risc0-ethereum/blob/365e7b2db4f620fa256580c27558d2623362b9ae/contracts/src/groth16/RiscZeroGroth16Verifier.sol)
- **Owner selected one real note per obligation in one EVM deployment.** A stable secret-bound consumption tag remains an unimplemented construction: authenticate key/real-note/nullifier linkage, bind the exact deployment and prevent fresh quote salts from changing identity across supported versions. Reserve uniqueness at fund/arm, roll reservation back if funding fails, retain terminal consumption. Other deployments/targets remain unsupported, not implicitly globally unique.

No source/proof dependency was installed and no new production code was written during this prerequisite investigation. The actual baseline remains one passing frame test; no gate was closed.

## 7. Acceptance and execution order

Full milestone goal remains M1 relations/state → M2 actual Q/user offline → M3 complete classifier/independent U → M4 actual source-proof/native-EVM transfers → M5 hiding/uniqueness/resources/lifetime. Runtime/driver integrates as real interfaces become available. Parallel branches after common contracts: authoring, app-proof relations, actual EVM verifier/escrow/client, durable execution; one integration owner controls shared statements. No source edits before required design/plan approvals.

Tests name real consumer-visible failure: wrong domain/network/pool/branch/units/amount/beneficiary/schema/VK, unsigned P export violation, forged real/dummy inputs, invalid auth/ciphertext/ownership, paying P′ and earlier P/T, omitted output, mixed gross/net attack, orphan/checkpoint/fork omissions, duplicate payment under fresh commitment/order, transfer failure/reentrancy, restart/concurrent funding/unknown send, old-version witness/proof retry. Permanent tests cannot assert mocks/source text; actual smoke must exercise changed path. Generated fixture/local VM/network/deployed evidence stays distinct.

Before money-related node actions, show exact network/signers/assets/recipients/fees/simulation and obtain authorization. Without network action permission, local evidence cannot close actual testnet/runtime gates. All wider closure criteria stay in canonical BLOCKERS. Deliver complete exercised protocol or explicit unresolved security/action prerequisite; do not label a partial frame/escrow a finished protocol.

## 8. Next owner review

Owner review approved full validating source proofs, development of proportional settlement and one-note/one-deployment uniqueness. Next review is the exact implementation plan, including concrete proportional rounding/excess treatment, supported-T witnesses, bootstrap/fork/finality and proof-artifact contracts. Source consensus cannot silently downgrade to SPV; setup/delegation/governance changes need owner review. The native end-to-end goal and all failure/privacy/lifetime requirements stay intact.
