# Kerb — privacy, admission, MPC và auction research

**Retrieved2026-09-30; P/I/U discipline.** Parent-completed source synthesis after privacy worker failed upstream before writing its final artifact. Earlier worker source/control observations retained only where delivered; primary core claims below were independently read by parent. No invented privacy result. No crypto/product code, deployment, funds, outreach, publication or paid API. No runtime matches, integration or independent operator claim.

**Current-authority banner 2026-10-01:** bản này là dated research snapshot. [Kerb current authority](../docs/00-CANONICAL.md#0-current-documentation-authority) adopts shared Zoss source/context/domain/Solana libraries **docs only**, chạy trong Kerb-controlled processes; không thêm viewing party/shared keys/private cache/daemon hoặc mandatory watchers/receipt/quorum. Optional message profile vẫn **OFF / non-money**. §10 giữ preSep30 schema observations, không current interface. [Oct1 financial/private candidate](../docs/docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md) chưa được duyệt, **GD2 structural FAIL**; common library không giải privacy/custody/funding proof hoặc approve financial design.

## 1. Recommendation

[I] Keep owner condition: no single matcher/control domain gets plaintext **or accepted-order linked identity**. First local non-settling D0 reference + adversarial metadata harness; research separated eligibility/custody/issuance, privately owned single-use funded relation, available receipted input set and correct sealed output. Arcium Cerberus **candidate**, not selected implementation. Blind credentials insufficient without private onchain enqueue/settlement, independent governance and controlled output leakage. All funded matching—including synthetic testnet—blocked until actual full-access-graph evidence.

## 2. Repo evidence and invariant

- staged mechanism01:23–25: funded available accepted set/credential unresolved, full matcher domain.
- staged offchain06:19,25–37: independent actual administrators, inventory/funding credentials, accepted-set and MPC proposed.
- staged architecture03:79–92: public opaque tags can join order→funding/destination; no funded executable set; corrected refund88.
- security08T01–T04/T07–T08: content+identity, shared control, private one-use ownership, admission/completeness, independent arithmetic. Cases planned, no reports passed.
- Zoss integration assessment says design-only positive same-note receive, metadata correlation, disabled funded; not credit, payout/absence/refund proof.

Pseudonym, encrypted payload, multiple servers under one owner or absent name field do not establish identity unlinkability. Distinct independent eligibility/custody may know identity/payment by disclosed policy; matcher cannot access those mappings. Public observers and compromised custodians have separate scopes; no global anonymity claim.

## 3. Actual MPC trust/configuration

**P vendor rolling [MPC protocols](https://docs.arcium.com/multi-party-execution-environments-mxes/mpc-protocols)**: Cerberus dishonest-majority detect-and-abort, privacy under at least one honest cluster member. This is protocol/vendor claim, not independent Kerb evaluation.

**P [Release0.15.0](https://docs.arcium.com/developers/release-notes), dated2026-09-14:** distributed preprocessing opt-in; existing node config unchanged keeps trusted dealer. **P [Node setup](https://docs.arcium.com/developers/node-setup):** distributed_preprocessing defaults false; unrecognized optional keys silently ignored; inspect resolved startup backend (`distributed (Cerberus)` vs `trusted dealer`). No secrets/config created. Pin synchronized CLI/Rust/TS/node versions, exact backend, authority identities, hosting/admin/observability/backups.

**P [Permissioned clusters](https://docs.arcium.com/clusters/permissioned-clusters):** all membership authority-gated; internal/mixed/external choices, unrelated operators require evidence. **P [Migration](https://docs.arcium.com/clusters/cluster-migration), [stakeholder recovery roles](https://docs.arcium.com/getting-started/network-stakeholders):** MXE authority/recovery peers can change active cluster/key distribution. Threat graph includes initialization, recovery, rotation, migration, governance and upgrade—not just current MPC processes. Review callback output authenticity with actual computation/cluster fields.

[I] Prefer distributed preprocessing candidate with independent control graph, real backend logs and actual circuit proof. Trusted-dealer option only separately reviewed stronger trust assumption; don't claim same no-single-domain guarantee by choosing Cerberus name. No current independent Kerb cluster/access/approved runtime.

## 4. Public signer/ciphertext and ingress

**P [Official program guide](https://docs.arcium.com/developers/program)** example `AddTogether` uses `pub payer: Signer<'info>`; instruction includes `ciphertext_0`, `ciphertext_1`, `pub_key`, `nonce`, queues same computation with public accounts. These bytes and signer are transaction-visible. Direct wallet submission yields signer→submitted ciphertext link **even if plaintext encrypted**. It doesn't prove no private relay route possible, but blind-token issuance alone doesn't fix this route.

[I] R1 candidate needs independently governed transport/relayer separating source identity from accepted ciphertext, batching/padding where justified, one-use encryption/client authorization keys, no shared accessible request logs, no wallet cookie/session join, and reviewed funding/settlement tags. Relayer can censor/see transport; Tor/proxy/no-log promise alone isn't guarantee, unique amounts/timing/active probes remain. Reused output pubkey/memo/fill ID/settlement amount can rejoin. Public payout effects matter even if ingress fixed. Do not route real users now; D0 synthetic traces first.

## 5. Candidate credentials—what they do not solve

| Candidate primary source | Capability stated | Kerb gap / tradeoff [I,U] |
|---|---|---|
| [PrivacyPass RFC9576](https://www.rfc-editor.org/rfc/rfc9576), June2024Informational; [RFC9578](https://www.rfc-editor.org/rfc/rfc9578), June2024StandardsTrack | Unlinkable issuance/redemption; private/public verification variants; deployment and sidechannel contexts. | Eligibility token/private bounded-denomination research starting point, **not** asset ownership, locked amount, range/max-debit, private order/ciphertext consistency or ledger synchronization. Blind bearer value can be stolen/transferred; bind holder/order without exposing identity. Distinct contexts/pair metadata can shrink anonymity sets. |
| [SemaphoreV4 circuit](https://docs.semaphore.pse.dev/technical-reference/circuits), rolling V4 | Private secret/membership path, public root; nullifier hashes secret+scope; public message bound to proof. | Membership ≠ deposit/sufficiency proof. Scope chooses one-use boundary; same user per epoch differs from each funding entitlement. Public membership group/root/message can identify small cohorts; root publication/revocation and exact SPL/ZEC relation separate. No selected Solana verifier/Arcis integration/CU proof. |
| [AnonCreds specification](https://hyperledger.github.io/anoncreds-spec/), v1.0Draft rolling | Blind issuance, hidden holder link secret, selective disclosure, predicates and non-revocation without unique revocation ID. | Useful eligibility/private signed attributes research, but extra schema/registry/revocation/witness/governance/crypto complexity; not automatic single-use fund spend or ciphertext-range relation. No Kerb deployed proof/adapter/cost/audit. |

[I] Compare smallest blind-issuance/private-attribute relation against ZK membership/ownership approach under exact threat model. Don't install a new credential stack by name. Issuer privately confirms funding+claimant entitlement, holder proves possession and relation to encrypted order/domain, system durably reserves once. Need `(network/pool, exact mint/program/pair, epoch/rules, credential secret/nullifier, ciphertext commitment, max amount/fee, expiry, client-bound destination)` relation with hidden attributes where unique values reveal identity. Proving nonce/msg correctness alone doesn't prove side/limit/qty sufficiency. Custody/eligibility issuer malicious tagging/revocation/collusion and credential cloning/double redemption across pairs/epochs/restarts must be tested. Zcash note nullifier **distinct** from business credential nullifier.

## 6. Minimal accepted-set/correctness contract

[I] Independently retrievable receipts bind ciphertext commitment, pair/epoch/rules/cutoff and verified privately funded predicate; freeze accepted root; every accepted input available to agreed circuit. Two roots/missing ciphertext/invalid credential/rules mismatch ⇒ abort/no executable fills. Public root alone authenticates chosen set, not fair preacceptance inclusion. Independent reference checks integer objective+allocation and named circuit version; signed callback authenticates output, not all external funding/ownership/issuer truth. Need malicious client authorization/range/overflow checks, output relation and replay safety before execution; no funds accepted by mocked gate.

## 7. Auction choice and bounds

[I] D0 candidate: max crossed raw lots, uniform price at half-even midpoint of maximizing plateau, price priority + marginal pro-rata; zero-cross ⇒ zero fills/no fabricated price. All arithmetic checked integers. Fixed <=8 synthetic slots can isolate unknowns; **not benchmarked/approved production bound**. Fee-free arithmetic baseline not revenue policy. No inherited64orders/1minute/5bps/residual-maker/dealer quote. No amend/min-fill D0 proposal simplifies rule only, not final production choice.

**P [Arcium limitations](https://docs.arcium.com/developers/limitations):** fixed circuit shape/arrays/bounded loops, callback shares entire Solana1232-byte transaction budget. Padding cannot leak presence/side through branches/output length; measure maximum actual callback and queue/network/preprocessing latency. No throughput/CU estimate made.

## 8. Ties and randomness not automatic fairness

[I] Deterministic commitment hash tie can be ground by nonce/order splitting; slot/owner tie leaks identity/time and is not portable. Research post-cutoff unpredictable randomness, root fixed first, all inclusion/results versioned, no seed retry/new book when result inconvenient; assess selective abort/failed beacon policy and liveness.

**P authors' [Cerberus paperv0.4](https://www.arcium.com/_astro/cerberus.DXoHIFmM.pdf), no visible dated publication in fetched excerpt, §2.3.4 pp14–15:** session/CRS distributed randomness not perfectly unbiased, rushing adversary may choose abort after outcome; controlling aborts/retries outside primitive scope. Therefore do not take SDK randomness/session beacon as auction fairness proof. This is authors' model, no independent Kerb fairness experiment.

## 9. Output leakage and observer acceptance

[I] Define explicit declassification before any public `reveal`: which price/volume/count/own-fill/status outputs, to whom, in what sample/epoch. Small cohorts or attacker-controlled orders can infer another order from exact output; withholding names doesn't stop. Minimum cohort/more padding/delayed prices may reduce leakage but aren't proven anonymity. D0 reference oracle sees researcher-only plaintext; matcher probe should get only proposed allowed surface. Preserve owner rule: cannot unilaterally call content inferred from output “allowed” unless exact contract reviewed.

Test full accessible data against withheld synthetic truth: negative controls unique quantity/time/address/shared admin/reused key, active probing and collusion; baseline/false positives/candidate-set changes; allowed outputs explicit. A successful deterministic order→identity or private field recovery fails. Failure of finite attacks alone isn't universal crypto proof; compositional argument, actual role configuration and independent review required.

## 10. Zoss options

**Historical Sep30 assessment [I]:** repo [assessment, current successor](../../../../../zoss/docs/kerb.md) and [architecture, current successor](../../../../../zoss/docs/ARCHITECTURE.md) were then proposals. PreSep30 v1 `cmx`-derived ID/height/value/envelope and attestation could link note/trade; these rejected defaults are not current wire. Only same receiver AND same note meaningful notification; Kerb scanner/ownership/canonical/inventory/dedup remains credit authority, no payout/absence/refund/Solana→Zcash capability from receipt. The historical recommendation was direct minimal Kerb quorum state authorization with Zoss v1 disabled. Still trusted testimony; public SPL amount/recipient/timing/opaque shared tags may leak. The banner's current shared-library docs adoption is separate from optional messaging; neither is magic atomic/payment proof or privacy acceptance.

## 11. Availability evidence—bounded observations only

Worker communicated: arcium/arcup absent PATH; Docker/Solana/Anchor/cargo present, binary URLHEAD200; read-only devnet program account executable observed. Worker then failed upstream without final artifact/raw output handoff. **Parent did not rerun these commands or receive full raw outputs; treat them as worker-reported observations**, not an exact independently reproducible runtime record. The exact full command/output is unavailable here; don't infer current local installation, operator independence, cluster preprocessing/callback execution or Kerb integration from those messages. Parent primary docs show public examples/local tooling path; no install/run/transaction authorized or executed by parent.

Hard gate is actual permission, pinned config and independently operated run, not blanket “Arcium unavailable”. A deployed program account can exist while actual chosen cluster governance/privacy assumptions unverified. Network program existence ≠ confidentiality result.

## 12. Deliverable/limits

Core primary pages parent read: protocol/release/node setup/limits/program/migration/permissioned clusters, RFC9576/9578, Semaphore circuit, AnonCreds spec, Cerberusv0.4§2.3.4. Repo known files read and exhaustive inventory links available. No independently executed Kerb reference/circuit/credential/ingress/payout/scanner, actual control graph, runtime benchmark, audit or privacy proof. Worker final delivery failed; parent completed synthesis from primary sources rather than presenting agent success as evidence. Every selection remains research option; no funded R1/legal/issuer/transaction gate passed.
