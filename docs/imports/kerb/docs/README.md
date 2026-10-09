# Kerb documentation

**Current documentation direction (2026-10-01): Kerb reuses Zoss's shared native cross-chain library core inside Kerb-controlled processes.** Common source acquisition/observation, context/domain/authorization encodings and Solana client plumbing may be reused without Zoss watchers, receipts, quorum, a shared daemon or an added viewing party. This is an adopted **docs-only direction**, not implemented imports, dependency installation or approval of a funded/private market.

**Product expansion recorded (2026-10-02):** the owner requests documenting **both** Hyperliquid paths: eligible Hyperliquid assets traded P2P on Kerb, and explicit user-authorized spot orders executed on HyperCore through Kerb. [Hyperliquid product scope](product/17-HYPERLIQUID-EXPANSION.md) owns this new direction and its user stories, privacy/custody boundaries and release prerequisites. Neither path is implemented or enabled; no perps, automatic remainder routing, funded actions or privacy waiver is approved. The original Solana↔Ironwood objective and approved local safety increment remain intact.

## Authority and current reading order

1. [`00-CANONICAL.md` §0](00-CANONICAL.md#0-current-documentation-authority) records the shared-library decision and separates it from financial and historical authority. [Zoss architecture](../../../../../zoss/docs/ARCHITECTURE.md) and [Kerb consumer contract](../../../../../zoss/docs/kerb.md) own the shared-core interfaces; [Zoss BLOCKERS](../../../../../zoss/docs/BLOCKERS.md) is the sole core readiness register. Existing core gates remain Open; no runtime/privacy pass follows from this documentation.
2. [Integrated production-demo candidate](docs/superpowers/specs/2026-10-01-kerb-production-demo-design.md) and [adversarial review](docs/superpowers/specs/2026-10-01-kerb-design-review.md) are **unapproved financial/private proposals**. The permitted singleton/public-membership/attacker-own-fill probe causes a known **GD2 structural FAIL**, not merely missing measurements. FAA/MPC/custody/ledger/FROST/payout/refund and recovery remain Kerb-owned; adopting libraries does not approve that proposal or waive privacy.
3. Current reuse requirements sit beside the retained [system architecture](architecture/03-SYSTEM-ARCHITECTURE.md), [off-chain operations](architecture/06-OFFCHAIN-SERVICES.md), [security](security/07-THREAT-MODEL.md), [verification obligations](security/08-TEST-AND-VERIFICATION-PLAN.md) and [decision log](product/16-ROADMAP-AND-DECISIONS.md). Their dated public-Solana designs below those updates are historical, not an approved replacement architecture.
4. [Sep29 Zolana review copy](../zolana-review-2026-09-29/README.md), [Sep30 research dossier](../zolana-research-2026-09-30/README.md) and [Sep29 proposal](docs/superpowers/specs/2026-09-29-kerb-zolana-design.md) preserve evidence and decision history. They do not restore historical Zoss payloads or supersede the current shared-library decision.

For the reviewed differences between both Zolana dossiers and today's objective, current-versus-historical architecture, user stories, maker-signing terminology and actors beyond users, see [Zolana concept and actor review](reviews/2026-10-02-zolana-concept-and-actors.md). Both Zolana dossiers retain the same native Solana↔Ironwood concept; their dates, research alternatives and historical implementation gaps do not make them disposable copies of the old public-Solana proposal.

The optional Zoss **messaging profile** stays **OFF / non-money**. Kerb's money workflows must not require that runtime, a receipt or a diagnostic callback. A private source observation must pass Kerb claimant/ownership, canonical-history, controlled unallocated inventory and durable credit-dedup checks before any credit; receipt acceptance is never credit, payout, refund, reverse-chain or payment-effect proof. No code, deployments, transactions, publication or financial-spec approval is authorized by this cutover.

## Implemented local safety cores (2026-10-02)

The approved [independent safety-core specification](docs/superpowers/specs/2026-10-02-kerb-safety-core-design.md) and [implementation plan](docs/superpowers/plans/2026-10-02-kerb-safety-core-build.md) authorize a separate implementation increment. The Rust workspace now contains `kerb-protocol`, `kerb-ledger`, `kerb-custody` and `kerb-runtime`; `contracts/solana` is an independent target workspace. This does not approve the Oct1 financial/private candidate or implement shared Zoss acquisition imports.

Observed local execution uses real PostgreSQL, three separately launched acknowledgement processes/databases, a compiled Solana ELF with real legacy-SPL transfers, and upstream unsigned Ironwood PCZT inspection. The independently invoked CLI retained 22 journal decisions/commits and two nonce tombstones; all three replica heads matched the coordinator. Synthetic SPL collateral `7` became buyer delivery `5` plus escrow remainder `2`; native quote debit `34` partitioned into `25` and `9`, with separate sponsor fee capital. The native payout observation is explicitly signed **LocalFixture testimony**, not a mined payment. The unsigned refund remains prepared/unknown with its inputs locked.

Epoch commit/abort and allocation activation are global canonical events, not per-hold receipts. One epoch decision classifies every retained bound hold; the immutable terminal blocks new admission. Accepted holds retain the same result while their portions remain disjoint per hold. Activation authorizations require every accepted hold's complete authenticated allocation before export; one observed activation activates all accepted allocations atomically. A partial result cannot fence out the remaining chunks with premature signatures.

Native approval compares every inspected input's structured occurrence, commitment, nullifier, value and user-versus-sponsor scope with authenticated retained PostgreSQL inventory before reserving inputs or exporting acknowledgements. Matching logical IDs, aggregate totals or equal-value notes is insufficient. Derived change carries the checked transaction/action index, commitment and owning-viewing-key-derived nullifier into its signed plan/observation and later spend. No FVK, full note or private identity dump is added to diagnostics.

Future-change note IDs remain exclusively reserved before materialization. Deposit credit issuance and sponsor inventory registration reject both materialized and reserved IDs in shared prepare-time validation, including each replica before ACK export. Only the exact retained native observation may materialize its reserved change; retries do not create extra backing or credit.

Physical claims also reserve source-network/pool/genesis-scoped occurrence, commitment and nullifier across logical labels and scopes. Migration0008 and V2 signed/02 wire records are a clean cutover: nonempty legacy financial/enrollment stores fail migration without modifying data; caller policy cannot backfill their missing identity. Do not reset or re-enroll an operational store to bypass this fence—an authenticated data migration requires separate design and approval.

Authenticated finalized conflicting transactions with **any reserved-input overlap** dispute and impair the pair, including additional unrelated inputs; wholly unrelated observations cannot impair it. Observations claiming the retained transaction must contain its exact complete user/fee input list. Exact-identity Reorged/Unknown impairment applies to both enrolled user and sponsor inventory scopes, preserving outstanding claims and existing locks while fencing new sends.

Cancelled SPL collateral and the buyer's native refund are distinct assets. Either return order is supported across prepared/Unknown/final BuyerRefund states, using the exact observed cancellation and retained custody fence; SPL return never rewrites native disposition. Cancellation directly from allocated state does not require a fictional PrepareFill: prepare-intent equality is enforced only when a prepare actually exists. Permanent single-use SPL return markers, observed-cancellation evidence and live SellerPayout/impairment fences remain required.

Build and run from the repository root:

```sh
cargo build -p kerb-runtime
cargo-build-sbf --manifest-path contracts/solana/program/Cargo.toml \
  --tools-version v1.57 --arch v0 --sbf-out-dir target/kerb-sbf
cargo build --manifest-path contracts/solana/Cargo.toml \
  -p kerb-solana-harness --bin local-safety-scenario
target/debug/kerb-runtime local-safety-scenario --config /absolute/path/local.json
```

`local.json` requires `schema_version: 1`, `environment: "LocalFixture"`, `database`, exactly three `replicas`, and absolute `solana_binary`, `solana_elf` and `native_policy` paths. Each database object requires `socket`, `port`, `user`, `database` and `max_connections`; provision four distinct disposable PostgreSQL databases. The native policy supplies public fixture viewing metadata and exact input/output policy, not spending keys. The scenario generates memory-only local authority keys and synthetic assets; public temporary process configuration is removed, while caller-owned databases remain for inspection. Do not point this fixture command at retained operational databases.

Other commands are `migrate`, `replica`, `inspect-ledger`, `inspect-pczt` and `reconcile`; `--help` exposes their required explicit configuration. Diagnostics do not export secret keys, full notes or PCZT contents. Reconciliation requires fresh signed retained heads; an unavailable result does not release backing. Business unanimity is distinct from native threshold signing.

Local process exchanges use real asynchronous pipe I/O with a 30-second request/bootstrap budget and five-second shutdown/exit budget. Timeout kills and reaps the owned child; it does not release prepared credit, inputs or unresolved chain operations. Real stopped-child checks exercise replica acknowledgement, shutdown and compiled-target exit, including retained debit `34` after a missing acknowledgement. These fixed local ceilings are not production latency guarantees.

`inspect-pczt` reports `effects-checked`, `signatures_verified: false`, `signing_performed: false` and `proofs_verified: false`. Supplied authorization fields may be present and unverified; the command does not assert their absence. The local scenario itself creates unsigned fixtures and performs no native proving, signing or broadcast.

Reproducible native inspection fixtures live at `crates/runtime/tests/fixtures/{unsigned.pczt,policy.json}`. Their viewing metadata comes from the public Orchard `0.15.5` key-components vectors (`ak || nk || rivk`), attributed to [zcash-test-vectors](https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/orchard/key_components.py). Notes, tree witnesses and transaction effects are synthetic; no spending key, signature, proof or real wallet history is included. Set `local.json.native_policy` to the absolute retained `policy.json` path.

Host integration tests require an explicitly provisioned disposable PostgreSQL service and the separately built target executable/ELF:

```sh
KERB_TEST_PG_SOCKET=/absolute/path/to/postgres/socket \
KERB_TEST_PG_PORT=55432 KERB_TEST_PG_USER="$USER" \
KERB_TEST_NATIVE_DIR="$PWD/crates/runtime/tests/fixtures" \
KERB_TEST_SOLANA_BIN="$PWD/contracts/solana/target/debug/local-safety-scenario" \
KERB_SBF_ELF="$PWD/target/kerb-sbf/kerb_solana.so" \
cargo test --workspace --all-features -- --test-threads=1
```

The tests create isolated databases and fail rather than silently skipping missing PostgreSQL/native/ELF prerequisites. `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo fmt --all --check` cover the host workspace; use the independent target manifest for target lint/format checks.

Actual database-server restart is a separate manual check, not a pool-reopen test:

```sh
KERB_TEST_PG_SOCKET=/absolute/path/to/owned/socket \
KERB_TEST_PG_PORT=55433 KERB_TEST_PG_USER="$USER" \
cargo run -p kerb-ledger --example postgres_restart
```

Use an expendable caller-owned cluster with CREATE/DROP DATABASE and `pg_read_file` privileges. At `READY_FOR_POSTGRES_RESTART`, all four database pools are closed. In another terminal, run `pg_ctl -D "$OWNED/data" -m fast -w stop`, then start **the same data directory** with its original socket/port/no-TCP options and wait for readiness. Send `POSTGRES_RESTARTED` to the harness stdin. It independently checks postmaster start/PID identity changed and the data directory did not; continuation without restart fails.

The exercised PostgreSQL16.15 stop/start preserved exact coordinator/replica rows, immutable pending bytes, Unknown native intent, locked input34, one nonce tombstone and one future-change reservation. Reopened mutations remained fenced until three freshly signed retained heads reconciled `PendingRetained`; committing the same retained decision advanced sequence13→14 without releasing backing, and exact replay was idempotent. This proves clean server stop/start persistence, not power-loss/crash recovery or independently governed operators.

**Not established:** actual source acquisition/history, FAA/MPC matching, FROST proving/signing, native broadcast/consensus/settlement, independently controlled operators, funded-network release or strict privacy. No private funded operation is exposed. Local safety implementation and its remaining verification do not close GD2 or any Zoss readiness gate.


## Retained public-Solana dossier

The 2026-09-28 proposal crosses same-mint tokenized-stock orders on Solana at a program-computed price before an optional pre-funded residual maker. It remains design-only, unimplemented and unbenchmarked; it is retained rather than silently replaced by the Oct1 candidate. Its exact-mint production gate is **BLOCKED**, and any actual demo uses test mints labelled **SYNTHETIC**. [`00-CANONICAL.md` §§1–6](00-CANONICAL.md) is an editorial consistency reference **for that historical proposal only**, not overall current Kerb architecture authority.

## Historical public-Solana reading order

| # | Document | Written from the perspective of | Answers |
|---|---|---|---|
| 00 | [Current authority and retained public-Solana contract](00-CANONICAL.md) | Protocol lead | Which documentation decision is adopted; which market contracts remain proposed |
| 01 | [Mechanism specification](mechanism/01-MECHANISM-SPEC.md) | Market-microstructure / auction designer | Clearing, allocation, residual phase, fees, test vectors |
| 02 | [Market design rationale](mechanism/02-MARKET-DESIGN-RATIONALE.md) | Exchange market-structure economist | Why a call auction, why oracle-free pricing, trade-offs |
| 03 | [System architecture](architecture/03-SYSTEM-ARCHITECTURE.md) | Principal systems architect | Components, trust boundaries, data flow |
| 04 | [On-chain program design](architecture/04-ONCHAIN-PROGRAM-DESIGN.md) | Senior Solana program engineer | Accounts, instructions, compute budget |
| 05 | [Token-2022 and issuer integration](architecture/05-TOKEN-2022-ISSUER-INTEGRATION.md) | Token-2022 / RWA integration engineer | Extension allowlist, raw units, multiplier windows |
| 06 | [Off-chain services](architecture/06-OFFCHAIN-SERVICES.md) | Backend / SRE lead | Crank, indexer, receipts, distributor SDK |
| 07 | [Threat model](security/07-THREAT-MODEL.md) | Smart-contract security auditor | Assets, adversaries, invariants, release blockers |
| 08 | [Test and verification plan](security/08-TEST-AND-VERIFICATION-PLAN.md) | Verification / QA engineer | Invariant-to-test mapping, property and fuzz tests |
| 09 | [Regulatory and legal issues](legal/09-REGULATORY-AND-LEGAL.md) | Securities / fintech counsel (issues map, not advice) | Venue status, distribution limits, open questions |
| 10 | [Market and competition](business/10-MARKET-AND-COMPETITION.md) | Crypto market-structure analyst | Substitutes, prior art, evidence gaps |
| 11 | [Business model](business/11-BUSINESS-MODEL.md) | Exchange business strategist | Fees, unit economics, scale hurdle |
| 12 | [GTM and validation](business/12-GTM-AND-VALIDATION.md) | Founder-led sales / validation lead | Distributor-first GTM, preregistered gates |
| 13 | [Pitch narrative](pitch/13-PITCH-NARRATIVE.md) | Pre-seed pitch coach | Deck, script, video, one-liner |
| 14 | [Judge red-flag audit](pitch/14-JUDGE-RED-FLAG-AUDIT.md) | Colosseum-style judge / VC | Every red flag from the source playbook and our answer |
| 15 | [Hackathon plan](product/15-HACKATHON-PLAN.md) | Hackathon-winning technical founder | Day-by-day plan to 2026-10-12 |
| 16 | [Roadmap and decisions](product/16-ROADMAP-AND-DECISIONS.md) | Product lead | Phased roadmap, ADRs, kill criteria |

## Sources

- [`sources/notion/idea-bank-row-5.md`](sources/notion/idea-bank-row-5.md): the source idea
  (Superteam Vietnam Idea Bank row #5), and how Kerb narrows it.
- [`sources/x/status-2038643299221729462.md`](sources/x/status-2038643299221729462.md): capture
  of Josip Volarević's "I Participated in 3 Colosseum Hackathons…" playbook, which governs the
  pitch and business evaluation (docs 11–16). It is founder advice, not official Colosseum policy.

## Central unknowns

1. Same-mint opposite-side flow at useful size and frequency (E17): **unverified**.
2. Any named buyer, seller, distributor or maker (E18): **none**.
3. Savings versus live routes (JupiterZ, AMMs, issuer xChange): **not measured**.
4. Venue legal status and holder eligibility: **counsel required**.
