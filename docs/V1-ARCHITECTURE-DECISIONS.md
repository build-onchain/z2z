# Z2Z V1 Architecture Decisions Required

**Created:** 2026-10-05; **updated** 2026-10-06  
**Purpose:** Record V1 architecture decisions and the remaining open choices.

Sections 1–2 preserve the 2026-10-05 contradiction analysis. Their hosted-backend option is **historical**, superseded by the P2P decision. The decision log at the end is current.

---

## 1. Network Architecture

### Current Contradiction

**Option A (Current BLOCKERS.md, SERVER-INDEPENDENCE.md):**
- Centralized backend API server
- PostgreSQL shared database
- Frontend → Backend → Runtime → Chain
- Users connect to hosted service

**Option B (User's latest clarification):**
- P2P network of nodes
- Every user runs `z2z-node` locally
- No central server (just bootstrap node)
- Decentralized order discovery via gossip

### Decision Required

**V1 will be:**
- [ ] Option A: Centralized backend (users connect to our server)
- [x] Option B: P2P network (users run own node)
- [ ] Hybrid: Both architectures supported

**Confirmed delivery boundaries:**
- GUI deferred to production (V1 = CLI only)
- `z2z-node` binary is the V1 deliverable

**Open implementation questions:**
- Which gossip/authentication/synchronization protocol supports decentralized order discovery?
- Which peer discovery/bootstrap arrangement avoids mandatory company infrastructure and paid services?

---

## 2. Database Architecture

### Current Contradiction

**SQL-VERIFICATION.md states:**
- PostgreSQL mandatory
- No SQLite allowed
- No local SQL tests

**P2P delivery requires owner-local operational state:**
- No mandatory shared order-book database or company service
- Durable intents, reservations and `Unknown` outcomes must survive restart
- A bounded volatile discovery cache is a candidate for rebuildable public advertisements, not durable financial state

### Unresolved Storage Questions

**Storage design target selected 2026-10-06: each owner's own PostgreSQL**, on the owner node by default. It stores lane-keyed digests and identities only. Executable certificate, signed-tx and preimage bytes live in an owner-local encrypted release capsule (X.REL-DIGEST). See [storage decision](V1-P2P-STORAGE-DECISION.md). [SQL-VERIFICATION](SQL-VERIFICATION.md) remains binding: SQLite is prohibited, and no local SQL execution, install, schema or migration is authorized. Existing stores and journals are preserved.

- How can each node retain durable intents, reservations, authorized bytes and pending/`Unknown` outcomes without a mandatory shared company database or paid service?
- Can the current PostgreSQL requirement satisfy that per-node design, or is explicit user approval needed to change the storage requirement?
- Which public discovery records can be rebuilt from a bounded volatile cache, and which financial records require durable owner-local retention?
- What separately authorized verification and migration demonstrate correct restart/reconciliation without losing existing rights or pending liabilities?

---

## 3. Proving Resources

### Current Evidence

The [native checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) records retained SP1 artifacts, a source-derived recursion-key resident-array lower bound and an observed capped OOM without a certificate. Those observations do not measure a whole-prover peak or qualify full samechain proving on the user's i5-11400H / 16GB target machine.

**Proving feasibility UNQUALIFIED until benchmarked on target hardware. Proof-system selection: UNRESOLVED.** Owner-local only, zero paid proving infrastructure and no secret-witness outsourcing are fixed requirements, not open alternatives.

### Required Benchmark and Open Questions

Must measure existing SP1 `prove-owner` first with the actual samechain guest and controlled non-production witnesses. Record available RAM, limits/swap, whole-prover/child/shared-memory peak, wall time, storage, result and failure stage across supported operations/witness sizes. Require genuine wrapping and exact target admission; CPU execution is not a wrapped proof.

- Does the existing SP1 **CANDIDATE** qualify full proving, privacy and recovery on the target machine?
- What measured node-only and full-prover resource/latency targets should be adopted? **TBD after benchmark.**
- If SP1 cannot qualify, which owner-local **CANDIDATE** preserves the same financial/recovery relations and passes constraint, complete-resource and verifier measurements?

See [PROVING-COST-SOLUTIONS](PROVING-COST-SOLUTIONS.md). No guessed hardware minimum, latency or preselected alternative is established.

---

## 4. V1 Scope Boundaries

### Current Contradiction

**User said:**
- "Demo = 90%+ finished product, linear to production"
- "Users can trade real money normally"
- "Just enough for demo, scale up in production"

**These imply different scopes:**
- 90% finished = most features complete
- "Just enough" = minimal viable only

### Decision Required

**V1 requirements — not completion evidence:**
- Real owner-local proofs and exact verifier admission (SP1 currently unqualified)
- Samechain create/fill/cancel/withdraw and supported partial remainder handling
- P2P discovery through `z2z-node`; CLI-only user journey
- Maker online with fresh exact samechain packet consent per fill
- Full company-off recovery: encrypted cold restore → independent authenticated history → witness → real proof → owner sign → independent submit → actual asset arrival
- Durable operational storage decision and restart/`Unknown` correctness

**Still V2/later production, not deleted or completed:**
- Maker-offline standing authorization and multi-fill
- GUI/frontend integration, hardware wallets and broader signing modes
- Mainnet release and release-scale/security qualification
- Intents/1Click, Raydium/LP/agents/ZSA

**Active in parallel (2026-10-06, not V2):** L-HEVM (spot first; isolated position-claim research), L-SOL owner-ZK, L-NEAR owner-ZK (native NEAR first), **L-ZEC native ZEC**, and cross-chain fills for all pairs. The project is complete only when all of these pass. See [BLOCKERS](BLOCKERS.md) §4.2.

Observation/decryption alone does not close V1 recovery. GUI deferral does not authorize taking over the user-owned sibling frontend. Existing strict GD2 privacy blockers remain; P2P transport does not solve or waive them.

---

## 5. Resource Constraints

### Stated Requirement

- **Zero cost** for proving infrastructure
- Must run on **weak hardware** (user's laptops)
- Node-only weak-hardware target remains to be selected and measured; it is not a prover minimum

### Decision Required

**Resource targets: TBD after benchmark.**
- What node-only peak RAM and CPU/storage needs are measured for supported operation?
- What full-prover peak RAM, CPU/storage and proof latency are measured across supported witnesses?
- Which measured acceptance targets satisfy the intended weak-hardware journey without changing requirements silently?

**If measured targets cannot be met:** research measured owner-local alternatives before changing requirements. Do not defer required proving, upload witnesses, fabricate proof success or silently increase hardware requirements. Any changed acceptance scope needs explicit user approval.

---

## 6. Settlement Scope

### Current BLOCKERS.md Gates

**S1-S7 are native Zcash gates** (Ironwood P/Q/T)

**Samechain §4.1 requirements are separate:**
- Proof qualification
- Funded lifecycle
- Recovery
- Asset control

### Decision Required

**V1 settlement scope:**
- First passing journey is samechain (owner answer Z1); native S1–S7 gates remain intact for the active L-ZEC lane, and are not redefined as simplified samechain gates.
- Select exact Native/ERC20 asset and deployment pins on one EVM public testnet
- Local Anvil is development, not public-testnet acceptance
- The samechain journey makes no native Zcash or mainnet claim. Native ZEC is delivered by L-ZEC.

---

## 7. Frontend Integration

### Current Contradiction

**[Archived PRODUCT-OVERVIEW-AND-FRONTEND-HANDOFF](history/PRODUCT-OVERVIEW-AND-FRONTEND-HANDOFF.md):**
- 71 user stories for React frontend
- Backend API contract defined
- Frontend is sibling project (user-owned)

**Latest clarification:**
- GUI deferred to production
- V1 = `z2z-node` CLI only

### Decision Required

**V1 user interface:**
- [x] CLI only (z2z-node commands)
- [ ] Simple TUI (terminal UI)
- [ ] Desktop app (Tauri/Electron) - deferred
- [ ] Web frontend - deferred

**Frontend handoff doc:**
- [ ] Keep for V2/production reference
- [ ] Update to reflect V1=CLI scope
- [ ] Archive as superseded

---

## 8. P2P Protocol Details

**If P2P network selected, need to specify:**

### Peer Discovery
- [ ] libp2p DHT (decentralized)
- [ ] Bootstrap nodes list (centralized list)
- [ ] mDNS for local network
- [ ] Combination of above

### Order Book Sync
- [ ] GossipSub broadcast
- [ ] Request/Response pattern
- [ ] Blockchain as source of truth
- [ ] Hybrid

### Settlement Coordination
- [ ] Both parties submit own transaction
- [ ] One party submits bilateral fill
- [ ] Relayer submits (who pays gas?)

### Company Bootstrap Nodes
- How many: _____ (1-5?)
- Role: discovery only; never owner proving, money authority or mandatory exit authorization
- Alternative peers/bootstrap replacement must work without company services; no mandatory paid VPS/service dependency

---

## 9. Proving System Selection

### Selection Status: UNRESOLVED

**SP1: CANDIDATE; feasibility UNQUALIFIED.** Integrated source and frozen SP1 v6.1.0 EVM verifier source exist; that is current implementation context, not a V1 system commitment or genuine wrapped-positive qualification. **Circom, Halo2 and other owner-local systems are CANDIDATES**, requiring constraint/resource measurement and independent relation, privacy, setup, verifier and recovery qualification.

### Benchmark Action and Open Selection Questions

Must measure existing SP1 `prove-owner` on the user's i5-11400H / 16GB machine first with controlled non-production witnesses.

- Do full wrapped-proof resources, private-data boundaries and exact target admission support selecting SP1?
- If not, which measured owner-local candidate implements the same financial/recovery relations within the adopted hardware targets?
- What independent setup/program/verifier and genuine-proof/funded/recovery evidence is required before selecting or migrating any candidate?

### Immutable Verifier Consequence

[`SamechainAuthority.sol`](../contracts/evm/src/SamechainAuthority.sol) constructs a new frozen SP1 verifier and pins `verifier`, `verifierCode` and `ownerProgram` immutably. No in-place VK update is supported. Changing proof system, verifier or program VKey requires a new authority deployment and, for a different verifier, reviewed contract implementation changes. Explicit deployment authorization, new client/deployment/artifact pins, independent compatibility and full funded/recovery qualification are required. Preserve old funded rights and original recovery artifacts; a new deployment does not migrate or retire them automatically.

---

## 10. Deployment Strategy

### Current Status

**Contracts:**
- SamechainAuthority.sol with SP1 v6.1.0 verifier
- Compiled but not deployed

**Target chains (from docs):**
- Base Sepolia (testnet) mentioned
- Local Anvil for development
- "Solana deferred" is superseded. Solana Devnet owner-ZK, NEAR testnet and HyperEVM 998 are active lanes.

Base Sepolia for the first journey is an **engineering default**, not owner approval.

### Decision Required

**V1 deployment target:**
- [ ] Local Anvil only (development)
- [ ] One public testnet (Sepolia/Base Sepolia)
- [ ] Multiple testnets
- [ ] Mainnet (needs explicit authorization)

**Deployment authorization:** specific user authorization is required even for local-node deployment, signing/submission and fund movement. Current SamechainAuthority/verifier/program pins are immutable, not an upgradeable selection. A replacement deployment does not authorize migration of existing assets.

---

## Remaining Open Architecture Questions

- How will `z2z-node` implement bounded authenticated discovery, coordination and independent reconnect without mandatory company services?
- How will PostgreSQL-only instructions and per-node durable state requirements be reconciled without approving SQLite by assumption?
- Which owner-local proof-system **CANDIDATE** qualifies after measuring existing SP1 first, and what node/prover resource targets follow from the results?
- Which exact Native/qualified ERC20 assets and immutable deployment pins will be selected on the public testnet?
- How will the full company-off cold-restore → proof/sign/submit → asset-arrival drill be independently exercised under specific action permissions?

These questions do not defer confirmed P2P/CLI/samechain/maker-online/full-recovery requirements or establish runtime acceptance. Retained V2 obligations remain unchanged.

---

## Next Steps After Decisions

1. Align the owned V1 documents with confirmed P2P/CLI/samechain/maker-online/full-recovery scope
2. Resolve durable storage approval without bypassing SQL restrictions
3. Specify bounded P2P discovery, coordination and reconnect behavior
4. Benchmark existing SP1 `prove-owner` first; measure owner-local alternatives if SP1 cannot qualify
5. Implement `z2z-node` and exercise genuine-proof, funded and company-off acceptance under specific action permissions

These are pending deliverables; documentation consolidation does not establish runtime readiness.

---

## Decision Log

**Date:** 2026-10-05  
**Decided:**
- V1 = P2P network (not centralized backend)
- V1 = CLI only (GUI deferred)
- `z2z-node` is core deliverable
- Zero-paid-infrastructure constraint confirmed
- Maker online/per-fill consent for V1; standing maker retained in V2
- Full company-off cold restore and independent proof/sign/submit/asset arrival required in V1

**Pending:**
- Durable node storage approval; PostgreSQL-only/no-local-SQL instructions remain in force
- Owner-local proof-system selection **UNRESOLVED**; existing SP1 must be measured first and all alternatives remain **CANDIDATES**
- Proving feasibility **UNQUALIFIED**; node/prover resource acceptance targets **TBD after benchmark**
- Exact public-testnet asset/deployment pins and specific external-action authorization

**2026-10-06 scoped recovery decision:** user approved samechain encrypted bundle and restore design/implementation/checks with generated keys only. Production-secret use, production recovery command/scanner and signing/submission remain held. User explicitly left the durable public node backend undecided; no alternative financial journal or SQL engine is selected. Backup snapshots alone do not resolve Released/Unknown or authorize export/funding.

**2026-10-06 owner decisions (supersede "backend undecided" above):**
- Per-owner PostgreSQL design target; no SQL execution grant.
- The written generated-key snapshot spec and plan are approved.
- A verified offline independent-media backup is required before deposit and before each new release capability.
- Packet order: descriptors → freeze → backup/read-back → consent.
- Z1: the first passing journey is samechain; L-ZEC is active and required for the whole project.
- Z2: native NEAR first; NEP-141 is active later; claimable credit is PROPOSED only.
- Z3: cross-chain token/collateral legs first; position-claim trading is active research.
