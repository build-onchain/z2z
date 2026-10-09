# Phase 0 — testnet, chain-lane, finality, prover and action policy (P0.03 / P0.08 / P0.09 / P0.11)

**Date:** 2026-10-06. **Owner:** PlanChainsProverPolicy (configured PLAN model), integration by ConfiguredPlanCoordinator.
**Scope:** research and proposals only. No build, test, RPC transaction, faucet claim, deploy, signing, SQL or heavy prover run happened. Nothing here authorizes an action. Repo source and the canonical docs listed in [V1-MICRO-IMPLEMENTATION-PLAN](../V1-MICRO-IMPLEMENTATION-PLAN.md) still win over this note.

Evidence tags: **SRC** = read in this repo at today's tree. **DOC** = first-party docs or source, retrieved 2026-10-06; live pages can change. **[INFERENCE]** = my derivation, not observed. "Unmeasured" means unmeasured.

Status vocabulary (coordinator schema): SOLVED-TECH, PROPOSED-MECHANISM, RESEARCH-OPEN, OWNER-DECISION, ACTION-HELD, EXTERNAL-INPUT.

Lane namespaces (pending MQ8): the existing 122 IDs are the EVM/Base lane. Lane work goes under `L-HEVM.*`, `L-SOL.*` and `L-NEAR.*`. Shared seams go under `X.*`.

---

## 1. Owner answers already recorded (don't re-ask)

V1 gets detailed plans and V2 gets a source-linked backlog. Each spec and plan is reviewed before code. Durability targets per-owner self-operated PostgreSQL as a design only; nothing is installed or run. Disclosure is bilateral-counterparty only. Transport is direct plus an optional independent relay, and network checks use generated keys on loopback only. Immutable generated-key snapshots are approved, and verified offline backup must exist before deposit. The required order is: descriptor → freeze → backup/readback → consent.

Latest owner direction:
- NEAR and Solana run in parallel with EVM. Every lane is immutable.
- HyperEVM covers **spot and perps positions**.
- Solana uses owner-ZK on Devnet. The existing 3-ACK target keeps its separate provenance.
- NEAR starts with owner-ZK. Intents/1Click stays in the backlog.
- Cross-chain fills are active scope. Release happens per first-passing lane, and the whole project stays incomplete until every lane passes.
- Finality uses two operators matching on finalized data. An own non-validating second source is a design option only, under separate resource permission.
- Methodology only, with no heavy trial. The ≤15 min proof latency is a provisional objective, not a guarantee.
- Native ZEC is an ACTIVE parallel lane (L-ZEC), required for the whole project but not for the first journey; standing maker and GUI stay V2.

## 2. Verified source facts

### 2.1 Current EVM authority and prover (SRC)
- `contracts/evm/foundry.toml` and `SamechainAuthority.sol:2` pin solc 0.8.34 with Cancun. [V1-TESTNET-SELECTION](../V1-TESTNET-SELECTION.md) already fixed the old 0.8.28 prose, so no downgrade is needed.
- Every packet path calls `SamechainAuthority.sol:169-171` `_checkIdentity`, which requires a matching `block.chainid`, token codehash and verifier codehash. Expiry is checked at `:181` as `block.timestamp > packet.expiry`. **A transaction with timestamp equal to the expiry still executes.**
- `SP1VerifierGroth16.sol` (v6.1.0) checks 5 public inputs at `:64-80`: programVKey, sha256(publicValues) masked to 253 bits, exitCode (must be 0), vkRoot (must equal `VK_ROOT`), and nonce. The proof is a 4-byte selector followed by an ABI tuple.
- Hashing: the tree, deployment and packet digests use `sha256` (`SamechainTree.sol:34-52`, `SamechainCodec.sol:136,304`). The ciphertext hash uses keccak (`:237`).
- `crates/chains/src/samechain/inspection.rs:800` reads state at an EIP-1898 `{"blockHash":…, "requireCanonical":true}`. Its `source_scope` is `TRUSTED_NODE_AT_SELECTED_BLOCK` (`:254`). It doesn't acquire timestamps, finality or receipts.
- Prover: `crates/proofs` pins SP1 6.8.1 with `native-gnark`. `artifacts.rs:253-273` pins the SDK and contract revisions, circuit v6.1.0, the 2,437,991,441 B circuit, the 5,862,173,061 B PK and the 492 B VK, plus their digests. These identify the local acquisition. They don't prove ceremony provenance.
- Recorded runs ([NATIVE-IMPLEMENTATION-STATUS](../NATIVE-IMPLEMENTATION-STATUS.md)):
  - A historical 4 GiB run with swap 0 hit OOM at 97 s.
  - The public light setup took 4.904416 s, with a charged cgroup peak of 632,758,272 B and maxRSS of 646,971,392 B.
  - A 12 GiB + 1 GiB wrap request was refused before launch because headroom was insufficient.
  - **No full owner wrap has ever been measured.**

### 2.2 Solana lane (SRC + DOC)
- **Repo target** (`contracts/solana`): pins `solana-program =3.0.0`, `spl-token-interface =2.0.0` and `litesvm =0.10.0`.
  - It is a public legacy-SPL escrow with 3 business ACKs. Token checks require the legacy SPL program id and match mint decimals to the pair (`accounts.rs:114-131`, `lib.rs:113-138`). Ed25519 authorization goes through the instructions sysvar (`authorization.rs:10-67`).
  - The recorded ELF SHA256 is `ffe8465d…9913`, with 16 compiled-ELF tests ([README](../../contracts/solana/README.md)).
  - **No owner-ZK verifier exists.**
- **BN254 syscall costs.** Source: `anza-xyz/agave` `program-runtime/src/execution_budget.rs` (master). These are the code defaults; activation on a given cluster was not checked.
  - g1_add 334 CU, g1_mul 3,840 CU, pairing 36,364 CU for the first pair + 12,121 CU per extra pair, g2_decompress 13,610 CU.
  - sha256: 85 CU + 1 CU/byte.
  - Max 1,400,000 CU per transaction, default 200,000 CU per instruction.
  - BLS12-381 syscall costs are also listed.
- **Measured Groth16 cost (DOC).** `Lightprotocol/groth16-solana` BENCHMARKS.md, measured under mollusk: plain Groth16 costs 91,448 CU with 4 public inputs and 108,762 CU with 8. **With 5 inputs it is ~95k CU [INFERENCE], unmeasured on our VK.**
- **sp1-solana (DOC, master) is not usable as-is.**
  - It pins SP1 5.0.3, solana 2.1.6 and `groth16-solana 0.2.0`.
  - It ships VKs only up to v5.0.0 and hardcodes `PublicInputs<2>` (vkey hash + digest) in `utils.rs`.
  - Our verifier is v6.1.0 with 5 inputs plus the exitCode and vkRoot checks.
  - It is marked "not audited", and its README states the 1,232-byte transaction data limit.
  - **Conclusion:** a reviewed v6.1.0 port is required, with 5 inputs, the `VK_ROOT` and exitCode checks, and the 356-byte proof. Each proof (~260 B raw) plus the packet must be staged through program-owned buffer accounts across several transactions. Fill2 carries two proofs.
- **Commitment levels (DOC, solana.com/docs/rpc):** `processed`, `confirmed` (more than 2/3 stake voted) and `finalized` (max lockout). Public Devnet RPC: `https://api.devnet.solana.com`, with the faucet at faucet.solana.com. Public endpoints rate-limit (429/403).

### 2.3 NEAR lane (SRC + DOC)
- **Repo:** `contracts/near` is an empty workspace (`members = []`). No contract, verifier or account exists.
- **Host functions (DOC):** `near-sdk-rs` `env.rs` (master) exposes `alt_bn128_g1_multiexp`, `alt_bn128_g1_sum`, `alt_bn128_pairing_check`, `bls12381_*`, `sha256`, `keccak256`, `ed25519_verify`, `block_timestamp` (ns), `block_height` and `promise_yield_create`.
- **Gas (DOC):** nearcore `core/parameters/res/runtime_configs/parameters.yaml` is the master base file. Per-version diffs and testnet activation were not checked.
  - Pairing: 9.686 TGas base + 5.102 TGas per element. Multiexp: 0.713 TGas base + 0.32 TGas per element.
  - `max_tx_gas` is 500 TGas. Max function arguments are 4,194,304 B.
  - **A 4-pair Groth16 check is roughly 32 TGas [INFERENCE arithmetic].** No SP1-on-NEAR verifier was found, so one must be written and reviewed.
- **Async model (DOC, NEP-141 Final).**
  - Cross-contract calls run as later-block receipts, and there's no atomic rollback across contracts.
  - `ft_transfer_call` → `ft_on_transfer` → `ft_resolve_transfer` returns any unused amount.
  - Amounts are U128. Decimals live in metadata (NEP-148).
  - Each transfer requires a 1 yocto deposit, and holders need storage registration (NEP-145).
  - Immutability means **"no access keys on the account"** (NEP-141 notes).
- **Finality (DOC):** RPC accepts `finality: "final"` or a `block_id` (api/rpc/block-chunk). A transaction is complete only once every receipt's outcome is final (transaction-execution docs).
- **Testnet RPCs (DOC, api/rpc/providers):**
  - `archival-rpc.testnet.near.org`, which is "severely rate limited"
  - `test.rpc.fastnear.com`
  - `near-testnet.drpc.org`
  - `testnet-rpc.intea.rs`
  - Faucet: docs.near.org/getting-started/faucet.

### 2.4 HyperEVM / HyperCore lane (DOC, hyperliquid.gitbook.io, retrieved 2026-10-06)
| Item | Fact | Tag |
|---|---|---|
| Chain | Testnet chain ID 998, RPC `https://rpc.hyperliquid-testnet.xyz/evm`. Cancun without blobs. Priority fees burned. HYPE has 18 decimals. Pre-EIP-155 txs accepted. | DOC hyperevm |
| Historical state | `eth_call`, `getCode`, `getStorageAt`, `getBalance` and `getTransactionCount` support **latest block only**. `eth_getLogs` allows ≤50 blocks and ≤4 topics. Historical state is unsupported on the default RPC. Archival providers are listed (Alchemy, Altitude, Chainstack, Dwellir, HypeRPC, OnFinality, QuickNode) plus a self-host option, nanoreth. | DOC json-rpc, hyperevm-tools |
| Conflict with repo | `inspection.rs:800` requires EIP-1898 blockHash reads, which the official RPC doesn't support. | SRC vs DOC |
| Finality | No `finalized`/`safe` tag is documented. HyperCore claims "one-block finality inherited from HyperBFT" (about-hyperliquid). nanoreth sets `safe = finalized = head` (`block_import/service.rs`, commit `2c6525d`, 2026-09-18). **The JSON-RPC `finalized` tag behavior is unverified.** | DOC + [INFERENCE] |
| Testnet history | EVM block S3 bucket `hl-testnet-evm-blocks` starts at block 18,000,000. Earlier blocks were not backfilled. | DOC raw-block-data |
| Gas | Small blocks: 1 s, 3M gas. Big blocks: 1 min, 30M gas. Big blocks need the HyperCore action `evmUserModify {usingBigBlocks:true}` from an existing Core user. The mempool accepts only the next 8 nonces and prunes after 1 day. | DOC dual-block |
| L1Read | Read precompiles start at `0x…0800`: perps positions, spot balances, vault equity, delegations, oracle prices, L1 block number. Values match **latest HyperCore state when the EVM block is built**. Gas is 2000 + 65·(in+out). An invalid input consumes all passed gas. | DOC interacting-with-hypercore |
| CoreWriter | `0x3333…3333` `sendRawAction`, ~47k gas. Version byte 1 plus a 3-byte action id. Order and vault-transfer actions are **delayed onchain for a few seconds** and processed after the EVM block. The account must already exist on Core before the EVM block. **The docs give no callback or return value for outcomes.** A contract can only observe results later through L1Read (positions/balances) [INFERENCE from the read-precompile semantics]. | DOC + [INFERENCE] |
| Actions | 1 limit order (asset, isBuy, px, sz, reduceOnly, tif, cloid), 2 vault transfer, 6 spot send, 7 USD class transfer (perp↔spot), 9 **add API wallet**, 10/11 cancel, 12 approve builder fee, 13 send asset (destination, subAccount, source_dex, destination_dex, token, wei; source subAccount when nonzero), 15 borrow/lend, 16 set abstraction (disabled/unifiedAccount/portfolioMargin), 17 outcome ops. | DOC |
| Sub-accounts | "Sub-accounts and vaults have no private keys"; the master signs with `vaultAddress`. Creation requires $100,000 volume (trading/sub-accounts). **No CoreWriter action creates sub-accounts.** No documented exchange action creates them either. | DOC; absence in listed docs only |
| Position transfer | **None found** among the documented CoreWriter or exchange actions. Positions move only by trading, closing or reopening, or by moving margin (isolated-margin update, USD class transfer). | DOC; absence in listed docs only |
| Spot link | The Core deployer runs `requestEvmContract` and the EVM deployer runs `finalizeEvmContract`. The system address must hold the entire supply on the other side. Hyperliquid **doesn't check ERC20 validity or supply**. Non-round amounts beyond the extra decimals are burned. Core→EVM credits arrive through a system transaction calling `transfer` (200k gas). | DOC transfers |
| Faucet | The Core testnet faucet (1,000 mock USDC) **requires a prior mainnet deposit from the same address**. Third-party HYPE gas faucets are listed: Chainstack (1 HYPE/24 h) and QuickNode. Their terms are unverified. | DOC testnet-faucet, tools |

### 2.5 Base Sepolia / Ethereum Sepolia (frozen prior handoff, re-checked links)
- **Base Sepolia:** chain 84532, `https://sepolia.base.org` (docs.base.org/get-started/connect-to-base). Cancun via Ecotone (activation 1708534800).
- **Sepolia Gloas (Glamsterdam):** scheduled for 2026-10-06 13:53:36 UTC, epoch 353024 (blog.ethereum.org 2026/09/17 and eth-clients/sepolia config). This is a schedule, not an observation.
- **Faucet:** the Alchemy Base Sepolia faucet requires ≥0.001 mainnet ETH, so it doesn't qualify as zero-paid.
- **Finality:** Base docs separate L2-included, L1-batch-included and L1-batch-finalized. Samechain Exit is not an L2→L1 withdrawal.

---

## 3. Per-ID rows

| ID | Acceptance | Current evidence | Contradiction | Status | Proposed resolution / interfaces | Future verification | Owner / permission |
|---|---|---|---|---|---|---|---|
| **P0.03** EVM/Base | Selected chain, RPC/explorer/faucet trust, token decimals/code/proxy/issuer, 0.8.34/Cancun | §2.1, §2.5 | Compiler prose already fixed. Alchemy faucet not zero-paid. | Engineering default (Base for the first samechain journey; owner Z1 says samechain first, Base itself not owner-approved) + EXTERNAL-INPUT (gas route) | Base Sepolia 84532 as the boring EVM lane. Token: new fixed-supply ERC20, 6 decimals, minted only in the constructor, no admin/proxy/hooks/pause/blocklist/fee. `_checkIdentity` pins the codehash. Descriptor = {chainId, genesis hash, authority/verifier/token address+codehash, ownerProgram, VK_ROOT}. | Read-only `eth_getCode` codehash match at a finalized block from 2 operators. Deploy only via a P0.11 packet. | Deploy/fund ACTION-HELD |
| **L-HEVM.03** HyperEVM spot+perps | Chain/assets plus spot and perps scope as stated | §2.4 | Latest-only RPC conflicts with `inspection.rs`. No sub-account creation from contracts. No position transfer. Faucet needs mainnet. | RESEARCH-OPEN (state/finality source, position claims) + EXTERNAL-INPUT | **Spot:** same immutable authority bytecode on 998 with HYPE plus an unlinked fixed ERC20 first, Core-linked token next (owner). **Perps/Core:** §4. **State source:** the official RPC can't serve EIP-1898 pinned state. Re-pinning or bracketing latest reads is **not** an acceptable substitute (owner/Main). Real qualification is required: two operators serving historical state at a common block hash (archive providers or an own nanoreth node under separate resource permission). Until then L-HEVM inspection is UNQUALIFIED. | Gas of deploy vs the 3M small-block limit is unmeasured. Measure in the in-process VM first. | Core actions, big-block toggle and faucet ACTION-HELD |
| **L-SOL.03** Solana Devnet owner-ZK | Cluster, assets, verifier, decimals | §2.2 | sp1-solana is v5/2-input. Repo only accepts legacy SPL. | PROPOSED-MECHANISM + RESEARCH-OPEN (verifier port CU) | New immutable program (upgrade authority set to None after deploy; [INFERENCE] verify via loader account) that ports the v6.1.0 5-input Groth16 check on `alt_bn128` syscalls. Buffer accounts stage packet+proofs. Asset: legacy SPL mint with 6 decimals, fixed supply, **mint authority and freeze authority set to None**, checked in-program like `accounts.rs:128`. Token-2022 excluded (extensions/hooks). SPL digests: sha256 syscall. | LiteSVM: exact v6.1.0 vector accepted, mutated proof/vkRoot/exitCode rejected, CU recorded vs the 1.4M cap. | Devnet deploy/airdrop ACTION-HELD |
| **L-NEAR.03** NEAR testnet owner-ZK | Account, asset, verifier, async outcome | §2.3 | Workspace empty. No SP1 verifier. Async receipts aren't atomic. | PROPOSED-MECHANISM + RESEARCH-OPEN | Contract on an account with **no access keys and no reachable deploy/upgrade/self-call path**. Groth16 via `alt_bn128_*`. **First asset: native NEAR only (owner Z2).** Follow-on (active): NEP-141+NEP-148 fixed supply, 6 decimals, keyless, deposit via `ft_on_transfer`. Packet execution marks the NF consumed and records owed payouts **in the same receipt**. Payouts are promises (native transfer, later `ft_transfer`) with a callback. Keeping a failed payout as a claimable credit (never reverting the NF) is **PROPOSED, not approved**. The outcome is final only when every receipt outcome is final. | near-workspaces sandbox: callback-failure, storage-unregistered recipient, and double-claim cases. Gas vs 300/500 TGas. | Testnet account/deploy ACTION-HELD |
| **P0.08** methodology | Node/prover/children/shared pages separated, failure stage, no extrapolation | §2.1, `scripts/owner_proof_benchmark.py` user-systemd scope (MemoryMax, MemorySwapMax=0, TasksMax=512, 100 ms sampler) | The harness covers setup and the synthetic creation runner only. Peak is charged memory, not tree RSS. | SOLVED-TECH (method) / ACTION-HELD (runs) | Run classes: node-only, public setup, one full owner proof, coexistence. One private proof per device at a time. Pre-launch manifest: device/kernel/swap/cgroup/devshm, toolchain, ELF/program/VK/PK digests, corpus case, cap+reserve (≥1 GiB, cap within MemAvailable), deadline. Record charged peak, current samples, maxRSS separately (non-additive), shmem as a subset, stage of failure, cleanup result. Missing counters → UNMEASURED. Corpus: creation (native/token), Fill2 both roles full and partial, Cancel/Exit, withdrawals with change, restored remainders. **Prover is chain-agnostic.** The same SP1 Groth16 proof serves all four lanes. Only verifier gas/CU differ (L-*.08 = verifier cost rows only). | Matrix: normal/error/cancel/parent-death/SIGKILL/OOM/devshm exhaustion with generated canaries. | Every run needs a resource packet. No repeat of 4 GiB/10 GiB/bwrap failures. |
| **P0.08-privacy** sinks | Private input never reaches logs/shm unaccounted | `owner_worker.rs:192-250,583-625`. SP1 6.8.1 forwards only `proof_nonce` to proving. sp1-jit POSIX shm under /dev/shm. Gnark caches R1CS+PK in Go globals. | No sandbox. Recorded bwrap UID-map denial. | RESEARCH-OPEN | Keep process-level null sinks and private 0700 scratch. Qualification = generated canary absent from stdout/stderr/journal/scratch/`/dev/shm` after each matrix case. Optional lazy deferred-key host change (`sp1-prover recursion.rs:508-538`) only with before/after measurement and unchanged VK root. | Same matrix. | Kill criterion: any canary residue in a shared sink → blocker. |
| **P0.09** finality/outcome | Inclusion/finality/reorg, lifecycle, RPC replacement | §2 | `inspection.rs` has no timestamp/finality/receipt. `PublicHistory` trusts provider completeness. | PROPOSED-MECHANISM | §5 policy. New `X.FIN` seam: `FinalizedAnchor{lane, chain_id/genesis, height/slot, hash, timestamp, operator_a, operator_b}` → durability reducer. Existing flags are not relabeled. | Fixture tests per §5 checks. | MQ7 answered (two operators). Own node needs resource permission. |
| **P0.11** action packets | Separate approvals with full preview | §6 | none | SOLVED-TECH (format) / ACTION-HELD (each use) | §6 packet fields per lane | Packet digest shown before any action | Each packet separately |

---

## 4. HyperEVM spot + perps: what the primitives allow

Source-confirmed constraints:
1. A contract that calls CoreWriter acts **as its own Core account**. Per the docs example, the action is sent "on behalf of its own contract address".
2. Actions are async and have no failure callback. Orders are delayed a few seconds.
3. The only visible state is the latest Core state via L1Read at EVM block build.
4. **There is no documented primitive to transfer an existing perp position.**
5. A contract can't create sub-accounts.
6. Action 9 (add API wallet) would hand trading authority to a key. An immutable contract must make it unreachable.

Consequences [INFERENCE from 1–6]:
- A "perps position" settled by Z2Z can't move an existing position between owners. It can only be (a) traded on Core by the account holding it, or (b) represented as collateral (USDC/spot) that the contract moves with action 6/7/13.
- One contract Core account per owner-claim needs one contract deployment per claim, because sub-accounts are unavailable. Each such account is public on Core, so perps privacy is minimal.
- Atomic fill ↔ Core trade is impossible. EVM state commits before the Core action executes, so a Core rejection leaves the EVM side committed. Outcome tracking must poll L1Read in later blocks and reconcile. Unknown persists until then.

**Superseded by the owner's final answer (2026-10-06).** My earlier recommendation (NQ1-a: owner-held Core orders with read-only views) was **not selected** and must not be implemented as the replacement design. The selected direction:
- HyperEVM spot ships first: HYPE plus an unlinked fixed ERC20, then a Core-linked token.
- All Core position features and use cases are active: foundational features first, then full scope.
- The direction is **investigating isolated position claims**, e.g. per-claim contract-owned Core accounts. That investigation must address every constraint 1–6 above: async/no callback, latest-only L1Read, no sub-account creation, no position transfer, action 9 unreachable, liquidation and margin safety. It is RESEARCH-OPEN with no feasibility claim.
- Cross-chain legs are token/collateral first; cross-chain position-claim trading is active research.

Light clients across lanes are covered in §7.

## 5. Finality and outcome policy (P0.09, all lanes)

Lifecycle (unchanged across lanes):
1. **Prepared → Authorized.** Private signed bytes.
2. **Released.** Durable commit of the exact packet, certificates and locks *before* export.
3. **Submitted.** Exact tx bytes/hash/nonce stored before send.
4. **Included / safe.** Provisional only.
5. **Finalized.** Terminal.

A missing send or receipt result becomes Unknown and keeps every liability. Negotiation timeout, ACK or disconnect never revokes a released certificate, because anyone can submit it.

Terminal predicate. For every outstanding released packet touching a reserved input, a lock clears only when one of these holds at a finalized anchor F that both operators agree on:
- **(a) Expiry.** `timestamp(F) > expiry`, strictly greater, because `:181` lets `==` execute. Then reconcile all effects through F to rule out earlier execution. If history through F is missing, the packet stays Unknown.
- **(b) Consumption.** A required input NF is consumed at a finalized block. Recovery keeps only the actual successor/proceeds rights and never refunds a consumed predecessor locally.

A finalized reverted transaction closes only that wallet attempt.

Chain-specific "finalized" mapping (no consensus claims; trust stays TRUSTED_NODE ×2):

| Lane | Finalized anchor | Timestamp used for expiry | History source | Reorg handling |
|---|---|---|---|---|
| Base Sepolia | `finalized` block tag (L1-batch finality per Base docs). Never a fixed L2 depth. | `block.timestamp` of F | `eth_getLogs`/receipts by blockHash. State at F via EIP-1898. | Rewind derived state to the common ancestor. Journals immutable. |
| HyperEVM | **Unqualified.** No finalized tag is documented, and "one-block finality" is a doc claim only. Candidate: a block both operators return with an identical hash, served by historical-state-capable sources. Needs qualification before any terminal use. | EVM `block.timestamp` | Archive providers or nanoreth (resource held). Receipts/logs by hash (≤50-block windows on the official RPC). **No latest-state substitute.** Testnet history before 18,000,000 is unavailable from S3. | A hash mismatch between operators fails closed as an incident. |
| Solana Devnet | `finalized` commitment slot. Blockhash plus slot from both operators. | `Clock.unix_timestamp` read in-program. It is a stake-weighted validator estimate [DOC, Solana Clock sysvar, not re-fetched today → INFERENCE]. Expiry compares the program-observed value only. | `getSignaturesForAddress` + `getTransaction` at `finalized`. Program accounts as the state source. | `confirmed` is provisional only. |
| NEAR testnet | `finality:"final"` block. A tx counts only when **all receipt outcomes** are in final blocks. | `env::block_timestamp()` (ns) of the executing receipt's block. Packet expiry must be in ns or converted exactly. | `tx` status with full receipts. Archival RPC for history. | Async: a later receipt can fail after the NF receipt succeeds. The first asset is native NEAR only. A retryable claimable credit is **PROPOSED, not approved**. |

Provider replacement: recheck the last durable finalized anchor, then replay through the new pair with explicit NF queries. No silent latest fallback, no majority vote, no "not found ⇒ absent". Contradictory finalized anchors fail closed and never erase fences.

## 6. Action packets (P0.11)

Every packet is shown in full, then approved once for that exact digest. Credentials stay outside chat, repo, argv and logs.
- **Resource run:** device, corpus case, public pins, cap+reserve, `/dev/shm` and disk budget, deadline, single attempt, abort and cleanup, retention.
- **Network:** owned processes, bind ports, peers (generated loopback only for now), duration.
- **Financial, all lanes:** cluster/chain + genesis, signer and fee payer, program/authority/token pins, nonce or recent blockhash, exact calldata/instruction bytes and packet digest, every recipient, asset in raw and display units, fees (EVM max fee + L1 data fee on Base; CU limit × price on Solana; attached gas/deposit including the 1 yocto and storage deposits on NEAR), simulation at a pinned block, action count, deadline, retry scope.
- **Certificate release** is its own packet, even before any wallet transaction.
- **HyperCore actions** (big-block toggle, Core user creation, spot link) are separate packets because they are Core-side signatures.

## 7. Cross-chain fills: hashlock tier first, proof-verified tier as a research gate

| Lane | Hash | Time source | Hashlock cost |
|---|---|---|---|
| EVM (Base, HyperEVM) | `sha256` precompile, keccak opcode (SRC uses both) | `block.timestamp` | Cheap. Unmeasured on our code. |
| Solana | sha256 syscall: 85 + 1 CU/byte (DOC agave) | `Clock` sysvar | Under 1k CU [INFERENCE] |
| NEAR | `env::sha256`: 4.54 GGas + 24.1 MGas/byte (DOC params), plus keccak256 | `block_timestamp` ns | Negligible vs 300 TGas [INFERENCE] |

Hashlock design constraints:
- Use the same sha256 preimage on both lanes.
- Use **asymmetric timelocks** with margin covering both lanes' finality plus the ≤15 min proof objective. The margins are unmeasured and need an owner decision on the values.
- Refunds happen only after the lane's finalized timestamp is strictly greater than its own timeout.
- NEAR's async payout means the claim must reveal the preimage in the same receipt that records the NF/claim.

Proof-verified tier (RESEARCH-OPEN, no feasibility claim):
- Ethereum sync-committee verification needs BLS12-381 on the destination. NEAR exposes `bls12381_pairing_check` (DOC). Agave lists BLS12-381 syscall costs (DOC). Cluster activation was unchecked.
- Base/HyperEVM finality isn't covered by an Ethereum sync committee alone. Base needs L1 batch/output proofs, and HyperBFT verification has no documented light client.
- **Kill criterion:** no pinned, audited verifier with a measured cost under the lane cap means the pair stays hashlock-only.

## 8. Questions (resolved state as of the owner's FINAL answers, 2026-10-06)

- NQ1 → owner: investigate isolated position claims; spot first; owner-held orders not selected.
- NQ2 → historical-state source stays a RESEARCH-OPEN qualification. Option (a) below is withdrawn.
- NQ3 → engineering default (a).
- NQ4 → owner: unlinked first, Core-linked next.
- NQ5 → engineering default (a), rule only.

The original options are kept below for provenance.


- **NQ1 — HyperEVM perps/Core authority.**
  - (a) **Recommended:** Z2Z settles HyperEVM spot only. Perps and Core spot stay owner-signed in owner accounts, with read-only views.
  - (b) Per-claim immutable contracts each owning a Core account via CoreWriter. Costs: async/no-callback, delayed orders, public positions, liquidation risk, action 9 must be unreachable, one deployment per claim.
  - (c) Pooled contract Core account. Not recommended: shared liquidation and loss of privacy.
- **NQ2 — HyperEVM state and finality source.**
  - (a) **Recommended:** receipts/blocks by hash, bracketed latest reads, two-operator hash agreement, and acceptance of the HyperBFT one-block-final claim as documented.
  - (b) A free archival provider as one of the operators. Vendor terms unverified.
  - (c) Own nanoreth. Needs separate resource permission, and the trust and cost of its S3/hl-node source are unverified.
- **NQ3 — Core testnet USDC requires a mainnet deposit.**
  - (a) **Recommended:** HYPE gas from a listed third-party faucet plus our own ERC20. Core/perps live steps ACTION-HELD.
  - (b) Owner supplies an address with a prior mainnet deposit. Paid, separate approval.
  - (c) Defer live Core evidence.
- **NQ4 — Link our HyperEVM ERC20 to Core spot?**
  - (a) **Recommended:** no link in V1. A link requires a Core deployer token plus a system-address supply transfer and adds an unchecked Core dependency.
  - (b) Link via `requestEvmContract`/`finalizeEvmContract`. Spot then moves across, but the system address holds supply and fungibility caveats apply.
- **NQ5 — Cross-chain timelock margins.**
  - (a) **Recommended:** fix only the rule (initiator timeout > responder timeout + both finality + proof objective) and set numbers after measurement.
  - (b) Provisional numbers now, e.g. 24 h / 12 h [INFERENCE placeholder]. Owner chooses.

## 9. What remains

- **ACTION-HELD:** every deploy, faucet claim, airdrop, signing, Core action and prover run.
- **EXTERNAL-INPUT:** zero-paid gas routes (Base Sepolia and Core USDC are both gated), operator choices, the genesis anchors acquired at a finalized block.
- **RESEARCH-OPEN, each with a falsifiable check:**
  - Solana v6.1.0 verifier port CU: exact vector in LiteSVM, under 1.4M CU.
  - NEAR verifier gas: sandbox, under 300 TGas.
  - HyperEVM authority deploy gas vs the 3M/30M block limits: in-process VM.
  - Full owner wrap memory on 8–16 GB: first resource packet.
  - Sink privacy matrix.
  - Light-client tier.
- **Not claimed:** bn128 integration on Solana or NEAR, HyperEVM finality semantics, any faucet's reliability, any measured proof latency or memory for full wrapping.
