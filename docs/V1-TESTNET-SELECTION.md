# V1 Testnet Selection — per lane

**Created:** 2026-10-05. **Updated:** 2026-10-06 with the owner's direction. The canonical direction lives in [V1-ARCHITECTURE-DECISIONS](V1-ARCHITECTURE-DECISIONS.md) and the [microplan](V1-MICRO-IMPLEMENTATION-PLAN.md).
**Status:** Each lane below has a testnet. The first journey is samechain (owner answer Z1). Using Base Sepolia for it is an **engineering default, not an owner approval**. Nothing has been deployed, funded or signed, and no deployment is authorized.
**Research:** [Phase 0 testnet/prover policy](research/2026-10-06-phase0-testnet-prover-policy.md). Its facts are dated retrievals from 2026-10-06. Values tagged [INFERENCE] are not measurements.

The lanes run in parallel. **Owner final answer (2026-10-06):** the first usable journey may be a samechain lane. That release does **not** complete the project. The other lanes, all cross-chain pairs and the **native Zcash/ZEC lane (L-ZEC)** stay active and required. L-ZEC covers the whole pipeline: S1–S7/M1–M5, native Tasks 1–10, and the P/Q/history/net/excess/uniqueness/privacy/manual-recovery obligations. **Wrapped or bridged ZEC never substitutes.** No EVM-only replacement is allowed. Every lane uses an immutable money authority (no upgrade, admin, proxy or redeploy path) and keeps owner-local proving. A lane passes only after a genuine journey with real assets and no demo mode, mock or special branding.

## Common criteria (every lane)

1. **Verifier.** The frozen SP1 Groth16 v6.1.0 statement has 5 public inputs: programVKey, sha256(publicValues) masked to 253 bits, exitCode = 0, `VK_ROOT`, and nonce. The proof is 356 bytes (`SP1VerifierGroth16.sol:51-81`). Non-EVM lanes need a reviewed port of exactly this statement. Changing the proof system, program or verifier means a new authority deployment, not an in-place switch.
2. **Immutability.**
   - EVM: no proxy or admin.
   - Solana: upgrade authority set to `None`.
   - NEAR: no full-access key **and** no reachable deploy, upgrade or self-call code path, checked against source.
3. **Finality.** Two independent operators must agree on a common finalized block hash. An owner-run non-validating node is allowed as the second source, as a design only; running it needs separate resource permission. This is trusted-node evidence, not a consensus proof.
4. **Release lock (I2).** A packet still executes when timestamp equals expiry E (`SamechainAuthority.sol:181`). A lock may clear only when either of these holds for **every** exported packet, followed by reconciliation:
   - the finalized timestamp is strictly greater than E, or
   - a required NF consumption is finalized.
5. **Zero paid infrastructure.** No mandatory company RPC, paid VPS, prover service or witness upload. Gas, hardware and storage still cost something.
6. **Assets.** Any new token is fixed-supply, 6 decimals, minted once at construction, with no mint, pause, freeze, blocklist, fee, hook, proxy or admin. Each lane uses its own token standard. Order of assets per lane:
   - **Base:** ETH + ERC20.
   - **HyperEVM:** HYPE + unlinked ERC20 first; Core-linked token next.
   - **Solana:** SOL + SPL.
   - **NEAR:** native NEAR **only** in the first journey; NEP-141 is an active follow-on.
   - **L-ZEC:** native ZEC.

## Lane table

| | **EVM/Base**: first samechain journey (owner Z1), 122-ID catalog. Base Sepolia is an **engineering default, not owner-approved** | **L-HEVM** HyperEVM | **L-SOL** Solana | **L-NEAR** NEAR |
|---|---|---|---|---|
| Network | Base Sepolia, chain 84532 | HyperEVM testnet, chain 998 | Devnet | testnet |
| Official RPC | `https://sepolia.base.org` | `https://rpc.hyperliquid-testnet.xyz/evm` | `https://api.devnet.solana.com` (rate-limited) | e.g. `test.rpc.fastnear.com`, `near-testnet.drpc.org`, `archival-rpc.testnet.near.org` (severely rate-limited) |
| Explorer (human inspection only) | `https://sepolia.basescan.org` — Base network table [B1] | `https://testnet.purrsec.com/` — Chainlink's chain-998 guide linked from Hyperliquid tools [H2–H3]; not a Hyperliquid-operated explorer claim | Outside this Base/HyperEVM descriptor update | Outside this Base/HyperEVM descriptor update |
| Native gas asset | ETH (18) | HYPE (18) | SOL (9) | NEAR (24) |
| Token standard | ERC20, 6 dp | ERC20, 6 dp. **Unlinked fixed token first; Core-linked token next** | Legacy SPL mint, 6 dp, mint and freeze authority `None`. Token-2022 excluded | **First: native NEAR only.** Follow-on (active): NEP-141 + NEP-148, 6 dp, keyless account, no owner methods, NEP-145 storage registration |
| Authority | Existing `SamechainAuthority` (0.8.34/Cancun) | Same bytecode, separate deployment | New owner-ZK program (the three-ACK escrow is separate provenance) | New owner-ZK contract (`contracts/near` is empty) |
| Verifier | Vendored v6.1.0 | Same | **Port required.** `sp1-solana` pins SP1 5.0.3 with 2 public inputs and VKs ≤ v5.0.0, which **mismatches** frozen v6.1.0 | **Must be written** on `alt_bn128_*` host functions |
| Verifier cost | Unmeasured | Unmeasured. Must fit small blocks (3M gas) or big blocks (30M gas, which need the Core action `evmUserModify`) | ≈95k CU [INFERENCE from groth16-solana benchmarks 91,448 CU at 4 inputs / 108,762 CU at 8]; cap 1.4M per tx. **Unmeasured on our VK** | ≈32.5 TGas [INFERENCE from master gas parameters]; `max_tx_gas` 500 TGas. **Unmeasured** |
| Size limits | — | — | 1,232-byte tx: stage through buffer accounts, then one atomic final instruction | 4 MiB args |
| Finalized anchor | `finalized` tag (L1-batch finality). Never a fixed L2 depth | **Unqualified.** No `finalized` tag documented; "one-block finality" is a doc claim only | `finalized` commitment | `finality:"final"` and **all receipt outcomes final** |
| Expiry clock | `block.timestamp` | `block.timestamp` | `Clock.unix_timestamp` | `block_timestamp` (ns) |
| History / state access | `eth_getLogs`/receipts, EIP-1898 blockHash state (`inspection.rs:800`) | Official RPC: **latest-only state**, `getLogs` ≤ 50 blocks. EIP-1898 is unsupported. Re-pinning to latest is **not** a substitute. Real qualification is needed: archive provider(s) or own nanoreth (resource held). Testnet S3 blocks start at 18,000,000 | `getTransaction` / account state at `finalized` | Archival RPC, `tx` with receipts |
| Atomicity | One EVM tx | EVM side is atomic. **CoreWriter actions are async, delayed and have no failure callback** | One final instruction | **Async receipts:** a payout (native transfer promise, later `ft_transfer`) can fail after the NF is consumed. A retryable claimable credit is **PROPOSED, not approved** |
| Faucet / zero-paid route | Alchemy Base Sepolia faucet requires ≥0.001 mainnet ETH, so **not zero-paid**. Route is EXTERNAL-INPUT | HYPE gas from listed third-party faucets (terms unverified). **Core USDC faucet requires a prior mainnet deposit** | faucet.solana.com (Devnet) | NEAR testnet faucet (docs.near.org) |

### Base / HyperEVM descriptor sources and trust (retrieved 2026-10-06)

- **[B1]** [Base official network table](https://docs.base.org/get-started/connect-to-base) explicitly lists Base Sepolia chain `84532`, RPC `https://sepolia.base.org`, ETH and explorer `https://sepolia.basescan.org`.
- **[H1]** [Hyperliquid official HyperEVM network documentation](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm) lists testnet chain `998`, RPC `https://rpc.hyperliquid-testnet.xyz/evm`, HYPE with 18 decimals and Cancun without blobs.
- **[H2–H3]** [Hyperliquid official tools directory](https://hyperliquid.gitbook.io/hyperliquid-docs/builder-tools/hyperevm-tools) links the [Chainlink HyperEVM Testnet RPC guide](https://docs.chain.link/ccip/evm/tools-resources/network-specific/hyperevm-testnet-rpc). That provider's official guide explicitly pairs chain `998` with explorer `https://testnet.purrsec.com/`. Hyperliquid's directory itself lists generic explorers, not a testnet-specific explorer URL; the testnet URL is verified from the linked provider guide, not guessed from a mainnet hostname. This does not select Chainlink as a second independent operator or qualify historical state/finality.
- **Faucet trust boundary:** all faucets are external funding services, outside the protocol and its financial authority. Availability, eligibility, rate limits and correct delivery depend on the faucet operator; a listing is not a reliability or zero-paid-route qualification. Claims are separate **manual, explicitly authorized actions**, never automatic node startup, deployment or protocol behavior. Never give a faucet private keys or recovery material. The Base mainnet-ETH prerequisite and unqualified gas route above remain unchanged. [Hyperliquid's official faucet policy](https://hyperliquid.gitbook.io/hyperliquid-docs/onboarding/testnet-faucet) confirms its Core mock-USDC faucet requires a prior mainnet deposit from the same address; it is not the HYPE gas faucet. [H2] lists Chainstack and QuickNode HYPE faucets, but their eligibility/terms remain unqualified. No mainnet deposit is authorized to satisfy either prerequisite.
- **RPC/explorer trust boundary:** URLs are selection descriptors, not availability measurements or consensus evidence. Explorers are optional human inspection tools, never authority for payment, finality, code identity or admission; RPC data remains subject to the two-independent-operator rule and the lane qualifications above.
- **P0.03 selection criterion:** the Base/HyperEVM network, RPC, explorer, faucet-trust and asset-policy descriptors are recorded. No funding address or live RPC probe is needed to complete this selection record. This satisfies the descriptor criterion only, not deployment authorization, a qualified funding route, deployed code/issuer evidence or genuine-journey acceptance; the post-deployment descriptor and action gates below remain held.

## L-HEVM scope: spot and perps

- **Spot ships first.** HYPE plus the fixed ERC20 settle through the samechain authority.
- **Perps and Core-spot positions are active scope.** All Core position features and use cases are covered: foundational features first, then full scope. The selected direction is investigating **isolated position claims**. Owner-held Core orders are **not** a replacement design.
- Source facts that the claim research must solve (hyperliquid docs, 2026-10-06):
  - HyperCore is reachable only through L1Read read precompiles (`0x…0800+`), which show the latest Core state when the EVM block is built, and the async `CoreWriter` at `0x3333…3333`.
  - A contract acts as its own Core account.
  - No documented action creates a sub-account from a contract. Sub-accounts need $100k volume and the master account signs for them.
  - No position-transfer primitive is documented.
  - Action 9 (add API wallet) must be unreachable from the authority.
- Cross-chain legs start with tokens/collateral only (HTLC can't lock a perp position). Cross-chain position claims are active research.

## Cross-chain (X.CROSSCHAIN, active)

- **All pairs run in parallel,** including ZEC↔{Base, HyperEVM, Solana, NEAR} on the native L-ZEC lane. **Wrapped ZEC is not a substitute.** The first legs are token/collateral only. Cross-chain position-claim trading is active research (owner answer Z3).
- First construction, CX-1: asymmetric hashlock/timelock. It is **not atomic**, and the conditions it needs before any safety claim are recorded in the microplan.
- Research gate, CX-2: proof-verified release. Hash and time primitives exist on every lane (sha256 on EVM/Solana/NEAR). Light-client feasibility is unproven.

## Required descriptor per lane (X.01, recorded after authorized deployment only)

Each lane records:
- chain/cluster ID and a genesis or finalized anchor acquired independently from both operators
- authority, verifier and token addresses/accounts, with code hash, program hash or deployed WASM hash
- immutability evidence: no admin, upgrade authority `None`, or no access keys plus a source path review
- owner program VKey and `VK_ROOT`
- token decimals and supply/authority state
- compiler/toolchain pins
- constructor or init arguments
- deployment transaction IDs

Credentials stay out of the repo, chat, argv and logs.

## Deployment authorization

None granted, on any lane. Each lane deployment, faucet claim, airdrop, Core action, token link, signing or send needs its own action packet ([Phase 0 policy §6](research/2026-10-06-phase0-testnet-prover-policy.md)). Prerequisites:
- reviewed spec and plan for that lane
- verifier qualified with genuine proofs
- immutability checked
- verified offline backup before funding

Local Anvil, LiteSVM and NEAR sandbox runs are code checks, not testnet acceptance. Anvil still needs explicit authorization.
