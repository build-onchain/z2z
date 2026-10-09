# Solana market safety target

Independent target workspace, excluded from the native host workspace. The Kerb interface/program/harness implementation is now consolidated here as `ziquid-solana-interface`, `ziquid-solana` and `ziquid-solana-harness`. It implements **public legacy-SPL escrow with three ordinary business-authorizer acknowledgements**, exact allocation/effect/recipient checks and token CPI; not a complete private DEX, owner-ZK samechain settlement or native-ZEC source verifier.

## Exercised build and target behavior — 2026-10-03

From the repository root:

```sh
NO_DNA=1 CARGO_BUILD_JOBS=1 cargo-build-sbf \
  --manifest-path contracts/solana/program/Cargo.toml \
  --tools-version v1.57 --arch v0 --sbf-out-dir target/z2z-sbf

NO_DNA=1 CARGO_BUILD_JOBS=1 cargo test --offline --locked \
  --manifest-path contracts/solana/Cargo.toml -p ziquid-solana-interface

NO_DNA=1 CARGO_BUILD_JOBS=1 \
Z2Z_SBF_ELF="$PWD/target/z2z-sbf/ziquid_solana.so" \
cargo test --offline --locked --manifest-path contracts/solana/Cargo.toml \
  -p ziquid-solana-harness --test compiled_elf -- --test-threads=1
```

Observed: destination SBF build succeeded; **2 interface tests and16 compiled-ELF tests passed**. The new ELF SHA256 is `ffe8465dee9cdbf70b8f1fa56ee665cad79f62b22006109986ebc5b2aefb9913`. Tests use generated synthetic in-process keys and assets with actual LiteSVM/precompile/SPL execution. They cover account/PDA/token/signature substitution, immutable recipients/effects, sequential conserved allocations, partial activation, cancel/release exclusion, no timer escape, frozen-recipient CPI rollback and retry. No network transaction, deployment or funding was performed.

The independent Cargo lock preserves all372 source registry package versions/checksums after destination package relocation. Protocol consumers select `default-features=false, features=["market"]`; native wallet/prover/runtime/SQL code is not part of the SBF program. Original signed bytes, PDA seeds and fixture program identity are unchanged by package/artifact names. Host dev/test debug symbols and incremental compilation are disabled to limit disk use; source release settings remain unchanged.

## Remaining acceptance

SQL-backed single-CLI market orchestration awaits approved private PostgreSQL URI/scope; **no local SQL tests**. A VM receipt or business signature is not mined ZEC, independent source history/finality, strict matching privacy, native SpendAuth, crosschain atomicity or unilateral company-off ZEC exit. New owner-proof samechain relations and full financial crosschain routes remain separate required implementations.

## Owner-ZK lane L-SOL (Devnet) — not implemented

The owner-ZK samechain lane is **active**. It will be a **new** immutable program (upgrade authority `None`), with this three-ACK target kept as separate provenance. Nothing has been built yet. Its prerequisites are:
- **Verifier:** a reviewed port of the exact SP1 Groth16 v6.1.0 statement: 5 public inputs, `VK_ROOT`, exitCode = 0, 356-byte proof. `sp1-solana` pins SP1 5.0.3, VKs ≤ v5.0.0 and `PublicInputs<2>`, which **mismatches** and is not usable as-is.
- **Cost:** `alt_bn128` costs ≈95k CU per proof **[INFERENCE]**, unmeasured on our VK. The cap is 1.4M CU per transaction.
- **Size:** the 1,232-byte transaction limit means packet and proofs are staged through buffer accounts, followed by one atomic final instruction.
- **Asset:** SOL plus a legacy SPL mint with 6 decimals and mint and freeze authority `None`. Token-2022 is excluded.
- **Finality:** `finalized` commitment from two agreeing operators; the expiry clock is `Clock.unix_timestamp`.

No Devnet deploy or airdrop is authorized ([testnet selection](../../docs/V1-TESTNET-SELECTION.md)).

[Architecture](../../docs/ARCHITECTURE.md), [blockers](../../docs/BLOCKERS.md), [implementation status](../../docs/NATIVE-IMPLEMENTATION-STATUS.md) and [server independence](../../docs/SERVER-INDEPENDENCE.md) own behavior, release evidence and manual acceptance. The [active V1 prompt](../../docs/Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md) governs continued V1 work; the [archived full-project prompt](../../docs/history/Z2Z-IMPLEMENTATION-SYSTEM-PROMPT.md) and [integration plan](../../docs/history/plans/2026-10-03-z2z-implementation-integration.md) retain broader scope and source-cutover history. This local target evidence closes no full-product privacy/financial gate and grants no deployment permission.
