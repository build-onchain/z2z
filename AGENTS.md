# Repository Guidelines

## Project Overview

Ziquid/Z2Z is a Rust-first protocol workspace for a P2P DEX. The active release path is one bilateral, full-quote native shielded ZEC testnet → ETH route, with owner-local keys/proofs/recovery and a user-owned frontend. The native route is incomplete; source replay, local cryptography, and CPU guest execution are not a funded swap, finality proof, wrapped certificate, or release approval.

The active product workflow is:

1. Connect a wallet.
2. Create or select a Buy/Sell order.
3. Review exact pair, amount, fee, recipient, and permissions.
4. Authorize the specific trade.
5. Execute the selected settlement path.
6. Show actual transfer, pending/Unknown, or eligible recovery.

Keep C-success and R-recovery mutually exclusive. `Unknown`, timeout, an RPC response, a peer ACK, or a database row never authorizes a refund or `Completed` state.

## Architecture & Data Flow

- `crates/protocol`: canonical units, context, allocation, market records, and route-specific encodings. Shape validation is not source/payment/finality proof.
- `crates/zcash`: owner-local Zcash authoring, PCZT, Ironwood V3/V6 transaction handling, F/J/C/R semantics, note/output recovery, and source parameters.
- `crates/proofs`: full-body source replay, note selection, deterministic native relations, guest-compatible crypto, source/origin joins, and proof/artifact consumers. A finite supplied prefix is not canonical/final history.
- `crates/chains`: bounded chain/RPC acquisition, public target observation, unsigned call construction, and target-specific clients. RPC observations do not create financial authority.
- `crates/threshold`: fixed 2-of-2 FROST/DKG primitives. Raw shares and nonce scalars remain owner-local.
- `crates/runtime`: CLI, P2P node, quote/session coordination, persistence, encrypted custody, recovery, and orchestration. Runtime state cannot replace target or source consensus.
- `contracts/evm`: Solidity target contracts, codecs, allocation rules, and vendored SP1 verifier. `contracts/solana` and `contracts/near` are separate target workspaces.
- `packages/sdk`: deferred private TypeScript SDK; do not make it a native protocol dependency.

Primary flow: wallet/source facts → `zcash` authoring → `proofs` relation and source evidence → `runtime` durable state/call orchestration → target contract/client → actual effects and reconciliation. Keep dependency direction toward protocol rules; runtime orchestrates and does not become a second money authority.

## Key Directories

- `crates/protocol/src/` — canonical protocol types and rules.
- `crates/zcash/src/` — Zcash transaction and wallet-local capability code.
- `crates/proofs/src/` and `crates/proofs/methods/*/` — host relations and independent SP1 guests.
- `crates/chains/src/` — source/target clients and bounded HTTP/RPC handling.
- `crates/runtime/src/` and `crates/runtime/tests/` — CLI, node, persistence, custody, recovery, and process tests.
- `crates/threshold/` — DKG/FROST primitives.
- `contracts/evm/src/`, `contracts/evm/test/` — Foundry contracts and tests.
- `docs/` — active product/architecture/roadmap/status authorities; `docs/history/` and dated research are provenance.
- `scripts/` — bounded owner-local utilities, including proving measurement.
- `target/` — contains protected journals, sidecars, ELFs, setup/proof identities, and other non-cache artifacts; inspect before cleanup.

## Development Commands

Use the existing toolchain and locked dependency cohort. Prefer one job on this resource-heavy repository.

```sh
# Native Rust workspace, SQL-off/default scope
CARGO_BUILD_JOBS=1 cargo test --offline --locked --workspace --all-targets --release
CARGO_BUILD_JOBS=1 cargo clippy --offline --locked --workspace --all-targets -- -D warnings

# Targeted native crate test
CARGO_BUILD_JOBS=1 cargo test --offline --locked -p ziquid-proofs <test-or-filter>
CARGO_BUILD_JOBS=1 cargo test --offline --locked -p ziquid-runtime <test-or-filter>

# Compile PostgreSQL-gated targets only; execution requires an authorized private URI/scope
CARGO_BUILD_JOBS=1 cargo test --offline --locked -p ziquid-runtime \
  --features postgres-tests --no-run

# EVM tests, independent from Cargo
forge test --offline --root contracts/evm --use /path/to/solc-0.8.34

# Private SDK only
npm install
npm run build:sdk
```

SP1 guests are independent Cargo workspaces. Use the pinned local builder, not root Cargo:

```sh
cd crates/proofs/methods/<guest>
~/.local/share/ziquid-tools/sp1-6.8.1/cargo-prove prove build --locked \
  --binaries <guest-binary> --output-directory <absolute-output> --elf-name <name>.elf
```

Preserve each guest's `.cargo/config.toml`; it pins `clang`, `llvm-ar`, and RV64IM flags. Guest CPU execution is distinct from wrapped proving and target acceptance.

## Code Conventions & Common Patterns

- Rust edition 2024, workspace resolver 3, `publish = false`, and forbidden unsafe code. Follow existing module ownership and prefer `pub(crate)` for internal seams.
- Use typed, sanitized error enums. Do not retain URLs, provider text, raw RPC responses, private bytes, keys, or paths in errors/debug output.
- Validate complete frames before publishing results. Enforce exact lengths, canonical encodings, bounded allocations, actual EOF, and full transaction/body validation.
- Prefer borrowed facts and existing helpers over duplicate validators or whole-transaction copies. Reuse `proofs::native_relation`, source replay, Zcash reviewers, and existing custody publishers.
- Keep sensitive buffers in `Zeroizing`/guarded allocations where the surrounding module does; redact `Debug` for private structures.
- Separate observation, proof, authorization, entitlement, target acceptance, and actual transfer. Never promote a nonzero digest, ACK, RPC result, or `verified` boolean into a money fact.
- Make state transitions durable before capability release. Use immutable bindings, CAS/version/generation checks, readback, and idempotent retries. `Unknown` is nonterminal.
- For async runtime code, use existing Tokio patterns and bounded request/response handling. Do not add a new framework or service for a single integration.
- Solidity contracts must pin context, beneficiaries, verifier/program identity, and consumed domains. Consume entitlement and perform all required transfers atomically; preserve retry on failed execution.
- New tests should assert consumer-visible behavior, boundaries, transitions, rejection, and preservation of rights. Avoid tautological tests of copies, forwarding, wiring, or non-empty output.

## Important Files

- `README.md` — native commands, fixture environment, artifact-preservation warnings, and current entrypoint.
- `Cargo.toml` / `Cargo.lock` — workspace members, profiles, patches, and locked dependency cohort.
- `crates/runtime/src/main.rs` — `ziquid` CLI dispatch.
- `crates/runtime/src/node/` — `z2z-node` transport, sessions, DKG, and network state.
- `crates/runtime/src/native_source.rs` — owner-local supplied-prefix J/C/R reconciliation.
- `crates/runtime/src/native_recovery.rs` — immutable preauthorized/finished R capsules.
- `crates/proofs/src/native_relation.rs` — shared F/J/C/R semantic predicates.
- `crates/proofs/src/source_note.rs` — full-replay note tracking and exact transaction bytes.
- `crates/zcash/src/funding.rs` / `joint_spend.rs` — generated F/J and C/R authoring/review.
- `contracts/evm/src/NativeFinancialCodec.sol` — native statement/boundary/journal encoding when present.
- `docs/PRODUCT.md` — product scope.
- `docs/ARCHITECTURE.md` — behavior and authority ownership.
- `docs/Z2Z-V1-ROADMAP.md` — active R1–R10 roadmap; retain all 30 task IDs.
- `docs/NATIVE-IMPLEMENTATION-STATUS.md` — observed evidence and precise limitations.
- `docs/BLOCKERS.md` — readiness register; do not silently convert blockers into completion.
- `docs/V1-MICRO-IMPLEMENTATION-PLAN.md` — retained 122-task catalog and provenance, not a second active roadmap.

## Runtime/Tooling Preferences

- Rust is the primary implementation language. Use TypeScript only for the deferred SDK/frontend boundary and Solidity/Foundry for EVM targets.
- Use `cargo` for host crates, the pinned `cargo-prove` for SP1 guests, `forge` for EVM, and `npm` for the private SDK. No Bun/pnpm/Yarn convention is established.
- Keep builds offline and locked whenever possible. Do not regenerate lockfiles casually or add dependencies without a concrete need.
- PostgreSQL is per-owner durable storage; SQL execution is a separately authorized scope. Do not put private URIs on argv or logs.
- Do not deploy, sign/send transactions, acquire funds, inspect real private keys, migrate operational databases, or publish/release without explicit action-specific authorization.
- Do not run blanket `cargo clean`, delete all `target/`, or remove retained ELF/journal/setup/custody artifacts. Clean only identified disposable outputs.

## Testing & QA

Use separate evidence scopes; never combine their counts into one readiness claim.

- Rust unit/integration tests use the built-in harness; async tests use Tokio; runtime process tests use `CARGO_BIN_EXE_*`; chain tests use bounded local HTTP fixtures.
- Default/SQL-off workspace tests do not qualify PostgreSQL lifecycle behavior, wrapped proofs, funded execution, deployment, or product acceptance.
- `postgres-tests` requires an explicitly authorized private PostgreSQL URI and isolated schemas. The repository’s documented policy distinguishes compile-only from actual SQL execution.
- `sp1-execute` proves CPU guest execution only. `sp1-local`/Groth16 wrapping, target verifier admission, and owner-hardware resource qualification are separate claims.
- Foundry tests are offline local EVM tests, not deployed or funded testnet evidence. Solana/NEAR workspaces have their own build/test commands and are not implicit root-workspace targets.
- Before claiming a change complete: run the narrow behavior test, run the affected crate/build scope, exercise the changed CLI or runtime surface when applicable, and report exact command/output scope. Product completion requires the connected wallet → order → authorized trade → settlement → receipt/recovery workflow, not only passing unit tests.
