# NEAR contract slot

Independent empty Cargo workspace, excluded from the native core build. No contract, verifier, escrow, account ID, or deployment exists here. This layout slot does not approve a NEAR settlement route or a 1Click adapter.

**Current scope — 2026-10-02:** [ARCHITECTURE](../../docs/ARCHITECTURE.md), [BLOCKERS](../../docs/BLOCKERS.md) and [native status](../../docs/NATIVE-IMPLEMENTATION-STATUS.md) own route behavior, readiness and evidence. [SERVER-INDEPENDENCE](../../docs/SERVER-INDEPENDENCE.md) and the [redesign spec](../../docs/superpowers/specs/2026-10-02-z2z-server-independent-architecture-design.md) describe proposed manual rights/artifacts/data requirements; they neither select a NEAR target nor implement a proof-controlled relation here. External provider/1Click support or status/refund promises do not give this slot custody, native ZEC recovery or independent exit authority. Native manual recovery/proving/direct submission is core acceptance for a selected qualifying route, while SDK/UI/bindings remain deferred. No new route, deployment, result or action permission follows from an empty workspace or docs redesign.

There are no members to build yet. The `cargo-near`/toolchain selection belongs to the reviewed L-NEAR spec and plan below. The 2026-10-02 sentence above ("does not approve a NEAR settlement route") is superseded for the owner-ZK samechain lane; it still applies to 1Click/Intents.

## Owner-ZK lane L-NEAR (testnet) — active, not implemented

As of 2026-10-06 this slot hosts an **active** owner-ZK samechain lane. Nothing has been built yet, and no account or deploy is authorized ([testnet selection](../../docs/V1-TESTNET-SELECTION.md)). Intents/1Click stays V2.
- **First asset:** native NEAR only. NEP-141 (+NEP-148/145, keyless, 6 dp) is an active follow-on.
- **Verifier:** to be written on `alt_bn128_*` host functions for the exact SP1 v6.1.0 statement (5 inputs, `VK_ROOT`, 356-byte proof). Gas is ≈32.5 TGas **[INFERENCE]**, unmeasured.
- **Immutability:** no full-access keys **and** no reachable deploy, upgrade or self-call path, checked against source.
- **Async receipts:** a payout promise can fail after the NF is consumed, and the NF is never unconsumed. A retryable claimable credit is **PROPOSED, not approved**.
- **Finality:** a transaction counts only when all of its receipt outcomes are in `final` blocks. The expiry clock is `block_timestamp` in nanoseconds.
