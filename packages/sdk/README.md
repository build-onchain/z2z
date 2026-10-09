# @ziquid/sdk

Private TypeScript package frame for Ziquid Protocol. No intent, wallet, settlement, transport, or Rust bindings are implemented; the module exports nothing.

**Active lanes (2026-10-06):** native ZEC is an active first-class lane (L-ZEC) in the whole pipeline, not V2; HyperEVM (L-HEVM), Solana devnet (L-SOL), NEAR testnet (L-NEAR) and cross-chain HTLC (X.CROSSCHAIN, HTLC first, all pairs in parallel, no atomicity/privacy claim) are active parallel lanes. This package implements none of them; the SDK stays a deferred consumer of canonical native rules.

**Current scope — 2026-10-02:** SDK, UI and Rust↔TS/WASM/FFI bindings are deferred; **the standalone manual native consumer is core protocol acceptance, not SDK work being deferred**. [SERVER-INDEPENDENCE](../../docs/SERVER-INDEPENDENCE.md) specifies recovery bundles, independently usable artifacts/history/witnesses/local proving and exact direct submission/retry; none is implemented by this empty export. [ARCHITECTURE](../../docs/ARCHITECTURE.md), [redesign spec](../../docs/superpowers/specs/2026-10-02-z2z-server-independent-architecture-design.md), [native status](../../docs/NATIVE-IMPLEMENTATION-STATUS.md) and [BLOCKERS](../../docs/BLOCKERS.md) distinguish proposed expanded relations from actual native primitives/readiness. Proposed samechain bilateral notes/partial-successor rights, imported custody/P2P and external venue lanes are not SDK APIs or supported routes. A package build adds no financial/proof/manual acceptance, implementation scope, privacy waiver or signing/deployment permission.

From the monorepo root:

```sh
npm install
npm run build:sdk
```

The build emits ESM and declarations into `packages/sdk/dist`. The local package name is not a registry-ownership or availability claim.
