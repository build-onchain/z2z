# V1 Resource Qualification and Targets

**Updated:** 2026-10-06  
**Purpose:** Define measurements required before selecting resource/latency targets. This is not measured execution evidence or permission to change V1 scope.

## 1. Targets Remain TBD

**Owner-local proving feasibility is UNQUALIFIED; proof-system selection is UNRESOLVED.** Benchmark the existing SP1 `prove-owner` implementation first, using the actual samechain guest and controlled non-production witnesses. The user's i5-11400H / 16GB Linux machine is the benchmark target, not a qualified minimum or guaranteed supported configuration.

The [native checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) owns retained-artifact, component-memory and capped-failure evidence. Artifact sizes, a source-derived recursion-key lower bound, CPU guest cycles and a capped OOM do not establish full-prover peaks, minimum RAM, wrapping latency or success/failure on that target. No RAM/CPU/disk/network minimum or proof-time promise follows.

Weak-hardware support remains the product objective. Node-only and full-prover resource envelopes must be measured separately; do not silently increase hardware requirements, defer proving or replace trading/recovery with observation-only delivery.

**Latency objective (owner, 2026-10-06):** at most 15 minutes per owner proof, **provisional**. It is an objective, not a guarantee or a measurement. It does not change signed expiry or cross-chain timelock margins until measured. **Resource policy: methodology only.** No heavy trial is authorized; every run needs its own resource packet ([Phase 0 policy](research/2026-10-06-phase0-testnet-prover-policy.md) §3 P0.08, §6). Do not repeat the recorded 4 GiB/10 GiB OOM attempts or the failed namespace probe.

**All lanes share one prover.** The same owner-local SP1 Groth16 v6.1.0 certificate is the proof for EVM/Base, L-HEVM, L-SOL and L-NEAR. Prover memory and time are therefore measured once per operation shape, not once per lane. What differs per lane is target verification cost:

| Lane | Verification limit | Status |
|---|---|---|
| Base / HyperEVM | Block gas limit (HyperEVM: 3M small blocks or 30M big blocks) | Unmeasured |
| Solana | 1.4M CU per tx; buffer staging | ≈95k CU **[INFERENCE]**, on a v6.1.0 port that does not exist yet |
| NEAR | 300 TGas per function call (500 TGas tx cap) | ≈32.5 TGas **[INFERENCE]** |

None of these are passing evidence.

## 2. Measurement Coverage

| Workload | Required measurements | Acceptance target |
|---|---|---|
| Node idle, discovery, gossip and bounded peer sync | RSS/whole-process memory, CPU, disk, network, cache/query/concurrency load | TBD after actual node measurement |
| Creation / note admission | Complete wrapped proving memory, wall time, scratch/shared memory and exact target admission | TBD after benchmark |
| Bilateral full and supported partial fill | Each owner role measured independently on one identical canonical packet, including proceeds/remainder output shapes | TBD after benchmark |
| Cancel/exit and ordinary withdrawal | Separate complete proving and admission results; no create/fill extrapolation | TBD after benchmark |
| Company-off recovery | Restored unfilled/proceeds/remainder/pending-state witness cases using retained actual artifacts | TBD after qualification |
| Node/prover coexistence | Responsiveness, bounded concurrency, cancellation and exhaustion under measured background load | TBD after measurement |

The existing [microplan](V1-MICRO-IMPLEMENTATION-PLAN.md) owns task dependencies: P0.08/P0.11 methodology/action scope, P1.01–P1.23 proving, P2.28 node measurements and P4 recovery. One successful packet is not all-operation or all-device qualification.

## 3. Required Run Record

### Environment and independent identities

- Exact CPU/RAM/OS/kernel; available memory, other load, swap and process/cgroup limits.
- Disk/filesystem and `/dev/shm` size/limits; owner-approved measurement and scratch scope.
- Actual source/toolchain/features, guest ELF hash, independently pinned program VKey, setup/PK/VK identities/provenance/availability and exact verifier/deployment/expected journal.
- Operation, role, supported witness-size boundary and canonical public packet identity; never publish witness bytes, private openings or production capabilities.

### Whole-prover accounting and outcome

- Peak owned process-group/cgroup memory including child/Gnark workers and shared pages/tmpfs. Distinguish host RSS and avoid double-counting shared memory; report method, sampling interval and limitations.
- Actual elapsed wall time, peak scratch/artifact disk and `/dev/shm` usage/lifecycle.
- Exit status, actual failure stage and surviving accounting on crash/OOM. A resource cap is a run condition, not the minimum memory requirement.
- Genuine wrapped certificate bytes and independent exact target-compatible verification against caller-selected pins and the complete expected journal. SDK self-verification alone is not frozen EVM compatibility; CPU execution/calldata/simulation is not wrapped proof or payment.

### Owner-private worker boundaries

- Diagnostics/trace sinks, stdin framing, shared-memory ownership and cleanup, owner-selected private scratch, retained buffers and normal/error/cancel/crash/OOM behavior.
- Worker identity/reaping and cleanup must be qualified before accepting a certificate. File deletion and process isolation are not complete-erasure claims.
- Keys, note openings, recovery material and proof witnesses remain owner-local, never in SQL/peer frames/cloud/shared prover requests, even as encrypted witness exchange.
- Observe only approved owned workloads; do not kill unrelated processes, change swap/system limits or consume production secrets by implication.

## 4. Selection and Acceptance

Record measured success as demonstrated only on the actual tested hardware/workload; record measured failure with its exact stage, cap and accounting limitations. Set targets from complete results plus a justified measured envelope, not guessed savings. Publish exercised results in [NATIVE-IMPLEMENTATION-STATUS](NATIVE-IMPLEMENTATION-STATUS.md); readiness belongs to [BLOCKERS](BLOCKERS.md).

Proving qualification requires genuine wrapped certificates for all supported modes, both fill roles/full/partial shapes and recovery, independent exact target admission, usable source/setup/artifact provenance and qualified private-worker/resource behavior. Funding also requires pre-funding backup/cold-restore qualification. Neither an unchecked requirement list nor a selected proof system closes those gates.

If SP1 cannot qualify, measure owner-local optimizations or alternative **candidates** preserving ownership, exact consent, conservation, uniqueness and recovery. Circom, Halo2 or another candidate needs actual constraints/resources, setup/privacy/verifier qualification and the same all-mode acceptance. Do not switch on a claimed small circuit or vendor benchmark.

The existing authority immutably pins its verifier and owner program. A changed proof system/verifier/program requires reviewed changes where applicable, a **new separately authorized authority deployment**, new pins and independent genuine-proof/funded/recovery qualification. Preserve old funded rights and usable original artifacts; no in-place VK update or automatic migration exists.

There is **no no-proof/observation-only fallback** and no automatic higher-hardware release path. If measured owner-local candidates cannot satisfy the required journey, report the concrete blocker; an acceptance-scope change requires explicit user approval. Full/partial/remainder, actual trading and full company-off recovery remain V1 requirements.

## 5. Cost and Permission Boundary

No paid VPS/GPU/cloud proving, Succinct Prover Network, remote shared prover or witness upload may substitute for owner-local proving. Zero paid proving infrastructure does not eliminate gas, storage, hardware or electricity. Owner-local proof generation can avoid a remote prover while history acquisition/submission still needs independent chain access.

The [active prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md), [proving qualification contract](PROVING-COST-SOLUTIONS.md) and action-specific permissions govern runs. This document authorizes no build, benchmark, network operation, SQL execution, deployment (including Anvil), signing or funds movement. Until actual evidence supports targets: **targets TBD, proving UNQUALIFIED**.
