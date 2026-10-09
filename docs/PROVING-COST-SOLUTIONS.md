# Owner-Local Proving Qualification for Z2Z V1

**Updated:** 2026-10-06 (per-lane verifier section, provisional latency objective)
**Purpose:** Qualify the existing samechain prover on actual owner hardware before selecting a different proof system. This document defines required measurements, not measured hardware minima or latency guarantees.

## Current Evidence

The [native checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) records retained SP1 setup artifacts, a source-derived recursion-key resident-array lower bound and an observed capped OOM without a certificate. Artifact sizes and component lower bounds are not measured whole-prover peaks or hardware minima. The capped trial does not establish success or failure on the user's target machine.

**Proving feasibility UNQUALIFIED until benchmarked on target hardware.** The target is the user's i5-11400H / 16GB machine; that hardware description is not a RAM requirement or a feasibility claim. No successful full samechain wrapped proof, minimum RAM or proof-generation time is established.

CPU guest execution, cycle counts and small-guest results do not qualify Groth16 wrapping or target admission. Setup provenance and independent program/verifier qualification remain separate prerequisites.

## Required First Step: Benchmark Existing `prove-owner`

Use the existing implementation, actual samechain guest and controlled non-production witnesses. Do not rebuild an already implemented circuit or switch proof systems on guessed memory savings.

Record:

1. Hardware, OS, exact source/ELF/program VKey and setup/PK/VK identities.
2. Available RAM, process/cgroup limits, swap configuration and other relevant memory pressure.
3. Peak **whole-prover** memory, including child workers and `/dev/shm`; distinguish these from host-process RSS.
4. Actual wall time, disk/scratch use, completion status and failure stage.
5. Supported witness sizes and operation coverage: creation, both bilateral fill roles, cancel/exit and withdrawal, including recovery proving.
6. Genuine wrapped proof bytes and independent acceptance against the exact intended SamechainAuthority, verifier and expected journal.

**Resource targets: TBD after benchmark.** Select node-only and proving resource/latency acceptance targets from measured results, not guessed minima. A successful measurement for one packet is not qualification for every operation or device. Publish actual results in the checkpoint and reference them from the [V1 delivery matrix](V1-DELIVERY-MATRIX.md).

### Controlled native operation corpus

`crates/proofs/tests/owner_artifacts.rs` now links real deterministic signed generation-one creation for both owners to one common partial-fill packet, then drops original openings and reconstructs both generation-two remainders/proceeds from retained owner-separated recovery capabilities and complete public ciphertexts. Mathematical append replay supplies exact insertion paths; fresh Cancel/Exit alternatives, proceeds withdrawal and restored ordinary change preserve concrete amounts/generation/nullifiers. Missing/tampered recovery capabilities/ciphertexts/context/history/path and impossible freshly consented successor generation reject. Run `cargo test --offline --locked -p ziquid-proofs --test owner_artifacts` without setup/proving. This is **MATHEMATICAL_NOT_ADMITTED** native corpus evidence, not guest execution, encrypted backup, current spentness, genuine proof or funded/cold-VM recovery. The active benchmark remains creation-only; native corpus coverage does not silently broaden its qualification.

### Controlled measurement CLI

[`scripts/owner_proof_benchmark.py`](../scripts/owner_proof_benchmark.py) measures only the existing `ziquid samechain owner-program` public light setup or [`owner_creation_qualification`](../crates/runtime/examples/owner_creation_qualification.rs) synthetic **creation** runner. It is a stdlib Linux CLI, not a different producer, all-mode corpus or financial qualification. Build the actual `sp1-local` binary/example separately as described in [destination settlement](modules/destination-settlement.md#public-owner-program-identity-and-controlled-creation-qualification); the harness never builds, downloads, changes swap or launches a benchmark without explicit invocation.

Select existing absolute binary/example/ELF/setup/private-root paths. The private root must already be caller-owned mode0700 with trusted, nonsymlink ancestors; it is never deleted. The setup argument is its base, not the `v6.1.0` child. Every invocation requires independent public ELF SHA/program pins, an explicit1..86400-second deadline, memory cap and local reserve. Wrapped mode additionally requires `--release-dir /ABS/OWNER_RELEASE_0700_DIR --backup-key-file /ABS/OWNER_0600_GENERATED_KEY_FILE --op-id 0xNONZERO_32_BYTE_ID`; the key must be an owner-owned, single-link, regular0600 file of exactly32bytes under a trusted owner0700 parent. Python validates key metadata only, never reads/hashes its contents. Setup mode rejects these three custody arguments. The following2GiB example is **setup only**, not a wrapped-proof envelope:

```text
python3 scripts/owner_proof_benchmark.py --mode setup \
  --binary /ABS/target/release/ziquid \
  --example /ABS/target/release/examples/owner_creation_qualification \
  --elf /ABS/CURRENT_FILL2_OWNER_ELF \
  --elf-sha256 0xINDEPENDENTLY_SELECTED_ELF_SHA256 \
  --program-vkey 0xINDEPENDENTLY_SELECTED_PROGRAM_VKEY \
  --groth16-artifact-base /ABS/target/ziquid-public-setup \
  --private-temp-dir /ABS/CALLER_PRIVATE_0700_ROOT \
  --timeout-seconds 90 --memory-max 2GiB --reserve-memory 1GiB
```

Use exact current ELF/program identities from the [native checkpoint](NATIVE-IMPLEMENTATION-STATUS.md), independently selected and qualified for the intended run. The earlier `samechain-tree.elf`/`00d55c…` pair is a preserved pre-Fill2 identity, **not the active four-mode guest**. [Current Fill2 ABI](modules/zcash-proofs.md#samechain-relation-and-authority-source--no-native-source-proof-substitution) is mode0 + one OwnerWitness frame2 with embedded packet/E/ordered leaves/own_salt; other modes retain witness1. New program means new specifically authorized immutable authority and genuine all-mode target/recovery qualification; old source/ELF/binary bytes stay under original identities without conversion/migration. Current CPU/program/correspondence and completed source-review evidence is not independently qualified source/setup/program, wrapping or funded support.

The checkpoint's observed light-setup program is **not independently qualified source/program evidence**; select actual current pins, not a historical measurement pair. The observed local memory checkpoint had `MemAvailable=5,313,208,320bytes` and only14,598,144bytes swap free; those are dated observations, not admission values. The harness rereads `MemAvailable` and effective ancestor-cgroup headroom immediately before running. Cap plus explicit reserve (at least1GiB) must fit. Wrapped mode additionally refuses caps at or below8GiB: a **conservative harness safety policy**, not a measured prover/product minimum; the5,611,078,880-byte recursion-array bound excludes shrink/FFT/decoded-PK memory. Do not repeat recorded sender4GiB or this VM's4GiB/10GiB OOM attempts as a new qualification run; a larger explicitly approved envelope and actual result remain required.

Only after a separately approved sufficient resource envelope, select `--mode wrapped` **and** supply all three custody arguments above. Do not reuse the setup example's2GiB cap: wrapped mode requires a cap strictly above8GiB plus independently checked reserve/headroom, a conservative refusal policy rather than measured feasibility. The owner's current permission remains methodology-only, so these instructions authorize no heavy run. Only the actual Rust runner generates, holds and streams the synthetic witness internally; Python keeps subprocess stdin at DEVNULL and needs no SQL configuration. Python never accepts witness stdin/files, reads private scratch or key contents, samples witnesses/process diagnostics, kills a worker group or recursively cleans the root. It may read the bounded encrypted capsule to validate its digest. The worker's proof/transport and equal cleanup deadlines remain primary; a later harness watchdog reports ambiguity and preserves any live workers/root rather than bypassing cleanup. Public-only setup may terminate its exact public command PID at its own deadline. Interrupted/ambiguous scope names are returned for owner inspection; do not delete artifacts while workers may still write.

Runs use a unique user-systemd transient **scope** with verified cgroup-v2 placement, enforced `MemoryMax`, `MemorySwapMax=0`, `TasksMax=512` and `OOMPolicy=continue`. An in-scope harness process keeps the cgroup alive through final counter harvest. Raw `memory.current/peak/events/stat` accounting covers charged descendants and shared/tmpfs pages; `/dev/shm` is not added again. `memory.stat.shmem` is a **subset of file and total**, not extra memory. Linux `wait4.ru_maxrss` (largest reaped process RSS, not an additive tree sum) and wall time are reported separately. Sampling is100ms; sample loss, missing counters, swap usage or peak below observed current samples produce **UNMEASURED**, never a low hardware minimum; the raw reported peak remains in the result for inspection. **Charged cgroup memory is not a total resident-tree guarantee:** preexisting shared pages may be charged elsewhere, so RSS can legitimately exceed cgroup peak and is not an ordering invariant. These counters do not prove complete privacy/erasure or shared-memory unlink. Private scratch disk usage/inner failing stage remain explicitly **UNMEASURED**; no private-file read is used to fill those gaps. Binary/example/ELF identities and retained setup sizes/frozen VK hash are recorded; PK/circuit rehash and provenance remain unqualified unless the wrapped runner's actual preflight succeeds.

One bounded JSON result distinguishes refusal, runner/limit/ambiguous failure, unmeasured benchmark, `PUBLIC_SETUP_ONLY` and `ACTUAL_WRAPPED_CAPSULE`. The wrapped success contract contains only the generated public context, canonical binding and digests, capsule basename, counts and timing; `proof_certificate` remains false, with no journal/proof bytes or peer certificate export on stdout. Python validates strict metadata/framing/context and the trusted encrypted-file digest; it does **not** perform pairing verification, decrypt the capsule or prove target admission. On a genuine successful run, actual SHA-Groth16 verification occurs inside the Rust owner producer and capsule save, not in Python. Fast tests using invalid encrypted certificate fixtures are not successful wraps. A runner result with missing/inconsistent accounting remains `BENCHMARK_UNMEASURED` and exits nonzero. Success names only the observed operation, **not P1 or hardware qualification**; financial execution, strict matching privacy and admission remain unqualified. No genuine wrapped positive has been established by the safe migration checks.

Fast checks do not run a prover or create a scope:

```text
python3 -m unittest discover -s scripts -p test_owner_proof_benchmark.py -v
```

### Privacy and Permission Boundaries

- Witnesses contain secrets and stay **owner-local**. No witness upload, Succinct Prover Network, paid GPU/cloud prover or shared remote prover fallback satisfies V1.
- Qualify private process diagnostics, SDK/Gnark shared-memory ownership/cleanup, scratch files and retained buffers, including abnormal exit/OOM. Do not claim complete erasure from file deletion alone.
- The dedicated owner-proof child reserves global null tracing/log defaults before private input and rejects preinstalled global/scoped diagnostic policies. This is process-default suppression, not an unoverrideable sandbox or SP1 async custom-consumer API; later scoped subscribers and ordinary SDK/native/Go allocations remain outside this guarantee. Actual private mount/PID namespace probe failed UID-map setup on this host, so `/dev/shm` lifetime isolation and full-proof abnormal cleanup remain unqualified; no privileged change or shared-host fallback is assumed.
- Preserve existing setup/artifact copies and funded-version recovery capabilities. Do not blanket-clean target directories or weaken the verifier to make a trial pass.
- Benchmarking uses controlled non-production witnesses. This document grants no permission to consume production secrets, sign, submit, deploy or move funds.
- Zero paid proving infrastructure does not mean zero chain gas, storage, hardware use or electricity.

## Proof-System Candidates — No Prequalified Alternative

**Proof-system selection is UNRESOLVED.** Must measure existing SP1 `prove-owner` first. Existing integration makes SP1 the first **CANDIDATE** to benchmark, not a qualified V1 choice.

| Path | Qualification required |
|---|---|
| Existing owner-local SP1 | **CANDIDATE; UNQUALIFIED.** Measure full samechain wrapped proving and exact target admission on the target hardware first. |
| Owner-local SP1 optimizations | **CANDIDATE.** Measure the actual failing stage, resource impact and preserved relation/verifier behavior; no assumed savings. |
| Circom | **CANDIDATE.** Measure constraints and complete proving resources for the same relations; independently qualify setup, privacy, recovery and EVM verification. |
| Halo2 | **CANDIDATE.** Measure constraints and complete proving resources for the same relations; independently qualify setup, privacy, recovery and EVM verification. |
| Other owner-local systems | **CANDIDATE.** Require the same constraint/resource measurements and independent relation/verifier qualification; no default fallback. |

If the existing benchmark cannot qualify SP1, identify the actual failing stage and resource requirement before evaluating these candidates against the **same** ownership, consent, conservation, uniqueness and recovery relations. No unmeasured alternative is feasible merely because its circuit or marketing benchmark appears smaller.

Compare actual whole-prover memory, wall time, artifact/scratch storage, setup provenance, privacy boundaries and exact EVM verifier compatibility on the intended hardware. Preserve real cryptography and financial semantics; mocked verification, witness outsourcing or deferring required proving is not an alternative.

### Pinned host-cache candidate — investigated 2026-10-06, not qualified

Read-only installed SP1 6.8.1 source at upstream revision `c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824` shows `SP1RecursionProver::new` (`sp1-prover/src/worker/prover/recursion.rs`) retains four compose preprocessing keys plus an eager deferred key. The samechain guest uses no deferred proof input. Its existing `deferred_keys=None` → `RecursionKeys::Program(deferred_program)` fallback already sets up/proves the unchanged deferred program on demand. A minimal **candidate pinned host-only patch** would avoid eager deferred-key caching while preserving the program, allowed VK tree/root, all compose/shrink/wrap verification and financial relation. Do not edit the global Cargo registry or loosen runtime tuning denylists to try it.

From actual fixed preprocessing row/column shapes, 32-bit SP1 fields, interleaved/LDE tensors and retained Merkle layers, the one cached bundle's resident-array component is **1,122,215,776 bytes**; removing it changes the five-key component from5,611,078,880 to4,488,863,104bytes. These are source-derived array bounds, **not measured RSS/peak savings or an8GB/16GB feasibility guarantee**. Other compiler/shrink buffers and later decoded Groth16 R1CS/PK/FFT/solver memory remain. A one-permit semaphore cannot cap allocations that occur before permit acquisition; smaller artifact read buffers do not remove fully decoded keys.

Qualification requires before/after public CPU-builder accounting, identical actual ELF/program and frozen setup/verifier hashes, actual all-mode wrapped certificates accepted by the exact native SHA-only/frozen Solidity verifier, normal/cancel/OOM cleanup and a legitimate deferred-proof regression. No proof-system switch, setup/key change, artifact deletion, weakened verification or remote witness is implied. The public-only owner-program path avoids this full builder for key derivation only; it cannot generate proofs.


**Deployment consequence:** `SamechainAuthority` constructs its SP1 verifier and immutably pins that verifier and the owner program. A different proof system, verifier or program VKey requires a reviewed contract change where applicable and a **new authority deployment**, not an in-place VK update. Deployment requires explicit authorization. New client/deployment pins and independent genuine-proof/funded/recovery qualification are required; old funded rights and their usable artifacts must remain recoverable under their original deployment.

## Per-lane target verification — 2026-10-06

The owner-local SP1 Groth16 v6.1.0 certificate serves every lane: Base, HyperEVM, Solana and NEAR. Prover qualification above is shared across lanes; **target admission is qualified per lane.** Each non-EVM lane needs a reviewed verifier for the *exact* frozen statement (`contracts/evm/src/sp1/v6.1.0/SP1VerifierGroth16.sol:51-81`):
- 5 public inputs: programVKey, sha256(publicValues) masked to 253 bits, exitCode = 0, `VK_ROOT` `0x002f85…5352`, nonce
- selector `VERIFIER_HASH` `0x4388a21c…`
- 356-byte proof

| Lane | Primitive (source) | Current state | Qualification needed |
|---|---|---|---|
| Base / HyperEVM | BN254 precompiles; vendored v6.1.0 | Real verifier rejects invalid proofs in Foundry. No genuine positive | Genuine positive and mutations; HyperEVM gas vs 3M/30M block limits |
| Solana | `alt_bn128` syscalls: g1_mul 3,840 CU, pairing 36,364 CU + 12,121 CU/pair (agave `execution_budget.rs`, master) | **No verifier.** `sp1-solana` pins SP1 5.0.3, VKs ≤ v5.0.0, 2 public inputs. This is a **critical mismatch** with v6.1.0 and it is not usable as-is | Reviewed v6.1.0 port. Exact vector accepted and mutations rejected in LiteSVM. Measured CU (≈95k **[INFERENCE]**, not passing). Buffer staging under the 1,232-byte tx limit |
| NEAR | `alt_bn128_pairing_check` / `g1_multiexp` host functions; gas 9.686 TGas + 5.102 TGas per pairing element (nearcore `parameters.yaml`, master base; per-version diffs unchecked) | **No verifier.** `contracts/near` is empty | Written and reviewed verifier. Sandbox exact vector and mutations. Measured gas (≈32.5 TGas **[INFERENCE]**, not passing) |
| L-ZEC (native) | Not an SP1-target verifier lane. Native source history, P/Q and payment proofs follow the native plan (S1–S7/M1–M5, Tasks 1–10) | Unchanged obligations | As in the native plan; wrapped ZEC never substitutes |

**Latency:** at most 15 minutes per owner proof is a **provisional objective**, not a guarantee or a measurement. Resource work is **methodology only**: no heavy trial without a separate resource packet ([Phase 0 policy](research/2026-10-06-phase0-testnet-prover-policy.md)).

## Decision Rule

Benchmark existing SP1 `prove-owner` first. Proving feasibility remains **UNQUALIFIED** until measured full wrapped proving and exact target admission succeed. The proof system remains **UNRESOLVED** until that evidence supports selection; alternatives are **CANDIDATES**, not commitments. No resource minimum, proving-time promise or paid/remote fallback is established by this document.
