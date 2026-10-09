# Ziquid

V1 is a **P2P `z2z-node` with CLI-only samechain trading**, maker online and fresh consent from both parties for every fill, owner-local proving, and full company-off recovery. **The whole pipeline includes native ZEC:** Zcash/ZEC is a first-class lane in the whole product, not a later phase. **Current code is incomplete:** real native primitives and an immutable samechain authority do not yet establish an end-to-end funded lifecycle. [Native implementation status](docs/NATIVE-IMPLEMENTATION-STATUS.md) owns exercised evidence and remaining proof, asset-transfer, recovery and resource qualification.

**Product definition:** the intended product is a **DEX with its own P2P order market**, RFQ quotes and separately chosen external-venue execution. P2P is part of the DEX, not a peripheral module or an alternative to decentralization; same-chain and native cross-chain relations are settlement constructions for qualified trades. [Unified product hierarchy](docs/PRODUCT.md#p2p-nằm-ở-đâu-trong-dex) separates this product scope from incomplete implementation, strict-private matching and custody/source-authority blockers. Native build priority is unchanged.

**V1 boundary and active lanes:** the **first passing journey is samechain** (Base Sepolia 84532 is the engineering default, owner-overridable). **Native ZEC is an ACTIVE first-class lane (L-ZEC) required for the whole project, not V2**, with pairs ZEC↔{Base, HyperEVM, Solana, NEAR}; wrapped/bridged ZEC never counts as a substitute. **HyperEVM (L-HEVM: spot ships first, Core-spot/perps position claims are active research and are not equivalent to transferring an actual Core position), Solana devnet (L-SOL), NEAR testnet (L-NEAR) and cross-chain fills (X.CROSSCHAIN: HTLC/CX-1 first, proof-verified release CX-2 active research, all pairs in parallel, no atomicity or privacy claim) are active parallel obligations.** A first passing samechain journey is a usable journey, but releasing it does **not** complete the project. Still V2: offline standing-maker multi-fill, GUI (71 stories), hardware wallets, mainnet, Intents/1Click, Raydium/LP/agents/ZSA. V1 requires fresh exact consent for each fill; existing standing-order research is not a V1 delivery claim.

Ziquid is the chosen local name; Rust packages use `ziquid-*` and the SDK uses `@ziquid/sdk`. The directory is now `ziquid-dex`; the original directory path is a deliberately temporary compatibility symlink for the live OMP session, not a supported API alias. This naming does not claim registry, domain or trademark availability; packages are private/unpublished.

**V1 implementation entry point:** follow the [Z2Z-V1 implementation prompt](docs/Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md), [consolidated summary](docs/V1-CONSOLIDATED-SUMMARY.md) and [delivery matrix](docs/V1-DELIVERY-MATRIX.md). Kerb source modules are consolidated under native market/custody/runtime and the independent Solana target; the [documentation archive](docs/imports/kerb/README.md) retains provenance, not current V1 instructions or completion evidence.

**Latest native checkpoint:** finite Zcash source validation reaches NU6.3 height4465025, with independent Ironwood state and complete V4/V5/V6 authorization;4465026 is rejected. Private preparation v3 opens input/payment commitments, derives the deployment-scoped note tag, binds the exact solver-private P/Q export and verifies owner consent before encrypted restart custody. Real native/CPU scenarios execute, but accepted-chain/finality, wrapped financial proofs, S funding authority and atomic target transfers remain incomplete. Retained v1/v2 custody is never rewritten; an authenticated old restore path is an explicit funded-release hold. Exact current evidence and limitations remain in [native status](docs/NATIVE-IMPLEMENTATION-STATUS.md).

**Server-independent redesign:** proposed owner-local authorization/recovery data/proving, immutable funded on-chain rights and replaceable discovery/matching/indexing/relay. A native manual consumer must exercise the same authorized path without company APIs/signers; contract existence, a state root or an artifact hash alone is not witness/data/resource availability. [Manual workflow and data requirements](docs/SERVER-INDEPENDENCE.md), [research-led design](docs/superpowers/specs/2026-10-02-z2z-server-independent-architecture-design.md) and [whole-document review](docs/research/ARCHITECTURE-REVIEW.md) distinguish qualifying same-chain rights, still-blocked native cross-chain capabilities, legacy custody and external venue assumptions. No strict-matching privacy waiver, unconditional censorship immunity or operator-free ZEC custody is claimed.

**Product continuation — 2026-10-04:** owner-local known-fill review checks input authority, recipient recovery, fees/net limits, conservation and partial successor **before** returning consent bytes. Ordinary received/cancel-return notes have separate withdrawal semantics and manual review/signed checks without fictional orders. Native processes/shared CPU exercised exact Exit/Fee/recoverable-change accounting, the creation mint predicate and reconstructed historical insertion paths. Private stdin is bounded/erasing; public exports do not authenticate backing. HyperCore proposals remain offline, with signing/submission/reservation false and fee enforcement unavailable. [Progress](docs/history/PROGRESS-2026-10-04.md) separates these exercised primitives from blocked private matching, actual receipt/root/global-consumption enforcement, backed atomic settlement and full company-off recovery. Latest permanent SQL-off workspace passed895 checks; market-only12 and all-target release Clippy passed. SQL/funded lifecycle remain unverified.

Samechain creation now opens exact public amount/asset/owner/deployment against the actual private note and complete recipient recovery ciphertext, including authenticated generation-one initial orders. Native review/check and the shared CPU guest rejected freshly consented amount inflation. This is a mint predicate, **not actual asset receipt, root admission or a wrapped proof**; funded settlement remains incomplete.

The native commitment tree now reconstructs canonical append roots and retained insertion paths; real owner checks and the shared CPU guest exercised those paths after later appends. This is tree arithmetic, not authenticated target admission, current spentness or funded recovery.

The immutable EVM samechain authority implements proof verification, receipt/root/nullifier/replay checks and atomic manifest effects. Reported offline VM checks are scoped primitive evidence; **genuine-certificate funded settlement and full manual/company-off recovery remain unqualified**. V1 does not depend on an offline standing-maker construction; the first samechain journey does not require native ZEC financial settlement, but native ZEC remains an active required lane for the whole project.

The Linux direct-transport prerequisite is runnable: `cargo run --offline --locked -p ziquid-runtime --bin z2z-node -- run --listen /ip4/127.0.0.1/tcp/0`. It authenticates explicit peers over TCP/Noise/yamux, exchanges ping/identify and stops on Ctrl-C or `--run-for-ms`. Identity remains **ephemeral by default**; omit the option for no transport-key file access or creation. Opt in to stable PeerId across restarts with `--peer-identity-file /absolute/external/private-directory/transport.key` (or strict schema1 JSON `"peer_identity_file"` holding only that path). The parent directory must already exist, belong to the effective user, have exact0700 permissions and lie outside checkout/build trees; the immutable52-byte file requires0600, trusted ancestors and no symlinks/hard links. Startup never provisions/chmods the directory, repairs invalid keys or silently falls back to ephemeral identity. **This is a plaintext transport secret:** anyone able to read it can impersonate that PeerId; it is not a wallet, financial authority or anonymity guarantee. Parent-observed48 scoped checks and Clippy include an actual persisted-peer restart with authenticated identify/ping and configured-peer reconnect. [Current evidence and boundaries](docs/NATIVE-IMPLEMENTATION-STATUS.md#2026-10-06--optional-persistent-transport-identity). [Transport usage and deliberate limits](docs/modules/solver-operations.md#direct-node-transport-usage--transport-only-prerequisite); discovery stays opt-in, and order gossip/backing/trading remain unqualified. [Owner-local measurement harness](docs/PROVING-COST-SOLUTIONS.md#controlled-measurement-cli) separately measures actual setup/proving runs and refuses unsafe resource envelopes; setup measurements are not successful wrapped proofs.

### Selected-peer DKG keygen

`z2z-node dkg-handshake` runs real, **ephemeral** 2-of-2 FROST keygen over an authenticated direct session. It does not fund J, sign a Zcash transaction, verify ETH arming, persist financial key shares or execute a swap. Both sides must explicitly supply matching caller-owned pool/J bytes and nonzero chain/deployment digests; transport does not qualify their financial meaning. The responder is disabled by default and accepts only its configured Ed25519 PeerId.

```sh
# Existing owner-private transport identity for the selected initiator.
# Obtain INITIATOR_PEER_ID from that identity's existing node output.
z2z-node run --listen /ip4/127.0.0.1/tcp/9000 --headless \
  --dkg-peer "$INITIATOR_PEER_ID" \
  --dkg-pool-id "$POOL_BYTE" --dkg-j-params "$FROZEN_J_HEX" \
  --dkg-chain-context "$CHAIN_DIGEST_HEX32" \
  --dkg-deployment-context "$DEPLOYMENT_DIGEST_HEX32"

z2z-node dkg-handshake --address "$RESPONDER_TCP_P2P_ADDRESS" \
  --peer-id "$RESPONDER_PEER_ID" --lane-id "$LANE_ID" \
  --peer-identity-file "$INITIATOR_TRANSPORT_IDENTITY_FILE" \
  --dkg-pool-id "$POOL_BYTE" --dkg-j-params "$FROZEN_J_HEX" \
  --dkg-chain-context "$CHAIN_DIGEST_HEX32" \
  --dkg-deployment-context "$DEPLOYMENT_DIGEST_HEX32"
```

J bytes are lowercase hex, 1–256 bytes; each context is nonzero lowercase hex32. The optional identity file stores only the existing transport identity, never DKG shares. Success emits `dkg_completed` with a public package digest, `ephemeral=true`, `financial_authority=false`. Errors, changed pins, mismatched contexts or malformed/trailing packages destroy the session; exact retries reuse guarded signed responses. Local owned share buffers are wiped, but complete wiping of libp2p-internal buffers/cancellation is **not qualified**.

### Offline native ETH call proposals

```sh
ziquid native build-arm-call --statement PUBLIC_STATEMENT --boundary PUBLIC_BOUNDARY \
  --deployment PINNED_DEPLOYMENT --arm-proof PUBLIC_ARM_PROOF \
  --origin-proof PUBLIC_ORIGIN_PROOF --acceptance-proof PUBLIC_ACCEPTANCE_PROOF
ziquid native build-resolve-call --statement PUBLIC_STATEMENT --boundary PUBLIC_BOUNDARY \
  --deployment PINNED_DEPLOYMENT --financial-proof PUBLIC_FINANCIAL_PROOF \
  --acceptance-proof PUBLIC_ACCEPTANCE_PROOF --sender 0xRELAYER_ADDRESS \
  --outcome completion --cnet CONSIDERATION_ZATOSHIS
```

Linux inputs are exact raw public canonical frames: statement638bytes, boundary100, independently selected deployment279 and each SP1 wrapper356. Regular no-follow bounded files only; no stdin, keys, SQL or RPC. `recovery` requires `--cnet 0`; `completion` requires1..=quotedA. JSON returns unsigned calldata, full-width wei, fixed recipients/context and expected journals while proof/deployment/source/finality/backing remain `UNVERIFIED`; signing/submission/financial execution stay false. Header/scalar checks are not cryptographic verification. [Observed evidence](docs/NATIVE-IMPLEMENTATION-STATUS.md#native-eth-unsigned-call-integration--2026-10-09).

### Offline full-body source replay

```sh
cargo run --offline --locked -p ziquid-runtime --example replay_source -- \
  HISTORY_FILE MAX_BLOCKS MAX_INPUT_BYTES
```

Linux read-only consumer: input is the existing ledger guest witness frame (`count:u32LE`, then `length:u32LE` and each complete raw block), starting at authentic testnet genesis. Caller limits include all framing; maximum count is4,465,026 including genesis, maximum body2,000,000bytes. Reads one reusable body buffer and rejects invalid/gapped/reordered/truncated/trailing history; actual ledger state still grows with UTXOs/nullifiers/anchors. Only complete success returns374raw stdout bytes (v11 subrelation journal, no newline); require both exact length and successful exit. Errors are sanitized, no partial validation journal is emitted, and FIFO/nonregular input fails without blocking. It does not read stdin, access RPC/SQL/keys, prove a SNARK, select a canonical/final chain or create settlement authority. The0..10 authentic fixture smoke is not whole-chain validation qualification. Guest source/artifact is unchanged.

To acquire an explicitly bounded historical prefix from a caller-selected endpoint and feed that same ledger:

```sh
cargo run --offline --locked -p ziquid-runtime --example acquire_replay_source -- \
  --endpoint-env SOURCE_ENDPOINT_ENV --through-height HEIGHT \
  --max-blocks COUNT_LIMIT --max-input-bytes FRAME_BYTE_LIMIT \
  --max-rpc-bytes RESPONSE_BYTE_LIMIT --max-elapsed-seconds TIME_LIMIT
```

No default endpoint or live-tip selection. The environment value stays out of diagnostics; HTTPS is accepted, literal-loopback HTTP needs explicit `--allow-loopback-http` (not hostname/shorthand HTTP). Strict JSON-RPC2.0 profile uses `getblockhash` and raw `getblock(hash,0)`, supports source `error:null`, bounds response/decoded/frame/cumulative bytes and elapsed time, and disables redirects/proxy/decompression/retries. Each raw body is bound to its requested header hash and admitted by the authentic full-body ledger; final boundary hash is rechecked before the374-byte journal. Recheck is node coherence, **not canonicality/finality**. Only controlled-loopback authentic0..10 acquisition has been exercised; real endpoint/auth dialect, later-era continuous acquisition and current supported source environment remain unqualified. This command grants no network/action permission.



## V1 Testnet Showcase

The acceptance target is a real selected-testnet journey: run owner-local nodes, discover a counterparty over P2P, create and fund a samechain order, review and freshly consent to a partial fill with both parties online, observe actual asset arrival, then cancel/withdraw the remainder. Cold restore and complete company-off recovery must work without company APIs, bootstrap, hosted signers or mandatory company approval. This is **required delivery, not an already working showcase**; mock balances, scripted success, CPU journals and unsigned calldata do not qualify.

This first samechain lane is one of the existing **122-ID catalog** and becomes the EVM/Base lane. **Releasing the first passing lane does NOT complete the project:** native ZEC (L-ZEC), HyperEVM, Solana devnet, NEAR testnet and cross-chain HTLC remain active obligations.

Proving feasibility is **UNQUALIFIED** until real owner-local proofs are benchmarked on the user's i5-11400H / 16GB machine. Lightweight-node and full-prover resource consumption must be measured separately. No paid services, cloud provers or paid infrastructure are permitted. Per-node storage is **UNRESOLVED** against the existing PostgreSQL requirement; no SQLite fallback or local SQL-test permission follows. GUI is deferred to production, and showcase signing/deployment/funding still requires explicit action authorization.

## Build and exercise native code

Use the installed Rust toolchain. Run from the repository root:

```sh
# First build the independent target and harness per contracts/solana/README.md.
export Z2Z_TEST_NATIVE_DIR="$PWD/crates/runtime/tests/fixtures/market"
export Z2Z_TEST_SOLANA_BIN="$PWD/contracts/solana/target/debug/local-safety-scenario"
export Z2Z_SBF_ELF="$PWD/target/z2z-sbf/ziquid_solana.so"
CARGO_BUILD_JOBS=1 cargo test --offline --locked --workspace --all-targets --release
cargo run --offline --locked -p ziquid-runtime --bin ziquid -- allocation 6000000 30000000 2000000
cargo run --offline --locked -p ziquid-runtime --bin ziquid -- market inspect-pczt \
  --config "$Z2Z_TEST_NATIVE_DIR/policy.json" --pczt "$Z2Z_TEST_NATIVE_DIR/unsigned.pczt"
cargo run --offline --locked -p ziquid-zcash --example prepare --release

# Explicit external venue information only; no signing or exchange submission.
cargo run --offline --locked --release -p ziquid-runtime --bin ziquid -- hypercore inspect-meta \
  --file crates/chains/tests/fixtures/hypercore-testnet-spot-meta.json --pair-index 0 \
  --base-token-id 0xc4bf3f870c0e9465323c0b6ed28096c2 \
  --quote-token-id 0xeb62eee3685fc4c43992febcd9e75443
cargo run --offline --locked --release -p ziquid-runtime --bin ziquid -- hypercore info \
  --network testnet --request spot-meta
# Account-scoped reads require --account; order-status also requires --oid or --cloid,
# fills-by-time requires --start-ms and --end-ms. See hypercore info --help.
# Successful output retains the selected request and typed observation; fills are
# explicitly incomplete history, and orders/fills can include perpetual markets.

# Owner-local semantic preflight; PRIVATE_WITNESS is an owner-held input stream,
# never a key/witness argument or a public file uploaded to a service.
ziquid samechain review-fill --packet OWNER_REVIEWED_PUBLIC_PACKET --execution OWNER_SELECTED_FILL_EXECUTION --role a --witness-stdin
ziquid samechain check-fill --witness-stdin
ziquid samechain review-cancel-exit --packet OWNER_REVIEWED_PUBLIC_SINGLE --deployment EXPECTED_DEPLOYMENT --order-id 0xORDER_ID --role a --action cancel --witness-stdin
ziquid samechain check-cancel-exit --witness-stdin
ziquid samechain review-note-withdrawal --packet OWNER_REVIEWED_WITHDRAWAL_PACKET --witness-stdin
ziquid samechain check-note-withdrawal --witness-stdin
ziquid samechain review-note-creation --packet OWNER_REVIEWED_CREATION_PACKET --witness-stdin
ziquid samechain check-note-creation --witness-stdin
# Each command reads one canonical witness from stdin through EOF. Review returns
# public consent bytes but does not sign; check commands return public journals.
# Supplied-root eligibility, global unspentness and asset backing stay UNVERIFIED.
# Cancel/exit review independently pins deployment, nonzero 32-byte order id,
# role a|b and action cancel|exit. It ignores existing consent, never installs a
# signature or emits a journal; the signed checker still requires fresh consent.
# Native review does not qualify frozen guest ELF identity or funded artifacts.
# Fill review requires a separately selected canonical FillExecution frame2, not
# JSON or execution copied from witness stdin; its packet must equal witness.packet.

# Real CPU owner guest through permanent native CLI; not a wrapped proof or funds.
# Build ziquid-runtime with --features sp1-execute; pin independently selected ELF/deployment.
ziquid samechain execute-owner --operation creation --elf PUBLIC_OWNER_ELF --elf-sha256 0xELF_SHA256 --deployment EXPECTED_DEPLOYMENT --witness-stdin
# Fill additionally requires --packet PUBLIC_FILL_PACKET; cancel/exit must match witness.action.
# Fill CPU/prove stdin is OwnerWitness frame2; guest mode0 adds only its mode byte.
# Canonical private witness only on stdin; public journal output, financial_execution=false.

# Public unsigned EVM calls only; EXPECTED_DEPLOYMENT is a canonical caller-selected
# descriptor, not authenticated RPC inspection. Proof framing does not prove validity.
ziquid samechain build-note-creation-call --packet PUBLIC_CREATION --deployment EXPECTED_DEPLOYMENT --proof PUBLIC_PROOF --token 0xTOKEN
ziquid samechain build-fill-call --packet PUBLIC_FILL --deployment EXPECTED_DEPLOYMENT --proof PUBLIC_A_PROOF --proof-b PUBLIC_B_PROOF --sender 0xSENDER
ziquid samechain build-cancel-exit-call --packet PUBLIC_SINGLE --deployment EXPECTED_DEPLOYMENT --proof PUBLIC_PROOF --sender 0xSENDER --role a --action cancel
ziquid samechain build-note-withdrawal-call --packet PUBLIC_WITHDRAWAL --deployment EXPECTED_DEPLOYMENT --proof PUBLIC_PROOF --sender 0xSENDER
# No private stdin, signing, simulation, network submission or financial execution.

# Actual public RPC simulation, not signing/financial execution; independent pins required.
ziquid samechain simulate-call --operation creation --packet PUBLIC_CREATION --deployment EXPECTED_DEPLOYMENT --proof PUBLIC_PROOF --token 0xTOKEN --token-code 0xTOKEN_RUNTIME_KECCAK --block-hash 0xBLOCK --policy-id 0xPOLICY --endpoint-env OWNER_RPC_ENV --gas-limit 1000000
# Fill requires --sender/--proof-b; cancel/exit --sender/--role; withdrawal --sender.
# Strict result is NODE_REPORTED_VOID_EXECUTION; all financial/proof/finality assurances unverified.

# Offline external spot proposals; intent files contain PUBLIC terms only.
ziquid hypercore prepare-order --metadata SPOT_METADATA_JSON --intent PUBLIC_ORDER_JSON
ziquid hypercore prepare-cancel --metadata SPOT_METADATA_JSON --intent PUBLIC_CANCEL_JSON
# Exact string amounts/limits and selected token IDs are bound; no rounding.
# Requested fee caps are NOT venue-enforced. Neither command signs or submits.

# Compile opt-in SQL cases without executing any connection or query.
CARGO_BUILD_JOBS=1 cargo test --offline --locked --release -p ziquid-runtime \
  --features postgres-tests --no-run
```

Allocation is arithmetic only; the prepare example generates local note/tree/Q cryptography, not a chain-valid note. Market inspection checks exact PCZT effects, not signatures/proofs/history or payment. Current SQL code uses PostgreSQL with separate native inventory and market/replica schemas; the P2P V1 per-node storage decision remains **UNRESOLVED**. Encrypted custody stays owner-local. **No local SQL tests**; SQL execution awaits a private user URI and authorized isolated schemas per [SQL-VERIFICATION](docs/SQL-VERIFICATION.md). Old SQLite journals/sidecars remain protected and are not automatically imported. [Native status](docs/NATIVE-IMPLEMENTATION-STATUS.md) records actual commands/results and limits; SDK remains deferred.

**Current Fill2 contract:** [reviewed construction](docs/superpowers/specs/2026-10-06-independent-owner-fill-design.md), [protocol](crates/protocol/src/samechain/fill.rs), [owner witness/reviewer](crates/proofs/src/samechain.rs) and [CLI](crates/runtime/src/samechain.rs) define frozen packet/public execution E/ordered A+B opaque policy leaves/private per-owner `own_salt`, not counterparty policy/common blind. Fill alone uses relation/witness2; packet/outer journal/schema/note/order/policy/tree/ciphertext and creation/single/withdrawal/blinds remain1. E quantities are counterparty-visible, not GD2-secret. [Guest mode0](crates/proofs/methods/samechain/src/main.rs) is byte0 + one OwnerWitness frame2; new ELF/program needs separately authorized new immutable authority and genuine all-mode proof/target/recovery qualification. Preserve [fill1 identities](legacy/samechain-fill-v1-pre-fill2-20261006/manifest.json), no reinterpretation/fallback/asset migration. [Native status](docs/NATIVE-IMPLEMENTATION-STATUS.md) exclusively owns current native/CPU/correspondence evidence and completed independent source reviews; independent source/setup/program qualification remains UNVERIFIED. Native counterparty-opening availability is addressed only for samechain, not wrapping/backing/privacy/backup/funded recovery.

**Bounded samechain public history:** `ziquid samechain inspect-history --config PUBLIC_HISTORY_JSON` acquires every independently pinned adjacent block, including the initial empty tree0 boundary and empty intermediate blocks, through one existing `SamechainInspectionClient`. All config fields/pins and the complete U256 number range are validated before any RPC. Replay uses `PublicHistory::ingest(independently_expected_hash, observation)` and emits one `samechain_history_observation` / `APPEND_STATE_COHERENT` JSON result only after every block succeeds; no retry, alternative endpoint, latest/range discovery or partial success is used. Ceilings are 2048 blocks including the origin, 4096 notes, 8192 observed nullifiers and 16 MiB ciphertext, with 256 append/256 NF events per block, 4096 bytes per ciphertext and 1 MiB per RPC response. The buffered JSON export is limited to 64 MiB before stdout; output-device errors may still interrupt an OS write. No eviction or root-only checkpoint import exists. `TRUSTED_NODE_AT_SELECTED_BLOCK`, `TRUSTED_PROVIDER_INITIAL_EMPTY_BOUNDARY` and `TRUSTED_PROVIDER_LOG_COMPLETENESS` are assumptions, not consensus/finality/backing: an omitted unqueried NF-only transaction can leave the tree unchanged, so absence from observed nullifiers does not prove unspentness. This public CLI does not implement private discovery or funded cold recovery.

The strict public JSON config is at most 1 MiB and requires **every** field below (unknown/duplicate fields, nulls, wrong types and trailing data are rejected). `deployment` is the existing independently selected canonical binary Deployment file, resolved from the process working directory, not the config directory. Token is nonzero 20-byte hex; code/policy/block pins are nonzero 32-byte hex with `0x` prefix. `origin_number` is a canonical unsigned decimal **string** through U256, including zero and values above u64; the full supplied adjacent number range must not overflow. `block_hashes` contains 1..2048 distinct independent pins in replay order, including origin. `endpoint_env` names a locally resolved secret environment value; HTTPS is normal, and HTTP requires explicit `allow_loopback_http: true` plus a literal loopback IP. The command has no witness/stdin or URL flag and never reads stdin.

```json
{
  "schema_version": 1,
  "deployment": "public-deployment.bin",
  "token": "0x1111111111111111111111111111111111111111",
  "token_code": "0x2222222222222222222222222222222222222222222222222222222222222222",
  "policy_id": "0x3333333333333333333333333333333333333333333333333333333333333333",
  "endpoint_env": "ZIQUID_INSPECTION_ENDPOINT",
  "allow_loopback_http": false,
  "origin_number": "42",
  "block_hashes": ["0x4444444444444444444444444444444444444444444444444444444444444444"]
}
```

These illustrative pins are not qualified deployment data; use independently selected actual pins. The result exports expected deployment/token/code/policy, origin number/hash, ordered blocks with number/hash/parent, final `tree`, `block_count`/`note_count`/`nullifier_count`/`ciphertext_bytes`, `retained_notes` and `observed_nullifiers`. Notes are in commitment-key order (`note_order: COMMITMENT_KEY`); nullifiers are in nullifier-key order (`nullifier_order: NULLIFIER_KEY`), **not chronological order**. Full containing-block and transaction/log occurrence metadata is retained so consumers can establish event order. Each note includes its full ciphertext/version/recovery-key commitment and exactly 32 `insertion_siblings` for its **historical insertion root**, not the final tree root. There is no inferred commitment↔nullifier ownership mapping or retained response-hash provenance. Finality, proof validity, deployment-profile qualification, root eligibility, global unspentness and backing remain `UNVERIFIED`; signing, submission and financial execution are false.

**Storage:** dev/test builds disable debug symbols and incremental compilation in both native and independent sender workspaces; release guest settings are unchanged. Build only the crate/features needed for the current task. These settings reduce growth, not enforce a disk quota: check `df -h .` before large builds/downloads, and require enough free space for archives **plus extraction/build output**. Do not automatically download proving artifacts on a nearly full disk.

**Guest C builds:** run the pinned `~/.local/share/ziquid-tools/sp1-6.8.1/cargo-prove prove build …` from `crates/proofs/methods/preparation` or `crates/proofs/methods/sprout-ledger`, with the installed `succinct` Rust toolchain and RISC-V-capable `clang`/`llvm-ar` on PATH. Each guest's `.cargo/config.toml` forces only `CC/CFLAGS/AR_riscv64im_succinct_zkvm_elf`, including `-march=rv64im -mabi=lp64`, overriding shell/compiler defaults so native C cannot emit unsupported compressed instructions. An intentional tool-path override belongs in that guest-local config, retaining the ISA/ABI flags; no root/global settings are changed. Use a new `--output-directory` and preserve original ELFs, setup/proof identities and journals; see [exact flags and observed execution limits](docs/NATIVE-IMPLEMENTATION-STATUS.md#reproducible-native-commands).

Safe compiler-cache cleanup from this repository root:

```sh
rm -rf -- target/debug target/release target/tmp contracts/evm/out contracts/evm/cache
```

Stop active builds first. **Do not use blanket `cargo clean` or delete all of `target/`:** current funding journals and the sender ELF also live there and must be retained. Never auto-prune keys, witnesses, proof/program identities, SQLite journals/sidecars or pending funding records. Global Cargo/sccache/toolchain caches and sibling repositories are outside this cleanup scope. Deferred SDK `node_modules`/`packages/sdk/dist` are reproducible with the retained package lockfile.

## Layout

```text
ziquid-dex/
├── Cargo.toml                  host-core workspace
├── crates/
│   ├── protocol/               checked native context and allocation
│   ├── zcash/                  real local Ironwood authoring/witness integration
│   ├── proofs/                 real source subrelations/genesis/headers/legacy verifier; full proof missing
│   ├── chains/                 closed HyperCore testnet info and exact offline spot proposals
│   └── runtime/                native/market tools, owner preflight, venue proposals, journals/custody
├── packages/sdk/               deferred empty TypeScript SDK frame
├── contracts/
│   ├── evm/                    allocation, real SP1 and immutable samechain authority; funded positives unqualified
│   ├── solana/                 actual public legacy-SPL safety program/interface/ELF harness
│   └── near/                   independent empty target Cargo workspace
└── docs/                       engineering decisions and open gates

Outside this repository: UI (../z2z-protocol, implemented landing; trading workspace missing); Zoss (shared native core; optional non-money messaging profile).
```

Solana/NEAR targets remain excluded from the host workspace. [Solana build/run](contracts/solana/README.md) exercises destination-built SBF escrow with three business authorizers; it is not owner-ZK or native-ZEC financial settlement, and the active L-SOL owner-ZK program is a separate new target. The L-NEAR lane is active scope, but `contracts/near` is still an empty target with no contract written. EVM has allocation, the actual SP1 base verifier and immutable samechain authority source; genuine-certificate funded DEX execution remains unqualified. UI is not created here. [Zoss](../zoss/docs/ARCHITECTURE.md) remains independently developed shared infrastructure, not a settlement/funds authority.

**Shared source integration:** owner agreed `zcash_protocol =0.10.5` across Ziquid and sibling Zoss. `ziquid_zcash::source::acquire_historical_block` uses actual `zoss-zcash::NodeRpc` for complete supported-era raw bytes; the native `acquire_source ENDPOINT HEIGHT POLICY_ID_HEX` example applies the stronger DEX structural parser. Loopback acceptance/full-authorizing-byte substitution rejection were exercised. Provenance stays `Unknown`/`UNVERIFIED`, not financial truth or genesis/history validity. No memo, runtime, viewing key or shared private store is required. DEX474-byte context is not Zoss's message encoding. [Shared-library readiness](../zoss/docs/BLOCKERS.md#7-shared-library-readiness) remains separate from financial gates.

Ziquid retains P/Q authoring, local Q proving without a user FVK given to the solver, independent user payout witnesses, transaction/payment/history circuits, target-specific `VerifiedSettlementFact` verification and financial allocation/actual transfers. Those proofs go directly to the DEX target verifier: library reuse requires no Zoss memo, inbox, watchers, IVK, quorum, receipt or runtime. The local native-EVM settlement candidate needs no Zoss EVM messaging route. [DEX integration boundary](../zoss/docs/private_dex.md) keeps shared-core reuse distinct from optional messages; no code or gate closure follows from this docs decision.

## Key documents

- [Z2Z-V1 implementation system prompt](docs/Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md): main V1 engineering guide.
- [V1 consolidated summary](docs/V1-CONSOLIDATED-SUMMARY.md): quick reference.
- [V1 delivery matrix](docs/V1-DELIVERY-MATRIX.md): required scope and acceptance matrix.
- [Native implementation status](docs/NATIVE-IMPLEMENTATION-STATUS.md): exercised evidence and current limitations.
- [Architecture](docs/ARCHITECTURE.md): whole system, distinct route/authority classes, invariants and proposed workflows.
- [Modules](docs/MODULES.md): current native paths, conceptual expanded roles, ownership and intended dependencies.
- [Archived product/frontend handoff](docs/history/PRODUCT-OVERVIEW-AND-FRONTEND-HANDOFF.md): complete historical 71-story record; current product authority is PRODUCT, GUI belongs to later production.
- [Status and progress — 2026-10-05](docs/history/STATUS-AND-PROGRESS-2026-10-05.md): exercised delivery, missing user flows, delays and next acceptance gates.
- [Order-book and onchain-rights brainstorm](docs/history/BRAINSTORM-2026-10-05-ORDERBOOK-AND-ONCHAIN-RIGHTS.md): saved expansion/storage/LayerZero discussion, not implementation approval.
- [Blockers](docs/BLOCKERS.md): closure evidence still required.
- [Documentation guide](docs/README.md): canonical reading order and distinct product lanes.
- [Unified product direction](docs/PRODUCT.md): expanded Ziquid, future Z2Z, users, routes and honest limits.
- [Consolidation decisions](docs/CONSOLIDATION.md): imported scope, authority, custody/privacy distinctions and code-migration prerequisites.
- [Complete Kerb documentation archive](docs/imports/kerb/README.md): original dated dossiers, source provenance and relocation manifest; no implementation migration.
- [Server independence](docs/SERVER-INDEPENDENCE.md): recovery bundles, data/prover lifetime and manual actions per funded state; drills not yet exercised.
- [Samechain private snapshot design](docs/superpowers/specs/2026-10-06-samechain-private-snapshot-design.md) and [plan](docs/superpowers/plans/2026-10-06-samechain-private-snapshot.md): generated-key snapshot (spec/plan approved).
- [Samechain release lifecycle design](docs/superpowers/specs/2026-10-06-samechain-release-lifecycle-design.md) and [plan](docs/superpowers/plans/2026-10-06-samechain-release-lifecycle.md): Wave B (P3.08). DRAFT. Approval is conditional on a clean independent review; no source changes until then.
- [Independent owner fill design](docs/superpowers/specs/2026-10-06-independent-owner-fill-design.md) and [plan](docs/superpowers/plans/2026-10-06-independent-owner-fill.md): Fill2 bilateral owner construction.
- [Phase-0 research](docs/research/2026-10-06-phase0-coverage-invariants.md), [durability/recovery](docs/research/2026-10-06-phase0-durability-recovery.md), [private discovery network](docs/research/2026-10-06-phase0-private-discovery-network.md) and [testnet prover policy](docs/research/2026-10-06-phase0-testnet-prover-policy.md): 2026-10-06 lane/release/prover research.
- [Native protocol implementation design](docs/superpowers/specs/2026-10-01-native-protocol-implementation-design.md): the **ACTIVE L-ZEC objective**.
- [Primary-source research](docs/research/SERVER-INDEPENDENCE-RESEARCH.md) and [cross-chain/market synthesis](docs/research/CROSSCHAIN-MARKET-RESEARCH.md): source claims, inference and technical feasibility limits.
- [Architecture review](docs/research/ARCHITECTURE-REVIEW.md): exhaustive current/imported-document coverage and unresolved blockers.

Current implementation follows the V1 guide above: P2P CLI samechain trading with fresh per-fill consent and full company-off recovery. Native ZEC (L-ZEC), HyperEVM, Solana, NEAR and cross-chain HTLC are **active parallel obligations, not later work**; offline standing-maker multi-fill and GUI remain V2. Nothing is completed or silently discarded. No signing, broadcast, deployment, funding, mainnet, new viewing party, commit or push permission follows from the documentation. Real primitive tests/local fixtures do not close funded-lifecycle, recovery or privacy gates.
