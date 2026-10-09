# Sprint demo runbook (presenter)

Target machine: this repo, loopback only, no funds, no testnet. Read with
`demo/contract.md` (v1.3) — that is the frozen UI contract; this file is the show.

## 0. One-line setup

```bash
cd /home/harry-riddle/dev/github.com/build-onchain/ziquid-dex
python3 demo/serve.py &          # optional UI bridge on http://127.0.0.1:8787
```

Everything below is stdlib Python 3 + prebuilt binaries. No network beyond
127.0.0.1.

## 1. Three acts

### Act 1 — real P2P transport with persistent identity (live, ~1 s)

```bash
python3 demo/run_demo.py --only s1_p2p_transport
```

Two real `z2z-node` processes over loopback: Noise handshake, identify, ping.
B is killed, restarted **with the same `--peer-identity-file` on the same port**,
and A reconnects to the **identical PeerId** (`peer_id_equal=true`).

**UI:** Offers (peer appears/disappears/reappears), Status (event stream).

### Act 2 — real native-Zcash cryptography (S5, ~85 s)

```bash
python3 demo/run_demo.py --only s5_native_zcash_prepare
```

Runs the prebuilt `target/debug/examples/prepare`. Both P and Q are **2-action,
real** — Q is fully signed/proved. Narrate the four real lines:

1. `Generated fixture only; no chain-valid note/anchor or node action.`
2. `P actions=2, SpendAuth absent; sender recovery=60000 zat without S IVK.`
3. `Q actions=2, all signatures/binding/proof valid; self-return=90000 zat; fee=10000 zat.`
4. `Q export is final consensus bytes only; no U FVK or spend key.`

**UI:** Status (artifact lines stream as they are produced).

### Act 3 — real recovery + release gate + owner CLI (S2 ~1 s, S3 ~1 s, S4 ~25 s)

```bash
python3 demo/run_demo.py --only s2_snapshot_restore,s3_pg_gate,s4_execute_owner
```

- **S2** encrypted snapshot: save one capability, then a **fresh process**
  restores and verifies it (`RESTORE_OK`); artifact `demo/out/s2_snapshot.bin`.
- **S3** real PostgreSQL release-journal fence: `committed_export_reads_key_only_after_real_journal_fence`
  — the key is read only after the journal lock commits. Needs Docker (below).
- **S4** `execute-owner` CLI preflight suite on CPU: 20 tests, 0 failures.

**UI:** Recovery (S2 snapshot restore), Status (S3/S4 evidence).

## 2. Full show / exact commands and durations

| command | duration | notes |
|---------|----------|-------|
| `python3 demo/run_demo.py` | ~110 s | all five, order S1→S5→S2→S4→S3 |
| `python3 demo/run_demo.py --quick` | ~87 s | S1 + S5 only (no Docker needed) |
| `python3 demo/run_demo.py --replay --replay-speed 1` | ≤90 s | zero preconditions |
| `python3 demo/run_demo.py --replay --replay-speed 4` | ~25 s | faster |
| `python3 demo/run_demo.py --replay --replay-speed 0` | instant | no sleeps |
| `python3 demo/serve.py` | until killed | bridge on 127.0.0.1:8787 |

The harness prints a per-segment summary with `state` and `duration_seconds`;
`demo/out/state.json` carries the same per segment.

## 3. Fallback ladder

1. **Live full run** — `python3 demo/run_demo.py` (needs binaries; S3 needs Docker).
2. **Quick** — `python3 demo/run_demo.py --quick` (S1 + S5 only; no Docker).
3. **Replay** — `python3 demo/run_demo.py --replay --replay-speed 1` (or `4`/`0`):
   streams `demo/fixtures/canonical_events.jsonl` (a previously captured **real**
   run), rewrites `demo/out/*`, marks every event `fields.replay=true`, sets
   `state.json.mode="replay"`, and needs **no binaries at all**.
4. **Pre-recorded video** — team-recorded screen capture; suggested location
   `demo/recording/sprint-demo.mp4` (not committed here).

**Kill rule:** if live S5 exceeds **~4 minutes** on the demo machine, escalate
to `--quick`, then to `--replay`.

Refresh the replay fixture after any real run (it is the canonical session):

```bash
cp demo/out/events.jsonl demo/fixtures/canonical_events.jsonl
cp demo/out/state.json   demo/fixtures/canonical_state.json
```

## 4. Demo-machine checklist

- [ ] Repo at `/home/harry-riddle/dev/github.com/build-onchain/ziquid-dex`.
- [ ] Prebuilt: `target/debug/z2z-node`, `target/debug/examples/prepare`,
      `target/release/ziquid`; S2 example built once:
      `cargo build --locked --offline -p ziquid-runtime --example snapshot_demo`.
- [ ] Port 8787 free (bridge) and loopback usable; no stray `z2z-node`/`serve.py`.
- [ ] Docker **optional** — only S3. Container `postgres` up on 5432 with the
      test creds file at `~/.ziquid-pg-test-5_tomcna/credentials.json` (never
      print it). If absent, S3 runs in labeled `replay`/`environment_unavailable`
      mode; the show continues.
- [ ] Python 3 stdlib only (no venv, no pip).
- [ ] `python3 demo/run_demo.py --self-test` prints `self-test ok`.

## 5. Q&A cheat sheet (honest answers)

- **Is the exchange working?** No. Settlement is gated by the **R1 construction
  decision** (the branch-lock kill criterion, documented in `docs/BLOCKERS.md`
  R1.3 and `docs/research/SETTLEMENT-RESEARCH.md`). The demo shows the **inputs**
  (crypto prep, custody, release fence, transport), not a settled trade.
- **What is real in this demo?** All five segments: S1 real libp2p transport +
  persistent identity; S5 real P/Q cryptography (real signed/proved Q); S2 real
  encrypted snapshot + fresh-process restore; S3 real PostgreSQL journal fence
  ordering; S4 real `execute-owner` preflight. Evidence: `demo/out/*` and the
  `artifact_line` events.
- **Custody?** Owner-local. No company keys; snapshots are encrypted and the key
  never leaves the owner (and is never copied into `demo/out`).
- **Scale / numbers?** Runtime suite recorded at **229 default / 373 with the
  PostgreSQL feature**; this demo session produced **74 events**; artifacts under
  `demo/out/`.
- **What's next?** Resolve the R1 decision, then the R2–R10 plan (roadmap docs).
- **Privacy?** Bilateral disclosure was approved for this release: the two parties
  see agreed terms/own outcomes; keys and witnesses stay local. **No anonymity
  claim** is made.
- **Can I see a proof?** S5 shows real cryptographic preparation and a fully
  signed/proved Q. Full P→Q wrapping on chain is the **killed** segment and is
  labeled as such — it is not claimed working.

## 6. Troubleshooting

- S5 slow: expected (~85 s). Use the kill rule above.
- S3 fails while Docker is down: expected — it is labeled
  `environment_unavailable` and replays `demo/out/s3_recorded.txt` if present.
- Bridge shows nothing: run the harness first (or a `--replay`), then reload
  `http://127.0.0.1:8787/events`.