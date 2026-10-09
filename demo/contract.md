# Demo Event Contract — v1.3 (FROZEN 2026-10-06)

v1.3 is **additive only** over v1–v1.2: the envelope, kinds, state machine and
artifacts are unchanged. It adds the explicit session-level `--replay` mode
(§9) and the `demo/fixtures/canonical_*.json(l)` snapshot. §8 is the v1.1
bridge; note the per-segment labeled replay rule already described in §4.

Frozen interface between the demo harness (`demo/run_demo.py`) and the frontend
team. Frontend consumes `demo/out/events.jsonl` + `demo/out/state.json` only; it
never talks to `z2z-node` directly. Everything is local loopback, no funds.

> **Settlement status: `IN_DEVELOPMENT`.** No settlement, fill, escrow, or
> payment event exists in v1. Any UI copy implying a settled trade is fictional.

## 1. Event envelope

One JSON object per line in `demo/out/events.jsonl`, and one line per event on
stdout while the harness runs.

| field     | type             | meaning                                                        |
|-----------|------------------|----------------------------------------------------------------|
| `ts`      | string           | observation time, ISO-8601 UTC, milliseconds, e.g. `...Z`      |
| `seq`     | integer          | monotonic across the whole stream (1-based); the stable order  |
| `segment` | string           | segment id, e.g. `s1_p2p_transport`                            |
| `node`    | string \| null   | `"A"`, `"B"`, or `"harness"`; `null` for pure lifecycle events |
| `kind`    | string           | event kind (see §2)                                            |
| `fields`  | object           | payload; for node events this is the raw node event *minus* `event` |

New keys may be added to `fields` without a version bump. Adding/removing a
top-level envelope field or changing a `kind` is a **v2** change.

Ordering note: node A and node B emit independently. Stream order is the order
the harness *observed* events (by `seq`), which is a total order but not a
causal one across nodes. Use `seq`, never timestamps, to reconstruct order.

## 2. Event kinds

**Passthrough node kinds** (verbatim from the node transport, see
`crates/runtime/src/node/network.rs`), e.g.:

- `node_started` — flags + `peer_id`; `transport_only:true`; all readiness flags
  (`trading_ready`, `settlement`-relevant flags, etc.) are `false`.
- `listening` — `address` includes `/p2p/<PeerId>` (source of truth for the
  listener's PeerId).
- `peer_connected` / `peer_identified` / `peer_ping` — the connect handshake.
- `peer_disconnected`, `peer_retry_scheduled` — outage + reconnect scheduling.
- `node_stopped` — `reason` is `duration_elapsed` or `ctrl_c`.
- (`peer_ping_failed`, `peer_identify_failed`, `peer_rejected`, `dial_failed`,
  `peer_discovered`, `peer_query_*`, `peer_disconnect*` may appear.)

**Harness-authored kinds** (synthetic):

- `segment_state` — a lifecycle transition; `fields = {from, to, ...}`.
- `harness_note` — orchestration annotation, not a protocol fact.
- `artifact_line` — one captured line of real local evidence from a segment's
  subprocess; `fields = {source, text}` (+ `replay: true` when replayed).
- `_unparsed` — a node line failed JSON parse; `fields.raw` holds the text.

## 3. Segment state machine

Each segment instance walks this machine; `segment_state` events record edges:

```
idle ─▶ running ─▶ connected ─▶ disconnected ─▶ reconnected ─▶ done
           │           │              │              │
           └───────────┴──────────────┴──────────────┴──▶ failed
```

- `idle`—`running`: `idle → running` is emitted at segment start.
- `connected`: both peers have `peer_connected` + `peer_identified`
  (`protocol_matches:true`) + `peer_ping`.
- `disconnected`: the listener was killed and the dialer observed
  `peer_disconnected` + `peer_retry_scheduled`.
- `reconnected`: the dialer re-established `peer_connected` to the **same
  PeerId** after listener restart.
- `done` / `failed`: terminal. `failed` carries `fields.error`.
- Segments that do not model a live connection (S5/S2/S4/S3) walk
  `idle → running → done` (or `→ failed`); `connected`/`disconnected`/
  `reconnected` apply to S1's transport segment.

## 4. Segment catalog

| id                   | status      | summary                                                        |
|----------------------|-------------|----------------------------------------------------------------|
| `s1_p2p_transport`   | implemented | two nodes connect, listener restart w/ same identity, reconnect |
| `s5_native_zcash_prepare` | implemented | prebuilt `examples/prepare` real 4-line output            |
| `s2_snapshot_restore`| implemented | encrypted snapshot save → fresh-process restore                |
| `s4_execute_owner`   | implemented | `execute-owner` CLI suite (sp1-local) on CPU                   |
| `s3_pg_gate`         | implemented | real PostgreSQL release-journal fence test                     |

**Replay mode.** Any segment may run in `replay` mode when its environment is
unavailable (e.g. PostgreSQL/Docker down): it emits a labeled `harness_note`
`{mode:"replay"}` plus `artifact_line` events (`replay:true`) from a previously
captured real run, and `state.json` records `replay:true` /
`mode:"replay"` for that segment. Replay is never presented as a live run.

Segments plug in by registering a `segment_*` function in `SEGMENTS` and
emitting the same envelope via `harness.emit(...)`.

## 5. Artifacts

- `demo/out/events.jsonl` — the append-only envelope stream (one JSON per line).
- `demo/out/state.json` — includes `segments.<id>.duration_seconds` and
  `segments.<id>.events` (count for that segment) plus segment outcome fields.
- Per-segment captured evidence: `s5_prepare.txt` (S5 stdout),
  `s3_recorded.txt` (S3 test output, secrets scrubbed),
  `s4_recorded.txt` (S4 suite output), `s2_snapshot.txt` (S2 output) and
  `s2_snapshot.bin` (the encrypted snapshot; its key is never copied here).

```json
{
  "schema_version": 1,
  "started_at": "...Z", "ended_at": "...Z",
  "exit_code": 0,
  "event_count": 28,
  "settlement": "IN_DEVELOPMENT",
  "segments": { "s1_p2p_transport": { "state": "done", "peer_id_b": "...",
                 "peer_id_equal": true, "reconnected": true },
                "s3_pg_gate": { "state": "done", "test": "enabled::committed_export_...",
                 "duration_seconds": 14.1, "events": 6 } }
}
```

`segments.<id>.state` mirrors the §3 machine. Segment outcome fields
(`peer_id_b`, `peer_id_equal`, `reconnected`, `duration_seconds`, `events`, ...)
live alongside under `segments.<id>`.

## 6. How to run / replay

```bash
python3 demo/run_demo.py                    # all segments, order S1→S5→S2→S4→S3
python3 demo/run_demo.py --quick            # S1 + S5 only
python3 demo/run_demo.py --only s1_p2p_transport,s5_native_zcash_prepare
python3 demo/run_demo.py --replay --replay-speed 1   # replay fixture (no binaries)
python3 demo/run_demo.py --out /tmp/demo-out --quiet
```

- Exit codes: `0` all segments `done`; `1` a segment `failed` (a
  `environment_unavailable` failure is labeled in `state.json`); `2` usage error.
- Each segment prints a `duration_seconds` in `state.json` and the stderr summary.
- Replay a captured fixture: iterate `demo/out/events.jsonl` and drive the UI
  from each envelope keyed by `seq`/`kind`. A recorded `demo/out/` directory is
  a complete offline fixture — no node or network required to replay.

## 7. Four-screen mapping

| Screen   | Source                                                             |
|----------|--------------------------------------------------------------------|
| Offers   | `peer_*`/`listening` events → peers known to the segment            |
| Review   | static v1 terms (no dynamic terms source yet)                      |
| Status   | the `events.jsonl` stream + `segment_state` transitions            |
| Recovery | `s2_snapshot_restore` events (snapshot save/restore is the S2 building block; product recovery remains `IN_DEVELOPMENT`) |

No v1 screen shows settlement state; that stays `IN_DEVELOPMENT`.

## 8. Bridge — `demo/serve.py` (v1.1, core-owned, OPTIONAL)

`demo/contract.md` and `demo/out/*` are the canonical interface. This bridge is a
convenience so a browser UI can consume them live without reading files itself;
if the UI team prefers, they can serve `demo/out/` from their own backend and
ignore this entirely.

```bash
python3 demo/serve.py                 # http://127.0.0.1:8787
python3 demo/serve.py --port 9000
```

Binds loopback only. No auth (local, no-funds demo) — do not expose beyond
127.0.0.1. Python3 stdlib only; logs to stderr only.

| Method | Path      | Response                                                                 |
|--------|-----------|--------------------------------------------------------------------------|
| GET    | `/state`  | `demo/out/state.json` verbatim (`application/json`); empty state if absent |
| GET    | `/events` | `text/event-stream` (SSE): replays `events.jsonl` from seq 1, then tails appended lines (`data: {json}\n\n`, ~200 ms poll, `: keep-alive`). `?from=<seq>` starts at that seq. Multiple concurrent clients supported. |
| GET    | `/health` | `{"ok":true,"events_count":N,"last_seq":S}`                               |
| OPTIONS| any       | CORS preflight (`Access-Control-Allow-Origin: *`, `Allow-Methods: GET, OPTIONS`) |

The SSE endpoint survives a harness rewrite (detects truncation and re-reads),
and the bridge creates `demo/out/` + an empty `events.jsonl` if missing rather
than crashing. CORS `*` lets the UI run on another localhost port.

Making a new contract version (v2) is a core decision; do not fork the schema
per bridge.

## 9. Replay mode — `--replay` (v1.3)

`demo/fixtures/canonical_events.jsonl` + `canonical_state.json` are a snapshot of
a previously captured **real** run. Refresh them after any real session:

```bash
cp demo/out/events.jsonl demo/fixtures/canonical_events.jsonl
cp demo/out/state.json   demo/fixtures/canonical_state.json
```

```bash
python3 demo/run_demo.py --replay --replay-speed 1   # ≤90 s, needs no binaries
python3 demo/run_demo.py --replay --replay-speed 4   # ~4x
python3 demo/run_demo.py --replay --replay-speed 0   # instant (no sleeps)
```

- Streams the canonical envelopes to stdout and rewrites `demo/out/events.jsonl`
  + `state.json`, so the SSE bridge shows an identical session.
- Every replayed event gets `"replay": true` **inside `fields`** (a `fields`
  addition, permitted); a leading `harness_note` states
  "replaying a previously captured real run; no live processes"; `state.json`
  gets `"mode":"replay"`, `"speed"`, `"source"`, plus a synthetic `replay`
  segment. A leading note shifts `seq` by one relative to the fixture; all other
  content is preserved.
- Inter-event delays are scaled by `1/speed` and clamped so a full 1× replay
  stays ≤ ~90 s. Exit `0`; works with zero binaries present.
- Because a leading note shifts `seq`, replay is for **presentation**; treat
  `demo/fixtures/canonical_events.jsonl` as the canonical artifact.