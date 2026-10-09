#!/usr/bin/env python3
"""VC-demo sprint harness (Day 1 + Day 2).

Runs real local evidence over loopback / local cargo, wraps every NDJSON event
into a stable envelope (see demo/contract.md), and writes demo/out/events.jsonl
+ demo/out/state.json. Segments:

  s1_p2p_transport        two nodes connect, restart, reconnect (loopback)
  s5_native_zcash_prepare run prebuilt examples/prepare, capture its 4 lines
  s2_snapshot_restore     encrypted snapshot save -> fresh-process restore
  s4_execute_owner        execute-owner CLI suite evidence (sp1-local)
  s3_pg_gate              real PostgreSQL release-journal fence test

A segment may be in "replay" mode showing a captured real run (labeled), e.g.
when its environment (PostgreSQL/Docker) is unavailable.

Constraints: Python3 stdlib only, loopback/local only, no funds, no commits.
Exit codes: 0 all segments done, 1 a segment failed, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BIN = REPO_ROOT / "target" / "debug" / "z2z-node"
DEFAULT_OUT = Path(__file__).resolve().parent / "out"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
PREPARE_BIN = REPO_ROOT / "target" / "debug" / "examples" / "prepare"
PG_CREDS = Path(os.environ.get("Z2Z_PG_CREDS", "/home/harry-riddle/.ziquid-pg-test-5_tomcna/credentials.json"))

SCHEMA_VERSION = 1
SEGMENT_ORDER = [
    "s1_p2p_transport",
    "s5_native_zcash_prepare",
    "s2_snapshot_restore",
    "s4_execute_owner",
    "s3_pg_gate",
]
QUICK_SEGMENTS = ["s1_p2p_transport", "s5_native_zcash_prepare"]

STATES = ("idle", "running", "connected", "disconnected", "reconnected", "done", "failed")
TRANSITIONS = {
    "idle": {"running"},
    "running": {"connected", "done", "failed"},
    "connected": {"disconnected", "done", "failed"},
    "disconnected": {"reconnected", "failed"},
    "reconnected": {"done", "failed"},
    "done": set(),
    "failed": set(),
}

TEST_LINE = re.compile(r"^running \d+ test|^test .+ \.\.\. |^test result:|^error|FAILED|panicked at")


def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def scrub(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def relpath(path: Path) -> str:
    """Path relative to the repo when possible, else absolute (e.g. --out /tmp)."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def replay_mode(out_dir: Path, speed: float, quiet: bool) -> int:
    """Stream a previously captured real run (no binaries needed). Exit 0."""
    canon = FIXTURES / "canonical_events.jsonl"
    cstate = FIXTURES / "canonical_state.json"
    source = canon if canon.exists() else out_dir / "events.jsonl"
    if not source.exists():
        print(f"error: no canonical events at {canon} or {source}", file=sys.stderr)
        return 2
    recs = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    harness = Harness(out_dir, quiet=quiet)
    harness.emit("replay", "harness_note",
                 {"text": "replaying a previously captured real run; no live processes",
                  "mode": "replay", "speed": speed, "source": relpath(source)}, node="harness")
    times = [datetime.fromisoformat(r["ts"].replace("Z", "+00:00")) for r in recs if "ts" in r]
    span = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0.0
    scale = 0.0 if speed == 0 else 1.0 / speed
    if scale and span > 0 and span * scale > 90.0:
        scale = 90.0 / span  # keep the full replay under ~90s
    previous = times[0] if times else None
    for i, rec in enumerate(recs):
        if scale and previous is not None and i < len(times):
            delta = (times[i] - previous).total_seconds()
            previous = times[i]
            if delta > 0:
                time.sleep(delta * scale)
        fields = dict(rec.get("fields", {}))
        fields["replay"] = True
        harness.emit(rec.get("segment", "replay"), rec.get("kind", "_unknown"), fields, node=rec.get("node"))
    segments: dict[str, Any] = {}
    if cstate.exists():
        segments = json.loads(cstate.read_text(encoding="utf-8")).get("segments", {})
    segments["replay"] = {"state": "done", "speed": speed, "events": len(recs)}
    harness.out_dir.mkdir(parents=True, exist_ok=True)
    with (harness.out_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for rec in harness.records:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    state = {"schema_version": SCHEMA_VERSION, "started_at": now_ts(), "ended_at": now_ts(),
             "exit_code": 0, "event_count": len(harness.records), "settlement": "IN_DEVELOPMENT",
             "mode": "replay", "speed": speed, "source": relpath(source), "segments": segments}
    (harness.out_dir / "state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print(f"replayed {len(recs)} events -> {harness.out_dir / 'events.jsonl'} (speed {speed})", file=sys.stderr)
    return 0


class Harness:
    """Owns the unified envelope stream and the segment state machines."""

    def __init__(self, out_dir: Path, quiet: bool = False) -> None:
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.quiet = quiet
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._seq = 0
        self._states: dict[str, str] = {}
        self.segment_starts: dict[str, str] = {}

    def emit(self, segment: str, kind: str, fields: dict[str, Any], node: Optional[str] = None) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            rec = {"ts": now_ts(), "seq": self._seq, "segment": segment, "node": node,
                   "kind": kind, "fields": fields}
            self.records.append(rec)
        if not self.quiet:
            label = f"[{segment}]" + (f" {node}" if node else "")
            line = f"{rec['ts']} {label} {kind} {json.dumps(fields, separators=(',', ':'))}\n"
            with self._print_lock:
                sys.stdout.write(line)
                sys.stdout.flush()
        return rec

    def segment_start(self, segment: str, **fields: Any) -> None:
        if segment in self._states:
            raise RuntimeError(f"segment {segment} already started")
        self._states[segment] = "idle"
        self.segment_starts[segment] = now_ts()
        self._state(segment, "running", **fields)

    def _state(self, segment: str, to: str, **fields: Any) -> None:
        cur = self._states.get(segment, "idle")
        if to not in TRANSITIONS[cur]:
            raise RuntimeError(f"illegal state transition {cur!r} -> {to!r} for {segment}")
        self._states[segment] = to
        self.emit(segment, "segment_state", {"from": cur, "to": to, **fields})

    def segment_to(self, segment: str, to: str, **fields: Any) -> None:
        self._state(segment, to, **fields)

    def write_artifacts(self, exit_code: int, started_at: str, extra_state: dict[str, Any]) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        with (self.out_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
            for rec in self.records:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        segments = {s: {"state": st} for s, st in self._states.items()}
        for s, info in extra_state.get("segments", {}).items():
            segments.setdefault(s, {}).update(info)
        state = {"schema_version": SCHEMA_VERSION, "started_at": started_at, "ended_at": now_ts(),
                 "exit_code": exit_code, "event_count": len(self.records), "segments": segments,
                 "settlement": "IN_DEVELOPMENT"}
        state.update({k: v for k, v in extra_state.items() if k != "segments"})
        (self.out_dir / "state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


class NodeProcess:
    """A z2z-node child whose events feed the Harness as they are read."""

    def __init__(self, label: str, argv: list[str], harness: Harness, segment: str) -> None:
        self.label = label
        self.segment = segment
        self.harness = harness
        self.events: list[dict[str, Any]] = []
        self.stderr_lines: list[str] = []
        self._cond = threading.Condition()
        self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, bufsize=1, start_new_session=True)
        self._threads = [
            threading.Thread(target=self._read, args=(self.proc.stdout, "stdout"), daemon=True),
            threading.Thread(target=self._read, args=(self.proc.stderr, "stderr"), daemon=True),
        ]
        for t in self._threads:
            t.start()

    def _read(self, stream, which: str) -> None:
        for line in stream:
            line = line.rstrip("\n")
            if which == "stderr":
                if line:
                    self.stderr_lines.append(line)
                continue
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                raw = {"event": "_unparsed", "raw": line}
            kind = raw.pop("event", "_unknown")
            with self._cond:
                self.events.append({"kind": kind, "fields": raw})
                self._cond.notify_all()
            self.harness.emit(self.segment, kind, raw, node=self.label)

    def mark(self) -> int:
        with self._cond:
            return len(self.events)

    def wait_for(self, kind: str, timeout: float, predicate: Optional[Callable[[dict[str, Any]], bool]] = None,
                 after: int = 0) -> Optional[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for ev in self.events[after:]:
                    if ev["kind"] == kind and (predicate is None or predicate(ev["fields"])):
                        return ev["fields"]
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def stop(self, sig: int = signal.SIGINT, timeout: float = 5.0) -> Optional[int]:
        if self.proc.poll() is not None:
            return self.proc.returncode
        try:
            os.killpg(os.getpgid(self.proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            return self.proc.wait(timeout=timeout)

    def kill(self) -> None:
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        self.proc.wait(timeout=5.0)


def peer_id_from_listening(address: str) -> str:
    marker = "/p2p/"
    idx = address.rfind(marker)
    if idx < 0:
        raise RuntimeError(f"listening address has no /p2p/<PeerId>: {address!r}")
    return address[idx + len(marker):]


def build_node_argv(binary: Path, *, listen: Optional[str], dial: Optional[str], reconnect: bool,
                    identity_file: Optional[Path], run_for_ms: int, max_peers: int) -> list[str]:
    argv = [str(binary), "run"]
    if listen:
        argv += ["--listen", listen]
    if dial:
        argv += ["--dial", dial]
    if reconnect:
        argv += ["--reconnect"]
    if identity_file:
        argv += ["--peer-identity-file", str(identity_file)]
    argv += ["--max-peers", str(max_peers), "--run-for-ms", str(run_for_ms)]
    return argv


def run_and_stream(harness: Harness, segment: str, label: str, argv: list[str], *,
                   env: Optional[dict[str, str]] = None, cwd: Optional[Path] = None,
                   timeout: Optional[float] = None, pattern: Optional[re.Pattern] = None,
                   emit_all: bool = False, out_file: Optional[Path] = None,
                   secrets: Optional[list[str]] = None) -> tuple[Optional[int], list[str]]:
    """Run a real local subprocess, emit matched lines as artifact_line, return (rc, lines)."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            bufsize=1, env=env, cwd=cwd, start_new_session=True)
    lines: list[str] = []
    started = time.monotonic()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            if emit_all or (pattern and pattern.search(line)):
                harness.emit(segment, "artifact_line", {"source": label, "text": line}, node="harness")
            if timeout and time.monotonic() - started > timeout:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                raise TimeoutError(f"{label} exceeded {timeout}s")
        rc: Optional[int] = proc.wait()
    except BaseException:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
        raise
    if out_file is not None:
        out_file.write_text(scrub("\n".join(lines) + "\n", secrets or []), encoding="utf-8")
    return rc, lines


def cargo_test_evidence(harness: Harness, segment: str, label: str, *, test: str, features: str,
                        env: Optional[dict[str, str]] = None, exact: Optional[str] = None,
                        out_file: Optional[Path] = None, timeout: float = 1800,
                        secrets: Optional[list[str]] = None) -> tuple[Optional[int], str]:
    argv = ["cargo", "test", "--locked", "--offline", "-p", "ziquid-runtime"]
    if features:
        argv += ["--features", features]
    argv += ["--test", test]
    tail = ["--", "--test-threads=1", "--nocapture"]
    if exact:
        tail += ["--exact", exact]
    rc, lines = run_and_stream(harness, segment, label, argv + tail, env=env, cwd=REPO_ROOT,
                               timeout=timeout, pattern=TEST_LINE, out_file=out_file, secrets=secrets)
    return rc, "\n".join(lines)


# --------------------------------------------------------------------------- segments

def segment_s1_p2p_transport(harness: Harness, ctx: dict[str, Any]) -> dict[str, Any]:
    segment = "s1_p2p_transport"
    binary: Path = ctx["binary"]
    identity_dir: Path = ctx["identity_dir"]
    harness.segment_start(segment, description="loopback P2P connect / restart / reconnect")
    identity_file = identity_dir / "transport.key"
    port = free_port()
    listen = f"/ip4/127.0.0.1/tcp/{port}"
    run_for_ms = 60000
    result: dict[str, Any] = {"peer_id_equal": False, "reconnected": False}
    b = b2 = a = None
    try:
        b = NodeProcess("B", build_node_argv(binary, listen=listen, dial=None, reconnect=False,
                                             identity_file=identity_file, run_for_ms=run_for_ms, max_peers=4),
                        harness, segment)
        started = b.wait_for("node_started", 10)
        listening = b.wait_for("listening", 10)
        if not started or not listening:
            raise RuntimeError("node B did not reach listening")
        peer_b = peer_id_from_listening(listening["address"])
        result.update(peer_id_b=peer_b, listen_port=port, identity_file_created=identity_file.exists())
        harness.emit(segment, "harness_note", {"text": "B listening; driving A dial", "peer_id_b": peer_b}, node="harness")

        dial = f"{listen}/p2p/{peer_b}"
        a = NodeProcess("A", build_node_argv(binary, listen="/ip4/127.0.0.1/tcp/0", dial=dial, reconnect=True,
                                             identity_file=None, run_for_ms=run_for_ms, max_peers=4), harness, segment)
        a_started = a.wait_for("node_started", 10)
        if not a_started:
            raise RuntimeError("node A did not start")
        result["peer_id_a"] = a_started["peer_id"]
        for node, peer, label in ((b, result["peer_id_a"], "B"), (a, peer_b, "A")):
            if not node.wait_for("peer_connected", 15, lambda f, p=peer: f.get("peer_id") == p):
                raise RuntimeError(f"{label} never connected to {peer}")
            if not node.wait_for("peer_identified", 10, lambda f, p=peer: f.get("peer_id") == p and f.get("protocol_matches") is True):
                raise RuntimeError(f"{label} never identified {peer}")
            if not node.wait_for("peer_ping", 15, lambda f, p=peer: f.get("peer_id") == p):
                raise RuntimeError(f"{label} never pinged {peer}")
        harness.segment_to(segment, "connected", peer_id_b=peer_b, peer_id_a=result["peer_id_a"])

        a_mark = a.mark()
        b.kill()
        if not a.wait_for("peer_disconnected", 15, lambda f: f.get("peer_id") == peer_b, after=a_mark):
            raise RuntimeError("A did not observe peer_disconnected after B was killed")
        retry = a.wait_for("peer_retry_scheduled", 10, lambda f: f.get("peer_id") == peer_b, after=a_mark)
        if not retry:
            raise RuntimeError("A did not schedule a reconnect retry")
        result.update(retry_attempt=retry.get("attempt"), retry_delay_ms=retry.get("delay_ms"))
        harness.segment_to(segment, "disconnected", reason="listener_killed")

        b2 = NodeProcess("B", build_node_argv(binary, listen=listen, dial=None, reconnect=False,
                                              identity_file=identity_file, run_for_ms=run_for_ms, max_peers=4),
                         harness, segment)
        b2_started = b2.wait_for("node_started", 10)
        b2_listening = b2.wait_for("listening", 10)
        if not b2_started or not b2_listening:
            raise RuntimeError("restarted node B did not reach listening")
        peer_b2 = peer_id_from_listening(b2_listening["address"])
        result.update(peer_id_b_restarted=peer_b2, peer_id_equal=peer_b2 == peer_b)
        if not result["peer_id_equal"]:
            raise RuntimeError(f"restarted B identity changed: {peer_b} != {peer_b2}")

        if not a.wait_for("peer_connected", 20, lambda f: f.get("peer_id") == peer_b, after=a_mark):
            raise RuntimeError("A did not reconnect to the restarted B")
        if not a.wait_for("peer_identified", 10, lambda f: f.get("peer_id") == peer_b and f.get("protocol_matches") is True, after=a_mark):
            raise RuntimeError("A did not re-identify the restarted B")
        if not a.wait_for("peer_ping", 15, lambda f: f.get("peer_id") == peer_b, after=a_mark):
            raise RuntimeError("A did not re-ping the restarted B")
        result["reconnected"] = True
        harness.segment_to(segment, "reconnected", peer_id=peer_b)
        harness.segment_to(segment, "done")
        return result
    finally:
        if a is not None:
            code = a.stop(signal.SIGINT)
            harness.emit(segment, "harness_note", {"text": "A shut down", "exit_code": code}, node="harness")
        if b2 is not None:
            b2.stop(signal.SIGINT)
        if b is not None and b.proc.poll() is None:
            b.kill()


def segment_s5_native_zcash_prepare(harness: Harness, ctx: dict[str, Any]) -> dict[str, Any]:
    segment = "s5_native_zcash_prepare"
    harness.segment_start(segment, description="prebuilt zcash prepare example, real stdout")
    binary = PREPARE_BIN
    if not binary.exists():
        harness.segment_to(segment, "failed", reason="binary_absent", path=str(binary))
        raise RuntimeError(f"prepare example missing: {binary}")
    out_file = harness.out_dir / "s5_prepare.txt"
    rc, lines = run_and_stream(harness, segment, "prepare", [str(binary)], emit_all=True,
                               timeout=600, out_file=out_file)
    if rc != 0:
        harness.segment_to(segment, "failed", reason="nonzero_exit", exit_code=rc)
        raise RuntimeError(f"prepare exited {rc}")
    harness.segment_to(segment, "done", lines=len(lines))
    return {"state": "done", "exit_code": rc, "lines": len(lines),
            "artifact": relpath(out_file)}


def segment_s2_snapshot_restore(harness: Harness, ctx: dict[str, Any]) -> dict[str, Any]:
    segment = "s2_snapshot_restore"
    harness.segment_start(segment, description="encrypted snapshot save -> fresh-process restore")
    work = Path(tempfile.mkdtemp(prefix="z2z-s2-", dir="/tmp"))
    os.chmod(work, 0o700)
    try:
        base = ["cargo", "run", "--locked", "--offline", "-p", "ziquid-runtime",
                "--example", "snapshot_demo", "--"]
        try:
            rc, lines = run_and_stream(harness, segment, "snapshot_demo save",
                                       base + ["save", str(work)], cwd=REPO_ROOT, timeout=1200,
                                       pattern=re.compile(r"^SNAPSHOT |^KEY_FINGERPRINT |^SELECTION |^SAVE_OK$|^error"),
                                       out_file=harness.out_dir / "s2_snapshot.txt")
            if rc != 0:
                raise RuntimeError(f"save exited {rc}")
            snapshot = re.search(r"^SNAPSHOT (\S+)$", "\n".join(lines), re.M)
            selection = re.search(r"^SELECTION (\S+)$", "\n".join(lines), re.M)
            if not snapshot or not selection:
                raise RuntimeError("save did not print snapshot/selection paths")
            snapshot_path, selection_path = snapshot.group(1), selection.group(1)
            artifact = harness.out_dir / "s2_snapshot.bin"
            shutil.copyfile(snapshot_path, artifact)
            rc, lines2 = run_and_stream(harness, segment, "snapshot_demo restore (fresh process)",
                                        base + ["restore", snapshot_path, selection_path], cwd=REPO_ROOT,
                                        timeout=600, pattern=re.compile(r"^RESTORE|^RESTORED_|^error"))
            if rc != 0 or "RESTORE_OK" not in "\n".join(lines2):
                raise RuntimeError(f"fresh-process restore failed (rc={rc})")
            harness.segment_to(segment, "done", mode="example", snapshot=artifact.name)
            return {"state": "done", "mode": "example", "fresh_process_restore": True,
                    "artifact": relpath(artifact)}
        except Exception as exc:  # noqa: BLE001 - fall back to live real test evidence
            harness.emit(segment, "harness_note", {"text": "example fallback -> test evidence",
                                                   "reason": f"{type(exc).__name__}: {exc}"}, node="harness")
            rc, text = cargo_test_evidence(harness, segment, "samechain_backup clean_process", 
                                           test="samechain_backup", features="", 
                                           exact="clean_process_snapshot_restore",
                                           out_file=harness.out_dir / "s2_snapshot.txt", timeout=1200)
            if rc == 0 and "test result: ok" in text:
                harness.segment_to(segment, "done", mode="test-evidence")
                return {"state": "done", "mode": "test-evidence",
                        "test": "samechain_backup::clean_process_snapshot_restore"}
            harness.segment_to(segment, "failed", reason="example_and_test_failed")
            raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def segment_s4_execute_owner(harness: Harness, ctx: dict[str, Any]) -> dict[str, Any]:
    segment = "s4_execute_owner"
    harness.segment_start(segment, description="execute-owner CLI path (sp1-local)")
    out_file = harness.out_dir / "s4_recorded.txt"
    rc, text = cargo_test_evidence(harness, segment, "samechain_owner_artifact_cli",
                                   test="samechain_owner_artifact_cli", features="sp1-local",
                                   out_file=out_file, timeout=1800)
    if rc == 0 and "test result: ok" in text:
        harness.segment_to(segment, "done")
        return {"state": "done", "exit_code": rc, "artifact": relpath(out_file)}
    harness.segment_to(segment, "failed", reason="suite_failed", exit_code=rc)
    raise RuntimeError(f"execute-owner suite failed (rc={rc})")


def pg_environment() -> Optional[tuple[dict[str, str], list[str], int, str]]:
    """Private creds -> (env, secrets, port, host). Never returns the URI in output."""
    try:
        creds = json.loads(PG_CREDS.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    uri = creds.get("database_url")
    if not uri:
        return None
    env = dict(os.environ, Z2Z_TEST_DATABASE_URL=uri,
               Z2Z_TEST_PG_SCHEMA_PREFIX="z2z_demo_20261006", Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES="yes")
    secrets = [s for s in (uri, creds.get("password"), creds.get("ca_cert")) if s]
    return env, secrets, int(creds.get("port", 5432)), str(creds.get("host", "127.0.0.1"))


def pg_reachable(host: str, port: int) -> bool:
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(("127.0.0.1" if host in ("localhost", "::1") else host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def replay_file(harness: Harness, segment: str, path: Path, note: str) -> bool:
    if not path.exists():
        return False
    harness.emit(segment, "harness_note", {"text": note, "mode": "replay", "source": path.name}, node="harness")
    for line in path.read_text(encoding="utf-8").splitlines():
        if TEST_LINE.search(line) or line.strip():
            harness.emit(segment, "artifact_line", {"source": path.name, "text": line, "replay": True}, node="harness")
    return True


def segment_s3_pg_gate(harness: Harness, ctx: dict[str, Any]) -> dict[str, Any]:
    segment = "s3_pg_gate"
    test = "enabled::committed_export_reads_key_only_after_real_journal_fence"
    harness.segment_start(segment, description="real PostgreSQL release-journal fence test")
    recorded = harness.out_dir / "s3_recorded.txt"
    env_info = pg_environment()
    available = env_info is not None and pg_reachable(env_info[3], env_info[2])
    if not available:
        harness.segment_to(segment, "failed", reason="environment_unavailable")
        replayed = replay_file(harness, segment, recorded, "PostgreSQL unavailable; replaying captured real run")
        return {"state": "failed", "reason": "environment_unavailable", "replay": replayed,
                "artifact": relpath(recorded)}
    env, secrets, _, _ = env_info
    rc, text = cargo_test_evidence(harness, segment, "samechain_release_cli", test="samechain_release_cli",
                                   features="sp1-local,postgres-tests", exact=test, env=env,
                                   out_file=recorded, timeout=1800, secrets=secrets)
    if rc == 0 and "test result: ok" in text:
        harness.segment_to(segment, "done", test=test)
        return {"state": "done", "test": test, "exit_code": rc, "artifact": relpath(recorded)}
    harness.segment_to(segment, "failed", reason="test_failed", exit_code=rc)
    raise RuntimeError(f"PG gate test failed (rc={rc})")


SEGMENTS: dict[str, Callable[[Harness, dict[str, Any]], dict[str, Any]]] = {
    "s1_p2p_transport": segment_s1_p2p_transport,
    "s5_native_zcash_prepare": segment_s5_native_zcash_prepare,
    "s2_snapshot_restore": segment_s2_snapshot_restore,
    "s4_execute_owner": segment_s4_execute_owner,
    "s3_pg_gate": segment_s3_pg_gate,
}


def self_test() -> int:
    """Binary-free check of the contract logic the frontend depends on."""
    assert peer_id_from_listening("/ip4/127.0.0.1/tcp/40197/p2p/12D3KooWabc") == "12D3KooWabc"
    for bad in ("/ip4/127.0.0.1/tcp/40197", ""):
        try:
            peer_id_from_listening(bad)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"accepted peerless address {bad!r}")
    assert set(TRANSITIONS) == set(STATES)
    assert TRANSITIONS["done"] == set() and TRANSITIONS["failed"] == set()
    assert set(SEGMENT_ORDER) == set(SEGMENTS) and len(SEGMENT_ORDER) == len(SEGMENTS)
    tmp = Path(tempfile.mkdtemp(prefix="z2z-selftest-"))
    h = Harness(tmp, quiet=True)
    h.segment_start("s5_native_zcash_prepare")
    h.segment_to("s5_native_zcash_prepare", "done")
    try:
        h.segment_to("s5_native_zcash_prepare", "connected")
    except RuntimeError:
        pass
    else:
        raise AssertionError("done -> connected must be rejected")
    assert h.records and all({"ts", "seq", "segment", "node", "kind", "fields"} <= set(r) for r in h.records)
    assert scrub("uri=postgres://x", ["postgres://x"]) == "uri=[REDACTED]"
    shutil.rmtree(tmp, ignore_errors=True)
    print("self-test ok", file=sys.stderr)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Z2Z VC-demo harness (loopback/local, no funds)")
    parser.add_argument("--only", default=None, help="comma-separated segment ids to run")
    parser.add_argument("--quick", action="store_true", help="run only s1_p2p_transport,s5_native_zcash_prepare")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="artifact output directory")
    parser.add_argument("--bin", default=os.environ.get("Z2Z_NODE_BIN", str(DEFAULT_BIN)), help="z2z-node binary path")
    parser.add_argument("--quiet", action="store_true", help="suppress the labeled stream on stdout")
    parser.add_argument("--self-test", action="store_true", help="run binary-free contract checks and exit")
    parser.add_argument("--replay", action="store_true", help="stream demo/fixtures/canonical_events.jsonl (no binaries)")
    parser.add_argument("--replay-speed", default="1", help="replay speed: 1, 4, or 0 (instant)")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.replay:
        try:
            speed = float(args.replay_speed)
        except ValueError:
            print(f"error: invalid --replay-speed {args.replay_speed!r}", file=sys.stderr)
            return 2
        return replay_mode(Path(args.out), speed, args.quiet)
    if args.quick:
        requested = list(QUICK_SEGMENTS)
    elif args.only:
        requested = [s.strip() for s in args.only.split(",") if s.strip()]
    else:
        requested = list(SEGMENT_ORDER)
    unknown = [s for s in requested if s not in SEGMENTS]
    if unknown:
        print(f"error: unknown segment(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    binary = Path(args.bin)
    if "s1_p2p_transport" in requested and not binary.exists():
        print(f"error: z2z-node binary not found: {binary}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    harness = Harness(out_dir, quiet=args.quiet)
    started_at = now_ts()
    extra_state: dict[str, Any] = {"segments": {}}
    identity_dir = Path(tempfile.mkdtemp(prefix="z2z-demo-identity-", dir="/tmp"))
    os.chmod(identity_dir, 0o700)
    ctx = {"binary": binary, "identity_dir": identity_dir, "out_dir": out_dir}
    exit_code = 0
    timings: list[tuple[str, float, str]] = []
    try:
        for segment in requested:
            begin = time.monotonic()
            outcome: dict[str, Any]
            try:
                outcome = SEGMENTS[segment](harness, ctx)
            except Exception as exc:  # noqa: BLE001 - harness boundary: report, do not crash
                exit_code = 1
                if harness._states.get(segment) not in ("done", "failed"):
                    harness.segment_to(segment, "failed", error=f"{type(exc).__name__}: {exc}")
                outcome = extra_state["segments"].get(segment) or {"state": "failed",
                                                                    "error": f"{type(exc).__name__}: {exc}"}
                print(f"segment {segment} FAILED: {exc}", file=sys.stderr, flush=True)
            outcome.setdefault("state", harness._states.get(segment, "failed"))
            outcome["duration_seconds"] = round(time.monotonic() - begin, 2)
            outcome["events"] = sum(1 for r in harness.records if r["segment"] == segment)
            extra_state["segments"][segment] = outcome
            timings.append((segment, outcome["duration_seconds"], outcome["state"]))
            if outcome["state"] != "done":
                exit_code = 1
    finally:
        shutil.rmtree(identity_dir, ignore_errors=True)
        harness.write_artifacts(exit_code, started_at, extra_state)

    print("\n=== segment summary ===", file=sys.stderr)
    for segment, secs, state in timings:
        print(f"  {segment:26s} {state:8s} {secs:7.2f}s", file=sys.stderr)
    print(f"wrote {out_dir / 'events.jsonl'} and {out_dir / 'state.json'}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())