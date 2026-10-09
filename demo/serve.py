#!/usr/bin/env python3
"""Loopback HTTP/SSE bridge over demo/out for the frontend UI (core-owned, OPTIONAL).

GET /state  -> demo/out/state.json verbatim
GET /events -> text/event-stream: replays events.jsonl then tails appends
               (?from=<seq>, default 1); keep-alives; concurrent clients
GET /health -> {"ok":true,"events_count":N,"last_seq":S}
OPTIONS *   -> CORS preflight

Wide-open CORS, no auth: loopback-only, no-funds demo; do not expose beyond
127.0.0.1. Robust to a missing demo/out. Python3 stdlib only; logs to stderr.
"""
import argparse, json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
EVENTS, STATE = os.path.join(OUT, "events.jsonl"), os.path.join(OUT, "state.json")
POLL, KEEPALIVE = 0.2, 15.0
EMPTY_STATE = {"schema_version": 1, "segments": {}, "settlement": "IN_DEVELOPMENT", "event_count": 0}


def stat():
    """(event_count, last_seq); (0, 0) if events.jsonl is absent."""
    n = last = 0
    try:
        for line in open(EVENTS, encoding="utf-8", errors="replace"):
            line = line.strip()
            if line:
                n += 1
                try: last = json.loads(line).get("seq", last)
                except ValueError: pass
    except OSError:
        pass
    return n, last


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
    def _json(self, code, body):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/health":
            n, last = stat()
            return self._json(200, {"ok": True, "events_count": n, "last_seq": last})
        if url.path == "/state":
            try:
                with open(STATE, "rb") as f: return self._json(200, f.read())
            except OSError:
                return self._json(200, EMPTY_STATE)
        if url.path == "/events":
            try: start = int(parse_qs(url.query).get("from", ["1"])[0])
            except ValueError: start = 1
            return self._sse(start)
        return self._json(404, {"ok": False, "error": "not found"})
    def _sse(self, start):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self._cors()
        self.end_headers()
        offset, beat = 0, time.monotonic()
        try:
            while True:
                try: size = os.path.getsize(EVENTS)
                except OSError: size = 0
                if size < offset:
                    offset = 0  # truncated/rotated by a new harness run
                if size > offset:
                    with open(EVENTS, encoding="utf-8", errors="replace") as f:
                        f.seek(offset)
                        for line in f:
                            line = line.strip()
                            if not line: continue
                            try: seq = json.loads(line).get("seq", 0)
                            except ValueError: seq = 0
                            if seq >= start:
                                self.wfile.write(b"data: " + line.encode() + b"\n\n")
                        offset = f.tell()
                    self.wfile.flush()
                    beat = time.monotonic()
                elif time.monotonic() - beat > KEEPALIVE:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    beat = time.monotonic()
                time.sleep(POLL)
        except (BrokenPipeError, ConnectionResetError):
            return


def main():
    ap = argparse.ArgumentParser(description="Loopback SSE bridge over demo artifacts")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if not os.path.exists(EVENTS): open(EVENTS, "a").close()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    sys.stderr.write("demo bridge on http://%s:%d (out=%s)\n" % (args.host, args.port, OUT))
    try: server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt: pass
    finally:
        server.shutdown(); server.server_close()


if __name__ == "__main__":
    main()