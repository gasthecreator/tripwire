#!/usr/bin/env python3
"""Local JSON-RPC proxy that retries rate-limited requests and caps concurrency.

Why: the false-positive study issues tens of thousands of calls against a
metered archive endpoint. A 429 must never surface as a missing baseline
(which would silently score as "no harm fact"), so every component -- the
adapter, the context source and `cast` -- is pointed at this proxy instead.

    UPSTREAM=https://eth-mainnet.g.alchemy.com/v2/<key> python3 scripts/rpc_retry_proxy.py
    ETH_RPC_URL=http://127.0.0.1:8899 cargo run --release -p replay-harness --example fp_study
"""
import os, sys, time, threading, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ["UPSTREAM"]
PORT = int(os.environ.get("PORT", "8899"))
MAX_INFLIGHT = int(os.environ.get("MAX_INFLIGHT", "3"))
MAX_WAIT = float(os.environ.get("MAX_WAIT_SECS", "120"))
sem = threading.BoundedSemaphore(MAX_INFLIGHT)
stats = {"requests": 0, "retries": 0, "gave_up": 0}


def forward(body: bytes):
    delay, deadline = 0.3, time.time() + MAX_WAIT
    while True:
        with sem:
            try:
                req = urllib.request.Request(
                    UPSTREAM, data=body, headers={"content-type": "application/json"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = r.read()
                # Alchemy can also report throttling inside a 200 body.
                if b'"code":429' not in data[:400]:
                    return 200, data
            except urllib.error.HTTPError as e:
                if e.code not in (429, 500, 502, 503, 504):
                    return e.code, e.read()
            except Exception:
                pass
        if time.time() > deadline:
            stats["gave_up"] += 1
            return 502, b'{"error":"proxy gave up after retries"}'
        stats["retries"] += 1
        time.sleep(delay)
        delay = min(delay * 2, 8)


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        stats["requests"] += 1
        code, data = forward(body)
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=lambda: [time.sleep(30) or print(stats, file=sys.stderr, flush=True) for _ in iter(int, 1)], daemon=True).start()
    srv.serve_forever()
