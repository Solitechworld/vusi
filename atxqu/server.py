#!/usr/bin/env python3
"""
ATXQU — Address Transaction Query Utility
=========================================
A local web app that finds every SPENT transaction of a Bitcoin address
(transactions where the address appears in the inputs), normalizes each to a
fixed JSON schema, and saves it as <txid>.json.

Run:
    python3 server.py                 # opens http://127.0.0.1:8787
    python3 server.py --port 9000 --no-open
    python3 server.py --outdir ./results

Stdlib only — no pip installs. Works on Apple silicon and Intel/T2 Macs with
the system python3. GPU/Metal is intentionally not used: the workload is
network-bound (HTTP fetches), so concurrency — not the GPU — is what makes it
fast.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import engine

HERE = os.path.dirname(os.path.abspath(__file__))
DASHBOARD = os.path.join(HERE, "dashboard.html")
REPO = os.path.dirname(HERE)  # vusi repo root (atxqu/ lives inside it)


def find_vusi_bin():
    """Locate the `vusi` CLI: $VUSI_BIN, then the repo's release/debug build,
    then anything on PATH. Returns a path/name or None."""
    env = os.environ.get("VUSI_BIN")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    for rel in ("target/release/vusi", "target/debug/vusi"):
        cand = os.path.join(REPO, rel)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("vusi")


# Extra CLI flags accepted per attack, mapped from JSON body keys.
_ATTACK_FLAGS = {
    "delta": "--delta",
    "gcd_a_max": "--gcd-a-max",
    "gcd_b_max": "--gcd-b-max",
    "bitflip_bits": "--bitflip-bits",
    "bias_max_bits": "--bias-max-bits",
    "known_bits": "--known-bits",
    "degree": "--degree",
}

# Known public data endpoints (Blockbook-style). The Atomic Wallet one is what
# the user's original script used. Users can point at any Blockbook or Haskoin
# instance from the UI.
DEFAULT_ENDPOINTS = {
    "blockbook": "https://bitcoin.atomicwallet.io/api/v2",
    "haskoin": "https://api.haskoin.com/btc",
}

JOBS: dict = {}
JOBS_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
#  Job model                                                                    #
# --------------------------------------------------------------------------- #
class Job:
    def __init__(self, addresses, provider_kind, base_url, mode, workers,
                 outdir, concurrency=1, resume=True):
        self.id = uuid.uuid4().hex[:12]
        self.all_addresses = list(addresses)      # full requested list
        self.addresses = list(addresses)          # what actually gets scanned
        self.address = self.all_addresses[0]      # first (for display)
        self.address_set = set(self.all_addresses)
        self.provider_kind = provider_kind
        self.base_url = base_url
        self.mode = mode
        self.workers = workers
        self.concurrency = concurrency            # addresses scanned at once
        self.resume = resume
        self.root_outdir = outdir
        self.outdir = outdir
        self.sig = hashlib.sha1("\n".join(self.all_addresses).encode()).hexdigest()[:10]
        if len(self.all_addresses) == 1:
            fname = f"{self.address}_sent_transactions.json"
        else:
            fname = f"batch_{self.sig}_{len(self.all_addresses)}_addresses_sent_transactions.json"
        self.combined_path = os.path.join(outdir, fname)
        self.done_path = self.combined_path + ".done"   # completed addresses, 1/line
        self.txs = []              # full target-schema dicts (the combined result)
        self._last_write = 0.0     # throttle combined-file rewrites for big jobs
        self._done_fh = None       # append handle for completed-address log
        self.addr_done = 0         # addresses fully scanned so far
        self.skipped = 0           # addresses skipped via resume
        self.seen = set()          # txids already saved (dedupe across addresses)
        self.scanned_total = 0     # txs inspected across all addresses
        self.senders_total = 0     # sender matches (may include cross-address dupes)
        self.events = queue.Queue()
        self.results = []          # list of {txid, address, height, time, fee, sent}
        self.status = "pending"
        self.error = None
        self._stop = False
        self._paused = False
        self._resume_event = threading.Event()
        self._resume_event.set()   # set = running, clear = paused

    def stop(self):
        self._stop = True
        self._resume_event.set()   # unblock a paused job so it can exit

    def pause(self):
        if not self._paused and self.status == "running":
            self._paused = True
            self._resume_event.clear()
            self.push({"type": "paused", "addr_done": self.addr_done,
                       "saved": len(self.results)})

    def resume_run(self):
        if self._paused:
            self._paused = False
            self._resume_event.set()
            self.push({"type": "resumed", "addr_done": self.addr_done,
                       "saved": len(self.results)})

    def wait_if_paused(self):
        self._resume_event.wait()

    def push(self, evt):
        self.events.put(evt)


def _write_combined(job: Job):
    """Write ALL spent transactions to a single JSON array file (atomic)."""
    tmp = job.combined_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(job.txs, f, indent=2)
    os.replace(tmp, job.combined_path)
    job._last_write = time.time()


def _maybe_write_combined(job: Job, force: bool = False):
    """
    Rewriting the whole JSON array on every save is O(n^2) for large result
    sets. Throttle to at most ~every 2s (or every 100 new txs); always force a
    final flush so the file is complete when the scan ends.
    """
    if force or len(job.txs) % 100 == 0 or (time.time() - job._last_write) >= 2.0:
        _write_combined(job)


def _resume_load(job: Job):
    """
    Cross-run resume: if a prior run's files exist, load the already-saved
    transactions and the set of completed addresses, and skip those addresses.
    Returns True if resuming (done-file should be opened in append mode).
    """
    if not (job.resume and os.path.isfile(job.done_path)
            and os.path.isfile(job.combined_path)):
        return False
    try:
        with open(job.combined_path) as f:
            prior = json.load(f)
        if not isinstance(prior, list):
            return False
        job.txs = prior
        job.seen = {t.get("txId") for t in prior if t.get("txId")}
        job.senders_total = len(prior)
        with open(job.done_path) as f:
            completed = {ln.strip() for ln in f if ln.strip()}
    except Exception:               # noqa: BLE001 - corrupt files → start fresh
        job.txs, job.seen, job.senders_total = [], set(), 0
        return False
    before = len(job.addresses)
    job.addresses = [a for a in job.addresses if a not in completed]
    job.skipped = before - len(job.addresses)
    job.addr_done = job.skipped
    return True


def _mark_done(job: Job, addr: str):
    """Append a completed address to the done-file (caller holds the lock)."""
    if job._done_fh is not None:
        job._done_fh.write(addr + "\n")


def _handle_target(job, addr, target, lock):
    """Thread-safe: dedupe, append, throttle-write, record + emit one sender tx."""
    with lock:
        job.senders_total += 1
        txid = target["txId"]
        if txid in job.seen:                      # shared between your addresses
            job.push({"type": "dup", "txid": txid, "address": addr})
            return
        job.seen.add(txid)
        job.txs.append(target)
        _maybe_write_combined(job)                # one file, flushed periodically
        sent = sum(i["value"] for i in target["inputs"]
                   if i.get("address") in job.address_set)
        job.results.append({
            "txid": txid, "address": addr,
            "height": target.get("blockHeight"),
            "time": target.get("time"),
            "fee": target.get("fee"),
            "inputs": len(target["inputs"]),
            "outputs": len(target["outputs"]),
            "sent": sent,
        })
        job.push({"type": "saved", "txid": txid, "address": addr,
                  "count": len(job.results), "sent": sent,
                  "senders_total": job.senders_total,
                  "scanned_total": job.scanned_total,
                  "height": target.get("blockHeight")})


def _scan_one_address(job, addr, idx, n, lock, concurrent):
    """Scan a single address end-to-end (used by both sequential & pooled paths)."""
    job.wait_if_paused()               # hold here while paused
    if job._stop:
        return
    job.push({"type": "address_start", "address": addr, "index": idx,
              "total": n, "concurrent": concurrent})

    def on_ev(e, _a=addr):
        e["address"] = _a
        if e.get("type") in ("progress", "sender"):
            with lock:
                job.scanned_total += 1
                e["scanned_total"] = job.scanned_total
        job.push(e)

    # each address gets its own provider instance (no shared client state)
    provider = engine.make_provider(job.provider_kind, job.base_url)
    eng = engine.ScanEngine(provider, on_event=on_ev)
    try:
        if job.mode == "parallel" and not concurrent:
            stream = eng.scan_parallel(addr, workers=job.workers,
                                       stop_flag=lambda: job._stop)
        else:
            # in address-concurrent mode, each address uses page mode so total
            # in-flight requests ≈ the address-concurrency setting.
            stream = eng.scan(addr)
        for target in stream:
            if job._stop:
                break
            job.wait_if_paused()       # pause between transactions
            _handle_target(job, addr, target, lock)
    except Exception as e:  # noqa: BLE001 - one address failing must not kill the batch
        job.push({"type": "addr_error", "address": addr, "message": str(e)})
    with lock:
        job.addr_done += 1
        done = job.addr_done - job.skipped     # completed THIS run
        _mark_done(job, addr)                  # persist for cross-run resume
        _maybe_write_combined(job, force=True)
    job.push({"type": "address_done", "address": addr, "index": done,
              "total": n, "saved": len(job.results)})


def run_job(job: Job):
    os.makedirs(job.root_outdir, exist_ok=True)
    job.status = "running"
    resuming = _resume_load(job)                  # may skip already-done addresses
    job._done_fh = open(job.done_path, "a" if resuming else "w")
    n = len(job.addresses)
    lock = threading.Lock()
    concurrency = max(1, min(1000, job.concurrency))
    job.push({"type": "job_start", "total": len(job.all_addresses),
              "to_scan": n, "skipped": job.skipped, "resume": job.resume,
              "combined_file": job.combined_path})
    try:
        if concurrency > 1 and n > 1:
            from concurrent.futures import ThreadPoolExecutor
            job.push({"type": "batch_mode", "concurrency": concurrency, "total": n})
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                for i, addr in enumerate(job.addresses, 1):
                    pool.submit(_scan_one_address, job, addr, i, n, lock, True)
                # ThreadPoolExecutor.__exit__ waits for all submitted tasks
        else:
            for i, addr in enumerate(job.addresses, 1):
                if job._stop:
                    break
                _scan_one_address(job, addr, i, n, lock, False)

        _write_combined(job)                         # final flush (also if 0 found)
        job.status = "stopped" if job._stop else "done"
    except Exception as e:  # noqa: BLE001 - report any provider/network failure to UI
        job.status = "error"
        job.error = str(e)
        job.push({"type": "error", "message": str(e)})
    finally:
        with lock:
            try:
                job._done_fh.flush()
                job._done_fh.close()
            except Exception:                        # noqa: BLE001
                pass
        job.push({"type": "end", "status": job.status,
                  "saved": len(job.results), "addresses": len(job.all_addresses),
                  "to_scan": n, "skipped": job.skipped})


# --------------------------------------------------------------------------- #
#  HTTP handler                                                                 #
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "ATXQU/1.0"
    OUTDIR = "output"
    MAX_ADDRESSES = 1_000_000

    def log_message(self, fmt, *args):
        pass  # keep the console clean; the UI shows progress

    # ---- helpers ----
    def _send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj), "application/json")

    # ---- routing ----
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path in ("/", "/index.html", "/dashboard.html"):
            return self._serve_dashboard()
        if path == "/api/endpoints":
            return self._json({"endpoints": DEFAULT_ENDPOINTS})
        if path.startswith("/api/stream/"):
            return self._stream(path.rsplit("/", 1)[-1])
        if path.startswith("/api/job/"):
            return self._job_snapshot(path.rsplit("/", 1)[-1])
        if path.startswith("/api/tx/"):
            parts = path[len("/api/tx/"):].split("/", 1)
            dl = parse_qs(u.query).get("dl", ["0"])[0] == "1"
            return self._serve_tx(parts[0], parts[1] if len(parts) > 1 else "", dl)
        if path.startswith("/api/combined/"):
            return self._download_combined(path.rsplit("/", 1)[-1])
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/scan":
            return self._start_scan()
        if u.path.startswith("/api/stop/"):
            return self._stop_job(u.path.rsplit("/", 1)[-1])
        if u.path.startswith("/api/pause/"):
            return self._pause_job(u.path.rsplit("/", 1)[-1], True)
        if u.path.startswith("/api/resume/"):
            return self._pause_job(u.path.rsplit("/", 1)[-1], False)
        if u.path.startswith("/api/analyze/"):
            return self._analyze_job(u.path.rsplit("/", 1)[-1])
        return self._send(404, b'{"error":"not found"}')

    # ---- endpoints ----
    def _serve_dashboard(self):
        try:
            with open(DASHBOARD, "rb") as f:
                html = f.read()
        except FileNotFoundError:
            return self._send(500, b"dashboard.html not found next to server.py")
        return self._send(200, html, "text/html; charset=utf-8")

    def _start_scan(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json({"error": "invalid JSON"}, 400)
        # accept a single "address" or a list of "addresses" (from a .txt upload)
        raw = payload.get("addresses")
        if raw is None:
            raw = [payload.get("address", "")]
        # normalize: trim, drop blanks / comment lines, dedupe (keep order)
        seen, addresses = set(), []
        for a in raw:
            a = (a or "").strip()
            if not a or a.startswith("#") or a in seen:
                continue
            seen.add(a)
            addresses.append(a)
        if not addresses:
            return self._json({"error": "at least one address is required"}, 400)
        if len(addresses) > self.MAX_ADDRESSES:
            return self._json({"error":
                f"too many addresses ({len(addresses)}); max is "
                f"{self.MAX_ADDRESSES}. Raise it with --max-addresses."}, 400)
        kind = payload.get("provider", "blockbook")
        base_url = (payload.get("base_url") or DEFAULT_ENDPOINTS.get(
            "haskoin" if str(kind).startswith("hask") else "blockbook")).strip()
        mode = payload.get("mode", "pages")
        workers = max(1, min(128, int(payload.get("workers", 32))))
        concurrency = max(1, min(1000, int(payload.get("concurrency", 1))))
        resume = bool(payload.get("resume", True))
        job = Job(addresses, kind, base_url, mode, workers, self.OUTDIR,
                  concurrency=concurrency, resume=resume)
        with JOBS_LOCK:
            JOBS[job.id] = job
        threading.Thread(target=run_job, args=(job,), daemon=True).start()
        return self._json({"job_id": job.id, "address": job.address,
                           "addresses": len(addresses),
                           "provider": kind, "mode": mode, "workers": workers,
                           "concurrency": concurrency, "resume": resume,
                           "outdir": job.root_outdir,
                           "combined_file": job.combined_path})

    def _stop_job(self, job_id):
        job = JOBS.get(job_id)
        if not job:
            return self._json({"error": "unknown job"}, 404)
        job.stop()
        return self._json({"ok": True})

    def _pause_job(self, job_id, pause):
        job = JOBS.get(job_id)
        if not job:
            return self._json({"error": "unknown job"}, 404)
        job.pause() if pause else job.resume_run()
        return self._json({"ok": True, "paused": job._paused})

    def _job_snapshot(self, job_id):
        job = JOBS.get(job_id)
        if not job:
            return self._json({"error": "unknown job"}, 404)
        return self._json({"id": job.id, "status": job.status,
                           "error": job.error, "address": job.address,
                           "paused": job._paused,
                           "addresses": len(job.all_addresses),
                           "to_scan": len(job.addresses), "skipped": job.skipped,
                           "outdir": job.root_outdir,
                           "combined_file": job.combined_path,
                           "results": job.results})

    def _stream(self, job_id):
        job = JOBS.get(job_id)
        if not job:
            return self._send(404, b'{"error":"unknown job"}')
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            # replay is not needed; the client connects before scanning starts
            while True:
                try:
                    evt = job.events.get(timeout=15)
                except queue.Empty:
                    # heartbeat to keep the connection alive
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                data = "data: " + json.dumps(evt) + "\n\n"
                self.wfile.write(data.encode("utf-8"))
                self.wfile.flush()
                if evt.get("type") == "end":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _serve_tx(self, job_id, txid, download=False):
        """Return one transaction from the job's in-memory combined results."""
        job = JOBS.get(job_id)
        if not job:
            return self._send(404, b'{"error":"unknown job"}')
        tx = next((t for t in job.txs if t.get("txId") == txid), None)
        if tx is None:
            return self._send(404, b'{"error":"not found"}')
        extra = ({"Content-Disposition": f'attachment; filename="{txid}.json"'}
                 if download else None)
        return self._send(200, json.dumps(tx, indent=2), "application/json", extra)

    def _analyze_job(self, job_id):
        """Run a vusi attack over this job's collected transactions and return
        the JSON report — the ATXQU → vusi hop, straight from the dashboard."""
        job = JOBS.get(job_id)
        if not job:
            return self._json({"error": "unknown job"}, 404)
        if not job.txs:
            return self._json({"error": "no transactions collected yet"}, 400)

        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            payload = {}
        attack = str(payload.get("attack", "reuse-r")).strip() or "reuse-r"

        vusi = find_vusi_bin()
        if not vusi:
            return self._json({
                "error": "vusi binary not found. Build it "
                         "(cargo build --release --features polynonce,biased-nonce) "
                         "or set VUSI_BIN to its path."
            }, 500)

        # Write the collected transactions to a temp file for `--from-tx`.
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="atxqu_", delete=False, encoding="utf-8")
        try:
            json.dump(job.txs, tmp)
            tmp.flush()
            tmp.close()
            cmd = [vusi, "--json", "analyze", "--from-tx", tmp.name, "--attack", attack]
            for key, flag in _ATTACK_FLAGS.items():
                if key in payload and payload[key] not in (None, ""):
                    cmd += [flag, str(payload[key])]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            except FileNotFoundError:
                return self._json({"error": f"cannot execute vusi at {vusi}"}, 500)
            except subprocess.TimeoutExpired:
                return self._json({"error": "vusi analysis timed out"}, 504)

            # Exit 0 = clean, 1 = vulnerabilities found — both carry a JSON report
            # on stdout. Exit 2 = error (e.g. attack needs a build feature).
            if proc.returncode == 2:
                msg = (proc.stderr or "").strip().splitlines()
                return self._json({"error": msg[-1] if msg else "vusi error",
                                   "stderr": proc.stderr}, 400)
            try:
                report = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                return self._json({"error": "could not parse vusi output",
                                   "stdout": proc.stdout, "stderr": proc.stderr}, 500)
            return self._json({
                "ok": True,
                "attack": attack,
                "found_vulnerabilities": proc.returncode == 1,
                "extract_note": (proc.stderr or "").strip(),
                "report": report,
                "vusi_bin": vusi,
            })
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def _download_combined(self, job_id):
        """Serve the single combined JSON file (array of all spent txs)."""
        job = JOBS.get(job_id)
        if not job:
            return self._send(404, b'{"error":"unknown job"}')
        body = json.dumps(job.txs, indent=2)
        fname = f"{job.address}_sent_transactions.json"
        return self._send(200, body, "application/json",
                          {"Content-Disposition": f'attachment; filename="{fname}"'})


def main():
    ap = argparse.ArgumentParser(description="ATXQU local server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--outdir", default="output",
                    help="where the combined JSON file is written")
    ap.add_argument("--max-addresses", type=int, default=1_000_000,
                    help="maximum addresses accepted per scan (default 1,000,000)")
    ap.add_argument("--no-open", action="store_true",
                    help="do not auto-open the browser")
    args = ap.parse_args()

    Handler.OUTDIR = os.path.abspath(args.outdir)
    Handler.MAX_ADDRESSES = args.max_addresses
    os.makedirs(Handler.OUTDIR, exist_ok=True)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    banner = r"""
    _   _____  _  ______  _   _
   /_\ |_   _|| |/ / _ \| | | |   Address Transaction Query Utility
  / _ \  | |  | ' <  __/| |_| |   sender / spent-tx extractor
 /_/ \_\ |_|  |_|\_\___| \___/    stdlib · no-GPU (network-bound) · macOS
"""
    print(banner)
    print(f"  Serving dashboard : {url}")
    print(f"  Output directory  : {Handler.OUTDIR}")
    print(f"  Default endpoint  : {DEFAULT_ENDPOINTS['blockbook']}")
    print("  Press Ctrl+C to stop.\n")
    if not args.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
