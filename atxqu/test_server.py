#!/usr/bin/env python3
"""End-to-end server test with a mock provider (no network)."""
import json, os, shutil, tempfile, threading, time, urllib.request
from http.server import ThreadingHTTPServer
import engine, server

ADDR = "12R9pR5J3G9dqJxCcZeU8uAotGY5N5rNb1"

# --- synthetic Blockbook-style sources: one sender, one receive-only ---
SENDER_SRC = {
    "txid": "aa"*32, "blockHeight": 964270, "blockTime": 1787821588,
    "confirmations": 5, "fees": "892", "size": 222, "version": 2, "lockTime": 0,
    "vin": [{"txid": "bb"*32, "vout": 0, "sequence": 0xffffffff,
             "addresses": [ADDR], "value": "4500000000"}],
    "vout": [{"value": "2299999108", "hex": "0014dc678df183b2bcf70a1b5845a530be6e2028a313",
              "addresses": ["bc1qm3ncmuvrk270wzsmtpz62v97dcsz3gcnn5lygc"], "spent": True},
             {"value": "2200000000", "hex": "76a9140f897827100baf3e86d34b5bdf2be913f08ea9f088ac",
              "addresses": [ADDR], "spent": False}],
}
RECV_SRC = {
    "txid": "cc"*32, "blockHeight": 964000, "blockTime": 1787000000,
    "confirmations": 9, "fees": "500", "size": 200, "version": 2, "lockTime": 0,
    "vin": [{"txid": "dd"*32, "vout": 1, "sequence": 0xffffffff,
             "addresses": ["1SomeoneElseXXXXXXXXXXXXXXXXXXXXX"], "value": "1000"}],
    "vout": [{"value": "900", "hex": "76a9140f897827100baf3e86d34b5bdf2be913f08ea9f088ac",
              "addresses": [ADDR], "spent": False}],
}

class FakeProvider:
    name = "fake"
    def iter_transactions(self, address, page_size=1000):
        for s in (SENDER_SRC, RECV_SRC):
            yield {"page": 1, "total_pages": 1}, s
    def list_txids(self, address, page_size=1000):
        return [SENDER_SRC["txid"], RECV_SRC["txid"]]
    def fetch_tx(self, txid):
        return SENDER_SRC if txid == SENDER_SRC["txid"] else RECV_SRC
    def normalize(self, source):
        return engine.build_target_schema(source, None)

# ---- batch fixtures: two addresses that share one transaction ----
ADDR2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
SHARED_SRC = {  # both ADDR and ADDR2 are senders here -> must be saved once
    "txid": "ee"*32, "blockHeight": 964300, "blockTime": 1787900000,
    "confirmations": 3, "fees": "700", "size": 300, "version": 2, "lockTime": 0,
    "vin": [{"txid": "1a"*32, "vout": 0, "sequence": 0xffffffff,
             "addresses": [ADDR], "value": "1000000"},
            {"txid": "2b"*32, "vout": 1, "sequence": 0xffffffff,
             "addresses": [ADDR2], "value": "2000000"}],
    "vout": [{"value": "2999000", "hex": "76a914"+"55"*20+"88ac",
              "addresses": ["1Dest"], "spent": False}],
}
ADDR2_SRC = {  # unique to ADDR2
    "txid": "ff"*32, "blockHeight": 964310, "blockTime": 1787910000,
    "confirmations": 2, "fees": "400", "size": 200, "version": 2, "lockTime": 0,
    "vin": [{"txid": "3c"*32, "vout": 0, "sequence": 0xffffffff,
             "addresses": [ADDR2], "value": "500000"}],
    "vout": [{"value": "499600", "hex": "76a914"+"66"*20+"88ac",
              "addresses": ["1Dest2"], "spent": False}],
}
class FakeBatchProvider:
    name = "fakebatch"
    MAP = {ADDR: [SENDER_SRC, RECV_SRC, SHARED_SRC], ADDR2: [SHARED_SRC, ADDR2_SRC]}
    def iter_transactions(self, address, page_size=1000):
        for s in self.MAP.get(address, []):
            yield {"page": 1, "total_pages": 1}, s
    def list_txids(self, address, page_size=1000):
        return [s["txid"] for s in self.MAP.get(address, [])]
    def fetch_tx(self, txid):
        for lst in self.MAP.values():
            for s in lst:
                if s["txid"] == txid:
                    return s
        return None
    def normalize(self, source):
        return engine.build_target_schema(source, None)

def run(mode):
    engine.make_provider = lambda *a, **k: FakeProvider()
    outdir = tempfile.mkdtemp(prefix="atxqu_")
    server.Handler.OUTDIR = outdir
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    # start scan
    req = urllib.request.Request(f"{base}/api/scan", method="POST",
        data=json.dumps({"address": ADDR, "provider": "blockbook",
                         "mode": mode, "workers": 8}).encode(),
        headers={"Content-Type": "application/json"})
    job = json.loads(urllib.request.urlopen(req).read())
    jid = job["job_id"]

    # drain SSE until 'end'
    events = []
    with urllib.request.urlopen(f"{base}/api/stream/{jid}", timeout=10) as s:
        for raw in s:
            line = raw.decode().strip()
            if line.startswith("data:"):
                ev = json.loads(line[5:].strip()); events.append(ev)
                if ev.get("type") == "end":
                    break

    snap = json.loads(urllib.request.urlopen(f"{base}/api/job/{jid}").read())
    dash = urllib.request.urlopen(f"{base}/").read()
    combined_dl = json.loads(urllib.request.urlopen(f"{base}/api/combined/{jid}").read())
    one_tx = json.loads(urllib.request.urlopen(
        f"{base}/api/tx/{jid}/{SENDER_SRC['txid']}").read())
    # single combined file on disk
    fpath = os.path.join(outdir, ADDR + "_sent_transactions.json")
    on_disk = json.load(open(fpath)) if os.path.isfile(fpath) else None
    # confirm there are NO per-txid files anymore
    stray = os.path.isfile(os.path.join(outdir, ADDR, SENDER_SRC["txid"] + ".json"))
    httpd.shutdown(); shutil.rmtree(outdir, ignore_errors=True)

    SCHEMA_KEYS = ["txId","blockHeight","blockPosition","mempool","mempoolTime",
        "time","fee","size","weight","rbf","inputs","outputs","version",
        "locktime","deleted","txid","block"]
    fails = []
    def ck(n, c):
        print(f"[{'PASS' if c else 'FAIL'}] ({mode}) {n}"); (fails.append(n) if not c else None)
    ck("scan endpoint returned job id", bool(jid))
    ck("exactly 1 sender in results", len(snap["results"]) == 1)
    ck("result is the sender tx", snap["results"] and snap["results"][0]["txid"] == SENDER_SRC["txid"])
    ck("receive-only tx NOT included", all(r["txid"] != RECV_SRC["txid"] for r in snap["results"]))
    ck("end event present", any(e["type"] == "end" for e in events))
    ck("saved event present", any(e["type"] == "saved" for e in events))
    ck("dashboard html served", b"ATXQU" in dash and b"<html" in dash.lower())
    ck("ONE combined file on disk", on_disk is not None)
    ck("combined file is a JSON array", isinstance(on_disk, list) and len(on_disk) == 1)
    ck("NO per-txid files left behind", stray is False)
    ck("combined download matches disk (array of 1)",
       isinstance(combined_dl, list) and len(combined_dl) == 1)
    ck("combined element has exact schema keys",
       on_disk and list(on_disk[0].keys()) == SCHEMA_KEYS)
    ck("single-tx endpoint returns the tx", one_tx.get("txId") == SENDER_SRC["txid"])
    ck("input pkscript reconstructed", on_disk and on_disk[0]["inputs"][0]["pkscript"] ==
       "76a9140f897827100baf3e86d34b5bdf2be913f08ea9f088ac")
    ck("sent amount computed", snap["results"] and snap["results"][0]["sent"] == 4500000000)
    return fails

def run_batch(mode, concurrency=1):
    engine.make_provider = lambda *a, **k: FakeBatchProvider()
    outdir = tempfile.mkdtemp(prefix="atxqu_batch_")
    server.Handler.OUTDIR = outdir
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    tag = f"batch/{mode}/c{concurrency}"

    req = urllib.request.Request(f"{base}/api/scan", method="POST",
        data=json.dumps({"addresses": [ADDR, ADDR2, ADDR, "  ", "# note"],
                         "provider": "blockbook", "mode": mode, "workers": 8,
                         "concurrency": concurrency}).encode(),
        headers={"Content-Type": "application/json"})
    job = json.loads(urllib.request.urlopen(req).read())
    jid = job["job_id"]

    events = []
    with urllib.request.urlopen(f"{base}/api/stream/{jid}", timeout=10) as s:
        for raw in s:
            line = raw.decode().strip()
            if line.startswith("data:"):
                ev = json.loads(line[5:].strip()); events.append(ev)
                if ev.get("type") == "end":
                    break

    snap = json.loads(urllib.request.urlopen(f"{base}/api/job/{jid}").read())
    fpath = job["combined_file"]      # path now includes a signature
    on_disk = json.load(open(fpath)) if os.path.isfile(fpath) else None
    combined_dl = json.loads(urllib.request.urlopen(f"{base}/api/combined/{jid}").read())
    httpd.shutdown(); shutil.rmtree(outdir, ignore_errors=True)

    saved_txids = [t["txId"] for t in (on_disk or [])]
    fails = []
    def ck(n, c):
        print(f"[{'PASS' if c else 'FAIL'}] ({tag}) {n}"); (fails.append(n) if not c else None)
    ck("job reports 2 unique addresses", job.get("addresses") == 2)
    ck("combined filename is batch_<sig>_2_addresses…",
       job["combined_file"].endswith("_2_addresses_sent_transactions.json")
       and "batch_" in os.path.basename(job["combined_file"]))
    ck("exactly 3 unique senders saved", len(saved_txids) == 3)
    ck("SENDER (addr1) saved", SENDER_SRC["txid"] in saved_txids)
    ck("ADDR2-unique saved", ADDR2_SRC["txid"] in saved_txids)
    ck("SHARED tx saved exactly once", saved_txids.count(SHARED_SRC["txid"]) == 1)
    ck("receive-only tx excluded", RECV_SRC["txid"] not in saved_txids)
    ck("dedupe event emitted for shared tx",
       any(e["type"] == "dup" and e.get("txid") == SHARED_SRC["txid"] for e in events))
    ck("address_start fired per address",
       sum(1 for e in events if e["type"] == "address_start") == 2)
    ck("address_done fired per address",
       sum(1 for e in events if e["type"] == "address_done") == 2)
    ck("result rows carry their address", all("address" in r for r in snap["results"]))
    ck("combined download == disk", combined_dl == on_disk)
    ck("cumulative scanned reported", any(e.get("scanned_total") for e in events))
    if concurrency > 1:
        ck("batch_mode (parallel) event emitted",
           any(e["type"] == "batch_mode" and e.get("concurrency") == concurrency
               for e in events))
    return fails

def run_cap():
    engine.make_provider = lambda *a, **k: FakeBatchProvider()
    outdir = tempfile.mkdtemp(prefix="atxqu_cap_")
    server.Handler.OUTDIR = outdir
    server.Handler.MAX_ADDRESSES = 3   # tiny cap for the test
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    req = urllib.request.Request(f"{base}/api/scan", method="POST",
        data=json.dumps({"addresses": [f"addr{i}" for i in range(10)]}).encode(),
        headers={"Content-Type": "application/json"})
    code, err = None, ""
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        code = e.code; err = e.read().decode()
    httpd.shutdown(); shutil.rmtree(outdir, ignore_errors=True)
    server.Handler.MAX_ADDRESSES = 1_000_000  # restore
    fails = []
    def ck(n, c):
        print(f"[{'PASS' if c else 'FAIL'}] (cap) {n}"); (fails.append(n) if not c else None)
    ck("over-cap request rejected with 400", code == 400)
    ck("error names the max", "max is 3" in err)
    return fails

def run_resume():
    """Cross-run resume: 2nd run skips addresses done in the 1st."""
    engine.make_provider = lambda *a, **k: FakeBatchProvider()
    outdir = tempfile.mkdtemp(prefix="atxqu_resume_")
    server.Handler.OUTDIR = outdir
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    def scan(resume):
        req = urllib.request.Request(f"{base}/api/scan", method="POST",
            data=json.dumps({"addresses": [ADDR, ADDR2], "provider": "blockbook",
                             "mode": "pages", "workers": 8, "concurrency": 1,
                             "resume": resume}).encode(),
            headers={"Content-Type": "application/json"})
        job = json.loads(urllib.request.urlopen(req).read())
        ev = []
        with urllib.request.urlopen(f"{base}/api/stream/{job['job_id']}", timeout=10) as s:
            for raw in s:
                ln = raw.decode().strip()
                if ln.startswith("data:"):
                    e = json.loads(ln[5:].strip()); ev.append(e)
                    if e.get("type") == "end":
                        break
        return job, ev

    job1, ev1 = scan(True)          # fresh
    js1 = next(e for e in ev1 if e["type"] == "job_start")
    combined1 = json.load(open(job1["combined_file"]))
    starts1 = sum(1 for e in ev1 if e["type"] == "address_start")

    job2, ev2 = scan(True)          # resume: everything already done
    js2 = next(e for e in ev2 if e["type"] == "job_start")
    combined2 = json.load(open(job2["combined_file"]))
    starts2 = sum(1 for e in ev2 if e["type"] == "address_start")

    job3, ev3 = scan(False)         # resume off: rescan
    js3 = next(e for e in ev3 if e["type"] == "job_start")
    combined3 = json.load(open(job3["combined_file"]))

    httpd.shutdown(); shutil.rmtree(outdir, ignore_errors=True)
    fails = []
    def ck(n, c):
        print(f"[{'PASS' if c else 'FAIL'}] (resume) {n}"); (fails.append(n) if not c else None)
    ck("run1 skipped 0", js1["skipped"] == 0)
    ck("run1 scanned both addresses", starts1 == 2 and js1["to_scan"] == 2)
    ck("run1 saved 3 unique txs", len(combined1) == 3)
    ck("run2 resume skips both", js2["skipped"] == 2 and js2["to_scan"] == 0)
    ck("run2 scanned nothing (no address_start)", starts2 == 0)
    ck("run2 combined unchanged (3 txs)", len(combined2) == 3)
    ck("run3 resume-off rescans both", js3["skipped"] == 0 and js3["to_scan"] == 2)
    ck("run3 combined still 3 (deduped)", len(combined3) == 3)
    return fails

def run_pause_mechanics():
    """Job-level pause/resume gate (deterministic, no network)."""
    outdir = tempfile.mkdtemp(prefix="atxqu_pause_")
    j = server.Job([ADDR, ADDR2], "blockbook", "http://x", "pages", 8, outdir, concurrency=1)
    j.status = "running"
    released = []
    j.pause()
    t = threading.Thread(target=lambda: (j.wait_if_paused(), released.append(1)), daemon=True)
    t.start(); time.sleep(0.15)
    paused_blocks = (j._paused and not j._resume_event.is_set() and not released)
    j.resume_run(); t.join(timeout=2)
    shutil.rmtree(outdir, ignore_errors=True)
    fails = []
    def ck(n, c):
        print(f"[{'PASS' if c else 'FAIL'}] (pause) {n}"); (fails.append(n) if not c else None)
    def _stop_unblocks():
        jj = server.Job([ADDR], "blockbook", "http://x", "pages", 8, outdir)
        jj.status = "running"; jj.pause()
        blocked = not jj._resume_event.is_set()
        jj.stop()
        return blocked and jj._resume_event.is_set()
    ck("pause blocks a waiter", paused_blocks)
    ck("resume releases the waiter", released == [1] and not j._paused)
    ck("stop also unblocks a paused job", _stop_unblocks())
    return fails

import urllib.error  # noqa: E402
allf = (run("pages") + run("parallel") +
        run_batch("pages") + run_batch("parallel") +
        run_batch("pages", concurrency=16) +     # address-level parallelism
        run_resume() + run_pause_mechanics() +
        run_cap())
print()
if allf:
    print(f"{len(allf)} FAILURE(S): {allf}"); raise SystemExit(1)
print("ALL SERVER TESTS PASSED")
