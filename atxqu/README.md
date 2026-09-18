# ATXQU — Address Transaction Query Utility

A local web app for macOS (Apple silicon **and** Intel/T2) that finds every
**spent** transaction of a Bitcoin address — i.e. every transaction where the
address appears in the **inputs** (it sent funds) — normalizes each one to a
fixed JSON schema, and saves them all to **one combined JSON file**.

It ships with a neon "cyberspace" dashboard: live progress stream, telemetry
tiles, a results table with an inline JSON viewer, and one-click download of the
combined file.

---

## Quick start

No installation, no `pip`, no dependencies — it uses only the Python standard
library that already ships with macOS.

```bash
cd ATXQU
python3 server.py
```

Your browser opens at **http://127.0.0.1:8787**. Paste an address, press
**Scan**, and watch the spent transactions stream in.

Or just **double-click `run.command`** in Finder.

> First time you double-click `run.command`, macOS Gatekeeper may block it.
> Right-click → **Open**, or run `chmod +x run.command` once in Terminal.

### Scan many addresses at once (.txt upload)

Click **Upload addresses (.txt)** and pick a plain-text file with **one address
per line**:

```
12R9pR5J3G9dqJxCcZeU8uAotGY5N5rNb1
1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
# lines starting with # are ignored, blank lines too
bc1qm3ncmuvrk270wzsmtpz62v97dcsz3gcnn5lygc
```

The file is parsed **in your browser** — only the address list is sent to the
local server, never the file itself. Then press **Scan**:

* every address is scanned in turn (the stream shows `[i/N] scanning …`);
* a transaction shared between two of your addresses is saved **once** (deduped
  by txid — you'll see a `shared tx … skipped` note);
* everything lands in a **single** file:
  `output/batch_<N>_addresses_sent_transactions.json`.

The results table shows which address each transaction came from. Use **clear
list** to go back to single-address mode.

> **Large lists:** the combined file is flushed to disk as it goes, so partial
> progress is never lost — you can **Stop** and keep what's been found. The
> default limit is 1,000,000 addresses per run; change it with `--max-addresses`.

#### Pause / Resume

* **Pause** halts the scan without ending it (it stops between transactions /
  addresses) and the button becomes **Resume** — click it to continue exactly
  where you left off. In-flight requests finish; no new ones start while paused.
* **Resume across runs** (checkbox, on by default): every address that finishes
  is recorded in a `…​.done` sidecar file next to the combined JSON. If a run is
  stopped, crashes, or you close the app, just run the **same list** again with
  Resume ticked — it reloads the transactions already saved and **skips the
  addresses already scanned**, continuing from where it stopped. Untick Resume to
  start the list over from scratch.

#### Speed: "Addresses at once"

The **Addresses at once** slider (1–1000) sets how many addresses are scanned
**simultaneously**. At `1` they run in turn; crank it up and that many addresses
are fetched in parallel — so with a fast/unlimited endpoint you can have ~1000
requests in flight at a time and blow through a huge list.

Under the hood this is a **thread pool** (concurrent network I/O), not the GPU.
GPUs/Metal accelerate parallel *math*; they can't issue HTTP requests, so they
do nothing for a fetch-bound workload. "1000 at once" = 1000 sockets waiting on
the network, which is a CPU/OS job. Set this high **only** for an endpoint that
can take the load (your own node, or a provider with no rate limit) — pointed at
a shared public endpoint, high concurrency will just get you throttled or
blocked. Transactions shared between your addresses are still saved exactly once
(deduped safely across threads).

### Options

```bash
python3 server.py --port 9000      # use a different port
python3 server.py --outdir results # change where JSON files are written
python3 server.py --no-open        # don't auto-open the browser
```

---

## About "GPU / Metal"

This tool deliberately does **not** use the GPU or Metal. The work here is
**network-bound** — it spends essentially all of its time waiting on HTTP
responses from the blockchain API. A GPU accelerates heavy parallel *math*
(hashing, matrix ops, rendering); there is no such computation in
"fetch JSON → filter → save". What actually makes this fast is **request
concurrency**, which is exactly what the app does:

* **Bulk pages (default):** asks the Blockbook API for up to 1000 full
  transactions per request (`?details=txs`), so thousands of transactions come
  back in a handful of round-trips instead of one request each.
* **Parallel per-tx:** lists the txids, then fetches transactions concurrently
  with a thread pool (the **Workers** slider, 1–128). Use this for providers or
  endpoints that don't support bulk detail pages.

It runs great on Apple silicon and T2 Macs because system `python3` is
universal — there is nothing to compile.

---

## Output

All spent transactions are written to a **single file**:

```
output/<address>_sent_transactions.json            # single address
output/batch_<N>_addresses_sent_transactions.json  # uploaded .txt list
```

(or under your `--outdir`). The file is a JSON **array**; each element is one
transaction in this exact schema:

```json
[{
  "txId": "...",
  "blockHeight": 964270,
  "blockPosition": 323,
  "mempool": false,
  "mempoolTime": null,
  "time": 1787821588,
  "fee": 892,
  "size": 222,
  "weight": 888,
  "rbf": false,
  "inputs": [
    { "coinbase": false, "txid": "...", "output": 0, "sigscript": "...",
      "sequence": 0, "pkscript": "...", "value": 4500000000,
      "address": "...", "witness": [] }
  ],
  "outputs": [
    { "address": "...", "pkscript": "...", "value": 2299999108, "spent": true }
  ],
  "version": 2,
  "locktime": 0,
  "deleted": false,
  "txid": "...",
  "block": { "height": 964270, "mempool": false, "position": 323 }
}]
```

The file is rewritten atomically as results stream in, so it always contains the
complete set found so far — even if you press **Stop** partway through.

### How fields are filled

The target schema is the **Haskoin-store** shape. When the data comes from a
**Blockbook** endpoint (like Atomic Wallet's), a few fields aren't in the
Blockbook response — the app reconstructs them locally so you don't pay for
extra round-trips:

| Field | Source |
|---|---|
| `weight`, input `witness` | parsed from the raw transaction hex |
| input `pkscript` | reconstructed from the input's address (P2PKH / P2SH / P2WPKH / P2WSH / P2TR) |
| `rbf` | `true` if any input sequence < `0xfffffffe` |
| `blockPosition` | provided by Haskoin; `null` from Blockbook (it isn't returned) |

If you use a **Haskoin** endpoint, every field (including `blockPosition`) comes
straight from the API.

---

## Providers & endpoints

Pick a provider in the UI and edit the **Endpoint base URL** to point at any
instance you trust:

* **Blockbook** (default): `https://bitcoin.atomicwallet.io/api/v2` — the API
  your original script used.
* **Haskoin-store**: e.g. `https://api.haskoin.com/btc` — returns the target
  schema natively.

> Public endpoints rate-limit. If a big address stalls, lower the **Workers**
> count or switch to **Bulk pages** mode.

---

## Files

| File | Purpose |
|---|---|
| `server.py` | Local HTTP server + scan job runner + live progress (SSE) |
| `engine.py` | Providers, raw-tx parser, address→script, schema normalizer |
| `dashboard.html` | The cyberpunk GUI (single file) |
| `run.command` | Double-click launcher for Finder |
| `test_engine.py` | Offline unit tests for the normalizer & parser |
| `test_server.py` | Offline end-to-end test (mock provider) |

Run the tests any time:

```bash
python3 test_engine.py && python3 test_server.py
```

---

## Notes

* Everything runs **locally** — the only outbound connections are to the
  blockchain endpoint you choose. Nothing is uploaded anywhere.
* Blockchain data is public; this tool only reads it.
* `Ctrl+C` in the terminal stops the server. **Stop** in the UI cancels an
  in-flight scan without killing the server.

---

## Using with vusi

This copy of ATXQU is bundled inside the [`vusi`](../README.md) repository as its
**data-acquisition front-end**. ATXQU turns an address into the spent
transactions; vusi turns those transactions into `(r, s, z, pubkey)` tuples and
runs ECDSA nonce attacks over them.

```bash
# one command: fetch -> extract -> analyze
../atxqu/scan_and_analyze.sh <address> reuse-r

# headless fetch/normalize to stdout (stdlib only), pipe into vusi
python3 atxqu_cli.py <address> | vusi analyze --from-tx - --attack reuse-r

# offline: normalize a raw provider dump you already saved
python3 atxqu_cli.py --normalize raw_blockbook.json -o txs.json
vusi extract txs.json          # -> [{r,s,z,pubkey}]
```

The normalized schema below is exactly what `vusi extract` / `vusi analyze
--from-tx` consume.

**From the dashboard (no terminal):** after a scan, the results panel has an
**⚡ ANALYZE IN VUSI** control — pick an attack and click **Run attack**. The
server runs the `vusi` CLI over the transactions it just collected and shows the
vulnerabilities and any recovered keys inline. It finds the binary via
`$VUSI_BIN`, then the repo's `target/release/vusi` / `target/debug/vusi`, then
`vusi` on `PATH` (build with
`cargo build --release --features polynonce,biased-nonce` for the lattice
attacks). Lattice modes can be slow on very large signature sets.
