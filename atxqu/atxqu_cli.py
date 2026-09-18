#!/usr/bin/env python3
"""
ATXQU headless CLI — the pipe between ATXQU and vusi.

Fetches every SENT transaction of a Bitcoin address (or a list of addresses),
normalizes each to the Haskoin/Blockbook target schema, and writes a single
JSON array to stdout (or a file). That array is exactly what
`vusi analyze --from-tx` / `vusi extract` consume, so:

    python3 atxqu_cli.py <address> | vusi analyze --from-tx - --attack reuse-r

Offline mode: instead of fetching, normalize a raw provider dump you already
have (e.g. a Blockbook `?details=txs` response saved to disk):

    python3 atxqu_cli.py --normalize raw_blockbook.json > normalized.json

Uses only the Python standard library (urllib), like the rest of ATXQU.
"""
import argparse
import json
import sys

import engine


def read_addresses(args) -> list:
    if args.addresses_file:
        addrs = []
        with open(args.addresses_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    addrs.append(line)
        return addrs
    return [a for a in args.address if a]


def scan_addresses(addrs, provider_kind, base_url, workers, parallel) -> list:
    provider = engine.make_provider(provider_kind, base_url)
    out = []
    seen = set()  # dedupe by txid across addresses
    eng = engine.ScanEngine(provider, on_event=lambda e: _log(e))
    for addr in addrs:
        it = (
            eng.scan_parallel(addr, workers=workers)
            if parallel
            else eng.scan(addr)
        )
        for tx in it:
            txid = tx.get("txId") or tx.get("txid")
            if txid in seen:
                continue
            seen.add(txid)
            out.append(tx)
    return out


def normalize_file(path, provider_kind, base_url) -> list:
    """Offline: normalize a raw provider dump (single object or array)."""
    provider = engine.make_provider(provider_kind, base_url)
    raw = json.load(open(path, "r", encoding="utf-8"))
    items = raw if isinstance(raw, list) else [raw]
    out = []
    for src in items:
        try:
            out.append(provider.normalize(src))
        except Exception as e:  # noqa: BLE001
            _log({"type": "skip", "message": str(e)})
    return out


def _log(evt):
    # Progress goes to stderr so stdout stays a clean JSON array for piping.
    t = evt.get("type")
    if t == "sender":
        sys.stderr.write(f"  + sender tx {evt.get('txid','')[:16]}… "
                         f"(scanned {evt.get('scanned')})\n")
    elif t in ("start", "done", "listed", "error", "skip"):
        sys.stderr.write(f"[{t}] {json.dumps({k: v for k, v in evt.items() if k != 'type'})}\n")
    sys.stderr.flush()


def main() -> int:
    ap = argparse.ArgumentParser(description="ATXQU headless fetch/normalize for vusi")
    ap.add_argument("address", nargs="*", help="Bitcoin address(es) to scan")
    ap.add_argument("-f", "--addresses-file", help="Text file, one address per line")
    ap.add_argument("--normalize", metavar="RAW_JSON",
                    help="Offline: normalize a raw provider dump instead of fetching")
    ap.add_argument("--provider", default="blockbook", choices=["blockbook", "haskoin"])
    ap.add_argument("--endpoint", default="https://bitcoin.atomicwallet.io/api/v2",
                    help="Provider base URL")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--parallel", action="store_true",
                    help="Use txid-listing + parallel per-tx fetch")
    ap.add_argument("-o", "--out", help="Write JSON array here instead of stdout")
    args = ap.parse_args()

    if args.normalize:
        txs = normalize_file(args.normalize, args.provider, args.endpoint)
    else:
        addrs = read_addresses(args)
        if not addrs:
            ap.error("provide at least one address, -f FILE, or --normalize RAW_JSON")
        txs = scan_addresses(addrs, args.provider, args.endpoint,
                             args.workers, args.parallel)

    payload = json.dumps(txs, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
        sys.stderr.write(f"[written] {len(txs)} tx -> {args.out}\n")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
