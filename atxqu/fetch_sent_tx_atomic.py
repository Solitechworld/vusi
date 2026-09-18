#!/usr/bin/env python3
"""
Fetch and save only transactions where the address is a SENDER (appears in inputs).

Uses the Atomic Wallet (Blockbook) API:
    https://bitcoin.atomicwallet.io/api/v2/address/{address}

Speed strategy:
  1. Request ?details=txs so each paginated page returns FULL transactions
     (including inputs/vin) in one round-trip. Filter senders in memory --
     no per-transaction fetch at all in the common case.
  2. Fall back to fetching a transaction individually ONLY if a page entry
     is missing input data, and do those fetches in parallel with a shared
     session (keep-alive) instead of a serial loop with sleeps.

Usage:
    python3 fetch_sent_tx_atomic.py 12R9pR5J3G9dqJxCcZeU8uAotGY5N5rNb1
"""
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests

ATOMIC_BASE = "https://bitcoin.atomicwallet.io/api/v2"
OUTPUT_DIR = "sent_transactions"
PAGE_SIZE = 1000          # max transactions per page
MAX_WORKERS = 10          # parallelism for fallback per-tx fetches
TIMEOUT = 30

# One session for the whole run -> connection reuse / keep-alive.
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "sent-tx-fetcher/2.0"})


def fetch_address_page(address: str, page: int = 1) -> Dict:
    """
    Fetch one page of the address endpoint WITH full transaction details.
    Returns the parsed JSON (or {} on error).
    """
    url = f"{ATOMIC_BASE}/address/{address}"
    params = {"page": page, "pageSize": PAGE_SIZE, "details": "txs"}
    try:
        resp = SESSION.get(url, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"Error fetching address page {page}: {e}")
        return {}


def fetch_transaction_details(txid: str) -> Optional[Dict]:
    """Fetch a single full transaction (fallback path only)."""
    url = f"{ATOMIC_BASE}/transaction/{txid}"
    try:
        resp = SESSION.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"Error fetching transaction {txid}: {e}")
        return None


def is_address_in_inputs(tx_data: Dict, address: str) -> bool:
    """
    True if the address appears in any input.
    Blockbook input objects expose addresses as `vin[].addresses` (a list);
    some responses use a flat `address`. Handle both.
    """
    for vin in tx_data.get("vin", []) or tx_data.get("inputs", []):
        addrs = vin.get("addresses")
        if addrs and address in addrs:
            return True
        if vin.get("address") == address:
            return True
    return False


def has_input_data(tx_data: Dict) -> bool:
    """
    Whether this tx object carries enough input info to judge the sender.
    A coinbase tx legitimately has no addressed inputs -> treat as 'known'.
    """
    vins = tx_data.get("vin", []) or tx_data.get("inputs", [])
    if not vins:
        return True  # e.g. coinbase; nothing to resolve
    return any(v.get("addresses") or v.get("address") or v.get("isAddress") is False
               for v in vins)


def save_transaction(tx_data: Dict, txid: str, output_dir: str) -> None:
    with open(os.path.join(output_dir, f"{txid}.json"), "w") as f:
        json.dump(tx_data, f, indent=2)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bitcoin_address>")
        sys.exit(1)

    address = sys.argv[1]
    print(f"Fetching transactions for {address} ...")

    txs_by_id: Dict[str, Dict] = {}   # full tx objects gathered from pages
    needs_refetch: List[str] = []     # txids whose page entry lacked inputs

    # 1. Page through the address endpoint with full tx details.
    page = 1
    total_pages = 1
    while page <= total_pages:
        print(f"Fetching page {page}/{total_pages if total_pages > 1 else '?'} ...")
        data = fetch_address_page(address, page)
        if not data:
            break
        total_pages = data.get("totalPages", 1)

        page_txs = data.get("transactions", [])
        if not page_txs:
            # Older/edge responses may only give txids -> mark all for refetch.
            for txid in data.get("txids", []):
                needs_refetch.append(txid)
        else:
            for tx in page_txs:
                txid = tx.get("txid")
                if not txid:
                    continue
                txs_by_id[txid] = tx
                if not has_input_data(tx):
                    needs_refetch.append(txid)

        print(f"  Page {page}: {len(page_txs)} full txs, "
              f"{len(needs_refetch)} pending refetch so far.")
        page += 1

    total_seen = len(txs_by_id) + len([t for t in needs_refetch if t not in txs_by_id])
    print(f"Collected {total_seen} transaction(s).")

    # 2. Parallel fallback ONLY for the ones missing input data.
    if needs_refetch:
        to_fetch = list(dict.fromkeys(needs_refetch))  # dedupe, keep order
        print(f"Refetching {len(to_fetch)} transaction(s) in parallel "
              f"({MAX_WORKERS} workers) ...")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(fetch_transaction_details, t): t for t in to_fetch}
            for fut in as_completed(futures):
                txid = futures[fut]
                tx_data = fut.result()
                if tx_data:
                    txs_by_id[txid] = tx_data

    if not txs_by_id:
        print("No transactions found.")
        return

    # 3. Filter to senders and save.
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    saved_count = 0
    for txid, tx_data in txs_by_id.items():
        if not is_address_in_inputs(tx_data, address):
            continue
        save_transaction(tx_data, txid, OUTPUT_DIR)
        saved_count += 1

    print(f"Done. Saved {saved_count} sent transaction(s) to {OUTPUT_DIR}/.")


if __name__ == "__main__":
    main()
