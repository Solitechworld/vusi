#!/usr/bin/env python3
"""
ATXQU — engine
==============
Core logic for the Address Transaction Query Utility.

Responsibilities
----------------
* Talk to a blockchain data provider (Blockbook-style, e.g. the Atomic Wallet
  API, or a Haskoin-store instance).
* For a given address, find every transaction where that address is a SENDER
  (i.e. it appears in the transaction inputs -> a "spent" transaction).
* Normalize each such transaction into the exact target JSON schema and hand it
  back to the caller (the server saves each one as <txid>.json).

Design notes
------------
* Pure Python standard library — no third-party packages required, so it runs
  on any Mac (Apple silicon or Intel/T2) with the system `python3`.
* The bottleneck is the network, so fetching is parallelized with a thread
  pool by the caller. The engine itself is thread-safe per-call.
* Per-input `pkscript` and `witness` and the exact `weight` are reconstructed
  locally (address -> script, and a raw-tx hex parser) so we never pay for an
  extra "fetch the previous transaction" round-trip.
"""

from __future__ import annotations

import http.client
import json
import math
import random
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, Iterator, List, Optional, Tuple

USER_AGENT = "ATXQU/1.0 (+stdlib)"
DEFAULT_TIMEOUT = 30
# Transient network failures to retry with back-off. Public endpoints throttle
# hard under high concurrency, dropping connections mid-flight — these recover.
MAX_RETRIES = 4
_RETRY_EXC = (
    urllib.error.URLError,
    ssl.SSLError,
    socket.timeout,
    ConnectionError,          # includes ConnectionReset / BrokenPipe
    http.client.IncompleteRead,
    http.client.RemoteDisconnected,
)


# --------------------------------------------------------------------------- #
#  HTTP helper (stdlib urllib, connection kept simple; the pool gives us       #
#  concurrency at the caller level).                                           #
# --------------------------------------------------------------------------- #
def http_get_json(url: str, params: Optional[dict] = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    last_exc: Optional[Exception] = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            # Retry only on throttling / transient server errors.
            if e.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                _backoff(attempt, retry_after=e.headers.get("Retry-After"))
                last_exc = e
                continue
            raise
        except _RETRY_EXC as e:
            if attempt < MAX_RETRIES:
                _backoff(attempt)
                last_exc = e
                continue
            raise
    if last_exc:
        raise last_exc
    raise urllib.error.URLError("request failed with no response")


def _backoff(attempt: int, retry_after: Optional[str] = None) -> None:
    """Exponential back-off with jitter (honours a Retry-After header if given)."""
    if retry_after:
        try:
            time.sleep(min(float(retry_after), 30.0))
            return
        except (TypeError, ValueError):
            pass
    delay = min(0.5 * (2 ** attempt), 8.0) + random.uniform(0.0, 0.4)
    time.sleep(delay)


# --------------------------------------------------------------------------- #
#  Address -> scriptPubKey (pkscript) reconstruction.                          #
#  Lets us fill an input's `pkscript` from just its address, with no extra     #
#  network call. Supports legacy Base58 (P2PKH / P2SH) and Bech32/Bech32m      #
#  segwit (P2WPKH / P2WSH / P2TR).                                             #
# --------------------------------------------------------------------------- #
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58)}
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _sha256(b: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(b).digest()


def _b58check_decode(s: str) -> Optional[bytes]:
    num = 0
    for ch in s:
        if ch not in _B58_MAP:
            return None
        num = num * 58 + _B58_MAP[ch]
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    # restore leading zero bytes (each leading '1' == one 0x00 byte)
    pad = len(s) - len(s.lstrip("1"))
    full = b"\x00" * pad + full
    if len(full) < 5:
        return None
    payload, checksum = full[:-4], full[-4:]
    if _sha256(_sha256(payload))[:4] != checksum:
        return None
    return payload


def _bech32_polymod(values: List[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_decode(bech: str) -> Tuple[Optional[str], Optional[List[int]], Optional[str]]:
    bech = bech.strip()
    if bech.lower() != bech and bech.upper() != bech:
        return None, None, None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        return None, None, None
    hrp, data_part = bech[:pos], bech[pos + 1:]
    data = []
    for c in data_part:
        if c not in _BECH32_CHARSET:
            return None, None, None
        data.append(_BECH32_CHARSET.index(c))
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const == 1:
        spec = "bech32"
    elif const == 0x2BC830A3:
        spec = "bech32m"
    else:
        return None, None, None
    return hrp, data[:-6], spec


def _convertbits(data: List[int], frm: int, to: int, pad: bool = True) -> Optional[List[int]]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to) - 1
    for value in data:
        if value < 0 or (value >> frm):
            return None
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    elif bits >= frm or ((acc << (to - bits)) & maxv):
        return None
    return ret


def address_to_pkscript(address: Optional[str]) -> Optional[str]:
    """Return the scriptPubKey (hex) implied by a Bitcoin address, or None."""
    if not address:
        return None
    a = address.strip()
    # Bech32 / Bech32m segwit
    if a.lower().startswith(("bc1", "tb1", "bcrt1")):
        hrp, data, spec = _bech32_decode(a)
        if data is None or not data:
            return None
        witver = data[0]
        prog = _convertbits(data[1:], 5, 8, False)
        if prog is None or len(prog) < 2 or len(prog) > 40:
            return None
        if witver == 0 and spec != "bech32":
            return None
        if witver != 0 and spec != "bech32m":
            return None
        op = b"\x00" if witver == 0 else bytes([0x50 + witver])
        return (op + bytes([len(prog)]) + bytes(prog)).hex()
    # Base58 legacy
    payload = _b58check_decode(a)
    if payload is None or len(payload) != 21:
        return None
    version, h160 = payload[0], payload[1:]
    if version in (0x00, 0x6F):        # P2PKH  (mainnet 0x00 / testnet 0x6f)
        return b"\x76\xa9\x14" + h160 + b"\x88\xac"  # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if version in (0x05, 0xC4):        # P2SH
        return (b"\xa9\x14" + h160 + b"\x87").hex()  # placeholder, fixed below
    return None


# NB: the P2PKH branch above returns bytes; wrap consistently.
def _fix_pkscript(x) -> Optional[str]:
    if x is None:
        return None
    return x.hex() if isinstance(x, (bytes, bytearray)) else x


# --------------------------------------------------------------------------- #
#  Raw transaction (hex) parser — gives us exact weight + per-input witness.   #
# --------------------------------------------------------------------------- #
class _Reader:
    __slots__ = ("b", "i")

    def __init__(self, b: bytes):
        self.b = b
        self.i = 0

    def read(self, n: int) -> bytes:
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def u8(self) -> int:
        return self.read(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    def varint(self) -> int:
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            return int.from_bytes(self.read(2), "little")
        if n == 0xFE:
            return int.from_bytes(self.read(4), "little")
        return int.from_bytes(self.read(8), "little")


def parse_raw_tx(hex_str: str) -> Optional[dict]:
    """
    Parse a raw Bitcoin transaction hex string.

    Returns a dict with:
      version, locktime,
      inputs: [{txid, vout, sigscript(hex), sequence, witness:[hex,...]}],
      outputs: [{value, pkscript(hex)}],
      size (total bytes), base_size, weight, vsize, has_witness
    or None if it can't be parsed.
    """
    try:
        raw = bytes.fromhex(hex_str)
    except (ValueError, TypeError):
        return None
    try:
        r = _Reader(raw)
        version = r.u32()
        has_witness = False
        # segwit marker/flag
        if r.b[r.i] == 0x00:
            marker = r.u8()
            flag = r.u8()
            if marker == 0x00 and flag != 0x00:
                has_witness = True
            else:
                # not really segwit; rewind
                r.i -= 2

        vin_count = r.varint()
        inputs = []
        for _ in range(vin_count):
            prev_hash = r.read(32)[::-1].hex()  # internal LE -> display BE
            vout = r.u32()
            slen = r.varint()
            sigscript = r.read(slen).hex()
            sequence = r.u32()
            inputs.append({"txid": prev_hash, "vout": vout,
                           "sigscript": sigscript, "sequence": sequence,
                           "witness": []})

        vout_count = r.varint()
        outputs = []
        for _ in range(vout_count):
            value = r.u64()
            plen = r.varint()
            pkscript = r.read(plen).hex()
            outputs.append({"value": value, "pkscript": pkscript})

        if has_witness:
            for vin in inputs:
                stack_items = r.varint()
                stack = []
                for _ in range(stack_items):
                    ilen = r.varint()
                    stack.append(r.read(ilen).hex())
                vin["witness"] = stack

        locktime = r.u32()

        total_size = len(raw)
        if has_witness:
            # base size = size of the tx serialized without marker/flag/witness
            # weight = base*3 + total ; recompute base by re-serializing sans witness
            base_size = _nonwitness_size(version, inputs, outputs, locktime)
        else:
            base_size = total_size
        weight = base_size * 3 + total_size
        vsize = math.ceil(weight / 4)
        return {"version": version, "locktime": locktime,
                "inputs": inputs, "outputs": outputs,
                "size": total_size, "base_size": base_size,
                "weight": weight, "vsize": vsize, "has_witness": has_witness}
    except (IndexError, ValueError):
        return None


def _varint_len(n: int) -> int:
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def _nonwitness_size(version: int, inputs: list, outputs: list, locktime: int) -> int:
    size = 4  # version
    size += _varint_len(len(inputs))
    for vin in inputs:
        sig = len(vin["sigscript"]) // 2
        size += 32 + 4 + _varint_len(sig) + sig + 4
    size += _varint_len(len(outputs))
    for vout in outputs:
        pk = len(vout["pkscript"]) // 2
        size += 8 + _varint_len(pk) + pk
    size += 4  # locktime
    return size


# --------------------------------------------------------------------------- #
#  Target-schema construction.                                                 #
# --------------------------------------------------------------------------- #
def _to_int(x, default=0) -> int:
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def build_target_schema(source: dict, parsed: Optional[dict]) -> dict:
    """
    Build the exact target JSON from a Blockbook-style `source` transaction and
    an optional locally-parsed raw tx (`parsed`) that supplies witness + weight.
    """
    txid = source.get("txid") or source.get("txId")
    block_height = source.get("blockHeight")
    confirmations = _to_int(source.get("confirmations"), 0)
    if source.get("mempool") is not None:
        is_mempool = bool(source.get("mempool"))
    elif isinstance(block_height, int) and block_height > 0:
        is_mempool = False
    elif confirmations > 0:
        is_mempool = False
    else:
        is_mempool = True
    block_time = source.get("blockTime") or source.get("time")

    # ---- inputs ----
    inputs = []
    any_rbf = False
    src_vins = source.get("vin", source.get("inputs", []))
    parsed_ins = (parsed or {}).get("inputs", [])
    for idx, vin in enumerate(src_vins):
        p = parsed_ins[idx] if idx < len(parsed_ins) else {}
        is_coinbase = bool(vin.get("coinbase")) or (vin.get("isAddress") is False and not vin.get("txid"))
        addrs = vin.get("addresses") or ([vin["address"]] if vin.get("address") else [])
        address = addrs[0] if addrs else None
        sequence = _to_int(vin.get("sequence", p.get("sequence", 0)))
        if sequence < 0xFFFFFFFE:
            any_rbf = True
        pkscript = _fix_pkscript(address_to_pkscript(address)) if address else None
        inputs.append({
            "coinbase": is_coinbase,
            "txid": vin.get("txid") or p.get("txid"),
            "output": _to_int(vin.get("vout", vin.get("output", p.get("vout", 0)))),
            "sigscript": vin.get("hex") or vin.get("sigscript") or p.get("sigscript") or "",
            "sequence": sequence,
            "pkscript": pkscript,
            "value": _to_int(vin.get("value", p.get("value", 0))),
            "address": address,
            "witness": p.get("witness", vin.get("witness", []) or []),
        })

    # ---- outputs ----
    outputs = []
    for vout in source.get("vout", source.get("outputs", [])):
        addrs = vout.get("addresses") or ([vout["address"]] if vout.get("address") else [])
        outputs.append({
            "address": addrs[0] if addrs else None,
            "pkscript": vout.get("hex") or vout.get("pkscript") or "",
            "value": _to_int(vout.get("value", 0)),
            "spent": bool(vout.get("spent", False)),
        })

    block_position = source.get("blockPosition")
    if block_position is None and isinstance(source.get("block"), dict):
        block_position = source["block"].get("position")

    weight = (parsed or {}).get("weight")
    if weight is None:
        vsize = source.get("vsize")
        weight = _to_int(vsize) * 4 if vsize else _to_int(source.get("size")) * 4

    if source.get("rbf") is not None:
        any_rbf = bool(source.get("rbf"))

    return {
        "txId": txid,
        "blockHeight": block_height,
        "blockPosition": block_position,
        "mempool": is_mempool,
        "mempoolTime": (_to_int(block_time) if is_mempool and block_time else None),
        "time": _to_int(block_time) if block_time is not None else None,
        "fee": _to_int(source.get("fees", source.get("fee", 0))),
        "size": _to_int(source.get("size", (parsed or {}).get("size", 0))),
        "weight": _to_int(weight),
        "rbf": any_rbf,
        "inputs": inputs,
        "outputs": outputs,
        "version": _to_int(source.get("version", (parsed or {}).get("version", 1)), 1),
        "locktime": _to_int(source.get("lockTime", source.get("locktime",
                    (parsed or {}).get("locktime", 0)))),
        "deleted": bool(source.get("deleted", False)),
        "txid": txid,
        "block": {
            "height": (None if is_mempool else block_height),
            "mempool": is_mempool,
            "position": block_position,
        },
    }


def address_is_sender(target_tx: dict, address: str) -> bool:
    """True if `address` appears in the transaction inputs (it spent funds)."""
    for vin in target_tx.get("inputs", []):
        if vin.get("address") == address:
            return True
    return False


# --------------------------------------------------------------------------- #
#  Providers                                                                    #
# --------------------------------------------------------------------------- #
class BlockbookProvider:
    """
    Blockbook v2 API (the Atomic Wallet endpoint is one such instance).
    Uses ?details=txs so each page returns full transactions in one round-trip.
    """
    name = "blockbook"

    def __init__(self, base_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def address_pages(self, address: str, page_size: int = 1000
                      ) -> Iterator[dict]:
        page = 1
        total_pages = 1
        while page <= total_pages:
            data = http_get_json(f"{self.base}/address/{address}",
                                 {"page": page, "pageSize": page_size,
                                  "details": "txs"}, self.timeout)
            total_pages = data.get("totalPages", 1) or 1
            yield {"page": page, "total_pages": total_pages, "data": data}
            page += 1

    def iter_transactions(self, address: str, page_size: int = 1000
                          ) -> Iterator[Tuple[dict, dict]]:
        """Yield (page_info, raw_source_tx) for every tx of the address."""
        for chunk in self.address_pages(address, page_size):
            data = chunk["data"]
            info = {"page": chunk["page"], "total_pages": chunk["total_pages"]}
            for tx in data.get("transactions", []):
                yield info, tx

    def list_txids(self, address: str, page_size: int = 1000) -> List[str]:
        txids: List[str] = []
        page = 1
        total_pages = 1
        while page <= total_pages:
            data = http_get_json(f"{self.base}/address/{address}",
                                 {"page": page, "pageSize": page_size,
                                  "details": "txids"}, self.timeout)
            total_pages = data.get("totalPages", 1) or 1
            txids.extend(data.get("txids", []))
            page += 1
        return txids

    def fetch_tx(self, txid: str) -> Optional[dict]:
        try:
            return http_get_json(f"{self.base}/tx/{txid}", timeout=self.timeout)
        except (urllib.error.URLError, ValueError):
            return None

    def normalize(self, source: dict) -> dict:
        parsed = parse_raw_tx(source["hex"]) if source.get("hex") else None
        return build_target_schema(source, parsed)


class HaskoinProvider:
    """
    Haskoin-store API — returns the target schema natively, so normalize() is a
    thin pass-through (it still fills any missing derived fields for safety).
    """
    name = "haskoin"

    def __init__(self, base_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def iter_transactions(self, address: str, page_size: int = 100
                          ) -> Iterator[Tuple[dict, dict]]:
        offset = 0
        while True:
            batch = http_get_json(
                f"{self.base}/address/{address}/transactions/full",
                {"limit": page_size, "offset": offset}, self.timeout)
            if not batch:
                break
            for tx in batch:
                yield {"page": offset // page_size + 1, "total_pages": None}, tx
            if len(batch) < page_size:
                break
            offset += page_size

    def list_txids(self, address: str, page_size: int = 100) -> List[str]:
        txids: List[str] = []
        offset = 0
        while True:
            batch = http_get_json(
                f"{self.base}/address/{address}/transactions",
                {"limit": page_size, "offset": offset}, self.timeout)
            if not batch:
                break
            for ref in batch:
                tid = ref.get("txid") if isinstance(ref, dict) else ref
                if tid:
                    txids.append(tid)
            if len(batch) < page_size:
                break
            offset += page_size
        return txids

    def fetch_tx(self, txid: str) -> Optional[dict]:
        try:
            return http_get_json(f"{self.base}/transaction/{txid}",
                                 timeout=self.timeout)
        except (urllib.error.URLError, ValueError):
            return None

    def normalize(self, source: dict) -> dict:
        # Haskoin already matches the schema; run it through the builder so the
        # output shape is guaranteed identical regardless of provider.
        return build_target_schema(source, None)


def make_provider(kind: str, base_url: str, timeout: int = DEFAULT_TIMEOUT):
    kind = (kind or "blockbook").lower()
    if kind.startswith("hask"):
        return HaskoinProvider(base_url, timeout)
    return BlockbookProvider(base_url, timeout)


# --------------------------------------------------------------------------- #
#  Scan engine                                                                  #
# --------------------------------------------------------------------------- #
class ScanEngine:
    """
    Drives a provider: iterate the address's transactions, keep only the ones
    where the address is a sender, normalize them, and report progress through
    a callback. Concurrency is applied when the provider only yields txids (or
    when re-fetching), via the caller-supplied thread pool.
    """

    def __init__(self, provider, on_event: Optional[Callable[[dict], None]] = None):
        self.provider = provider
        self.on_event = on_event or (lambda e: None)

    def emit(self, kind: str, **kw):
        evt = {"type": kind}
        evt.update(kw)
        self.on_event(evt)

    def scan(self, address: str) -> Iterator[dict]:
        """
        Yield normalized target-schema dicts for every SENT transaction of the
        address. Emits progress events along the way.
        """
        scanned = 0
        senders = 0
        self.emit("start", address=address, provider=self.provider.name)
        try:
            for info, source in self.provider.iter_transactions(address):
                scanned += 1
                target = self.provider.normalize(source)
                if address_is_sender(target, address):
                    senders += 1
                    self.emit("sender", txid=target["txId"],
                              scanned=scanned, senders=senders,
                              page=info.get("page"),
                              total_pages=info.get("total_pages"))
                    yield target
                else:
                    self.emit("progress", scanned=scanned, senders=senders,
                              page=info.get("page"),
                              total_pages=info.get("total_pages"))
        except (urllib.error.URLError, ValueError, KeyError) as e:
            self.emit("error", message=str(e), scanned=scanned, senders=senders)
            raise
        self.emit("done", scanned=scanned, senders=senders)

    def scan_parallel(self, address: str, workers: int = 32,
                      stop_flag: Optional[Callable[[], bool]] = None
                      ) -> Iterator[dict]:
        """
        Parallel mode: list all txids, then fetch each transaction concurrently
        with a thread pool (real network concurrency). Works with any provider,
        and is the fallback when bulk detail pages aren't available.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        stop_flag = stop_flag or (lambda: False)
        self.emit("start", address=address, provider=self.provider.name)
        self.emit("listing")
        try:
            txids = self.provider.list_txids(address)
        except (urllib.error.URLError, ValueError, KeyError) as e:
            self.emit("error", message=str(e), scanned=0, senders=0)
            raise
        total = len(txids)
        self.emit("listed", total=total)

        scanned = 0
        senders = 0
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(self.provider.fetch_tx, t): t for t in txids}
            for fut in as_completed(futures):
                if stop_flag():
                    break
                scanned += 1
                source = fut.result()
                if not source:
                    self.emit("progress", scanned=scanned, senders=senders,
                              total=total)
                    continue
                target = self.provider.normalize(source)
                if address_is_sender(target, address):
                    senders += 1
                    self.emit("sender", txid=target["txId"],
                              scanned=scanned, senders=senders, total=total)
                    yield target
                else:
                    self.emit("progress", scanned=scanned, senders=senders,
                              total=total)
        self.emit("done", scanned=scanned, senders=senders)
