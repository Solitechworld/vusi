#!/usr/bin/env python3
"""Self-contained verification for engine.py (no network needed)."""
import json
import engine

FAILS = []


def check(name, cond, extra=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  {extra}" if extra and not cond else ""))
    if not cond:
        FAILS.append(name)


# --- 1. address -> pkscript reconstruction (P2PKH from the user's example) ---
addr = "12R9pR5J3G9dqJxCcZeU8uAotGY5N5rNb1"
pk = engine._fix_pkscript(engine.address_to_pkscript(addr))
check("P2PKH pkscript reconstruction",
      pk == "76a9140f897827100baf3e86d34b5bdf2be913f08ea9f088ac", pk)

# bech32 P2WPKH from the example output address
bpk = engine._fix_pkscript(engine.address_to_pkscript("bc1qm3ncmuvrk270wzsmtpz62v97dcsz3gcnn5lygc"))
check("P2WPKH pkscript reconstruction",
      bpk == "0014dc678df183b2bcf70a1b5845a530be6e2028a313", bpk)

# --- 2. build_target_schema reproduces the user's exact example ---
example = {
    "txId": "55076e347e66ccbc075df55e7f5b27c04d62c54c1ea14d9a646567e8de7a750f",
    "blockHeight": 964270, "blockPosition": 323, "mempool": False,
    "mempoolTime": None, "time": 1787821588, "fee": 892, "size": 222,
    "weight": 888, "rbf": False,
    "inputs": [{
        "coinbase": False,
        "txid": "8766ed302ca6369550fe65de75d2d8db4f7ccefddb0b8c7d6fa86e15aaaa3624",
        "output": 0,
        "sigscript": "473044022017addfce183302bde8bf2aa7120126066da4e6fe4a479556d3b4de9aade7917602201e5825361195fa81808fb76d75f2f2cf9636632ab29d4182df165d116fd7eac001210343bcdb6c14d76f501adbe5e0eba2a01d83420b194cb32fdb7ef37ceafaebea0e",
        "sequence": 0,
        "pkscript": "76a9140f897827100baf3e86d34b5bdf2be913f08ea9f088ac",
        "value": 4500000000, "address": addr, "witness": []}],
    "outputs": [
        {"address": "bc1qm3ncmuvrk270wzsmtpz62v97dcsz3gcnn5lygc",
         "pkscript": "0014dc678df183b2bcf70a1b5845a530be6e2028a313",
         "value": 2299999108, "spent": True},
        {"address": addr,
         "pkscript": "76a9140f897827100baf3e86d34b5bdf2be913f08ea9f088ac",
         "value": 2200000000, "spent": False}],
    "version": 2, "locktime": 0, "deleted": False,
    "txid": "55076e347e66ccbc075df55e7f5b27c04d62c54c1ea14d9a646567e8de7a750f",
    "block": {"height": 964270, "mempool": False, "position": 323},
}

built = engine.build_target_schema(example, None)

# weight can't be recomputed without raw hex here; source provides none, so
# the builder falls back to size*4. Confirm every OTHER field matches exactly.
mismatch = {}
for k in example:
    if k == "weight":
        continue
    if built.get(k) != example[k]:
        mismatch[k] = (example[k], built.get(k))
check("schema reproduces example (all fields except weight)", not mismatch,
      json.dumps(mismatch, indent=2))
check("keys identical to target schema", set(built) == set(example),
      f"missing={set(example)-set(built)} extra={set(built)-set(example)}")
check("key ORDER identical to target schema", list(built) == list(example),
      f"{list(built)}")

# --- 3. raw-tx parser round-trip (legacy + segwit), incl. weight formula ---
def _ser_legacy():
    # version=2, 1 in, 1 out, locktime 0, no witness
    tx = bytes.fromhex("02000000")
    tx += b"\x01"
    tx += bytes.fromhex("aa"*32) + bytes.fromhex("00000000")  # prev + vout 0
    sig = bytes.fromhex("48"*1)  # not real, just length marker below
    script = bytes.fromhex("76a914" + "11"*20 + "88ac")
    tx += bytes([len(script)]) + script
    tx += bytes.fromhex("ffffffff")  # sequence (no RBF)
    tx += b"\x01"
    tx += (5000).to_bytes(8, "little")
    out = bytes.fromhex("76a914" + "22"*20 + "88ac")
    tx += bytes([len(out)]) + out
    tx += bytes.fromhex("00000000")
    return tx.hex()

leg = engine.parse_raw_tx(_ser_legacy())
check("legacy parse ok", leg is not None)
if leg:
    check("legacy: no witness", leg["has_witness"] is False)
    check("legacy: weight == size*4", leg["weight"] == leg["size"] * 4,
          f'w={leg["weight"]} size={leg["size"]}')
    check("legacy: 1 input / 1 output",
          len(leg["inputs"]) == 1 and len(leg["outputs"]) == 1)

def _ser_segwit():
    tx = bytes.fromhex("02000000")       # version
    tx += bytes.fromhex("0001")          # marker+flag (segwit)
    tx += b"\x01"                         # 1 input
    tx += bytes.fromhex("bb"*32) + bytes.fromhex("01000000")  # prev + vout 1
    tx += b"\x00"                         # empty scriptSig
    tx += bytes.fromhex("fdffffff")      # sequence (RBF-signaling)
    tx += b"\x01"                         # 1 output
    tx += (9000).to_bytes(8, "little")
    out = bytes.fromhex("0014" + "33"*20)
    tx += bytes([len(out)]) + out
    # witness: 2 items
    tx += b"\x02"
    item1 = bytes.fromhex("30"*10); item2 = bytes.fromhex("02"*33)
    tx += bytes([len(item1)]) + item1 + bytes([len(item2)]) + item2
    tx += bytes.fromhex("00000000")      # locktime
    return tx.hex()

seg = engine.parse_raw_tx(_ser_segwit())
check("segwit parse ok", seg is not None)
if seg:
    check("segwit: has_witness", seg["has_witness"] is True)
    check("segwit: witness stack of 2", len(seg["inputs"][0]["witness"]) == 2)
    check("segwit: weight == base*3 + total",
          seg["weight"] == seg["base_size"] * 3 + seg["size"])
    check("segwit: base < total (witness discounted)",
          seg["base_size"] < seg["size"])
    # feed through build_target_schema to confirm rbf + witness flow through
    src = {"txid": "x"*64, "blockHeight": 1, "blockTime": 1, "fees": "1",
           "size": seg["size"], "version": 2, "lockTime": 0, "hex": _ser_segwit(),
           "vin": [{"txid": "bb"*32, "vout": 1, "sequence": 0xfdffffff,
                    "addresses": ["bc1qxyz"], "value": "9000"}],
           "vout": [{"value": "9000", "hex": "0014"+"33"*20,
                     "addresses": ["bc1qout"], "spent": False}]}
    tgt = engine.build_target_schema(src, seg)
    check("rbf detected from sequence < 0xfffffffe", tgt["rbf"] is True)
    check("witness carried into target input", tgt["inputs"][0]["witness"] == seg["inputs"][0]["witness"])
    check("weight carried from parser", tgt["weight"] == seg["weight"])

# --- 4. sender detection ---
check("address_is_sender True", engine.address_is_sender(example, addr) is True)
check("address_is_sender False for stranger",
      engine.address_is_sender(example, "1StRaNgErAddReSs") is False)

print()
if FAILS:
    print(f"{len(FAILS)} FAILURE(S): {FAILS}")
    raise SystemExit(1)
print("ALL TESTS PASSED")
