# vusi-gui — Cyberspace GUI for the vusi ECDSA analyzer

A native, GPU-accelerated desktop front-end for [`vusi`](../README.md), the
ECDSA signature-vulnerability analysis tool. Built for macOS on Apple Silicon
and T2 Intel Macs: rendering runs through **Metal** automatically (via
`wgpu`), and all analysis happens on a background thread so the UI never
stutters — even in continuous-watch or batch mode.

It reuses the exact `vusi` library the CLI uses, so results are identical to
`vusi analyze`; the GUI just makes loading data, running attacks, and saving
reports a point-and-click affair.

## What it does

`vusi` audits a set of ECDSA signatures you already have (JSON or CSV with
`r, s, z, pubkey` fields) and reports nonce-reuse / biased-nonce weaknesses,
recovering the private key for any signatures that are already broken by those
flaws. This GUI drives that engine. It does **not** scan wallets, generate
keys, or touch the network — it only analyzes signature data you load.

## Requirements

- macOS 11+ on Apple Silicon (M1/M2/M3/M4) or a T2 Intel Mac
- [Rust toolchain](https://rustup.rs) (`rustup`, stable)

## Build & run

From the project root:

```bash
# Debug run
cargo run -p vusi-gui

# Optimized run (recommended)
cargo run -p vusi-gui --release
```

Or just double-click **`run-gui.command`** in Finder (first launch compiles;
later launches are instant).

To build a proper double-clickable **`Vusi.app`** bundle (with app icon,
ad-hoc code-signing, and quarantine cleared so it opens on first double-click):

```bash
./bundle-macos.sh            # all three attacks (needs GMP/MPFR)
./bundle-macos.sh minimal    # no biased-nonce, no GMP needed
open "Vusi.app"              # or drag Vusi.app into /Applications
```

The icon is generated from `assets/icon-1024.png` via `sips` + `iconutil`
(both ship with macOS). Delete or replace that PNG to use your own.

### Biased-nonce lattice attack (enabled by default)

All three vectors — **Nonce Reuse**, **Polynonce**, and **Biased Nonce** — are
built in by default. The biased-nonce attack uses lattice reduction via the
`rug` crate, which needs GMP/MPFR:

```bash
brew install gmp mpfr    # one-time
```

If you're on a machine without GMP, build without it — the app still offers
Nonce Reuse and Polynonce and marks the biased-nonce vector *unavailable*:

```bash
cargo run -p vusi-gui --release --no-default-features
```

## Every button, wired

| Control | What it does |
|---|---|
| **FILE / PASTE** | Choose whether input comes from a file or a pasted JSON/CSV blob. |
| **LOAD FILE…** | Native file picker for a `.json` / `.csv` signature set. |
| **⛏ EXTRACT FROM TX…** | Pick a raw Bitcoin transaction JSON; the app pulls `(r, s, z, pubkey)` from every input, loads them into the box, and analyzes automatically. |
| **verified only** | Keep only signatures that verify against the recomputed sighash (recommended). |
| **⤓ SAVE JSON** | Save the last extracted `r,s,z` set to a file. |
| **ATTACK VECTOR** | Pick Nonce Reuse, Polynonce, or Biased Nonce; the relevant parameters appear inline. |
| **▶ RUN ANALYSIS** | Analyze the current input once, off the UI thread. |
| **▦ BATCH FOLDER…** | Pick a folder and analyze every `.json`/`.csv` in it, one report each. |
| **◉ CONTINUOUS WATCH** | Watch the loaded file and re-run automatically whenever it changes (continuous generation). Click again to stop. |
| **interval** | How often watch mode polls the file for changes. |
| **Autosave** | When on, every finished report is written as timestamped JSON. |
| **SET FOLDER…** | Choose where autosaved reports land (defaults to `vusi-reports/` next to the input). |
| **⭱ EXPORT** | Save the latest report to a JSON file you choose. |
| **✖ CLEAR** | Clear the current results. |
| **⧉** (in the table) | Copy a recovered private key to the clipboard. |

## Extracting r, s, z from Bitcoin transactions

Feed the analyzer straight from raw transactions. **⛏ EXTRACT FROM TX…** accepts
a block-explorer-style transaction JSON — either a single transaction object or
an array of them — and for each input it:

1. parses the DER signature out of the `sigscript` → `(r, s)` and the sighash type,
2. reconstructs the **legacy P2PKH `SIGHASH_ALL` sighash** → the message `z`,
3. reads the compressed public key, and
4. **verifies** the signature against the recomputed `z` (so a wrong or
   unsupported input is flagged, never silently mis-extracted).

The verified tuples are loaded into the input box and analyzed automatically;
**⤓ SAVE JSON** exports them for reuse.

Supported inputs are legacy **P2PKH** signed with **`SIGHASH_ALL`** — the classic
reused-nonce target. SegWit (BIP143) and non-`ALL` sighash types are skipped with
a reason in the console rather than mis-handled.

> **Finding nonce reuse:** a nonce is reused when two signatures share the same
> `r`. That rarely happens inside one transaction — collect signatures from many
> transactions of the same address into one array/file, extract, and analyze the
> pooled set. `vusi` groups by pubkey and recovers the key from any reused pair.

## Interface

- **Top bar** — title, live GPU/renderer badge (shows *Metal* on your Mac),
  and IDLE / WORKING / WATCHING status.
- **Control deck** (left) — every button above.
- **Results** (center) — SIGNATURES / VULNERABILITIES / KEYS-RECOVERED tiles
  over an animated neon grid, plus a table of detected vulnerabilities with
  recovered keys.
- **Console** (bottom) — timestamped, color-coded live event log.

## Architecture

```
vusi (lib)          the original analysis library (unchanged)
└─ vusi-engine      thin, tested wrapper: parse → detect → recover → report → autosave
   └─ vusi-gui      eframe/egui app (wgpu → Metal) + background worker thread
```

The engine has no UI dependencies and is unit-tested independently, so the
analysis logic is verified separately from the interface.
