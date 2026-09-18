# vusi

> **Fork.** Based on [oritwoen/vusi](https://github.com/oritwoen/vusi) (MIT). This copy adds a native, Metal-accelerated desktop GUI (`gui/`), a macOS `.app` bundle, the `vusi-engine` shared analysis crate, and Bitcoin raw-transaction → `(r, s, z, pubkey)` extraction. Upstream copyright is retained in [LICENSE](LICENSE).

![vusi — ECDSA Signature Vulnerability Analyzer](assets/screenshot.png)

*The native Metal GUI: load a signature set or extract `(r, s, z, pubkey)` from a raw Bitcoin transaction, pick an attack vector, and run — nonce reuse, biased nonce, polynonce. Rendered through Metal on Apple Silicon / T2.*

[![Crates.io](https://img.shields.io/crates/v/vusi?style=flat&colorA=130f40&colorB=474787)](https://crates.io/crates/vusi)
[![Downloads](https://img.shields.io/crates/d/vusi?style=flat&colorA=130f40&colorB=474787)](https://crates.io/crates/vusi)
[![License](https://img.shields.io/crates/l/vusi?style=flat&colorA=130f40&colorB=474787)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/oritwoen/vusi)

ECDSA signature vulnerability analysis library and CLI tool.

> **New: native desktop GUI.** A GPU-accelerated "cyberspace" front-end ships in
> [`gui/`](gui/README.md) — Metal-rendered on Apple Silicon / T2 Macs, with a
> button for every action, batch-folder processing, continuous file watching,
> and autosave. Launch it with `cargo run -p vusi-gui --release` or by
> double-clicking `run-gui.command`. See [gui/README.md](gui/README.md).

## What it does

`vusi` is a multi-tool for ECDSA signature-vulnerability analysis: it audits a
set of signatures you already hold and, for any that are broken by a nonce
weakness, recovers the private key. Three independent attack classes:

- **Nonce reuse** — signatures sharing a nonce (identical `r`). Two are enough
  to recover the key algebraically.
- **Polynonce** — polynomial relationships between successive nonces
  (configurable degree: linear, quadratic, …), recovered from a chain of
  signatures.
- **Biased nonce (HNP)** — nonces with systematic bias (known LSBs, known MSBs,
  or a restricted range) solved as a Hidden Number Problem via lattice
  reduction (LLL, or windowed-LLL with tunable block size and rounds). Needs
  4+ signatures.

Around those:

- **Bitcoin transaction extraction** — pull `(r, s, z, pubkey)` straight from a
  raw Bitcoin transaction: it parses the DER signature out of each input's
  scriptSig, derives the sighash `z`, and hands the tuples to the analyzer.
- **Three ways to drive it** — a CLI (`vusi analyze`), a native Metal GUI
  (`gui/`), and a library (`vusi-engine`) that both front-ends share, so every
  interface gives identical results.
- **JSON or CSV in**, human-readable or JSON out; batch a folder or watch one
  continuously (GUI).

## Installation

```bash
cargo install --path .
```

## Usage

### Analyze signatures from file

```bash
vusi analyze signatures.json
```

### Analyze from stdin

```bash
echo '[{"r":"...","s":"...","z":"..."}]' | vusi analyze
```

### JSON output

```bash
vusi --json analyze signatures.json
```

## Input Format

### JSON

```json
[
  {
    "r": "6819641642398093696120236467967538361543858578256722584730163952555838220871",
    "s": "5111069398017465712735164463809304352000044522184731945150717785434666956473",
    "z": "4834837306435966184874350434501389872155834069808640791394730023708942795899",
    "pubkey": null
  }
]
```

### CSV

```csv
r,s,z,pubkey
6819641642398093696120236467967538361543858578256722584730163952555838220871,5111069398017465712735164463809304352000044522184731945150717785434666956473,4834837306435966184874350434501389872155834069808640791394730023708942795899,
```

## Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected
- `2`: Error (invalid input, etc.)

## Library Usage

```rust
use vusi::attack::{Attack, NonceReuseAttack};
use vusi::provider::load_signatures;

let signatures = load_signatures("signatures.json")?;
let attack = NonceReuseAttack;
let vulnerabilities = attack.detect(&signatures);

for vuln in vulnerabilities {
    if let Some(key) = attack.recover(&vuln) {
        println!("Recovered key: {}", key.private_key_decimal);
    }
}
```

## Development

### Run tests

```bash
cargo test
```

### Build release

```bash
cargo build --release
```

## Funding

Donations support a separate, unreleased project I am building, aimed at
Bitcoin. It is my conviction and my bet to make, not a claim to take on trust —
judge it when there is something to judge. This tool stays free either way.

```
bitcoin:1Be6LLAEndprdWKiH6YM62setFQRXJzfha
```

`1Be6LLAEndprdWKiH6YM62setFQRXJzfha` — mainnet P2PKH.

**Verify before you send.** This repository is about analysing ECDSA
signatures, which makes a donation address in it an attractive thing for
someone to quietly swap in a fork or a pull request. Before sending anything
you would mind losing, open an issue and ask me to confirm the address, and
compare the first and last four characters (`1Be6` … `zfha`) against the reply.

Nothing here is an investment offer and no return of any kind is implied.

## License

This project is a fork of [oritwoen/vusi](https://github.com/oritwoen/vusi).
Original work © 2026 oritwoen, MIT. Additions in this fork are likewise MIT.
See [LICENSE](LICENSE).
