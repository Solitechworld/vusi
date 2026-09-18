## [Unreleased]

### Fixed

- GUI no longer crashes when extracting from a large transaction file: the
  extracted signatures are kept in memory (and analyzed) but only mirrored into
  the on-screen text box when small (≤256 KB), avoiding an egui text-layout
  blow-up. Large sets show a placeholder and can be exported with SAVE JSON.
- ATXQU fetches now retry transient network failures (broken pipe, SSL EOF,
  connection reset, timeouts, HTTP 429/5xx) with exponential back-off + jitter,
  so high-concurrency scans against throttling endpoints recover instead of
  dropping requests. Dashboard hint now warns to keep concurrency low on shared
  public endpoints.

### Features

- Bundle **ATXQU** (Address Transaction Query Utility) under `atxqu/` and wire
  it into vusi as the data-acquisition front-end: address → spent transactions →
  extract → attack. Adds a headless `atxqu/atxqu_cli.py` and a one-command
  `atxqu/scan_and_analyze.sh` pipeline
- GUI **ADDRESS input mode**: scan an address (or several) directly in the
  desktop app — it runs the bundled ATXQU fetcher, extracts, and attacks in one
  window (provider/endpoint selectable; `VUSI_ATXQU_CLI`/`VUSI_PYTHON` override
  the script and interpreter paths)
- ATXQU dashboard **"Analyze in vusi"** button + `POST /api/analyze/<job_id>`
  server route: run any vusi attack over the transactions a scan just collected
  and see recovered keys inline, without leaving the web UI (`$VUSI_BIN` or the
  repo's built binary; unknown attacks/jobs return clear errors)
- Move the raw-transaction extractor into the core `vusi` library
  (`vusi::extract`) and expose it on the CLI: `vusi extract <tx.json>` and
  `vusi analyze --from-tx <tx.json>` (extract + analyze in one step)
- Related-nonce attack family on a shared affine solver (eprint 2025/705):
  `delta-bias` (known Δ), `bitflip` (single-bit nonce fault, ±2^i sweep) and
  `gcd` (unknown small affine relation `k2 = a·k1 + b`, swept + verified)
- `shared-nonce` and `reuse-r` modes (reuse-r groups by `r` alone and flags
  cross-key `r` reuse)
- `nonce-bias` mode: MSB HNP lattice attack that auto-sweeps the known-bit width
- `low-bit`, `lll`, `broken-nonce` aliases for the biased-nonce lsb/msb/range
  variants; all attacks exposed as first-class CLI modes and GUI options
- Shared candidate verification (`verify_candidate_key`) reused across attacks

## [0.2.0] - 2026-01-16

### Features

- Polynonce attack detection (#9)

### Documentation

- Standardize badges
## [0.1.0] - 2026-01-13

### Miscellaneous Tasks

- *(release)* V0.1.0
## [list] - 2026-01-13

### Bug Fixes

- Use push instead of push_str for single char
- Remove Cargo.lock from release script

### Other

- Vusi - ECDSA signature vulnerability analysis

### Documentation

- Update license to MIT
- Add crate version and license badges

### Miscellaneous Tasks

- Retrigger workflows
- Track Cargo.lock for reproducible builds
