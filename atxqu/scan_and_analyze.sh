#!/usr/bin/env bash
# ATXQU → vusi pipeline: fetch every spent tx of an address, extract its ECDSA
# signatures, and run a vusi attack over them — in one command.
#
# Usage:
#   ./scan_and_analyze.sh <address> [attack] [extra vusi args...]
#   ./scan_and_analyze.sh -f addresses.txt reuse-r
#   ./scan_and_analyze.sh --normalize raw.json nonce-reuse
#
# The attack defaults to reuse-r. Any args after it are passed to `vusi analyze`
# (e.g. --json, --delta 1337, --gcd-b-max 512).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

# Locate the vusi binary: prefer an installed one, else a release/debug build.
if command -v vusi >/dev/null 2>&1; then
  VUSI="vusi"
elif [[ -x "$repo/target/release/vusi" ]]; then
  VUSI="$repo/target/release/vusi"
elif [[ -x "$repo/target/debug/vusi" ]]; then
  VUSI="$repo/target/debug/vusi"
else
  echo "vusi binary not found — build it first: (cd '$repo' && cargo build --release --features polynonce,biased-nonce)" >&2
  exit 2
fi

# Split ATXQU fetch args from the vusi attack + extra args.
fetch_args=()
case "${1:-}" in
  -f|--addresses-file) fetch_args=(-f "${2:?address file}"); shift 2 ;;
  --normalize)         fetch_args=(--normalize "${2:?raw json}"); shift 2 ;;
  "" ) echo "usage: $0 <address|-f file|--normalize raw.json> [attack] [vusi args...]" >&2; exit 2 ;;
  * )  fetch_args=("$1"); shift ;;
esac

attack="${1:-reuse-r}"; [[ $# -gt 0 ]] && shift || true

tmp="$(mktemp -t atxqu_txs.XXXXXX.json)"
trap 'rm -f "$tmp"' EXIT

echo ">> ATXQU: fetching/normalizing transactions…" >&2
python3 "$here/atxqu_cli.py" "${fetch_args[@]}" -o "$tmp"

echo ">> vusi: extracting signatures and running '$attack'…" >&2
"$VUSI" analyze --from-tx "$tmp" --attack "$attack" "$@"
