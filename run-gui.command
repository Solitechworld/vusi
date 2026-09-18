#!/bin/bash
# Double-click me in Finder to launch the vusi cyberspace GUI.
# First launch compiles a release build (a few minutes); later launches are fast.
cd "$(dirname "$0")" || exit 1

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust is not installed. Install it from https://rustup.rs then re-run."
  echo "Press any key to close."
  read -r -n 1
  exit 1
fi

echo "Launching vusi GUI (Metal via wgpu)…"
cargo run -p vusi-gui --release
