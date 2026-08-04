#!/usr/bin/env bash
# ---
# tags: lytics, script
# crystal-type: source
# crystal-domain: cyber
# ---
# build the wasm tracker core and generate its browser bindings into
# ingest/static/tracker/. the rustup toolchain owns wasm32 std; homebrew
# rustc (first in PATH) does not, so we pin RUSTC explicitly.
set -euo pipefail
cd "$(dirname "$0")"

TC="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin"
OUT=ingest/static/tracker

RUSTC="$TC/bin/rustc" ~/.cargo/bin/cargo +stable build \
  -p lytics-core --target wasm32-unknown-unknown --release

~/.cargo/bin/wasm-bindgen --target web --no-typescript \
  --out-dir "$OUT" target/wasm32-unknown-unknown/release/lytics_core.wasm

if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int "$OUT/lytics_core_bg.wasm" -o "$OUT/lytics_core_bg.wasm"
fi

echo "tracker built:"
ls -la "$OUT"
printf "wasm gzip: %s bytes\n" "$(gzip -c "$OUT/lytics_core_bg.wasm" | wc -c | tr -d ' ')"
