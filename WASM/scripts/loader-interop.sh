#!/usr/bin/env bash
# §12.9 interop — the definition of "done" for the Go/native loader target.
#
# A Go loader node and JS (node + bun) nodes share one seedstore cohort over real
# loopback TCP, exercising the same signed bundle on the byte-identical genesis. It
# proves wire + crypto + bundle parity in both directions:
#   1. Go  put → node get   (Go writes blocks JS can read back)
#   2. node put → Go  get   (Go reads blocks JS wrote)
#   3. bun put → Go  get    (literal Bun ↔ Go, the read path)
# all against a cohort of `node` StorageNode holders. Storage rides on the runtime
# as signed content; neither side links the other's code — only the wire + the
# bundle are shared.
#
# Manual integration check (NOT part of `go test`): needs `node` + `bun` on PATH
# and a built Windows seedloader.exe. Run from Git Bash on Windows:
#   bash scripts/loader-interop.sh [path/to/seedloader.exe]
set -euo pipefail

SK=/c/Users/ander/Documents/GitHub/seedkernel/WASM
SS=/c/Users/ander/Documents/GitHub/seedstore/WASM
# A bundle is ONE blob (§12.4) — both targets read this file, not a directory.
BUNDLE="$SS/bundle/seedstore.skb"
NODEMAIN="$SK/build/host/main-node.js"
GOEXE="${1:-$SK/../native/seedloader.exe}"

HOLDERS=6
BASEPORT=47100

[ -f "$GOEXE" ]    || { echo "missing seedloader exe: $GOEXE"; exit 1; }
[ -f "$NODEMAIN" ] || { echo "missing built shell: $NODEMAIN (run: npm run build:host)"; exit 1; }
[ -f "$BUNDLE" ]   || { echo "missing seedstore bundle: $BUNDLE (run: npm run build:bundle in seedstore/WASM)"; exit 1; }

# Read the author through the shared loader rather than re-deriving container and
# envelope offsets here: the bundle is a packed blob whose manifest envelope leads with
# a suite byte (§12.4), so `bytes[0:32]` is not the author key and never was after the
# suite byte landed. verifyBundle is the one definition of both layouts.
AUTHOR=$(cd "$SK" && node --input-type=module -e "
const { verifyBundle } = await import('./build/host/bundle.js');
const { loadSodium } = await import('./build/host/node.js');
const { readFileSync } = await import('node:fs');
const sodium = await loadSodium();
process.stdout.write(Buffer.from(verifyBundle(sodium, new Uint8Array(readFileSync(process.argv[1]))).author).toString('hex'));
" "$BUNDLE")

WORK=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

echo "{\"authors\":[\"$AUTHOR\"]}" > "$WORK/policy.json"
# The §14 byte budget is OPERATOR policy: it is deliberately absent from the signed
# bundle, and the guest FAILS CLOSED at 0 rather than guessing a generous default. Every
# node here — holders and initiators — therefore needs one, or the holders answer every
# OFFER and decline every STORE ("chunk landed 0/N distinct blocks").
echo '{"quota": 67108864}' > "$WORK/app.json"
SRC="$WORK/src.bin"; head -c 4096 /dev/urandom > "$SRC"   # > smallMaxBlocks ⇒ RS path
echo "interop: author=$AUTHOR  holders=$HOLDERS  src=$(wc -c < "$SRC") B"

# ── a cohort of node holders, each on its own loopback port ──────────────────
PEERS=""
for i in $(seq 0 $((HOLDERS-1))); do
  port=$((BASEPORT+i)); d="$WORK/h$i"; mkdir -p "$d"
  node "$NODEMAIN" --bundle "$BUNDLE" --policy "$WORK/policy.json" --app-config "$WORK/app.json" \
    --dir "$d/data" --key "$d/key" --listen "127.0.0.1:$port" --timeout 5000 \
    > "$d/log" 2>&1 &
  PIDS+=($!)
done
for i in $(seq 0 $((HOLDERS-1))); do
  port=$((BASEPORT+i)); d="$WORK/h$i"
  for _ in $(seq 1 100); do grep -q "serving" "$d/log" 2>/dev/null && break; sleep 0.1; done
  pk=$(head -1 "$d/log" | awk '{print $2}')
  [ -n "$pk" ] || { echo "holder $i never came up:"; cat "$d/log"; exit 1; }
  PEERS="${PEERS:+$PEERS,}$pk@127.0.0.1:$port"
done
echo "cohort up: $HOLDERS holders"

# put with $1 runtime, echo "<manifestIdHex>:<keyHex>" (the get arg, mirrors shell-run).
# Diagnostics go to stderr so they survive the $() that captures the get arg.
put() {
  local out; out=$("$@" 2>&1) || true
  local hex; hex=$(echo "$out" | grep -A1 'PUT ok' | tail -1 | tr -d ' \r')
  if [ -z "$hex" ]; then echo "PUT FAILED ($1):" >&2; echo "$out" >&2; return 1; fi
  echo "${hex:0:64}:${hex:74:64}"
}
check() { cmp -s "$1" "$SRC" && echo "  ✓ $2" || { echo "  ✗ $2 (mismatch)"; exit 1; }; }

# 1. Go put → node get
A=$(put "$GOEXE" --bundle "$BUNDLE" --policy "$WORK/policy.json" --app-config "$WORK/app.json" --peers "$PEERS" --put "$SRC" --timeout 6000 --dir "$WORK/ga" --key "$WORK/ga.key")
node "$NODEMAIN" --bundle "$BUNDLE" --policy "$WORK/policy.json" --app-config "$WORK/app.json" --peers "$PEERS" \
  --get "$A" --out "$WORK/got1.bin" --dir "$WORK/ng" --key "$WORK/ng.key" --timeout 6000 >/dev/null 2>&1
check "$WORK/got1.bin" "Go put → node get"

# 2. node put → Go get
B=$(put node "$NODEMAIN" --bundle "$BUNDLE" --policy "$WORK/policy.json" --app-config "$WORK/app.json" --peers "$PEERS" --put "$SRC" --dir "$WORK/np" --key "$WORK/np.key" --timeout 6000)
"$GOEXE" --bundle "$BUNDLE" --policy "$WORK/policy.json" --app-config "$WORK/app.json" --peers "$PEERS" --get "$B" --out "$WORK/got2.bin" --dir "$WORK/gg" --key "$WORK/gg.key" --timeout 6000 >/dev/null 2>&1
check "$WORK/got2.bin" "node put → Go get"

# 3. bun put → Go get
C=$(put bun "$NODEMAIN" --bundle "$BUNDLE" --policy "$WORK/policy.json" --app-config "$WORK/app.json" --peers "$PEERS" --put "$SRC" --dir "$WORK/bp" --key "$WORK/bp.key" --timeout 6000)
"$GOEXE" --bundle "$BUNDLE" --policy "$WORK/policy.json" --app-config "$WORK/app.json" --peers "$PEERS" --get "$C" --out "$WORK/got3.bin" --dir "$WORK/gg3" --key "$WORK/gg3.key" --timeout 6000 >/dev/null 2>&1
check "$WORK/got3.bin" "bun put → Go get"

echo "INTEROP OK — Go ↔ JS (node + bun) parity across the cohort"
