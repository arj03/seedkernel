#!/usr/bin/env bash
# §12.9 interop: the acceptance check for the native binary target.
#
# A native binary node and JS (node and bun) nodes share one seedstore cohort over real
# loopback TCP, running the same signed bundle. It checks wire, crypto and bundle parity
# in both directions:
#   1. Go put   -> node get  (Go writes blocks JS can read back)
#   2. node put -> Go get    (Go reads blocks JS wrote)
#   3. bun put  -> Go get    (Bun to Go, the read path)
# all against a cohort of `node` holders. Storage runs on the runtime as a signed bundle;
# neither side links the other's code, only the wire format and the bundle are shared.
#
# Manual integration check (not part of `go test`): needs `node` and `bun` on PATH
# and a built Windows seedkernel.exe. Run from Git Bash on Windows:
#   bash scripts/native-interop.sh [path/to/seedkernel.exe]
set -euo pipefail

SK=/c/Users/ander/Documents/GitHub/seedkernel/WASM
SS=/c/Users/ander/Documents/GitHub/seedstore/WASM
# A bundle is one blob (§12.4); both targets read this file.
BUNDLE="$SS/bundle/seedstore.skb"
NODEMAIN="$SK/build/host/main-node.js"
GOEXE="${1:-$SK/../native/seedkernel.exe}"

HOLDERS=6
BASEPORT=47100

[ -f "$GOEXE" ]    || { echo "missing seedkernel exe: $GOEXE"; exit 1; }
[ -f "$NODEMAIN" ] || { echo "missing built shell: $NODEMAIN (run: npm run build:host)"; exit 1; }
[ -f "$BUNDLE" ]   || { echo "missing seedstore bundle: $BUNDLE (run: npm run build:bundle in seedstore/WASM)"; exit 1; }

# Read the author through verifyBundle instead of parsing offsets here: the envelope
# starts with a suite byte and the author id is a hash of both keys (§12.4), so no fixed
# byte range holds it.
AUTHOR=$(cd "$SK" && node --input-type=module -e "
const { verifyBundle } = await import('./build/host/bundle.js');
const { loadCrypto } = await import('./build/host/crypto-node.js');
const { readFileSync } = await import('node:fs');
const sodium = await loadCrypto();
process.stdout.write(Buffer.from(verifyBundle(sodium, new Uint8Array(readFileSync(process.argv[1]))).author).toString('hex'));
" "$BUNDLE")
# Each node explicitly loads the embedded transport at boot. Policy lists only the app author.
WORK=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

echo "{\"authors\":[\"$AUTHOR\"]}" > "$WORK/policy.json"
# seedstore's byte quota is operator policy: it is not in the signed bundle, and the guest
# treats a missing quota as 0 instead of guessing a default. Every node here, holders and
# initiators, needs one, or the holders decline every STORE ("chunk landed 0/N distinct
# blocks").
echo '{"quota": 67108864}' > "$WORK/app.json"
SRC="$WORK/src.bin"; head -c 4096 /dev/urandom > "$SRC"   # > smallMaxBlocks, so the RS path
echo "interop: author=$AUTHOR  holders=$HOLDERS  src=$(wc -c < "$SRC") B"

# ── a cohort of node holders, each on its own loopback port ──────────────────
PEERS=""
for i in $(seq 0 $((HOLDERS-1))); do
  port=$((BASEPORT+i)); d="$WORK/h$i"; mkdir -p "$d"
  node "$NODEMAIN" --bundle "$BUNDLE" --policy "$WORK/policy.json" --local-config "$WORK/app.json" \
    --dir "$d/data" --key "$d/key" --listen "127.0.0.1:$port" \
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

# put through the runtime in $2..., writing the GET argument to the file named by $1.
#
# The op takes its argument on stdin and answers on stdout, and the runtime knows nothing
# else about it (§12.8), so a PUT is a plain redirect and its answer is seedstore's raw
# PutResult envelope:
#
#   [K 32][chunkCount u32][placed u32][intended u32][rootLen u32][root ...][idCount u32]...
#
# and a GET's argument is [K 32][root ...]. Converting one to the other depends on
# seedstore's format, so it belongs in this script, not in the application-neutral CLI.
# The root is a signed descriptor of variable length, not a fixed id, so `rootLen` is
# read, not assumed.
put() {
  local getarg="$1"; shift
  local res="$WORK/put.$$.$RANDOM.bin"
  local err; err=$("$@" --op put < "$SRC" 2>&1 > "$res") || true
  if [ ! -s "$res" ]; then echo "PUT FAILED ($1):" >&2; echo "$err" >&2; return 1; fi
  node -e 'const fs=require("fs"), b=fs.readFileSync(process.argv[1]), n=b.readUInt32BE(44);
fs.writeFileSync(process.argv[2], Buffer.concat([b.subarray(0,32), b.subarray(48,48+n)]));' "$res" "$getarg"
}
check() { cmp -s "$1" "$SRC" && echo "  ✓ $2" || { echo "  ✗ $2 (mismatch)"; exit 1; }; }

# 1. Go put -> node get
put "$WORK/a.arg" "$GOEXE" --bundle "$BUNDLE" --policy "$WORK/policy.json" --local-config "$WORK/app.json" --peers "$PEERS" --dir "$WORK/ga" --key "$WORK/ga.key"
node "$NODEMAIN" --bundle "$BUNDLE" --policy "$WORK/policy.json" --local-config "$WORK/app.json" --peers "$PEERS" \
  --op get --dir "$WORK/ng" --key "$WORK/ng.key" < "$WORK/a.arg" > "$WORK/got1.bin" 2>/dev/null
check "$WORK/got1.bin" "Go put → node get"

# 2. node put -> Go get
put "$WORK/b.arg" node "$NODEMAIN" --bundle "$BUNDLE" --policy "$WORK/policy.json" --local-config "$WORK/app.json" --peers "$PEERS" --dir "$WORK/np" --key "$WORK/np.key"
"$GOEXE" --bundle "$BUNDLE" --policy "$WORK/policy.json" --local-config "$WORK/app.json" --peers "$PEERS" --op get --dir "$WORK/gg" --key "$WORK/gg.key" < "$WORK/b.arg" > "$WORK/got2.bin" 2>/dev/null
check "$WORK/got2.bin" "node put → Go get"

# 3. bun put -> Go get
put "$WORK/c.arg" bun "$NODEMAIN" --bundle "$BUNDLE" --policy "$WORK/policy.json" --local-config "$WORK/app.json" --peers "$PEERS" --dir "$WORK/bp" --key "$WORK/bp.key"
"$GOEXE" --bundle "$BUNDLE" --policy "$WORK/policy.json" --local-config "$WORK/app.json" --peers "$PEERS" --op get --dir "$WORK/gg3" --key "$WORK/gg3.key" < "$WORK/c.arg" > "$WORK/got3.bin" 2>/dev/null
check "$WORK/got3.bin" "bun put → Go get"

echo "INTEROP OK — Go ↔ JS (node + bun) parity across the cohort"
