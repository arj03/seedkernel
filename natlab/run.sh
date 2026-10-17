#!/usr/bin/env bash
# NAT lab: run two native nodes behind every pair of NAT kinds in a patchbay lab, meeting
# on a seedrelay, and print whether each pair's link went direct against what it should do.
#
#   natlab/run.sh                     every pair of none, open, moderate, strict, and the
#                                     IPv6 pairs in V6_PAIRS
#   natlab/run.sh moderate strict     just that pair
#   natlab/run.sh strict+v6 strict    a kind with +v6 also has IPv6 behind a firewall
#   NATS="open strict" natlab/run.sh  every pair of the kinds named, and no IPv6 pairs
#
# Needs Linux with unprivileged user namespaces, `tc` and `nft` on PATH, node, and the
# patchbay CLI (`cargo install --git https://github.com/n0-computer/patchbay patchbay-cli`).
# Paths, all overridable:
#   SEEDKERNEL  the native binary   (default native/seedkernel: `npm run build:native` in
#                                    WASM/, then `go build -o seedkernel .` in native/)
#   SEEDRELAY   a seedrelay checkout (default ../seedrelay)
#   PATCHBAY    the patchbay CLI    (default patchbay on PATH)
#
# Exit status: 0 when every pair did what `expect` says or better, 1 when a pair never
# linked or stayed on the relay where a direct path was expected. A pair going direct
# where `expect` says relayed is reported as better than expected, so the table can be
# tightened. Logs stay in natlab/.work/latest/<sim>/.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
export NATLAB="$HERE"
export SEEDKERNEL=$(realpath "${SEEDKERNEL:-$ROOT/native/seedkernel}")
export SEEDRELAY=$(realpath "${SEEDRELAY:-$ROOT/../seedrelay}")
PATCHBAY=${PATCHBAY:-patchbay}
WORK="$HERE/.work"

[ -x "$SEEDKERNEL" ] || { echo "natlab: no native binary at $SEEDKERNEL (set SEEDKERNEL)"; exit 2; }
[ -f "$SEEDRELAY/server.mjs" ] || { echo "natlab: no seedrelay at $SEEDRELAY (set SEEDRELAY)"; exit 2; }
command -v "$PATCHBAY" >/dev/null || { echo "natlab: no patchbay CLI (set PATCHBAY)"; exit 2; }

# What each pair of NAT kinds should do today (order-free). The UDP path punches with the
# relay's STUN and probes every candidate, so it gets through whenever one side keeps one
# public port per socket and the other lets that port in. Against a strict NAT that
# filters, the strict end opens 256 ports toward the peer and the other end probes random
# ports until it lands on one (the birthday paradox). Two strict ends cannot meet that way
# over IPv4, but two ends with IPv6 meet over it, whatever their IPv4 NATs: a firewall that
# lets replies in is punched as a moderate NAT is.
expect() {
  case "$1-$2" in
    *+v6-*+v6) echo direct ;;
    strict*-strict*) echo relayed ;;
    *) echo direct ;;
  esac
}

# The IPv6 pairs a full run adds: two strict NATs that only IPv6 gets past, the same with
# IPv6 on one side only, which stays relayed, and a pair IPv4 punches too.
V6_PAIRS=("strict+v6 strict+v6" "strict+v6 strict" "moderate+v6 strict+v6")

# A kind's parts for the template: its NAT, the router's address families, and whether
# the node has IPv6 behind a firewall.
nat_of() { echo "${1%+v6}"; }
ip_of() { case "$1" in *+v6) echo dual-stack ;; *) echo v4-only ;; esac; }
v6_of() { case "$1" in *+v6) echo true ;; *) echo false ;; esac; }
sim_of() { echo "nat-${1/+/-}-${2/+/-}"; }

# The pairs: one from the arguments, or every ordered pair of $NATS. Order matters, since
# the smaller key offers the path and Alice is the one who dials.
pairs=()
if [ $# -eq 2 ]; then
  pairs=("$1 $2")
elif [ $# -eq 0 ]; then
  for a in ${NATS:-none open moderate strict}; do
    for b in ${NATS:-none open moderate strict}; do pairs+=("$a $b"); done
  done
  [ -n "${NATS:-}" ] || pairs+=("${V6_PAIRS[@]}")
else
  echo "usage: natlab/run.sh [nat-a nat-b]"; exit 2
fi

SIMS="$WORK/sims"
rm -rf "$SIMS"; mkdir -p "$SIMS"
for p in "${pairs[@]}"; do
  read -r a b <<<"$p"
  sed "s/@A@/$(nat_of "$a")/g; s/@B@/$(nat_of "$b")/g; s/@IPA@/$(ip_of "$a")/g; s/@IPB@/$(ip_of "$b")/g;
       s/@V6A@/$(v6_of "$a")/g; s/@V6B@/$(v6_of "$b")/g; s/^name = \"nat-.*/name = \"$(sim_of "$a" "$b")\"/" \
    "$HERE/templates/pair.toml" > "$SIMS/$(sim_of "$a" "$b").toml"
done

# patchbay's exit status covers the sims' asserts (every pair must link at all); the
# matrix below is the verdict, so go on either way.
"$PATCHBAY" run --work-dir "$WORK" "$SIMS" || true

RUN="$WORK/latest"
[ -d "$RUN" ] || { echo "natlab: patchbay left no run in $WORK"; exit 1; }

# Alice's verdict: the last result line her probe printed.
result_of() {
  grep -s '"kind":"result"' "$RUN/$1/device.alice.alice.stdout.log" | tail -1
}

status=0
printf '\n%-11s %-11s %-9s %-9s %7s  %s\n' alice bob expected got ms ""
for p in "${pairs[@]}"; do
  read -r a b <<<"$p"
  want=$(expect "$a" "$b")
  line=$(result_of "$(sim_of "$a" "$b")" || true)
  got=$(sed -n 's/.*"route":"\([a-z]*\)".*/\1/p' <<<"$line"); got=${got:-none}
  # Time to go direct; a relayed result's ms is only how long Alice watched.
  ms=""
  [ "$got" = direct ] && ms=$(sed -n 's/.*"ms":\([0-9]*\).*/\1/p' <<<"$line")
  if [ "$got" = none ]; then note="FAIL: never linked"; status=1
  elif [ "$got" = "$want" ]; then note="ok"
  elif [ "$got" = relayed ]; then note="FAIL: expected a direct path"; status=1
  else note="better than expected"
  fi
  printf '%-11s %-11s %-9s %-9s %7s  %s\n' "$a" "$b" "$want" "$got" "${ms:--}" "$note"
done
echo
echo "logs: $(realpath "$RUN")/<sim>/"
exit $status
