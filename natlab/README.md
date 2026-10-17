# natlab: NAT traversal in a virtual network

Tests the UDP direct path (RUNTIME §12.7) against real NAT behaviour, without real routers.
[patchbay](https://github.com/n0-computer/patchbay), the lab iroh tests its hole punching
with, builds routers and hosts out of Linux network namespaces with NAT rules in nftables.
Two native nodes sit behind a pair of NAT routers, register on a public seedrelay that also
answers STUN, and Alice dials Bob by key. The question is whether the link then goes direct.

```sh
natlab/run.sh                     # every pair of none, open, moderate, strict
natlab/run.sh moderate strict     # one pair
NATS="open strict" natlab/run.sh  # every pair of the kinds named
```

It prints one line per pair:

```
alice     bob       expected  got            ms
moderate  moderate  direct    direct         71  ok
strict    strict    relayed   relayed         -  ok
```

`ms` is how long after the relayed link came up the path went direct. A pair that never
links fails, and so does one that stays relayed where `expect` in `run.sh` says direct.
Logs for each sim, each node's console and its probe's output, are under
`natlab/.work/latest/<sim>/`.

## What it needs

- Linux with unprivileged user namespaces, IPv6 enabled, and `tc` (iproute2) and `nft`
  (nftables) on PATH. On macOS, run it in a Linux VM.
- `node`, the patchbay CLI
  (`cargo install --git https://github.com/n0-computer/patchbay patchbay-cli`),
  the native binary (`npm run build:native` in `WASM/`, then `go build -o seedkernel .` in
  `native/`), and a [seedrelay](https://github.com/arj03/seedrelay) checkout beside this
  repo. `SEEDKERNEL`, `SEEDRELAY` and `PATCHBAY` override the paths.

## The parts

- `templates/pair.toml` is the patchbay sim for one pair. `run.sh` writes one per pair with
  the NAT kinds filled in; patchbay's own `[matrix]` cannot set a router's NAT.
- `probe.mjs` runs a node with a fresh key and watches the `link <key> direct|relayed|gone`
  lines the CLI prints, reporting the outcome as NDJSON for patchbay's captures.
- `run.sh` writes the sims, runs patchbay and judges the results.

## NAT kinds

| patchbay | RFC 4787 | Typical of |
| --- | --- | --- |
| `none` | public address | servers |
| `open` | endpoint-independent mapping and filtering (full cone) | routers with UPnP or port forwarding |
| `moderate` | endpoint-independent mapping, address and port dependent filtering | most home routers, Linux masquerade |
| `strict` | endpoint-dependent mapping, random ports | enterprise firewalls, cloud NAT gateways |

`strict` against `moderate` takes the birthday paradox: the relay answers STUN on two ports,
so the strict end sees its two answers differ, and the UDP path then has it open 256 ports
toward the peer while the moderate end probes random ports until one lands (RUNTIME
§12.7). Two `strict` ends would each have to guess the other's random port for the other's
random port, so that pair is expected to stay on the relay.

Worth adding next: link conditions (`set-link-condition` with loss and latency, for the
stream's congestion control and path MTU probing), two nodes behind the same NAT (hairpin),
a home router behind a carrier NAT (a router's `upstream`), and a NAT that changes mid-link
to exercise path moves.
