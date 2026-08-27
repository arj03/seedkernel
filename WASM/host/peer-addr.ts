import { fromHex, isHex64 } from "../core/util.js";
import type { PeerAddr, PeerId } from "../core/socket-seam.js";

// ── the `pk[.secret]@location` grammar ────────────────────────────────────────
//
// A human types this string; the driver never sees it, only the 32 bytes and the
// `PeerAddr` it produces. Where a peer lives is the transport's business, so the TCP
// and WS edges (`./net-node`, `./net-ws`) parse `location` themselves.

/** The credential half of a peer spec — `pk[.secret]` — plus whatever followed the `@`.
 *  `pk` names WHO lives there and keys the address book; the optional `.secret` is THAT
 *  PEER's contact secret, what makes an address a credential rather than a location.
 *  Where a peer LIVES differs by transport, so `location` comes back unparsed. Every
 *  check here is syntax, so nothing about admission or trust changes if a target
 *  hand-rolled its own parser. */
export function parsePeerRef(spec: string): { peerId: PeerId; contactSecret?: Uint8Array; location: string } {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`bad peer spec (want pk[.secret]@location): ${spec}`);
  const idPart = spec.slice(0, at).trim().toLowerCase();
  const dot = idPart.indexOf(".");
  const peerId = dot < 0 ? idPart : idPart.slice(0, dot);
  if (!isHex64(peerId)) throw new Error(`bad peer pubkey hex (want 32 bytes): ${spec}`);
  let contactSecret: Uint8Array | undefined;
  if (dot >= 0) {
    const hex = idPart.slice(dot + 1);
    if (!isHex64(hex)) throw new Error(`bad peer contact secret hex (want 32 bytes): ${spec}`);
    contactSecret = fromHex(hex);
  }
  return { peerId, contactSecret, location: spec.slice(at + 1).trim() };
}

/** Split a `host:port` address. The strict form (the default) is a peer dial
 *  address: an explicit host and a port in 1..65535. `defaultHost` fills an empty
 *  host (a bare `:port`), and `allowEphemeral` permits port 0 (ask the OS) — the
 *  two relaxations the operator's `--listen`/`--ws-listen` forms need. */
export function parseHostPort(s: string, opts: { defaultHost?: string; allowEphemeral?: boolean } = {}): { host: string; port: number } {
  const colon = s.lastIndexOf(":");
  if (colon < 0) throw new Error(`expected host:port, got ${s}`);
  const host = s.slice(0, colon) || (opts.defaultHost ?? "");
  const port = Number(s.slice(colon + 1));
  // Bounded, not merely positive: learning at connect time that a port names nothing
  // makes a typo look like an unreachable peer.
  if (!Number.isInteger(port) || port < (opts.allowEphemeral ? 0 : 1) || port > 65535) throw new Error(`bad port in ${s}`);
  if (!host) throw new Error(`bad host in ${s}`);
  return { host, port };
}

/** Split a location into its `host:port` and whatever path followed — `/` and everything
 *  after it, at most once, and never inside the `//` of a scheme. A WS peer behind a
 *  reverse proxy answers at a path rather than at the root, and only the address can say
 *  so; `host:port` alone answers `undefined`, which is the root. */
function splitPath(location: string): { hostPort: string; path?: string } {
  const scheme = location.indexOf("://");
  const from = scheme < 0 ? 0 : scheme + 3;
  const slash = location.indexOf("/", from);
  if (slash < 0) return { hostPort: location };
  return { hostPort: location.slice(0, slash), path: location.slice(slash) };
}

/** Parse a `pk[.secret]@host:port[/path]` peer spec into the peer id + the address to
 *  dial: the socket-seam form (`PeerAddr`), for a target that opens its own TCP/WS
 *  sockets. A scheme stays with the host — `wss://` is how a deployment asks for TLS —
 *  and a path rides in `PeerAddr.path`. */
export function parsePeerSpec(spec: string, transport: "tcp" | "ws"): { peerId: PeerId; addr: PeerAddr } {
  const { peerId, contactSecret, location } = parsePeerRef(spec);
  const { hostPort, path } = splitPath(location);
  const { host, port } = parseHostPort(hostPort);
  return { peerId, addr: { host, port, transport, contactSecret, path } };
}
