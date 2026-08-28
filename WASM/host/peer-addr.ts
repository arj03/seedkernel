import { fromHex, toHex, isHex64 } from "../core/util.js";
import type { JsonObject } from "./bundle.js";

// ── the `pk[.secret]@dest` grammar ────────────────────────────────────────────
//
// A human types this string; nothing below the transport guest sees it, only the 32 bytes
// and the destination string it produces. Where a peer lives is the socket seam's
// business, so `dest` comes back as the opaque string `link/open` carries and only the
// target's `ChannelFactory` takes apart (`parseDest` below, the one parser both socket
// edges share).

/** The schemes a destination can name. `tcp` is node↔node LENGTH framing, `ws`/`wss` the
 *  RFC 6455 codec — and `wss` additionally asks for TLS, which only a target with a TLS
 *  stack under its sockets can honour. */
export type DestScheme = "tcp" | "ws" | "wss";

/** A destination taken apart: `scheme://host:port[/path]`. `null` rather than a throw for
 *  anything malformed, because the caller is a `ChannelFactory.connect` whose answer for an
 *  unroutable destination is "no route" and not an exception (core/socket-seam.ts). */
export function parseDest(dest: string): { scheme: DestScheme; host: string; port: number; path?: string } | null {
  const sep = dest.indexOf("://");
  if (sep < 0) return null;
  const scheme = dest.slice(0, sep).toLowerCase();
  if (scheme !== "tcp" && scheme !== "ws" && scheme !== "wss") return null;
  const rest = dest.slice(sep + 3);
  const slash = rest.indexOf("/");
  const hostPort = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? undefined : rest.slice(slash);
  try {
    const { host, port } = parseHostPort(hostPort);
    return { scheme, host, port, path };
  } catch {
    return null;
  }
}

/** One peer reference — `pk[.secret]@dest` — split into WHO and WHERE. `pk` names the peer
 *  and keys the transport's address book; the optional `.secret` is THAT PEER's contact
 *  secret, what makes a reference a credential rather than merely a location; `dest` is
 *  what `link/open` carries, normalized to `scheme://host:port[/path]` so the string that
 *  reaches a socket factory always says which codec it wants. A reference that names no
 *  scheme takes `defaultScheme` — the flag the operator typed it under already said which
 *  network this is.
 *
 *  Every check here is syntax, and it is done HERE rather than at connect time because
 *  learning at dial that a port names nothing makes a typo look like an unreachable
 *  peer. Nothing about admission or trust changes if a target hand-rolled its own parser. */
export function parsePeerRef(spec: string, defaultScheme: DestScheme = "tcp"): { peerId: string; contactSecret?: Uint8Array; dest: string } {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`bad peer spec (want pk[.secret]@dest): ${spec}`);
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
  const location = spec.slice(at + 1).trim();
  const dest = location.includes("://") ? location : `${defaultScheme}://${location}`;
  const parsed = parseDest(dest);
  if (!parsed) throw new Error(`bad peer destination (want [scheme://]host:port[/path]): ${spec}`);
  return { peerId, contactSecret, dest };
}

/** A list of `pk[.secret]@dest` references as the transport reads them out of its
 *  installation-local config — the boot-time half of an address book that now lives in the
 *  transport guest and dies with its realm (§12.10). Hex, like every other `LOCAL` fact, so
 *  the whole object survives a JSON round trip through a target that holds no bytes.
 *
 *  This is the ONE way a deployment names its cohort: the same list goes into the first
 *  load's `transportConfig` and into a replacement's, because a transport upgrade is a
 *  reconnect from an empty book. */
export function peersConfig(specs: readonly string[], defaultScheme: DestScheme = "tcp"): JsonObject[] {
  return specs.map((spec) => {
    const { peerId, contactSecret, dest } = parsePeerRef(spec, defaultScheme);
    const entry: JsonObject = { peerId, dest };
    // Left OUT rather than spelled as zeros for a peer that named none: the transport reads
    // an absent secret as an open door, and a zero secret means the same, but only one of
    // the two says so in the config an operator reads back.
    if (contactSecret !== undefined) entry.contactSecret = toHex(contactSecret);
    return entry;
  });
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
