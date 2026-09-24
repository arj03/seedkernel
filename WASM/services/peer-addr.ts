// Destinations and bind addresses, as the socket edges read them. A destination is the
// opaque string `link/open` carries; only a target's `ChannelFactory` takes it apart, and
// `parseDest` is the one parser the socket edges share. How a transport spells a PEER —
// which key lives where — is that transport's own grammar, never read here.

/** The schemes a destination can name. `tcp` is node↔node LENGTH framing, `ws`/`wss` the
 *  RFC 6455 codec — and `wss` additionally asks for TLS, which only a target with a TLS
 *  stack under its sockets can honour. */
export type DestScheme = "tcp" | "ws" | "wss";

/** A destination taken apart: `scheme://host:port[/path]`. `null` rather than a throw for
 *  anything malformed, because the caller is a `ChannelFactory.connect` whose answer for an
 *  unroutable destination is "no route" and not an exception (services/socket-seam.ts). */
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

/** Split a `host:port` address. The strict form (the default) is a peer dial
 *  address: an explicit host and a port in 1..65535. `defaultHost` fills an empty
 *  host (a bare `:port`), and `allowEphemeral` permits port 0 (ask the OS) — the
 *  two relaxations the operator's `--listen` entries need. */
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
