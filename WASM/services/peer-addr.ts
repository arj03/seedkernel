// Destinations and bind addresses, as the socket layer reads them. A destination is the
// opaque string `link/open` carries; only a target's `ChannelFactory` parses it, using
// `parseDest`. How a transport writes a peer address (which key lives where) is that
// transport's own grammar and is never read here.

/** The schemes a destination can name. `tcp` is node-to-node length framing, `ws` and
 *  `wss` the RFC 6455 codec; `wss` also needs TLS, which only a target with a TLS stack
 *  under its sockets supports. */
export type DestScheme = "tcp" | "ws" | "wss";

/** Parse `scheme://host:port[/path]`. Returns `null` instead of throwing for anything
 *  malformed, because the caller is a `ChannelFactory.connect`, which answers "no route"
 *  for an unroutable destination (services/socket-seam.ts). */
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

/** Split a `host:port` address. By default it must be a dialable address: an explicit
 *  host and a port in 1..65535. `defaultHost` fills an empty host (a bare `:port`) and
 *  `allowEphemeral` permits port 0 (let the OS pick), as `--listen` entries need. */
export function parseHostPort(s: string, opts: { defaultHost?: string; allowEphemeral?: boolean } = {}): { host: string; port: number } {
  const colon = s.lastIndexOf(":");
  if (colon < 0) throw new Error(`expected host:port, got ${s}`);
  const host = s.slice(0, colon) || (opts.defaultHost ?? "");
  const port = Number(s.slice(colon + 1));
  // Range-checked here, since an invalid port found only at connect time looks like an
  // unreachable peer.
  if (!Number.isInteger(port) || port < (opts.allowEphemeral ? 0 : 1) || port > 65535) throw new Error(`bad port in ${s}`);
  if (!host) throw new Error(`bad host in ${s}`);
  return { host, port };
}
