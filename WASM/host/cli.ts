// cli.ts — the operator's side of a node, written once for every target: what an operator
// types, what each flag defaults to, what order the node does things in, and what it
// prints. A `CliHost` names the few things that genuinely differ by target — files, a log
// line, raw stdout, entropy, and "stand a node up here".
//
// Tokenizing `--name value` is not what is shared; everything downstream of the split is:
// the flag SET, the defaults, the deny-all reading of an absent `--policy` (§14), the
// order (remedies before the bundle, §12.5), which failures are fatal, and the console
// lines. Those are decisions, and a decision made twice eventually gets made differently.
import { toHex, fromHex, isHex64, errMessage } from "../core/util.js";
import { deriveNodeKeys, type NodeKeys, type SubkeyCrypto, type Keypair } from "../core/subkeys.js";
import { appKeyFor, type LoadedBundle } from "./bundle.js";
import type { PeerAddr, PeerId } from "../core/socket-seam.js";
import { requireTransport, type Shell } from "./shell-core.js";

/** Where a node's store lives when `--dir` is omitted. One value on every target, so
 *  the same command line runs the same node over the same store wherever it runs. */
export const DEFAULT_DIR = "./data";
/** Where the node's 32-byte master seed lives when `--key` is omitted (§12.6.2b). */
export const DEFAULT_KEY = "./seedkernel.key";

/** Every flag the shell accepts. An allowlist rather than a parse-and-ignore, because
 *  the failure an unknown flag would hide is silent: a mistyped `--polcy` would build a
 *  deny-all node that boots, serves, and installs nothing — which looks exactly like a
 *  node whose policy is doing its job. The allowlist makes the typo say so. */
const FLAGS = new Set([
  "policy", "dir", "key", "listen", "ws-listen", "peers", "contact-secret",
  "bundle", "op", "app-config", "revoke", "uninstall",
  "request-deadline", "guest-timeout", "guest-memory", "transport",
]);

/** File access, as the flow needs it: a read that answers `null` for "absent" rather
 *  than throwing (the `--key` path takes that branch on a first boot), and a write that
 *  is atomic — a half-written key file or freshness mark is worse than none. */
export interface CliFiles {
  readFile(path: string): Uint8Array | null;
  writeFile(path: string, bytes: Uint8Array, mode?: number): void;
}

/** What a node needs to exist, once the flags have been read. The targets build it from
 *  very different parts — `NodeFs` + `node:net` here, a wazero table + Go sockets there —
 *  which is why `standUp` is a member rather than code in this file. */
export interface NodeSetup {
  dir: string;
  policyJson?: string;
  identity: Keypair;
  contactSecret?: Uint8Array;
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
  requestDeadlineMs?: number;
  guestDeadlineMs?: number;
  realmMemoryBytes?: number;
  transportBundle?: Uint8Array;
  config?: Record<string, string | number>;
}

/** The platform under the operator flow. */
export interface CliHost extends CliFiles {
  /** The first word of the first console line — the artifact you are running
   *  (`seedkernel-shell` on Node, `seedkernel-loader` natively). The only thing on that
   *  line allowed to differ; the peer id after it is not. */
  banner: string;
  /** Arguments after the program name. */
  argv: string[];
  /** One console line. `console.log` on Node; a Go stdout write natively, where
   *  QuickJS's own `console` writes to a discarded WASI stdout. */
  log(line: string): void;
  /** Raw bytes to stdout — `--op` writes the app's response verbatim, so this cannot go
   *  through `log`, and `log` must not go to stdout either (both targets send it to
   *  stderr: a diagnostic interleaved into a response corrupts it). */
  stdout(bytes: Uint8Array): void;
  /** Raw bytes from stdin — `--op`'s argument, verbatim; empty when nothing is piped in,
   *  which is how an op that takes no argument is spelled. A function rather than a field
   *  so a node that boots and serves never blocks on a stdin nobody will write to. */
  stdin(): Uint8Array;
  /** Entropy + the subkey derivation's crypto (§12.9). */
  sodium: SubkeyCrypto & { randombytes_buf(n: number): Uint8Array };
  /** Assemble a node on this platform: the platform seam, `createShell`, and the
   *  transport bundle that is its network. */
  standUp(cfg: NodeSetup): Promise<Shell>;
}

/** What `runCli` leaves behind: whether the node is listening (so the caller knows to
 *  keep the process alive and hook SIGINT) and how to shut it down. Both are the
 *  binding's business — Node exits by returning from `main`, the native target hands
 *  the loop back to Go — so the flow reports rather than decides. */
export interface CliResult {
  serving: boolean;
  close(): void;
}

const utf8 = new TextDecoder();
const utf8enc = new TextEncoder();

/** Split `--name value` / `--name=value` pairs, refusing anything else: an unknown flag is
 *  an error rather than an ignored token, and a flag without a value is an error rather
 *  than a `true` that later reads as a path. */
export function parseArgs(argv: string[], known: ReadonlySet<string> = FLAGS): Map<string, string> {
  const out = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) throw new Error(`unexpected argument "${arg}" — flags are --name value`);
    const eq = arg.indexOf("=");
    const name = eq >= 0 ? arg.slice(2, eq) : arg.slice(2);
    if (!known.has(name)) throw new Error(`unknown flag --${name}`);
    if (eq >= 0) { out.set(name, arg.slice(eq + 1)); continue; }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`--${name} needs a value`);
    out.set(name, value);
    i++;
  }
  return out;
}

/** A comma-separated flag as a list, empty when the flag is absent. */
function list(v: string | undefined): string[] {
  return v === undefined ? [] : v.split(",").map((s) => s.trim()).filter(Boolean);
}

/** Read a file the operator named, failing with the flag rather than the errno — a
 *  missing `--policy` file is an operator mistake, and the message should say which
 *  flag was wrong. */
function mustRead(files: CliFiles, path: string, label: string): Uint8Array {
  const b = files.readFile(path);
  if (b === null) throw new Error(`${label}: cannot read ${path}`);
  return b;
}

/** Parse 64 hex characters into the 32 bytes they name. Validated rather than decoded
 *  loosely, because `fromHex` maps a non-hex pair to 0: a corrupt key file would boot the
 *  node under a *different* identity, and a typo'd contact secret would produce a node
 *  that looks healthy and is reachable by nobody (§12.6.2). Parse time is the only place
 *  an operator can still be told. */
export function parseHex32(hex: string, label: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex.trim())) {
    throw new Error(`${label} must hold 32 bytes as 64 hex characters`);
  }
  return fromHex(hex.trim());
}

// ── the address syntax an operator types ──────────────────────────────────────
//
// `pk[.secret]@location` is a thing a HUMAN writes — into `--peers`, into a demo page's
// input box. It is not the transport's: the driver never sees a string, only the 32 bytes
// and the `PeerAddr` these produce. So the grammar lives with the rest of the operator's
// surface, and the edges with their own address form (`./net-node`, `./net-ws`) reach it
// from here rather than the other way round.

/** The credential half of a peer spec — `pk[.secret]` — plus whatever followed the `@`.
 *  `pk` names WHO lives there and keys the address book; the optional `.secret` is THAT
 *  PEER's contact secret, the gate our opening message must be sealed under — which is
 *  what makes an address a credential rather than a location.
 *
 *  Where a peer LIVES differs by transport (a `host:port`, a whole `ws://` URL), so
 *  `location` comes back unparsed for each caller to read its own form out of.
 *
 *  Every check here is syntax, so nothing about admission or trust would change if a
 *  target hand-rolled its own parser. */
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

/** Parse a `pk[.secret]@host:port` peer spec into the peer id + the address to dial:
 *  the socket-seam form (`PeerAddr`), for a target that opens its own TCP/WS sockets. */
export function parsePeerSpec(spec: string, transport: "tcp" | "ws"): { peerId: PeerId; addr: PeerAddr } {
  const { peerId, contactSecret, location } = parsePeerRef(spec);
  const { host, port } = parseHostPort(location);
  return { peerId, addr: { host, port, transport, contactSecret } };
}

/** A 32-byte secret from a file — the master seed (`--key`) and the deployment secret
 *  (`--contact-secret`) are the same shape, read the same way, and fail the same way. */
function loadHex32(files: CliFiles, path: string, label: string): Uint8Array {
  return parseHex32(utf8.decode(mustRead(files, path, label)), label);
}

/** Load the node's MASTER SEED from `--key`, or mint one and persist it 0600, and derive
 *  the node's keypair from it (§12.9). One 32-byte secret on disk; the master signs
 *  nothing itself, and the node's peer id is the derived channel key's public half. */
function loadNodeKeys(host: CliHost, keyPath: string): NodeKeys {
  const existing = host.readFile(keyPath);
  if (existing !== null) return deriveNodeKeys(host.sodium, parseHex32(utf8.decode(existing), `--key ${keyPath}`));
  const master = host.sodium.randombytes_buf(32);
  host.writeFile(keyPath, utf8enc.encode(toHex(master)), 0o600);
  return deriveNodeKeys(host.sodium, master);
}

/** The one console line a successful load prints (§12.4, §12.10): the app, its version, the
 *  app key an operator would pass to `--uninstall`, and what the load CLAIMED to serve.
 *  The protocols come from the manifest, so a node that will answer nothing says so at the
 *  load rather than at the first frame. */
export function loadedLine(b: LoadedBundle): string {
  const serves = b.manifest.protocols ?? [];
  return `${b.manifest.app} v${b.manifest.version}  key ${appKeyFor(b.author, b.manifest.app)}` +
    `  serves ${serves.length ? serves.join(", ") : "(nothing — this bundle claims no protocol)"}`;
}

/** Run the operator flow to completion. Throws on anything the operator got wrong — a bad
 *  flag, an unreadable file, a bundle that will not load — and the caller reports and
 *  exits, because how a target reports a fatal error is the last platform thing here. */
export async function runCli(host: CliHost): Promise<CliResult> {
  const args = parseArgs(host.argv);
  const dir = args.get("dir") ?? DEFAULT_DIR;
  const keyPath = args.get("key") ?? DEFAULT_KEY;
  const policyPath = args.get("policy");
  // Omitting --policy is not "no policy" but deny-all: the shell resolves an absent
  // policy to an empty author set, so the node boots and serves and nothing installs —
  // including the --bundle below, whose manifest author must be listed too (§14).
  const policyJson = policyPath === undefined
    ? undefined
    : utf8.decode(mustRead(host, policyPath, "--policy"));
  const keys = loadNodeKeys(host, keyPath);
  const contactSecretPath = args.get("contact-secret");

  const shell = await host.standUp({
    dir,
    policyJson,
    identity: keys.channel,
    contactSecret: contactSecretPath === undefined
      ? undefined
      : loadHex32(host, contactSecretPath, "--contact-secret"),
    listen: args.has("listen")
      ? parseHostPort(args.get("listen")!, { defaultHost: "0.0.0.0", allowEphemeral: true })
      : undefined,
    wsListen: args.has("ws-listen")
      ? parseHostPort(args.get("ws-listen")!, { defaultHost: "0.0.0.0", allowEphemeral: true })
      : undefined,
    requestDeadlineMs: args.has("request-deadline") ? Number(args.get("request-deadline")) : undefined,
    // Guest resource bounds (§12.3), which only widen or tighten the shell's own
    // defaults. `--guest-timeout 0` reads as Infinity — "no budget" said explicitly,
    // rather than reached by leaving a flag off.
    guestDeadlineMs: args.has("guest-timeout") ? (Number(args.get("guest-timeout")) || Infinity) : undefined,
    realmMemoryBytes: args.has("guest-memory") ? Number(args.get("guest-memory")) * 1024 * 1024 : undefined,
    transportBundle: args.has("transport") ? mustRead(host, args.get("transport")!, "--transport") : undefined,
    // Operator-supplied app config (e.g. a storage node's quota), merged over the
    // bundle's author-signed config. Opaque JSON the shell forwards into `const APP`.
    config: args.has("app-config")
      ? JSON.parse(utf8.decode(mustRead(host, args.get("app-config")!, "--app-config")))
      : undefined,
  });
  // The node's transport driver, or null when the policy admitted no transport bundle.
  // Read once and held: nothing below stands a second one up.
  const net = shell.transport;

  // Cohort peers: teach the transport their addresses so it can dial them. A policy
  // admitting no transport bundle leaves nothing to dial FROM — say so, rather than
  // letting the flag pass silently on a node with no network.
  const peers = list(args.get("peers"));
  if (peers.length > 0) {
    const dialer = requireTransport(shell, "--peers given, but there is nothing to dial from");
    for (const spec of peers) {
      const { peerId, addr } = parsePeerSpec(spec, "tcp");
      dialer.addPeerAddr(peerId, addr);
    }
    // Best-effort: ready() resolves on its own timeout rather than rejecting, so a
    // cohort member that is not up yet delays the boot but never fails it.
    await dialer.ready();
  }

  host.log(`${host.banner} ${toHex(keys.channel.publicKey)}`);
  host.log(`  policy ${policyPath ?? "(none — installs disabled)"}`);
  host.log(`  store  ${dir} (fs.* backend)`);
  host.log(`  cohort ${peers.length} peer(s)`);
  if (net?.port) host.log(`  tcp    listening on :${net.port}`);
  if (net?.wsPort) host.log(`  ws     listening on :${net.wsPort}`);

  // Operator remedies (§12.5), deliberately BEFORE the bundle: a node booting with both
  // should never briefly install what it was told to refuse. --revoke is the whole remedy
  // for a compromised key; --uninstall drops an app without writing its author off.
  for (const authorHex of list(args.get("revoke"))) {
    const gone = shell.revoke(authorHex);
    host.log(`  revoke ${authorHex}` +
      (gone.length ? ` (uninstalled ${gone.length} app(s): ${gone.join(", ")})` : " (no apps of its were loaded)"));
  }
  for (const appKey of list(args.get("uninstall"))) {
    host.log(`  uninstall ${appKey}${shell.uninstall(appKey) ? "" : " (nothing bound)"}`);
  }

  // A signed bundle from disk. Reading the file is all the operator flow does: the whole
  // load — signature, policy, freshness, integrity, binding, claiming the manifest's
  // protocol ids — is the shared shell's (§12.4, §12.10).
  const bundlePath = args.get("bundle");
  if (bundlePath !== undefined) {
    let loaded: LoadedBundle;
    try {
      loaded = await shell.loadBundleBlob(mustRead(host, bundlePath, "--bundle"));
    } catch (err) {
      // Fatal, and labelled: a node whose bundle did not land has no app to run, and a
      // driving script must see that rather than a silent bundle-less relay.
      throw new Error("bundle: " + errMessage(err));
    }
    host.log("  bundle " + loadedLine(loaded));

    // ONE one-shot op through the loaded guest — "the shell runs the app" as the
    // *initiator* (§12.8). `handle`'s ABI and nothing more (§12.2): stdin is the argument,
    // stdout is the response, and the op name is passed through unread. Nothing here
    // decodes or knows an app's argument shape, which a flag per operation could not
    // avoid.
    //
    // Addressed to the app THIS flow loaded, by the key its load returned, rather than
    // left to `invoke`'s "the only app" default: a node with a network has the transport
    // loaded too, so "the only one" is not something `--bundle` can mean.
    const op = args.get("op");
    if (op !== undefined) {
      host.stdout(await shell.invoke(op, host.stdin(), appKeyFor(loaded.author, loaded.manifest.app)));
    }
  }

  const close = () => shell.close();
  if (!net?.port && !net?.wsPort) return { serving: false, close };
  // A serving node with an app loaded also answers for the cohort: inbound requests route
  // by protocol id to whichever app claims it, answered from its own confined realm — no
  // app-specific host code, no second dispatch (§12.8, §12.10).
  if (bundlePath !== undefined) {
    await shell.serve();
    host.log("  serving the app's request side from the confined guest");
  }
  host.log("serving — Ctrl-C to stop");
  return { serving: true, close };
}
