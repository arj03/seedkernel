// cli.ts — the operator's side of a node, written once for every target.
//
// What an operator types, what each flag defaults to, what order the node does things
// in, and what it prints while doing them. None of that is platform: it is the same
// decision on Node, on Bun and inside the native binary's QuickJS, so this module is
// one flow, with a `CliHost` naming the few things that genuinely differ by target.
//
// **Argument tokenizing is not what is shared here.** Splitting `--name value` is a
// dozen lines in any language and a bad split fails loudly; the reason this module
// exists is everything downstream of the split — the flag SET, the defaults, the
// deny-all reading of an absent `--policy` (§14), the order (remedies before the
// bundle, §12.5), which failures are fatal, and the console lines. Those are decisions,
// and a decision made twice is a decision that will eventually be made differently.
//
// The platform record is deliberately small: files, a log line, raw stdout, entropy,
// and "stand a node up on this platform". Everything else the flow needs it computes.
import { toHex, fromHex, concatBytes, errMessage } from "../core/util.js";
import { deriveNodeKeys, type NodeKeys, type SubkeyCrypto, type Keypair } from "../core/subkeys.js";
import { appKeyFor, type LoadedBundle } from "./bundle.js";
import { parseHostPort, parsePeerSpec } from "./transport-host.js";
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
  "bundle", "put", "get", "out", "app-config", "revoke", "uninstall",
  "request-deadline", "guest-timeout", "guest-memory", "transport",
]);

/** File access, as the flow needs it: a read that answers `null` for "absent" rather
 *  than throwing (the `--key` path takes that branch on a first boot), and a write that
 *  is atomic — a half-written key file or freshness mark is worse than none. */
export interface CliFiles {
  readFile(path: string): Uint8Array | null;
  writeFile(path: string, bytes: Uint8Array, mode?: number): void;
}

/** What a node needs to exist, once the flags have been read. The two targets build it
 *  from very different parts — `NodeFs` + `node:net` here, a wazero table + Go sockets
 *  there — which is the whole of why `standUp` is a member and not code in this file. */
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
   *  line that is allowed to differ; the peer id after it is not. */
  banner: string;
  /** Arguments after the program name. */
  argv: string[];
  /** One console line. `console.log` on Node; a Go stdout write natively, where
   *  QuickJS's own `console` writes to a discarded WASI stdout. */
  log(line: string): void;
  /** Raw bytes to stdout — `--get` with no `--out` writes the app's response
   *  verbatim, so this cannot go through `log`. */
  stdout(bytes: Uint8Array): void;
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

/** Split `--name value` / `--name=value` pairs, refusing anything else.
 *
 *  Stricter than either parser it replaces, in the two places silence was expensive: an
 *  unknown flag is an error rather than an ignored token (Node's old parser dropped
 *  `--timeout` on the floor for as long as `scripts/loader-interop.sh` has been passing
 *  it), and a flag given without a value is an error rather than a `true` that later
 *  reads as a path. */
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

/** Parse 64 hex characters into the 32 bytes they name.
 *
 *  Validated rather than decoded loosely: `fromHex` maps a non-hex pair to 0, so a
 *  corrupt key file would otherwise boot the node happily under a *different*
 *  identity, and a typo'd contact secret would produce a node that looks healthy and
 *  is reachable by nobody (§12.6.2 — a gated node refuses callers in silence). Parse
 *  time is the only place an operator can still be told. */
export function parseHex32(hex: string, label: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex.trim())) {
    throw new Error(`${label} must hold 32 bytes as 64 hex characters`);
  }
  return fromHex(hex.trim());
}

/** A 32-byte secret from a file — the master seed (`--key`) and the deployment secret
 *  (`--contact-secret`) are the same shape, read the same way, and fail the same way. */
function loadHex32(files: CliFiles, path: string, label: string): Uint8Array {
  return parseHex32(utf8.decode(mustRead(files, path, label)), label);
}

/** Load the node's MASTER SEED from `--key`, or mint one and persist it 0600, and
 *  derive the node's keypair from it (§12.9).
 *
 *  One secret on disk, 32 bytes. The master signs nothing itself — it only derives. The
 *  node's peer id is the derived channel keypair's public half. */
function loadNodeKeys(host: CliHost, keyPath: string): NodeKeys {
  const existing = host.readFile(keyPath);
  if (existing !== null) return deriveNodeKeys(host.sodium, parseHex32(utf8.decode(existing), `--key ${keyPath}`));
  const master = host.sodium.randombytes_buf(32);
  host.writeFile(keyPath, utf8enc.encode(toHex(master)), 0o600);
  return deriveNodeKeys(host.sodium, master);
}

/** The one console line a successful load prints (§12.4, §12.10): the app, its version,
 *  the app key an operator would pass to `--uninstall`, and what the load CLAIMED to
 *  serve. The protocols come from the manifest, so this REPORTS the routing rather than
 *  asking the operator to name it — and a node that will answer nothing says so here,
 *  at the load, instead of at the first frame. */
export function loadedLine(b: LoadedBundle): string {
  const serves = b.manifest.protocols ?? [];
  return `${b.manifest.app} v${b.manifest.version}  key ${appKeyFor(b.author, b.manifest.app)}` +
    `  serves ${serves.length ? serves.join(", ") : "(nothing — this bundle claims no protocol)"}`;
}

/** Run the operator flow to completion.
 *
 *  Throws on anything the operator got wrong — a bad flag, an unreadable file, a bundle
 *  that will not load. The caller reports and exits, because how a target reports a
 *  fatal error (a Go `os.Exit`, a rejected promise on Node) is the last thing about
 *  this that is platform. */
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
    // Guest resource bounds (§12.3). Both default to a real number inside the shell, so
    // omitting the flags leaves the guest bounded rather than unbounded; these only
    // widen or tighten. `--guest-timeout 0` reads as Infinity — "no budget" said
    // explicitly, rather than reached by leaving a flag off.
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
  // Read once and held: nothing below this line mounts a second one, and every use is
  // guarded on the null rather than on which class the object turned out to be.
  const net = shell.transport;

  // Cohort peers the guest may reach: teach the transport their addresses so it can
  // dial them. The transport owns connectivity (§12.10), so a policy admitting no
  // transport bundle leaves nothing to dial FROM — say that, rather than letting the
  // flag pass silently on a node with no network.
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

  // Operator remedies (§12.5), applied BEFORE the bundle deliberately: a node booting
  // with both should never briefly install what it was told to refuse. --revoke is the
  // whole remedy for a compromised key (refuse + tear down); --uninstall is the
  // narrower one — drop an app without writing its author off.
  for (const authorHex of list(args.get("revoke"))) {
    const gone = shell.revoke(authorHex);
    host.log(`  revoke ${authorHex}` +
      (gone.length ? ` (uninstalled ${gone.length} app(s): ${gone.join(", ")})` : " (no apps of its were loaded)"));
  }
  for (const appKey of list(args.get("uninstall"))) {
    host.log(`  uninstall ${appKey}${shell.uninstall(appKey) ? "" : " (nothing bound)"}`);
  }

  // A signed bundle from disk. Reading the one file is all the operator flow does: the
  // whole load — manifest signature, policy governance, freshness, per-module and guest
  // integrity, binding the modules, claiming the manifest's protocol ids — is the
  // shared shell's (§12.4, §12.10).
  const bundlePath = args.get("bundle");
  if (bundlePath !== undefined) {
    let loaded: LoadedBundle;
    try {
      loaded = await shell.loadBundleBlob(mustRead(host, bundlePath, "--bundle"));
    } catch (err) {
      // Fatal, and labelled: a node whose bundle did not land has no app to run or
      // serve, and a driving script must see that rather than a node that came up as a
      // silent bundle-less relay.
      throw new Error("bundle: " + errMessage(err));
    }
    host.log("  bundle " + loadedLine(loaded));

    // One-shot client ops through the loaded guest — "the shell runs the app" as the
    // *initiator* (§12.8). The shell stays application-neutral: arguments cross as raw
    // bytes (a file for --put, hex tokens joined by ':' for --get) and responses come
    // back as raw bytes, so it prints hex or writes them verbatim and never decodes.
    if (args.has("put")) {
      const r = await shell.runGuest("put", mustRead(host, args.get("put")!, "--put"));
      host.log(`  PUT ok: ${r.length} B response`);
      host.log(`    ${toHex(r)}`);
    }
    if (args.has("get")) {
      const data = await shell.runGuest("get", concatBytes(args.get("get")!.split(":").map(fromHex)));
      const outPath = args.get("out");
      if (outPath !== undefined) {
        // An ordinary output file, explicitly: the atomic write's temp is created 0600,
        // so leaving the mode off would hand the operator a result only they can read.
        host.writeFile(outPath, data, 0o644);
        host.log(`  GET ok: ${data.length} B → ${outPath}`);
      } else {
        host.stdout(data);
      }
    }
  }

  const close = () => shell.close();
  if (!net?.port && !net?.wsPort) return { serving: false, close };
  // A serving node with an app loaded also answers for the cohort: inbound requests are
  // routed by protocol id to whichever installed app claims it, and a guest app answers
  // from its own confined realm — no app-specific host code, no second dispatch
  // (§12.8, §12.10).
  if (bundlePath !== undefined) {
    await shell.serve();
    host.log("  serving the app's request side from the confined guest");
  }
  host.log("serving — Ctrl-C to stop");
  return { serving: true, close };
}
