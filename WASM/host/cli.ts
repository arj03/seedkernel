// cli.ts — the operator's side of a node, written once for every target. A `CliHost`
// names the few things that genuinely differ by target — files, a log line, raw stdout,
// entropy, and "stand a node up here". Tokenizing `--name value` is not what is shared;
// everything downstream of the split is: the flag SET, the defaults, the deny-all reading
// of an absent `--policy` (§14), the order (remedies before the bundle, §12.5), which
// failures are fatal, and the console lines. Those are decisions, and a decision made twice
// eventually gets made differently.
import { toHex, fromHex, errMessage } from "../core/util.js";
import { deriveNodeKey, type SubkeyCrypto, type Keypair } from "../core/subkeys.js";
import { isJsonObject, type JsonObject } from "./bundle.js";
import { PRIVILEGE_LINK } from "../core/domains.js";
import { writeOp } from "./op-frame.js";
import { parseHostPort, parsePeerSpec } from "./peer-addr.js";
import type { TransportHost } from "./transport-host.js";
import type { AppHandle, Shell } from "./shell-core.js";

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
}

/** Platform-owned channel integration kept beside the shell. */
export interface NodeRuntime {
  shell: Shell;
  transport: TransportHost;
}

/** The diagnosis a cohort operation needs when no bundle owns the raw-link binding. The
 *  adapter is always there — it is the platform's — so a node with no transport bundle answers
 *  "no route" rather than failing, which is a legitimate configuration (§12.6) and exactly
 *  the wrong answer to give an operator who typed `--peers`. */
export function requireLinkBinding(transport: Pick<TransportHost, "available">, what: string): void {
  if (!transport.available()) {
    throw new Error(`shell: ${what} — load a bundle granted the "${PRIVILEGE_LINK}" privilege first`);
  }
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
  /** Raw bytes from stdin — `--op`'s argument, verbatim; empty when nothing is piped in.
   *  A function rather than a field so a node that boots and serves never blocks on a
   *  stdin nobody will write to. */
  stdin(): Uint8Array;
  /** Entropy + the subkey derivation's crypto (§12.9). */
  sodium: SubkeyCrypto & { randombytes_buf(n: number): Uint8Array };
  /** Assemble a node on this platform: the platform seam, `bootShell`, and the
   *  transport bundle that is its network. */
  standUp(cfg: NodeSetup): Promise<NodeRuntime>;
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

/** A 32-byte secret from a file — the master seed (`--key`) and the deployment secret
 *  (`--contact-secret`) are the same shape, read the same way, and fail the same way. */
function loadHex32(files: CliFiles, path: string, label: string): Uint8Array {
  return parseHex32(utf8.decode(mustRead(files, path, label)), label);
}

/** Load the node's MASTER SEED from `--key`, or mint one and persist it 0600, and derive
 *  the node's keypair from it (§12.9). One 32-byte secret on disk; the master signs
 *  nothing itself, and the node's peer id is the derived channel key's public half. */
function loadNodeKeys(host: CliHost, keyPath: string): Keypair {
  const existing = host.readFile(keyPath);
  if (existing !== null) return deriveNodeKey(host.sodium, parseHex32(utf8.decode(existing), `--key ${keyPath}`));
  const master = host.sodium.randombytes_buf(32);
  host.writeFile(keyPath, utf8enc.encode(toHex(master)), 0o600);
  return deriveNodeKey(host.sodium, master);
}

/** The one console line a successful load prints (§12.4, §12.10): the app, its version, the
 *  app key an operator would pass to `--uninstall`, and what the load CLAIMED: what a PEER
 *  may reach (`protocols`) always, and what a co-resident guest may reach (`services`) when
 *  there is one — two audiences, so folding them into one list would leave a reader to
 *  guess which name a peer can send to. Both come from the manifest, so a node says what it
 *  will and will not answer at the load rather than at the first frame. */
export function loadedLine(b: AppHandle): string {
  const protocols = b.manifest.protocols ?? [];
  const services = b.manifest.services ?? [];
  const serves = protocols.length ? protocols.join(", ") : "(nothing — this bundle claims no protocol)";
  return `${b.manifest.app} v${b.manifest.version}  key ${b.key}  serves ${serves}` +
    (services.length ? `  locally ${services.join(", ")}` : "");
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
  const key = loadNodeKeys(host, keyPath);
  const contactSecretPath = args.get("contact-secret");
  const bundlePath = args.get("bundle");
  if (args.has("app-config") && bundlePath === undefined) {
    throw new Error("--app-config requires --bundle so the configuration has one app scope");
  }
  // Checked here, not at the load, so a malformed file fails before a node is listening.
  let localConfig: JsonObject | undefined;
  if (args.has("app-config")) {
    const parsed: unknown = JSON.parse(utf8.decode(mustRead(host, args.get("app-config")!, "--app-config")));
    if (!isJsonObject(parsed)) throw new Error("--app-config must hold a JSON object");
    localConfig = parsed;
  }

  const { shell, transport: net } = await host.standUp({
    dir,
    policyJson,
    identity: key,
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
  });
  // Cohort peers: teach the transport their addresses so it can dial them. A policy
  // admitting no transport bundle leaves nothing to dial FROM — say so, rather than
  // letting the flag pass silently on a node with no network.
  const peers = list(args.get("peers"));
  if (peers.length > 0) {
    requireLinkBinding(net, "--peers given, but there is nothing to dial from");
    for (const spec of peers) {
      const { peerId, addr } = parsePeerSpec(spec, "tcp");
      net.addPeerAddr(peerId, addr);
    }
    // Best-effort: ready() resolves on its own timeout rather than rejecting, so a
    // cohort member that is not up yet delays the boot but never fails it.
    await net.ready();
  }

  host.log(`${host.banner} ${toHex(key.publicKey)}`);
  host.log(`  policy ${policyPath ?? "(none — installs disabled)"}`);
  host.log(`  store  ${dir} (fs.* backend)`);
  host.log(`  cohort ${peers.length} peer(s)`);
  if (net.port) host.log(`  tcp    listening on :${net.port}`);
  if (net.wsPort) host.log(`  ws     listening on :${net.wsPort}`);

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
  if (bundlePath !== undefined) {
    let loaded: AppHandle;
    try {
      // The file named by --app-config belongs only to this explicit load. It never
      // reaches the transport bundle stood above or another app loaded into this shell.
      loaded = await shell.loadBundleBlob(
        mustRead(host, bundlePath, "--bundle"),
        localConfig === undefined ? undefined : { localConfig },
      );
    } catch (err) {
      // Fatal, and labelled: a node whose bundle did not land has no app to run, and a
      // driving script must see that rather than a silent bundle-less relay.
      throw new Error("bundle: " + errMessage(err));
    }
    host.log("  bundle " + loadedLine(loaded));

    // ONE one-shot op through the loaded guest — "the shell runs the app" as the
    // *initiator* (§12.8). `handle`'s ABI and nothing more (§12.2): stdin is the argument,
    // stdout is the response, and the op name is framed here with the app's own
    // convention (`writeOp`, the leaf client helper) and passed through unread. Nothing
    // here decodes or knows an
    // app's argument shape, which a flag per operation could not avoid. A name too long
    // or not ASCII is refused there rather than truncated into a different frame.
    //
    // Addressed through the handle THIS flow's load returned. A node with a network has
    // the transport loaded too, so no shell-level "the only app" operation exists.
    const op = args.get("op");
    if (op !== undefined) {
      host.stdout(await loaded.invoke(writeOp(op, host.stdin())));
    }
  }

  const close = () => shell.close();
  if (!net.port && !net.wsPort) return { serving: false, close };
  // A serving node with an app loaded also answers for the cohort: inbound requests route
  // by protocol id to whichever app claims it, answered from its own confined realm — no
  // app-specific host code, no second dispatch (§12.8, §12.10). Nothing to arm: the load
  // stood the guest, so the app has been answerable since the line above.
  if (bundlePath !== undefined) {
    host.log("  serving the app's request side from the confined guest");
  }
  host.log("serving — Ctrl-C to stop");
  return { serving: true, close };
}
