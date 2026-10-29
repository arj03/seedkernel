// The operator side of a node, shared by every target: flags, defaults, deny-all without
// `--policy` (§14), remedies before the bundle (§12.5), which failures are fatal, and the
// console output. A `CliHost` supplies only what differs per target.
import { toHex, fromHex, isHex64, isRecord, errMessage, enc, dec, u8 } from "./util.js";
import type { RawFiles } from "../services/fs-files.js";
import { deriveNodeKey, type SubkeyCrypto, type Keypair } from "./subkeys.js";
import { FreshnessMarks, freshnessPathFor, type JsonObject } from "./bundle.js";
import { OpArgs, writeOp } from "./op-frame.js";
import { TRANSPORT_SERVICE } from "./transport-bundle.js";
import { parseHostPort } from "../services/peer-addr.js";
import type { TransportHost } from "../services/link.js";
import type { ListenAddress, LocalChannels } from "../services/socket-seam.js";
import { controlInvoke, controlServes, serveControl } from "./control.js";
import { DEFAULT_DIR } from "./abi.js";
import type { AppHandle, BootShellOptions, Shell, TransportOptions } from "./shell-core.js";
/** Where the node's 32-byte master seed lives when `--key` is omitted (§12.6.2b). */
export const DEFAULT_KEY = "./seedkernel.key";

/** Every flag the shell accepts. An allowlist, so a mistyped `--polcy` fails instead of
 *  silently booting a deny-all node. */
const FLAGS = new Set([
  "policy", "dir", "key", "listen", "peers", "relay", "relay-secret", "contact-secret",
  "bundle", "op", "app", "local-config", "revoke", "uninstall",
  "guest-timeout", "guest-memory", "transport", "transport-config",
]);
/** The flags an `--op` to the node already serving `--dir` takes. */
const CONTROL_FLAGS = new Set(["dir", "op", "app"]);

/** The platform's files (abi.ts `PlatformFs`). A read returns `null` only for a missing
 *  file and throws otherwise, since an unreadable key file taken as a first boot would get
 *  a new identity written over it. Writes are atomic and private to this user. */
export type CliFiles = Pick<RawFiles, "read" | "write">;

/** What a node needs once the flags are read: the store, the policy, and `bootShell`'s
 *  own options. Each target builds the rest from its own parts (`standUp`). An embedder
 *  whose gate is not a policy file passes `admit` in place of `policyJson`. */
export interface NodeSetup extends Pick<BootShellOptions, "identity" | "admit" | "guestDeadlineMs" | "realmMemoryBytes"> {
  /** The network, `bootShell`'s `services.transport` (§12.6). Omitted means none. */
  transport?: TransportOptions;
  /** Directory backing the `fs` service. */
  dir: string;
  /** Policy file contents (policy.ts). Omit ⇒ deny-all for ordinary apps. */
  policyJson?: string;
}

/** Platform-owned channel integration kept beside the shell. */
export interface NodeRuntime {
  shell: Shell;
  transport: TransportHost | null;
}

/** The platform under the operator flow. */
export interface CliHost extends CliFiles {
  /** The first word of the first console line: `seedkernel-shell` or `seedkernel-native`. */
  banner: string;
  /** Arguments after the program name. */
  argv: string[];
  /** One console line: `console.error` on Node, a Go stderr write on native. */
  log(line: string): void;
  /** Raw bytes to stdout for `--op`'s response. `log` goes to stderr so it cannot
   *  corrupt them. */
  stdout(bytes: Uint8Array): void;
  /** `--op`'s argument from stdin; a function so a serving node never blocks on it. */
  stdin(): Uint8Array;
  /** Entropy and the subkey derivation's crypto (§12.6.2b). */
  sodium: SubkeyCrypto & { randombytes_buf(n: number): Uint8Array };
  /** Assemble a node on this platform through `bootShell`. */
  standUp(cfg: NodeSetup): Promise<NodeRuntime>;
  /** The platform's local sockets, for the control endpoint; absent on a platform with none. */
  local?: LocalChannels;
}

/** Whether the node is listening (so the caller keeps the process alive) and how to shut
 *  it down. */
export interface CliResult {
  serving: boolean;
  close(): void;
}

/** Split `--name value` / `--name=value` pairs. Unknown flags and flags without a value
 *  are errors. */
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

/** The label for a `--listen` entry that names none. The shipped transport treats every
 *  label except `ws` as length framing. */
const DEFAULT_LISTEN_LABEL = "tcp";

/** `--listen [label=]host:port,...`: one listener per entry. The transport decides what a
 *  label means; only its shape is checked here. */
function parseListen(v: string): ListenAddress[] {
  return list(v).map((entry) => {
    const eq = entry.indexOf("=");
    const label = eq < 0 ? DEFAULT_LISTEN_LABEL : entry.slice(0, eq);
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(label)) throw new Error(`--listen: bad label in ${JSON.stringify(entry)}`);
    const at = parseHostPort(entry.slice(eq + 1), { defaultHost: "0.0.0.0", allowEphemeral: true });
    return { label, ...at };
  });
}

/** Read a file the operator named, naming the flag on failure; `null` when absent. */
function readNamed(files: CliFiles, path: string, label: string): Uint8Array | null {
  // The operator's own files, so no cap.
  try {
    const b = files.read(path, Number.MAX_SAFE_INTEGER);
    return b === null ? null : u8(b);
  } catch (e) { throw new Error(`${label}: cannot read ${path}: ${errMessage(e)}`, { cause: e }); }
}

/** `readNamed` for a file that must exist. */
function mustRead(files: CliFiles, path: string, label: string): Uint8Array {
  const b = readNamed(files, path, label);
  if (b === null) throw new Error(`${label}: cannot read ${path}`);
  return b;
}

/** A secret from the file a flag names, kept out of `ps` that way: its text, trimmed. */
function readSecret(files: CliFiles, path: string, flag: string): string {
  return dec.decode(mustRead(files, path, flag)).trim();
}

/** One op through the transport's service id, refused when there is no transport. */
function transportCall(shell: Shell, op: OpArgs, flag: string): Promise<Uint8Array> {
  const answer = shell.call(TRANSPORT_SERVICE, op.build());
  if (!answer) throw new Error(`shell: ${flag} given, but this node has no transport to carry it`);
  return answer;
}

/** A whole-number flag, validated instead of coerced (`Number("")` is 0, which would lift
 *  the bound). */
function wholeNumberFlag(args: Map<string, string>, flag: string): number | undefined {
  const v = args.get(flag);
  if (v === undefined) return undefined;
  if (!/^[0-9]+$/.test(v)) throw new Error(`--${flag} must be a whole number (got ${JSON.stringify(v)})`);
  return Number(v);
}

/** Parse 64 hex characters into 32 bytes. Validated, since `fromHex` maps a bad pair to 0
 *  and a corrupt key file would boot under a different identity. */
export function parseHex32(hex: string, label: string): Uint8Array {
  const trimmed = hex.trim();
  if (!isHex64(trimmed)) throw new Error(`${label} must hold 32 bytes as 64 hex characters`);
  return fromHex(trimmed);
}

/** Load the master seed from `--key`, or create one and save it, then derive the
 *  node's keypair from it (§12.6.2b). The master itself signs nothing. */
function loadNodeKeys(host: CliHost, keyPath: string): Keypair {
  const existing = readNamed(host, keyPath, "--key");
  if (existing !== null) return deriveNodeKey(host.sodium, parseHex32(dec.decode(existing), `--key ${keyPath}`));
  const master = host.sodium.randombytes_buf(32);
  host.write(keyPath, enc.encode(toHex(master)), true);
  return deriveNodeKey(host.sodium, master);
}

/** The freshness store (§12.4) beside the data directory. An unreadable file fails the
 *  boot instead of dropping every mark and revocation. */
export function freshnessStoreFor(files: CliFiles, dir: string): FreshnessMarks {
  const path = freshnessPathFor(dir);
  const raw = readNamed(files, path, "freshness store");
  return new FreshnessMarks(raw === null ? null : dec.decode(raw), (json) => files.write(path, enc.encode(json), true));
}

/** The console line a load prints (§12.4, §12.10): label, version, author and claims.
 *  `protocols` always, `services` when there are any, listed apart since their audiences
 *  differ. */
export function loadedLine(b: AppHandle): string {
  const protocols = b.manifest.protocols ?? [];
  const services = b.manifest.services ?? [];
  const serves = protocols.length ? protocols.join(", ") : "(nothing — this bundle claims no protocol)";
  return `${b.manifest.app} v${b.manifest.version}  author ${toHex(b.author)}  serves ${serves}` +
    (services.length ? `  locally ${services.join(", ")}` : "");
}

/** Run the operator flow. Throws on any operator error; the caller reports and exits. */
export async function runCli(host: CliHost): Promise<CliResult> {
  const args = parseArgs(host.argv);
  // Guest bounds (§12.3); the shell checks their range. `--guest-timeout 0` is Infinity.
  const guestTimeout = wholeNumberFlag(args, "guest-timeout");
  const guestMemory = wholeNumberFlag(args, "guest-memory");
  const dir = args.get("dir") ?? DEFAULT_DIR;
  const keyPath = args.get("key") ?? DEFAULT_KEY;
  const bundlePath = args.get("bundle");
  const op = args.get("op");
  if (args.has("app") && (op === undefined || bundlePath !== undefined)) {
    throw new Error("--app names the app an --op goes to on the node serving --dir, so it takes --op and no --bundle");
  }
  const opArg = op === undefined ? undefined : host.stdin();
  // `--op` goes to the node already serving `--dir` when there is one, through its control
  // endpoint, rather than to a second node booted over the same store. That node reads no
  // other flag, so a command line with one is refused there rather than half obeyed.
  if (op !== undefined && host.local) {
    const control = { dir, local: host.local };
    const unread = [...args.keys()].filter((f) => !CONTROL_FLAGS.has(f));
    if (unread.length === 0) {
      const answer = await controlInvoke(control, args.get("app") ?? "", writeOp(op, opArg!));
      if (answer !== null) {
        host.stdout(answer);
        return { serving: false, close: () => {} };
      }
    } else if (await controlServes(control)) {
      throw new Error(`--op: a node already serves ${dir} and takes the op itself, reading no --${unread.join(", --")}: drop them, or stop that node`);
    }
  }
  if (op !== undefined && bundlePath === undefined) {
    throw new Error(`--op: no node is serving ${dir}, and without --bundle there is no app to boot`);
  }
  const policyPath = args.get("policy");
  // An absent policy denies ordinary apps; the boot transport needs no entry in it.
  const policyJson = policyPath === undefined
    ? undefined
    : dec.decode(mustRead(host, policyPath, "--policy"));
  const key = loadNodeKeys(host, keyPath);
  const contactSecretPath = args.get("contact-secret");
  if (args.has("local-config") && bundlePath === undefined) {
    throw new Error("--local-config requires --bundle so the configuration has one app scope");
  }
  // Transport-only flags on a node with no network would otherwise be silently ignored.
  const relay = args.get("relay");
  // Neither console target's sockets speak TLS, so a wss:// destination, the relay's or a
  // peer's, would only be redialed forever. A relay serves plain ws:// beside it
  // (seedrelay's deployment guide).
  for (const flag of ["relay", "peers"]) {
    if (/wss:\/\//i.test(args.get(flag) ?? "")) {
      throw new Error(`--${flag}: this node's sockets have no TLS, so it cannot reach wss://; use the ws:// address`);
    }
  }
  // A private relay's secret (seedrelay's `--secret`).
  const relaySecretPath = args.get("relay-secret");
  if (relaySecretPath !== undefined && relay === undefined) {
    throw new Error("--relay-secret requires --relay, the relay it is the secret of");
  }
  const relaySecret = relaySecretPath === undefined ? undefined : readSecret(host, relaySecretPath, "--relay-secret");
  const network = args.has("listen") || args.has("peers") || relay !== undefined;
  for (const flag of ["transport", "transport-config", "contact-secret"]) {
    if (args.has(flag) && !network) {
      throw new Error(`--${flag} requires --listen, --peers or --relay, which enable the network it configures`);
    }
  }
  const listen = args.has("listen") ? parseListen(args.get("listen")!) : [];
  // Checked here, not at install, so a malformed file fails before the node listens.
  const jsonFlag = (flag: string): JsonObject | undefined => {
    if (!args.has(flag)) return undefined;
    const parsed: unknown = JSON.parse(dec.decode(mustRead(host, args.get(flag)!, `--${flag}`)));
    if (!isRecord(parsed)) throw new Error(`--${flag} must hold a JSON object`);
    return parsed as JsonObject;
  };
  const localConfig = jsonFlag("local-config");

  // Transport config (§12.6.3), passed through unread: the transport checks it at load.
  // `--peers` and `--contact-secret` take precedence over the file.
  const peers = list(args.get("peers"));
  const transportConfig: JsonObject = jsonFlag("transport-config") ?? {};
  if (peers.length > 0) transportConfig.peers = peers;
  if (contactSecretPath !== undefined) {
    transportConfig.contactSecret = readSecret(host, contactSecretPath, "--contact-secret");
  }

  // One line each time a peer is linked, changes how it is reached, or goes, so an
  // operator, or a script driving the node, sees a relayed link move to a direct path
  // (§12.7). The shipped transport's status is `[relay u8]` and then `[key 32][direct u8]`
  // per linked peer, repeated whole on each change, so only differences print. A transport
  // that reports itself in text (a relay's) starts with a printable byte, which that relay
  // byte never is, and prints as it is.
  let routes = new Map<string, boolean>();
  const onStatus = (status: Uint8Array) => {
    if (status[0] >= 0x20) { host.log(`  ${dec.decode(status)}`); return; }
    const now = new Map<string, boolean>();
    for (let off = 1; off + 33 <= status.length; off += 33) {
      now.set(toHex(status.subarray(off, off + 32)), status[off + 32] === 1);
    }
    for (const [k, direct] of now) {
      if (routes.get(k) !== direct) host.log(`  link   ${k} ${direct ? "direct" : "relayed"}`);
    }
    for (const k of routes.keys()) {
      if (!now.has(k)) host.log(`  link   ${k} gone`);
    }
    routes = now;
  };

  const { shell, transport: net } = await host.standUp({
    dir,
    policyJson,
    identity: key,
    transport: network ? {
      listen,
      bundle: args.has("transport") ? mustRead(host, args.get("transport")!, "--transport") : undefined,
      config: transportConfig,
      onStatus,
    } : undefined,
    guestDeadlineMs: guestTimeout === 0 ? Infinity : guestTimeout,
    realmMemoryBytes: guestMemory === undefined ? undefined : guestMemory * 1024 * 1024,
  });
  // Register on the relay through the transport's service id, passing the URL and any
  // secret unread, so a node nobody can dial is reachable there (§12.7). The answer says
  // whether it registered; a relay that is down or refuses the node is redialed, not fatal.
  let registered = false;
  if (relay !== undefined) {
    const op = new OpArgs("relay").text(relay);
    if (relaySecret !== undefined) op.text(relaySecret);
    registered = (await transportCall(shell, op, "--relay"))[0] === 1;
  }
  // Wait for the cohort through the transport's service id. Best effort: `ready` settles
  // at its deadline instead of rejecting, so a missing peer delays boot but never fails it.
  if (peers.length > 0) await transportCall(shell, new OpArgs("ready").u32(5000), "--peers");

  host.log(`${host.banner} ${toHex(key.publicKey)}`);
  host.log(`  policy ${policyPath ?? "(none — app installs disabled)"}`);
  host.log(`  store  ${dir} (fs.* backend)`);
  host.log(`  cohort ${peers.length} peer(s)`);
  if (relay !== undefined) host.log(`  relay  ${relay} (${registered ? "registered" : "not registered, redialing"})`);
  for (const l of net?.listening ?? []) host.log(`  ${l.label.padEnd(6)} listening on :${l.port}`);

  // Operator remedies (§12.5) before the bundle, so a node never briefly installs what it
  // was told to remove.
  for (const authorHex of list(args.get("revoke"))) {
    const gone = shell.revoke(authorHex);
    host.log(`  revoke ${authorHex}` +
      (gone.length ? ` (uninstalled ${gone.length} app(s): ${gone.join(", ")})` : " (no apps of its were loaded)"));
  }
  for (const app of list(args.get("uninstall"))) {
    host.log(`  uninstall ${app}${shell.uninstall(app) ? "" : " (nothing bound)"}`);
  }

  // A signed bundle from disk, installed by the shell (§12.4, §12.10).
  let loaded: AppHandle | undefined;
  if (bundlePath !== undefined) {
    try {
      // --local-config belongs to this load only.
      loaded = await shell.install(
        mustRead(host, bundlePath, "--bundle"),
        localConfig === undefined ? undefined : { localConfig },
      );
    } catch (err) {
      // Fatal, so a driving script does not end up with a node silently missing its app.
      throw new Error("bundle: " + errMessage(err));
    }
    host.log("  bundle " + loadedLine(loaded));

    // A single op through this install's handle (§12.8): stdin is the argument, stdout the
    // response. The op name is framed by `writeOp` and not otherwise interpreted (§12.2).
    if (op !== undefined) {
      host.stdout(await loaded.invoke(writeOp(op, opArg!)));
    }
  }

  const close = () => shell.close();
  // A node on a relay serves through it, listening or not.
  if (!net?.listening.some((l) => l.port > 0) && relay === undefined) return { serving: false, close };
  // Inbound requests already route to the loaded app by protocol id (§12.8, §12.10).
  if (loaded !== undefined) {
    host.log("  serving the app's request side from the confined guest");
    if (host.local) {
      const app = loaded;
      // Without it the node still serves; only a later --op boots its own node.
      try {
        const path = await serveControl({ dir, local: host.local, app: (name) => (name === "" || name === app.manifest.app ? app : undefined) });
        host.log(`  control ${path} (--op from this user reaches this node)`);
      } catch (err) { host.log(`  control unavailable: ${errMessage(err)}`); }
    }
  }
  host.log("serving — Ctrl-C to stop");
  return { serving: true, close };
}
