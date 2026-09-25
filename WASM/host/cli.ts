// cli.ts — the operator's side of a node, written once for every target: the flag set,
// defaults, deny-all without `--policy` (§14), remedies before the bundle (§12.5), which
// failures are fatal, and the console lines. A `CliHost` supplies only what differs by
// target.
import { toHex, fromHex, isHex64, errMessage, enc, dec } from "../services/util.js";
import { deriveNodeKey, type SubkeyCrypto, type Keypair } from "../services/subkeys.js";
import { FreshnessMarks, freshnessPathFor, isJsonObject, type JsonObject } from "./bundle.js";
import { OpArgs, writeOp } from "../services/op-frame.js";
import { TRANSPORT_SERVICE } from "./transport-bundle.js";
import { parseHostPort } from "../services/peer-addr.js";
import type { TransportHost } from "./transport-host.js";
import type { ListenAddress } from "../services/socket-seam.js";
import type { AppHandle, BootShellOptions, Shell } from "./shell-core.js";

/** Where a node's store lives when `--dir` is omitted, on every target. */
export const DEFAULT_DIR = "./data";
/** Where the node's 32-byte master seed lives when `--key` is omitted (§12.6.2b). */
export const DEFAULT_KEY = "./seedkernel.key";

/** Every flag the shell accepts. An allowlist, because a mistyped `--polcy` would
 *  otherwise build a deny-all node that looks like one whose policy works. */
const FLAGS = new Set([
  "policy", "dir", "key", "listen", "peers", "contact-secret",
  "bundle", "op", "local-config", "revoke", "uninstall",
  "guest-timeout", "guest-memory", "transport",
]);

/** File access. A read answers `null` only for "absent" and throws otherwise — an
 *  unreadable key file read as a first boot would mint a new identity over it. A write is
 *  atomic. */
export interface CliFiles {
  readFile(path: string): Uint8Array | null;
  writeFile(path: string, bytes: Uint8Array, mode?: number): void;
}

/** What a node needs once the flags are read: the store, the policy, and `bootShell`'s
 *  own options. Each target builds the rest from its own parts (`standUp`). */
export interface NodeSetup extends Pick<BootShellOptions, "identity" | "transport" | "guestDeadlineMs" | "realmMemoryBytes"> {
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
  /** One console line: `console.error` on Node, a Go stderr write natively. */
  log(line: string): void;
  /** Raw bytes to stdout for `--op`'s response; `log` goes to stderr so it cannot
   *  corrupt it. */
  stdout(bytes: Uint8Array): void;
  /** `--op`'s argument from stdin; a function so a serving node never blocks on it. */
  stdin(): Uint8Array;
  /** Entropy + the subkey derivation's crypto (§12.9). */
  sodium: SubkeyCrypto & { randombytes_buf(n: number): Uint8Array };
  /** Assemble a node on this platform through `bootShell`. */
  standUp(cfg: NodeSetup): Promise<NodeRuntime>;
}

/** Whether the node is listening (so the caller keeps the process alive) and how to shut
 *  it down; each target acts on it its own way. */
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

/** The label a `--listen` entry without one gets; the shipped transport reads every label
 *  but `ws` as length framing. */
export const DEFAULT_LISTEN_LABEL = "tcp";

/** `--listen [label=]host:port,…`: one listener per entry. The label's meaning is the
 *  transport's; only its shape is checked here. */
export function parseListen(v: string): ListenAddress[] {
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
  try { return files.readFile(path); }
  catch (e) { throw new Error(`${label}: cannot read ${path}: ${errMessage(e)}`, { cause: e }); }
}

/** `readNamed` for a file that must exist. */
function mustRead(files: CliFiles, path: string, label: string): Uint8Array {
  const b = readNamed(files, path, label);
  if (b === null) throw new Error(`${label}: cannot read ${path}`);
  return b;
}

/** A whole-number flag, refused rather than coerced (`Number("")` is 0, which would lift
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

/** Load the master seed from `--key`, or mint and persist one 0600, and derive the node's
 *  keypair from it (§12.9). The master itself signs nothing. */
function loadNodeKeys(host: CliHost, keyPath: string): Keypair {
  const existing = readNamed(host, keyPath, "--key");
  if (existing !== null) return deriveNodeKey(host.sodium, parseHex32(dec.decode(existing), `--key ${keyPath}`));
  const master = host.sodium.randombytes_buf(32);
  host.writeFile(keyPath, enc.encode(toHex(master)), 0o600);
  return deriveNodeKey(host.sodium, master);
}

/** The freshness store (§12.4) beside the data directory. An unreadable file fails the boot
 *  rather than dropping every mark and revocation; writes are atomic and 0600. */
export function freshnessStoreFor(files: CliFiles, dir: string): FreshnessMarks {
  const path = freshnessPathFor(dir);
  const raw = readNamed(files, path, "freshness store");
  return new FreshnessMarks(raw === null ? null : dec.decode(raw),
    (json) => files.writeFile(path, enc.encode(json), 0o600));
}

/** The console line a load prints (§12.4, §12.10): label, version, author, and its claims —
 *  `protocols` always, `services` when any, kept apart since their audiences differ. */
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
  const policyPath = args.get("policy");
  // An absent policy denies ordinary apps; the boot transport needs no entry in it.
  const policyJson = policyPath === undefined
    ? undefined
    : dec.decode(mustRead(host, policyPath, "--policy"));
  const key = loadNodeKeys(host, keyPath);
  const contactSecretPath = args.get("contact-secret");
  const bundlePath = args.get("bundle");
  if (args.has("local-config") && bundlePath === undefined) {
    throw new Error("--local-config requires --bundle so the configuration has one app scope");
  }
  // Transport-only flags on a node with no network would be read and silently dropped.
  const network = args.has("listen") || args.has("peers");
  for (const flag of ["transport", "contact-secret"]) {
    if (args.has(flag) && !network) {
      throw new Error(`--${flag} requires --listen or --peers, which enable the network it configures`);
    }
  }
  const listen = args.has("listen") ? parseListen(args.get("listen")!) : [];
  // Checked here, not at the load, so a malformed file fails before a node is listening.
  let localConfig: JsonObject | undefined;
  if (args.has("local-config")) {
    const parsed: unknown = JSON.parse(dec.decode(mustRead(host, args.get("local-config")!, "--local-config")));
    if (!isJsonObject(parsed)) throw new Error("--local-config must hold a JSON object");
    localConfig = parsed;
  }

  // Transport config (§12.10), passed through unread: the transport checks it at load.
  // The contact secret comes from a file to keep it out of `ps`.
  const peers = list(args.get("peers"));
  const transportConfig: JsonObject = {};
  if (peers.length > 0) transportConfig.peers = peers;
  if (contactSecretPath !== undefined) {
    transportConfig.contactSecret = dec.decode(mustRead(host, contactSecretPath, "--contact-secret")).trim();
  }

  const { shell, transport: net } = await host.standUp({
    dir,
    policyJson,
    identity: key,
    transport: network ? {
      listen,
      bundle: args.has("transport") ? mustRead(host, args.get("transport")!, "--transport") : undefined,
      config: transportConfig,
    } : false,
    guestDeadlineMs: guestTimeout === 0 ? Infinity : guestTimeout,
    realmMemoryBytes: guestMemory === undefined ? undefined : guestMemory * 1024 * 1024,
  });
  // Wait for the cohort through the transport's service id. Best-effort: `ready` settles
  // at its deadline rather than rejecting, so a missing member delays boot, never fails it.
  if (peers.length > 0) {
    const ready = shell.call(TRANSPORT_SERVICE, new OpArgs("ready").u32(5000).build());
    if (!ready) throw new Error("shell: --peers given, but there is nothing to dial from — enable transport first");
    await ready;
  }

  host.log(`${host.banner} ${toHex(key.publicKey)}`);
  host.log(`  policy ${policyPath ?? "(none — app installs disabled)"}`);
  host.log(`  store  ${dir} (fs.* backend)`);
  host.log(`  cohort ${peers.length} peer(s)`);
  for (const l of net?.listening ?? []) host.log(`  ${l.label.padEnd(6)} listening on :${l.port}`);

  // Operator remedies (§12.5) before the bundle, so a node never briefly installs what it
  // was told to refuse.
  for (const authorHex of list(args.get("revoke"))) {
    const gone = shell.revoke(authorHex);
    host.log(`  revoke ${authorHex}` +
      (gone.length ? ` (uninstalled ${gone.length} app(s): ${gone.join(", ")})` : " (no apps of its were loaded)"));
  }
  for (const app of list(args.get("uninstall"))) {
    host.log(`  uninstall ${app}${shell.uninstall(app) ? "" : " (nothing bound)"}`);
  }

  // A signed bundle from disk; the whole load is the shell's (§12.4, §12.10).
  if (bundlePath !== undefined) {
    let loaded: AppHandle;
    try {
      // --local-config belongs to this load only.
      loaded = await shell.install(
        mustRead(host, bundlePath, "--bundle"),
        localConfig === undefined ? undefined : { localConfig },
      );
    } catch (err) {
      // Fatal: a driving script must not get a silent bundle-less relay.
      throw new Error("bundle: " + errMessage(err));
    }
    host.log("  bundle " + loadedLine(loaded));

    // One one-shot op through this load's handle (§12.8): stdin is the argument, stdout the
    // response, the op name framed by `writeOp` and otherwise unread (§12.2).
    const op = args.get("op");
    if (op !== undefined) {
      host.stdout(await loaded.invoke(writeOp(op, host.stdin())));
    }
  }

  const close = () => shell.close();
  if (!net?.listening.some((l) => l.port > 0)) return { serving: false, close };
  // Inbound requests already route to the loaded app by protocol id (§12.8, §12.10).
  if (bundlePath !== undefined) {
    host.log("  serving the app's request side from the confined guest");
  }
  host.log("serving — Ctrl-C to stop");
  return { serving: true, close };
}
