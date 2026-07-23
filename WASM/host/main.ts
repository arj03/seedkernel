// seedkernel-shell — the generic runtime entry (README §12).
// It stands up the handler table under an install policy and serves; it knows
// nothing about storage or any other app. Everything an app needs arrives as a signed bundle
// (§12.4) whose manifest author must clear the --policy gate. The runtime offers
// raw-byte capabilities — crypto (the bundled sumo), fs.* on --dir, net.* on
// --listen — and the safe-js confinement host, wired to a bundle's declared cap
// domains when one loads (§12.4); the kernel itself stays application-neutral.
//
//   node build/host/main-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 --bundle ./app.skb
//
// For a self-contained non-browser binary, the Go/native target (native/,
// README §12.9) embeds and runs this same shared host JS — no Node install needed.

import { readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import type { KernelHost } from "./kernel-host.js";
import { loadSodium } from "./node.js";
import { policyFromJson, type AdmitPredicate } from "./policy.js";
import {
  FreshnessMarks, loadBundle as loadBundleBlob,
  type BundleManifest, type FreshnessStore, type LoadedBundle,
} from "./bundle.js";
import { NodeNetwork, parsePeerSpec } from "./net-node.js";
import { type Network, type PeerId, type Transport } from "./net.js";
import { NodeFs } from "./fs-node.js";
import type { Fs } from "./fs.js";
import { toHex, fromHex, concatBytes } from "./util.js";
import { createShell, type Shell as CoreShell, type KernelTable, type ShellSodium } from "./shell-core.js";

type Sodium = Awaited<ReturnType<typeof loadSodium>>;

export interface ShellOptions {
  /** allowed-keys.json contents (see policy.ts). Omit ⇒ a deny-all policy (no
   *  authors), so the node boots and serves but accepts no installs — handy for
   *  just bringing a node online (e.g. to test connectivity). */
  policyJson?: string;
  /** Directory backing the fs.* capability. */
  dir: string;
  /** This node's kernel keypair (README §12.6). */
  identity: { publicKey: Uint8Array; privateKey: Uint8Array };
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
  /** Inject a Network (tests). Defaults to a NodeNetwork on listen/wsListen — the
   *  shell `start()`s and `close()`s the one it makes, but never an injected one. */
  network?: Network;
  /** Cohort peers the guest may reach via net.peers (the CLI also dials them). */
  peers?: PeerId[];
  /** net.send timeout in ms (how long before a peer is treated unreachable). */
  timeoutMs?: number;
  /** Operator-supplied app config, merged *over* the bundle manifest's `config`
   *  into the guest's `const APP = …`. This is where per-node operator policy
   *  lives — e.g. a storage node's `quota` byte budget — as opposed to the
   *  author-signed manifest, which carries only content-structural constants
   *  (k/m/blockSize…). Opaque to the runtime: the shell merges two maps and never
   *  inspects a key, so it stays application-neutral. */
  config?: Record<string, string | number>;
}

export type { LoadedBundle, FreshnessStore };

/** The Node-side Shell — the platform-neutral CoreShell plus a file-backed
 *  `loadBundle` and a guaranteed `fs` (Node always has a filesystem). */
export interface Shell extends CoreShell {
  fs: Fs;
  /** Load a signed bundle *file*: read it from disk then delegate to
   *  loadBundleBlob (§12.4). This is the Node convenience wrapper;
   *  cross-platform callers use loadBundleBlob directly. */
  loadBundle(file: string): Promise<LoadedBundle>;
}

/** A `FreshnessStore` backed by one JSON file (`{ "authorHex:app": version }`). Kept
 *  *outside* the guest-writable fs directory (a sibling file), so a `fs`-capable guest
 *  cannot tamper with its own freshness mark. An operator rolls back by deleting or
 *  lowering it out of band (the operator is the TCB, README §14).
 *
 *  The monotonic rule and the serialization live in `FreshnessMarks` (bundle.ts) —
 *  this adds only the Node persistence seam. */
export class FileFreshnessStore extends FreshnessMarks {
  constructor(private readonly path: string) {
    super();
    let json: string | null = null;
    try { json = readFileSync(path, "utf8"); }
    catch { /* absent/unreadable ⇒ start empty (−∞ for every key) */ }
    this.load(json);
  }
  protected override persist(json: string): void {
    // Persist atomically: write a sibling temp then rename onto the path (atomic within
    // a directory on POSIX; ReplaceFile semantics on Windows). A bare writeFileSync
    // truncates the file in place, so a crash mid-write could leave truncated JSON — which
    // the constructor's catch would silently read as "start empty", discarding the entire
    // downgrade-protection mark set on the next boot (README §12.4). Rename swaps the whole
    // file in one step, so a reader only ever sees the old or the complete new contents.
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, json);
    renameSync(tmp, this.path);
  }
}

/** The freshness file for a data directory: a sibling of the dir, so it can never
 *  collide with or be clobbered by a guest fs key (which is a file *inside* the dir). */
function freshnessPathFor(dir: string): string {
  return resolve(dir).replace(/[/\\]+$/, "") + ".freshness.json";
}

/** Assemble the runtime on Node: create the Node platform (NodeFs, FileFreshnessStore,
 *  NodeNetwork) and hand it to the shared createShell(). The Node shell is the platform-
 *  neutral core plus a file-backed `loadBundle` — that is the whole platform seam. */
export async function boot(opts: ShellOptions): Promise<Shell> {
  const sodium = await loadSodium();

  // ── Node platform seam ─────────────────────────────────────────────────────
  const fs = new NodeFs(opts.dir);
  const freshness = new FileFreshnessStore(freshnessPathFor(opts.dir));
  const ownsNet = !opts.network;
  const net: Network = opts.network ?? new NodeNetwork({
    identity: opts.identity, sodium, listen: opts.listen, wsListen: opts.wsListen,
  });
  if (ownsNet) await (net as NodeNetwork).start();

  // ── Assemble the shared shell ───────────────────────────────────────────────
  const core = createShell({
    platform: { sodium: sodium as unknown as ShellSodium, identity: opts.identity, fs, freshnessStore: freshness, network: net },
    admit: policyFromJson(opts.policyJson),
    peers: opts.peers,
    timeoutMs: opts.timeoutMs,
    config: opts.config,
  });

  // ── Node wrapper: add file-backed loadBundle ───────────────────────────────
  return {
    host: core.host,
    bindings: core.bindings,
    net: core.net,
    transport: core.transport,
    fs: core.fs!,
    sodium: core.sodium,
    peers: core.peers,
    addPeer: core.addPeer,
    removePeer: core.removePeer,
    loadBundleBlob: core.loadBundleBlob,
    uninstall: core.uninstall,
    async loadBundle(file) {
      return core.loadBundleBlob(new Uint8Array(readFileSync(file)));
    },
    runGuest: core.runGuest,
    serve: core.serve,
    close() { core.close(); if (ownsNet) (net as NodeNetwork).close(); },
  };
}

/** Load a signed bundle *file* onto a host — the Node binding of the shared loader
 *  (bundle.ts `loadBundle`), which owns the verify → govern → freshness → integrity →
 *  install order. Reading the file is the whole platform seam: a bundle is one blob, so
 *  there is no directory walk and no filename to resolve. */
export function loadBundle(
  host: KernelHost, sodium: Sodium, file: string,
  freshness?: FreshnessStore,
  admit?: AdmitPredicate,
): LoadedBundle {
  return loadBundleBlob(host, sodium, new Uint8Array(readFileSync(file)), freshness, admit);
}

// Re-export the shared types so callers get everything from one import.
export { createShell, type KernelTable } from "./shell-core.js";
export type { ShellPlatform } from "./shell-core.js";

// ── CLI ────────────────────────────────────────────────────────────────────

interface Args { [k: string]: string | boolean; }

function parseArgs(argv: string[]): Args {
  const out: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) out[key] = true;
    else { out[key] = next; i++; }
  }
  return out;
}

function str(a: Args, k: string, def?: string): string | undefined {
  const v = a[k];
  return typeof v === "string" ? v : def;
}

function parseHostPort(s: string): { host: string; port: number } {
  const colon = s.lastIndexOf(":");
  if (colon < 0) throw new Error(`expected host:port, got ${s}`);
  const host = s.slice(0, colon) || "0.0.0.0";
  const port = Number(s.slice(colon + 1));
  if (!Number.isInteger(port) || port < 0) throw new Error(`bad port in ${s}`);
  return { host, port };
}

/** Load the identity from --key, or mint one and persist it. The libsodium
 *  ed25519 secret key is seed‖pubkey, so the 32-byte public key is its tail. */
function loadIdentity(sodium: Sodium, keyPath: string): { publicKey: Uint8Array; privateKey: Uint8Array } {
  if (existsSync(keyPath)) {
    const sk = fromHex(readFileSync(keyPath, "utf8").trim());
    if (sk.length !== 64) throw new Error(`--key must hold a 64-byte secret key (got ${sk.length})`);
    return { privateKey: sk, publicKey: sk.slice(32) };
  }
  const kp = sodium.crypto_sign_keypair();
  writeFileSync(keyPath, toHex(kp.privateKey), { mode: 0o600 });
  return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

export async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  // --policy is optional: omit it for a deny-all node (boots + serves, no installs).
  const policyPath = str(args, "policy");
  const policyJson = policyPath ? readFileSync(policyPath, "utf8") : undefined;
  const dir = str(args, "dir", "./seedkernel-data")!;
  const keyPath = str(args, "key", "./seedkernel.key")!;

  const sodium = await loadSodium();
  const identity = loadIdentity(sodium, keyPath);

  // Operator-supplied app config (e.g. a storage node's quota), merged over the
  // bundle's author-signed config. Opaque JSON the shell forwards into `const APP`.
  const appConfig = args["app-config"]
    ? JSON.parse(readFileSync(str(args, "app-config")!, "utf8")) as Record<string, string | number>
    : undefined;

  const shell = await boot({
    policyJson, dir, identity,
    listen: args["listen"] ? parseHostPort(str(args, "listen")!) : undefined,
    wsListen: args["ws-listen"] ? parseHostPort(str(args, "ws-listen")!) : undefined,
    timeoutMs: args["timeout"] ? Number(str(args, "timeout")) : undefined,
    config: appConfig,
  });
  const nodeNet = shell.net as NodeNetwork;

  // Cohort peers the guest may reach (net.peers): teach the network their
  // addresses and add them to the cohort — the same wiring a storage node does.
  if (args["peers"]) {
    for (const spec of str(args, "peers")!.split(",").map((s) => s.trim()).filter(Boolean)) {
      const { peerId, addr } = parsePeerSpec(spec, "tcp");
      nodeNet.addPeerAddr(peerId, addr);
      shell.addPeer(peerId);
    }
    await nodeNet.ready();
  }

  console.log(`seedkernel-shell ${toHex(identity.publicKey)}`);
  console.log(`  policy ${policyPath ?? "(none — installs disabled)"}`);
  console.log(`  store  ${dir} (fs.* backend)`);
  console.log(`  cohort ${shell.peers.size} peer(s)`);
  if (nodeNet.port) console.log(`  tcp    listening on :${nodeNet.port}`);
  if (nodeNet.wsPort) console.log(`  ws     listening on :${nodeNet.wsPort}`);

  // A signed bundle from disk (the file-first path; relay delivery is the next
  // step). The shell verifies + governs it before anything lands.
  if (args["bundle"]) {
    const b = await shell.loadBundle(str(args, "bundle")!);
    console.log(`  bundle ${b.manifest.app} v${b.manifest.version}`);
  }
  // One-shot client ops through the loaded guest — "the shell runs the app" as the
  // *initiator* (README §12.8). The request side is served below once we start
  // listening, from the same confined guest. The shell stays application-neutral:
  // arguments cross as raw bytes (a file for --put, hex tokens joined by ':' for
  // --get) and responses come back as raw bytes — any structure in them belongs to
  // the app, so the shell prints hex or writes them verbatim and never decodes.
  if (args["bundle"] && args["put"]) {
    const data = new Uint8Array(readFileSync(str(args, "put")!));
    const r = await shell.runGuest("put", data);
    console.log(`  PUT ok: ${r.length} B response`);
    console.log(`    ${toHex(r)}`);
  }
  if (args["bundle"] && args["get"]) {
    const arg = concatBytes(str(args, "get")!.split(":").map(fromHex));
    const data = await shell.runGuest("get", arg);
    const outFile = str(args, "out");
    if (outFile) { writeFileSync(outFile, data); console.log(`  GET ok: ${data.length} B → ${outFile}`); }
    else process.stdout.write(data);
  }

  const serving = !!(nodeNet.port || nodeNet.wsPort);
  if (!serving) { shell.close(); return; }
  // A serving node with an app loaded also answers for the cohort: route incoming
  // requests to the app's confined request side, with no app-specific host code in
  // the runtime — the request types are the app's own (README §12.8).
  if (args["bundle"]) {
    await shell.serve();
    console.log("  serving the app's request side from the confined guest");
  }
  console.log("serving — Ctrl-C to stop");
  process.on("SIGINT", () => { shell.close(); process.exit(0); });
}
