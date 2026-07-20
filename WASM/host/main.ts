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

import { KernelHost } from "./kernel-host.js";
import { loadSodium } from "./node.js";
import { policyFromJson, buildAdmit, type ShellPolicy } from "./policy.js";
import {
  FreshnessMarks, loadBundle as loadBundleBlob,
  type BundleManifest, type FreshnessStore, type LoadedBundle,
} from "./bundle.js";
import { NodeNetwork, parsePeerSpec } from "./net-node.js";
import { Transport, type Network, type PeerId } from "./net.js";
import { createCapBridge, capPreamble, bundlePreamble, opsForCaps, guestSignScope, type CapSodium } from "./cap-bridge.js";
import { createSafeRealm, type SafeRealm, type SafeRealmBridge } from "./safe-js.js";
import { NodeFs } from "./fs-node.js";
import { toHex, fromHex, concatBytes } from "./util.js";

type Sodium = Awaited<ReturnType<typeof loadSodium>>;
type Identity = { publicKey: Uint8Array; privateKey: Uint8Array };

export interface ShellOptions {
  /** allowed-keys.json contents (see policy.ts). Omit ⇒ a deny-all policy (no
   *  authors), so the node boots and serves but accepts no installs — handy for
   *  just bringing a node online (e.g. to test connectivity). */
  policyJson?: string;
  /** Directory backing the fs.* capability. */
  dir: string;
  /** This node's kernel keypair (README §12.6). */
  identity: Identity;
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

export interface Shell {
  host: KernelHost;
  net: Network;
  transport: Transport;
  fs: NodeFs;
  sodium: Sodium;
  policy: ShellPolicy;
  /** Cohort peers the guest reaches via net.peers (CAP_NET_PEERS). */
  readonly peers: Set<PeerId>;
  /** Add a peer to the cohort the guest can reach (and dial, if a NodeNetwork). */
  addPeer(peerId: PeerId): void;
  /** Load a signed bundle file: verify the manifest, govern it against the policy,
   *  integrity-check + install the modules, and return the guest source. */
  loadBundle(file: string): LoadedBundle;
  /** Run one of a loaded bundle's guest entrypoints — whichever names the app
   *  declares — through a generic cap-bridge over the kernel's primitives. Load a
   *  bundle first. This is "the shell runs the app" (README §12.8). */
  runGuest(entry: string, payload: Uint8Array): Promise<Uint8Array>;
  /** Serve the app's request side: route incoming transport requests to the loaded
   *  guest's `handle` entrypoint on the *same* confined realm `runGuest` uses. The
   *  holder path answers from local fs + crypto synchronously (`callSync`) without
   *  yielding, so it can respond while an initiator `runGuest` call is parked
   *  mid-await in that realm — this is how the runtime answers for a cohort with no
   *  app-specific host code (README §12.8). Idempotent; load a bundle first. */
  serve(): Promise<void>;
  close(): void;
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

/** Assemble the runtime: the kernel and the bundle loader under its admission policy,
 *  plus the fs/net capability backends. Application-neutral. */
export async function boot(opts: ShellOptions): Promise<Shell> {
  const sodium = await loadSodium();
  const host = new KernelHost(sodium);

  // Omitted policy ⇒ deny-all; a provided one is parsed strictly (policy.ts). Wiring the
  // admission policy is what lets the loader admit bundle modules (README §12.4–§12.5).
  const policy = policyFromJson(opts.policyJson);
  host.setAdmitPolicy(buildAdmit(policy));

  // Capability backends — all application-neutral primitives. The cap-bridge
  // (built lazily in runGuest) exposes exactly these to a loaded bundle's guest:
  // crypto (sumo), net (this transport), fs (this dir), the installed handlers,
  // clock, and identity. The kernel itself never learns what app it is running.
  const fs = new NodeFs(opts.dir);
  const freshness = new FileFreshnessStore(freshnessPathFor(opts.dir));
  const ownsNet = !opts.network;
  const net: Network = opts.network ??
    new NodeNetwork({ identity: opts.identity, sodium, listen: opts.listen, wsListen: opts.wsListen });
  if (ownsNet) await (net as NodeNetwork).start();

  const peerId = toHex(opts.identity.publicKey);
  const transport = new Transport(peerId, net, opts.timeoutMs ?? 2000);
  const peers = new Set<PeerId>(opts.peers ?? []);

  let loaded: LoadedBundle | null = null;
  let realm: SafeRealm | null = null;         // one confined realm: initiator + holder
  let served = false;                         // serve() wired transport.onRequest already

  const requireLoaded = (): LoadedBundle => {
    if (!loaded) throw new Error("shell: load a bundle first (loadBundle)");
    return loaded;
  };
  // One cap-bridge shape for the realm — kernel primitives only. `runGuest` awaits net;
  // the holder `handle` path only ever calls the synchronous ops.
  // The bundle's signed manifest declares the capability *domains* it needs
  // (`caps`); the shell expands those to the concrete op set the bridge enforces
  // and wires only the matching backends, so a guest holds exactly what it
  // declared — nothing outside its caps resolves.
  const buildBridge = (b: LoadedBundle): SafeRealmBridge => {
    // No guest ⇒ no caps at all: authority is declared inside `guest` precisely so a
    // handler-only bundle cannot hold any (§12.4).
    const caps = new Set(b.manifest.guest?.caps ?? []);
    return createCapBridge({
      // The bundled sumo's overloaded .d.ts isn't structurally assignable to the
      // bridge's minimal crypto surface (its crypto_generichash types the key as
      // required) — narrow it with a cast; the bundled sumo build satisfies the
      // surface at runtime.
      sodium: sodium as unknown as CapSodium,
      identity: opts.identity,
      callHandler: (name, p) => host.callHandler(name, p),
      transport, peers: () => [...peers],
      fs: caps.has("fs") ? fs : undefined,   // only hand over the fs backend if declared
      now: () => Date.now(),
      allowedOps: opsForCaps(caps),
      // Scope the guest's SIGN op to this bundle's namespace (README §12.2): the host
      // signs `DOMAIN_guest ‖ scope ‖ msg`, never the raw node key over guest bytes.
      signScope: guestSignScope(b.author, b.manifest.app),
    });
  };
  // The guest source as signed content, fronted by three injected blocks:
  //
  //   capPreamble()     the generic op ABI (`const CAP_X = n`).
  //   bundlePreamble()  `const BUNDLE` — what the RUNTIME derived from the admitted
  //                     manifest: author, app, the signing prefix, and the kernel names
  //                     its modules landed at. No author writes these by hand.
  //   const APP         author config from the signed manifest, with the operator's
  //                     `opts.config` merged OVER it (and winning) for per-node policy
  //                     like a storage quota. Opaque to the shell.
  //
  // BUNDLE and APP are separate consts on purpose: operator config merges into APP, so
  // anything that lived there would be operator-writable — including, before this split,
  // the guest's own signing prefix. Nothing in BUNDLE can be overridden at boot.
  // Both realms load the byte-identical program.
  const guestFullSource = (b: LoadedBundle): string =>
    capPreamble()
    + bundlePreamble({
      app: b.manifest.app,
      author: b.author,
      modules: Object.fromEntries(b.manifest.modules.map((m) => [m.name, m.kernelName])),
    })
    + `const APP = ${JSON.stringify({ ...(b.manifest.guest?.config ?? {}), ...(opts.config ?? {}) })};\n`
    + b.guestSource;

  return {
    host, net, transport, fs, sodium, policy, peers,
    addPeer(p) { if (p !== peerId) peers.add(p); },
    loadBundle(file) { return (loaded = loadBundle(host, sodium, policy, file, freshness)); },
    async runGuest(entry, payload) {
      const b = requireLoaded();
      if (!realm) realm = await createSafeRealm({ source: guestFullSource(b), bridge: buildBridge(b) });
      return realm.call(entry, payload);
    },
    async serve() {
      const b = requireLoaded();
      if (served) return;
      if (!realm) realm = await createSafeRealm({ source: guestFullSource(b), bridge: buildBridge(b) });
      const hr = realm;
      served = true;
      // arg = [type u8][payload]; the guest's `handle` returns the response bytes
      // synchronously (admission / store / fetch are local fs + crypto only), so it can
      // run re-entrantly while an initiator call is parked mid-await in this same realm.
      transport.onRequest((_from, type, payload) => {
        const arg = new Uint8Array(1 + payload.length);
        arg[0] = type & 255;
        arg.set(payload, 1);
        return hr.callSync("handle", arg);
      });
    },
    close() { realm?.dispose(); transport.close(); if (ownsNet) (net as NodeNetwork).close(); },
  };
}

/** Load a signed bundle *file* onto a host — the Node binding of the shared loader
 *  (bundle.ts `loadBundle`), which owns the verify → govern → freshness → integrity →
 *  install order. Reading the file is the whole platform seam: a bundle is one blob, so
 *  there is no directory walk and no filename to resolve. */
export function loadBundle(host: KernelHost, sodium: Sodium, policy: ShellPolicy, file: string, freshness?: FreshnessStore): LoadedBundle {
  return loadBundleBlob(host, sodium, policy, new Uint8Array(readFileSync(file)), freshness);
}

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
function loadIdentity(sodium: Sodium, keyPath: string): Identity {
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
    const b = shell.loadBundle(str(args, "bundle")!);
    console.log(`  bundle ${b.manifest.app} v${b.manifest.version} → installed ${b.installed.join(", ") || "(none)"}`);
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

