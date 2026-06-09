// seedkernel-shell — the generic runtime entry (the runtime split).
// It boots the kernel under an install policy and serves; it knows nothing about
// storage or any other app. Everything an app needs arrives as signed installs
// that must clear the --policy gate. The runtime offers raw-byte capabilities —
// crypto (the bundled sumo), fs.* on --dir, net.* on --listen — and the safe-js
// confinement host, held ready to be wired to an app's declared caps once the
// app cap ABI lands (step 6); the kernel itself stays application-neutral.
//
//   node build/host/main.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 --install ./codec.install,./reputation.install
//
// The Bun standalone (main-bun.ts) embeds kernel+bootstrap so
// `bun build --compile host/main-bun.ts` yields a single-file runtime.

import { readFile } from "node:fs/promises";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { KernelHost } from "./kernel-host.js";
import { loadSodium } from "./node.js";
import { parsePolicy, buildApproveInstall, type ShellPolicy } from "./policy.js";
import { verifyManifest, contentMatches, type BundleManifest } from "./bundle.js";
import { NodeNetwork, parsePeerSpec } from "./net-node.js";
import { Transport, type Network, type PeerId } from "./net.js";
import { createCapBridge, capPreamble, type CapSodium } from "./cap-bridge.js";
import { createSafeRealm, createSyncSafeRealm, type SafeRealm, type SyncSafeRealm, type SafeRealmBridge } from "./safe-js.js";
import { NodeFs } from "./fs-node.js";
import { toHex, fromHex, readU32BE, concatBytes } from "./util.js";

type Sodium = Awaited<ReturnType<typeof loadSodium>>;
type Identity = { publicKey: Uint8Array; privateKey: Uint8Array };

/** The two genesis modules the runtime always loads. */
export interface KernelWasm {
  kernelBytes: Uint8Array;
  bootstrapBytes: Uint8Array;
}

export interface ShellOptions extends KernelWasm {
  /** allowed-keys.json contents (see policy.ts). */
  policyJson: string;
  /** Directory backing the fs.* capability. */
  dir: string;
  /** This node's kernel keypair (§2). */
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
}

export interface LoadedBundle {
  manifest: BundleManifest;
  author: Uint8Array;
  guestSource: string;
  /** Logical names of the modules that registered on the kernel. */
  installed: string[];
}

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
  /** Dispatch a signed install envelope; the policy decides whether it lands. */
  installFromEnvelope(bytes: Uint8Array): void;
  /** Load a signed bundle directory: verify the manifest, govern it against the
   *  policy, integrity-check + install the modules, and return the guest source. */
  loadBundle(dir: string): LoadedBundle;
  /** Run a loaded bundle's guest entrypoint (e.g. put/get/repair) through a
   *  generic cap-bridge over the kernel's primitives. Load a bundle first. This
   *  is "the shell runs the app" (the runtime split). */
  runGuest(entry: string, payload: Uint8Array): Promise<Uint8Array>;
  /** Serve the app's request side: build a *synchronous* confined realm from the
   *  loaded guest and route incoming transport requests to its `handle`
   *  entrypoint. The sync realm answers from local fs + crypto without yielding,
   *  so it can respond while the async `runGuest` realm is parked mid-await — this
   *  is how the runtime becomes a holder with no app-specific host code (PLAN-
   *  runtime-split.md, step 8). Idempotent; load a bundle first. */
  serveAsHolder(): Promise<void>;
  close(): void;
}

/** Assemble the runtime: kernel + bootstrap + signature + installer under the
 *  loaded policy, plus the fs/net capability backends. Application-neutral. */
export async function boot(opts: ShellOptions): Promise<Shell> {
  const sodium = await loadSodium();
  const host = await KernelHost.load(opts.kernelBytes as BufferSource, opts.bootstrapBytes as BufferSource, sodium);

  host.registerSignature(host.deriveBootstrapName("signature"));
  host.registerInstaller(
    host.deriveBootstrapName("install"),
    host.deriveBootstrapName("installer.lookup"),
    host.deriveBootstrapName("installer.caps_of"),
  );
  const policy = parsePolicy(opts.policyJson);
  host.setApproveInstall(buildApproveInstall(host, policy));

  // Capability backends — all application-neutral primitives. The cap-bridge
  // (built lazily in runGuest) exposes exactly these to a loaded bundle's guest:
  // crypto (sumo), net (this transport), fs (this dir), the installed handlers,
  // clock, and identity. The kernel itself never learns what app it is running.
  const fs = new NodeFs(opts.dir);
  const ownsNet = !opts.network;
  const net: Network = opts.network ??
    new NodeNetwork({ identity: opts.identity, sodium, listen: opts.listen, wsListen: opts.wsListen });
  if (ownsNet) await (net as NodeNetwork).start();

  const peerId = toHex(opts.identity.publicKey);
  const transport = new Transport(peerId, net, opts.timeoutMs ?? 2000);
  const peers = new Set<PeerId>(opts.peers ?? []);

  let loaded: LoadedBundle | null = null;
  let realm: SafeRealm | null = null;          // async — the initiator (put/get/repair)
  let holderRealm: SyncSafeRealm | null = null; // sync — the request side (handle)

  const requireLoaded = (): LoadedBundle => {
    if (!loaded) throw new Error("shell: load a bundle first (loadBundle)");
    return loaded;
  };
  // One cap-bridge shape for both realms — kernel primitives only. The async
  // realm awaits net; the sync holder realm only ever calls the synchronous ops.
  const buildBridge = (): SafeRealmBridge => createCapBridge({
    // The bundled sumo's overloaded .d.ts isn't structurally assignable to the
    // bridge's minimal crypto surface (its crypto_generichash types the key as
    // required) — narrow it, the same cast seedstore's loadSodium does.
    sodium: sodium as unknown as CapSodium,
    identity: opts.identity,
    callHandler: (name, p) => host.callHandler(name, p),
    transport, peers: () => [...peers], fs, now: () => Date.now(),
  });
  // The guest source as signed content, fronted by the generic op preamble and
  // the bundle's app constants (`const APP = …`) — the same two blocks seedstore's
  // Tier-2 coordinator injects. Both realms load the byte-identical program.
  const guestFullSource = (b: LoadedBundle): string =>
    capPreamble() + `const APP = ${JSON.stringify(b.manifest.config ?? {})};\n` + b.guestSource;

  return {
    host, net, transport, fs, sodium, policy, peers,
    addPeer(p) { if (p !== peerId) peers.add(p); },
    installFromEnvelope(bytes) { host.dispatch(bytes); },
    loadBundle(dir) { return (loaded = loadBundle(host, sodium, policy, dir)); },
    async runGuest(entry, payload) {
      const b = requireLoaded();
      if (!realm) realm = await createSafeRealm({ source: guestFullSource(b), bridge: buildBridge() });
      return realm.call(entry, payload);
    },
    async serveAsHolder() {
      const b = requireLoaded();
      if (holderRealm) return;
      const hr = holderRealm = await createSyncSafeRealm({ source: guestFullSource(b), bridge: buildBridge() });
      // arg = [type u8][payload]; the guest's `handle` returns the response bytes
      // synchronously (admission / store / fetch are local fs + crypto only).
      transport.onRequest((_from, type, payload) => {
        const arg = new Uint8Array(1 + payload.length);
        arg[0] = type & 255;
        arg.set(payload, 1);
        return hr.call("handle", arg);
      });
    },
    close() { realm?.dispose(); holderRealm?.dispose(); transport.close(); if (ownsNet) (net as NodeNetwork).close(); },
  };
}

/** Load a signed bundle directory onto a host: verify the manifest signature,
 *  require its author to be in the policy, integrity-check each module against its
 *  declared content hash, dispatch the pre-signed installs (the installer re-checks
 *  author + module hash), and integrity-check the guest. Returns the parsed
 *  manifest + guest source + which modules registered. */
export function loadBundle(host: KernelHost, sodium: Sodium, policy: ShellPolicy, dir: string): LoadedBundle {
  const env = new Uint8Array(readFileSync(join(dir, "manifest.bundle")));
  const v = verifyManifest(sodium, env);
  if (!v) throw new Error("bundle: manifest signature invalid");
  if (!policy.authors.map((a) => a.toLowerCase()).includes(toHex(v.author))) {
    throw new Error("bundle: manifest author is not in the policy's allowed set");
  }
  const gh = (b: Uint8Array) => host.genesisHash(b);
  const installed: string[] = [];
  for (const mod of v.manifest.modules) {
    const wasm = new Uint8Array(readFileSync(join(dir, mod.file)));
    if (!contentMatches(wasm, mod.hash, gh)) throw new Error(`bundle: ${mod.name} content hash mismatch`);
    host.dispatch(new Uint8Array(readFileSync(join(dir, mod.install))));
    if (host.isRegistered(fromHex(mod.kernelName))) installed.push(mod.name);
  }
  const guestSource = readFileSync(join(dir, v.manifest.guest.file), "utf8");
  if (!contentMatches(new TextEncoder().encode(guestSource), v.manifest.guest.hash, gh)) {
    throw new Error("bundle: guest content hash mismatch");
  }
  return { manifest: v.manifest, author: v.author, guestSource, installed };
}

/** Default node loader: read the two genesis modules from the build dir. */
export async function loadKernelWasmNode(): Promise<KernelWasm> {
  const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
  const [k, b] = await Promise.all([
    readFile(join(root, "build/kernel.wasm")),
    readFile(join(root, "build/bootstrap.wasm")),
  ]);
  return { kernelBytes: new Uint8Array(k), bootstrapBytes: new Uint8Array(b) };
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

export async function main(loadWasm: () => Promise<KernelWasm> = loadKernelWasmNode): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  const policyPath = str(args, "policy");
  if (!policyPath) {
    console.error("seedkernel-shell: --policy <allowed-keys.json> is required");
    process.exit(2);
  }
  const policyJson = readFileSync(policyPath, "utf8");
  const dir = str(args, "dir", "./seedkernel-data")!;
  const keyPath = str(args, "key", "./seedkernel.key")!;

  const sodium = await loadSodium();
  const identity = loadIdentity(sodium, keyPath);
  const { kernelBytes, bootstrapBytes } = await loadWasm();

  const shell = await boot({
    kernelBytes, bootstrapBytes, policyJson, dir, identity,
    listen: args["listen"] ? parseHostPort(str(args, "listen")!) : undefined,
    wsListen: args["ws-listen"] ? parseHostPort(str(args, "ws-listen")!) : undefined,
    timeoutMs: args["timeout"] ? Number(str(args, "timeout")) : undefined,
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
  console.log(`  policy ${policyPath}`);
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
  // Bare signed installs from disk (each must clear the --policy gate to land).
  if (args["install"]) {
    for (const f of str(args, "install")!.split(",").map((s) => s.trim()).filter(Boolean)) {
      shell.installFromEnvelope(new Uint8Array(readFileSync(f)));
      console.log(`  install ${f} → dispatched`);
    }
  }
  // One-shot client ops through the loaded guest — "the shell runs the app" as
  // the *initiator* (the runtime split). The request (holder) side is
  // served below once we start listening (step 8), from the same confined guest.
  if (args["bundle"] && args["put"]) {
    const data = new Uint8Array(readFileSync(str(args, "put")!));
    const r = await shell.runGuest("put", data);
    console.log(`  PUT ok: ${readU32BE(r, 33)} chunk(s)${r[32] === 1 ? " (replicated)" : ""}`);
    console.log(`    --get ${toHex(r.slice(0, 32))}:${toHex(r.slice(37, 69))}`);
  }
  if (args["bundle"] && args["get"]) {
    const [mid, key] = str(args, "get")!.split(":");
    const data = await shell.runGuest("get", concatBytes([fromHex(mid), fromHex(key)]));
    const outFile = str(args, "out");
    if (outFile) { writeFileSync(outFile, data); console.log(`  GET ok: ${data.length} B → ${outFile}`); }
    else process.stdout.write(data);
  }

  if (args["relay"]) {
    console.warn(`  relay  ${str(args, "relay")}: relay client not yet wired (step 5 follow-up) — ignored`);
  }

  const serving = !!(nodeNet.port || nodeNet.wsPort);
  if (!serving) { shell.close(); return; }
  // A serving node with an app loaded also *holds* for the cohort: route incoming
  // requests to the app's confined request side (HAVE/OFFER/STORE/FETCH for
  // storage), with no app-specific host code in the runtime (step 8).
  if (args["bundle"]) {
    await shell.serveAsHolder();
    console.log("  holder serving the app's request side from the confined guest");
  }
  console.log("serving — Ctrl-C to stop");
  process.on("SIGINT", () => { shell.close(); process.exit(0); });
}

// Auto-run only when invoked directly as the Node CLI (build/host/main.js). The
// Bun standalone entry (main-bun.ts) imports main() and calls it with the
// embedded-core loader, so it must not double-run here.
const entry = process.argv[1] ?? "";
if (/[\\/]main\.(ts|js)$/.test(entry)) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
