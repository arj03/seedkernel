// The host's side of the platform ABI (abi.ts, §12.9): adapts the loader's primitives
// (private modules, entropy, an `fs` directory, TCP and UDP sockets, the engine table that
// realms and the host's crypto run on) to what `bootShell` takes, and runs the operator flow. The same script runs on
// every loader: it awaits each call a loader may answer asynchronously.
import { policyFromJson } from "./policy.js";
import { type PureModuleLoader } from "./bundle.js";
import { freshnessStoreFor, runCli, type CliFiles, type CliHost, type NodeRuntime, type NodeSetup } from "./cli.js";
import { parseDest } from "../services/peer-addr.js";
import { bootShell } from "./shell-core.js";
import { engineSodium, type HostSodium, type SyncEngine } from "./sodium-engine.js";
import { monotonicMs, type RealmFactory } from "./realm-queue.js";
import { engineRealms } from "./engine-realm.js";
import { combineChannels, type ChannelFactory, type RawLink } from "../services/socket-seam.js";
import { UdpNetwork, ipv6Text, type DatagramPlatform } from "../services/udp/net-udp.js";
import {
  DEFAULT_MAX_RAW_LINKS,
  MAX_INBOUND_HOLD_BYTES,
  MAX_INBOUND_HOLD_SLICES,
  TCP_LINGER_MS,
} from "../services/net-limits.js";
import { FS_AVAILABLE_UNKNOWN, type Fs } from "../services/fs.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_SCRATCH_SIZE } from "./wasm-limits.js";
import { enc } from "../services/util.js";
import {
  PLATFORM_ABI,
  type Bytes, type PlatformBridge, type PlatformFs, type PlatformNet, type PlatformUdp,
} from "./abi.js";

declare const bridge: PlatformBridge;
declare const __fs: PlatformFs;
declare const __net: PlatformNet;
declare const __udp: PlatformUdp;

if (bridge.abi !== PLATFORM_ABI) {
  throw new Error(`host: this loader implements platform ABI ${bridge.abi}, the host needs ${PLATFORM_ABI}`);
}

/** Bytes as a Uint8Array, without a copy when they already are one. */
const u8 = (b: Bytes): Uint8Array => (b instanceof Uint8Array ? b : new Uint8Array(b));

/** The engine table over the loader's. */
const platformEngine: SyncEngine = (wasm, imports) => {
  const id = bridge.engineInstantiate(wasm, imports);
  return {
    exported: (name) => {
      const fn = bridge.engineExport(id, name);
      // A fixed arity rather than a spread, which costs the interpreted host realm.
      return (a, b, c, d, e, f, g, h, i, j, k, l) => bridge.engineCall(id, fn, a, b, c, d, e, f, g, h, i, j, k, l);
    },
    read: (ptr, len) => u8(bridge.engineRead(id, ptr, len)),
    grow: (pages) => bridge.engineGrow(id, pages),
    global: (name) => bridge.engineGlobal(id, name),
    write: (ptr, bytes) => { bridge.engineWrite(id, ptr, bytes); },
    dispose: () => { bridge.engineDispose(id); },
  };
};
/** This node's crypto, run on the engine table (sodium-engine.ts); exported so the native
 *  tests drive the production one. */
export const sodium: HostSodium = engineSodium(platformEngine, u8(bridge.sodiumWasm()), u8(bridge.mldsaWasm()),
  (n) => u8(bridge.random(n)));

/** The async `Fs` seam over `__fs`; `async` so a loader's throw becomes a rejection.
 *  Exported for the native tests. */
export const fs: Fs = {
  async get(key) { const r = await __fs.get(key); return r === null ? null : u8(r); },
  async put(key, bytes) { await __fs.put(key, bytes); },
  async size(key) { return __fs.size(key); },
  // An empty listing arrives as "", which must map to [], not split's [""].
  async list(prefix) { const s = await __fs.list(prefix); return s === "" ? [] : s.split("\n"); },
  async delete(key) { return __fs.delete(key); },
  // The ABI's -1 becomes the seam's sentinel.
  async stat() {
    const s = await __fs.stat();
    return { used: s.used, available: s.available === -1 ? FS_AVAILABLE_UNKNOWN : s.available };
  },
};

// Limits are passed once; the loader enforces the ones that apply before JS sees a socket.
__net.install(DEFAULT_MAX_RAW_LINKS, TCP_LINGER_MS,
  MAX_INBOUND_HOLD_BYTES, MAX_INBOUND_HOLD_SLICES);

// ── RawLink over the loader's sockets ───────────────────────────────────────────
// The loader delivers through the dispatchers at the end of this block.

/** Open channels by socket id, and accept callbacks by bound port. */
const netChans = new Map<number, { deliver: (bytes: Uint8Array) => void; closed: () => void }>();
const netAccepts = new Map<number, (id: number, remoteAddr: string) => void>();

function makeLink(id: number, remoteAddr?: string): RawLink {
  let onData: (bytes: Uint8Array) => void = () => {};
  let onClose: () => void = () => {};
  netChans.set(id, {
    deliver: (bytes) => onData(bytes),
    closed: () => { netChans.delete(id); onClose(); },
  });
  return {
    stream: true,
    remoteAddr,
    send: (bytes) => { __net.send(id, bytes); },
    buffered: () => __net.buffered(id),
    // One read per resume, so only enabling needs to be passed on.
    setReadable: (enabled) => { if (enabled) __net.resume(id); },
    onData: (cb) => { onData = cb; },
    onClose: (cb) => { onClose = cb; },
    // A local close never fires __netClosed, so drop the entry here.
    close: (graceful) => { __net.close(id, graceful); netChans.delete(id); },
  };
}

declare global {
  var __netDeliver: (id: number, bytes: Bytes) => void;
  var __netClosed: (id: number) => void;
  var __netAccept: (port: number, id: number, remoteAddr: string) => void;
  var __udpDeliver: (id: number, batch: Bytes) => void;
}

globalThis.__netDeliver = (id, bytes) => { const c = netChans.get(id); if (c) c.deliver(u8(bytes)); };
globalThis.__netClosed = (id) => { const c = netChans.get(id); if (c) c.closed(); };
globalThis.__netAccept = (port, id, remoteAddr) => { const a = netAccepts.get(port); if (a) a(id, remoteAddr); };

const udpSockets = new Map<number, (bytes: Uint8Array, host: string, port: number) => void>();

/** The UDP path's platform over the loader's datagrams. */
export const platformDatagrams: DatagramPlatform = {
  async bind() {
    const { id, port } = await __udp.bind();
    let onMessage: (bytes: Uint8Array, host: string, port: number) => void = () => {};
    udpSockets.set(id, (bytes, host, from) => onMessage(bytes, host, from));
    return {
      port,
      socket: {
        send: (bytes, to, host) => { __udp.send(id, host, to, bytes); },
        onMessage: (cb) => { onMessage = cb; },
        close: () => { udpSockets.delete(id); __udp.close(id); },
      },
    };
  },
  addresses: () => { const s = __udp.addresses(); return s === "" ? [] : s.split("\n"); },
};

globalThis.__udpDeliver = (id, batch) => {
  const deliver = udpSockets.get(id);
  const b = u8(batch);
  // A batch is mostly one peer's, so its address is spelled once, not once a datagram: an
  // IPv4 one is told from the last by its four bytes as a number, an IPv6 one by its text.
  let host = "", ip = -1;
  for (let at = 0; deliver && at < b.length;) {
    const n = b[at++];
    if (n === 4) {
      const from = ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
      if (from !== ip) { ip = from; host = `${b[at]}.${b[at + 1]}.${b[at + 2]}.${b[at + 3]}`; }
    } else {
      ip = -1;
      host = ipv6Text(b, at);
    }
    at += n;
    const len = (b[at + 2] << 8) | b[at + 3];
    deliver(b.subarray(at + 4, at + 4 + len), host, (b[at] << 8) | b[at + 1]);
    at += 4 + len;
  }
};

// ── The platform ─────────────────────────────────────────────────────────────
/** A deadline as the ABI carries it: `Infinity` as -1, omitted as the shared default. */
const abiMs = (ms: number | undefined): number =>
  ms === undefined ? DEFAULT_GUEST_DEADLINE_MS : ms === Infinity ? -1 : ms;

/** Private module values over opaque slot names. */
let moduleSlotSeq = 0;
const modules: PureModuleLoader = {
  async build(mods) {
    const slot = `slot:${++moduleSlotSeq}`;
    await bridge.buildModules(slot, mods, DEFAULT_SCRATCH_SIZE, DEFAULT_GUEST_DEADLINE_MS);
    return {
      async call(module, payload, deadlineMs) {
        const t0 = monotonicMs();
        const r = bridge.callModule(slot, module, payload, abiMs(deadlineMs));
        if (r instanceof Promise) {
          const { bytes, ms } = await r;
          return { bytes: bytes === null ? null : u8(bytes), ms };
        }
        // Answered in this frame, so the wall clock around it is the module's own compute.
        return { bytes: r === null ? null : u8(r), ms: monotonicMs() - t0 };
      },
      dispose() { bridge.disposeModules(slot); },
    };
  },
};
/** `CliFiles` over the loader's files. A read throws for anything but a missing file; a
 *  write throws when it fails, which `FreshnessMarks` relies on to roll back. */
const files: CliFiles = {
  readFile(path) {
    const r = bridge.readFile(path);
    return r === null ? null : u8(r);
  },
  writeFile(path, bytes, mode) { bridge.writeFile(path, bytes, mode ?? 0); },
};
/** The driver's ChannelFactory over the loader's TCP sockets. */
const tcpChannels: ChannelFactory = {
  // The ABI has no TLS socket, so `wss://` is unroutable (§12.1).
  connect: (dest) => {
    const d = parseDest(dest);
    if (!d || d.scheme === "wss") return null;
    return makeLink(__net.connect(d.host, d.port));
  },
  listen: async (addrs, onAccept) => {
    const ports: number[] = [];
    for (const a of addrs) {
      const bound = await __net.listen(a.host, a.port);
      netAccepts.set(bound, (id, remoteAddr) => onAccept(makeLink(id, remoteAddr), { listener: a.label }));
      ports.push(bound);
    }
    return ports;
  },
  // Close the bound listeners on teardown. Every accept callback is dead then; drop them
  // so they can be collected.
  close: () => {
    __net.closeListeners();
    netAccepts.clear();
  },
};
/** A node's sockets: TCP, and the UDP path over the loader's datagrams. A factory per
 *  node, since a UDP factory keeps the one node's accept sink. */
export function platformChannels(): ChannelFactory {
  return combineChannels(tcpChannels, new UdpNetwork({ datagrams: platformDatagrams }));
}
let qjsWasm: Uint8Array | undefined;
/** The realm factory (§12.3): realms on the engine table, the shared driver
 *  (engine-realm.ts). */
const createRealm: RealmFactory = (opts) =>
  engineRealms(platformEngine, qjsWasm ??= u8(bridge.qjsWasm()), { billModules: !bridge.modulesInSegment })(opts);

/** Boot a node through `bootShell` (§12.9), for the operator flow and the native tests.
 *  `__fs` serves one directory, so nodes in one host share `cfg.dir`. The policy is parsed
 *  before anything is opened. */
async function standUp(cfg: NodeSetup): Promise<NodeRuntime> {
  const admit = policyFromJson(cfg.policyJson);
  __fs.open(cfg.dir);
  return bootShell({
    sodium, identity: cfg.identity, modules, fs, admit,
    createRealm,
    freshnessStore: freshnessStoreFor(files, cfg.dir),
    // The network as configured, over the loader's sockets unless the caller brings its own.
    transport: cfg.transport && { ...cfg.transport, channels: cfg.transport.channels ?? platformChannels() },
    guestDeadlineMs: cfg.guestDeadlineMs,
    realmMemoryBytes: cfg.realmMemoryBytes,
    hostStaging: { stage: (blob: Uint8Array) => bridge.stageHost(blob) },
  });
}

// ── the operator flow ────────────────────────────────────────────────────────
/** This platform as `cli.ts` needs it; cli.ts makes every decision. */
function cliHost(): CliHost {
  return {
    ...files,
    banner: bridge.banner,
    argv: JSON.parse(bridge.argv()) as string[],
    log(line) { bridge.log(line); },
    stdout(bytes) { bridge.stdout(bytes); },
    stdin() { return u8(bridge.stdin()); },
    sodium,
    standUp,
  };
}
/** Run the operator flow. The loader reads back, as JSON bytes, whether to keep running. */
async function runMain(): Promise<Uint8Array> {
  const { serving, close } = await runCli(cliHost());
  if (!serving) close();
  return enc.encode(JSON.stringify({ serving }));
}
// What the loader reaches by name; the native tests drive these same functions.
export { runMain, standUp, createRealm };
