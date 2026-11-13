// The host's side of the platform ABI (abi.ts, §12.9): adapts a loader's primitives
// (private modules, entropy, files, TCP and UDP sockets, the engine table that realms and
// the host's crypto run on) to what `bootShell` takes. The same code runs on every target:
// as the host script over a loader's globals (host-main.ts, which adds the operator flow),
// in-process under the Node library (shell-node.ts) and on a page (platform-web.ts). It
// awaits each call a platform may answer asynchronously.
import { policyFromJson } from "./policy.js";
import { FreshnessMarks, freshnessPathFor, moduleSet, type PureModuleLoader } from "./bundle.js";
import { parseDest } from "../services/peer-addr.js";
import { bootShell, type BootShellOptions, type Shell, type TransportOptions } from "./shell-core.js";
import type { TransportHost } from "../services/link.js";
import { engineSodium, type HostSodium, type SyncEngine } from "./sodium-engine.js";
import type { RealmFactory } from "./realm-queue.js";
import { engineRealms } from "./engine-realm.js";
import { type ChannelFactory, type LocalChannels, type RawLink } from "../services/socket-seam.js";
import {
  SILENT_SOCKET_MS,
  TCP_KEEPALIVE_MS,
  TCP_LINGER_MS,
} from "../services/net-limits.js";
import { FilesFs } from "../services/fs-files.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_SCRATCH_SIZE, WASM_PAGE_BYTES } from "./wasm-limits.js";
import { dec, enc, errMessage, u8 } from "./util.js";
import { moduleShims, scratchModule } from "./pure-module.js";
import { checkStagedHost, readHostBlob } from "./host-blob.js";
import {
  PLATFORM_ABI,
  type EngineTable, type HostBridge, type PlatformFs, type PlatformNet, type PlatformUdp,
} from "./abi.js";

/** A loader's primitives, as the globals of abi.ts, less what only the script's entry
 *  reads. A page has no sockets of its own (platform-web.ts): its channels are the ones it
 *  passes to `standUp`. */
export interface Platform {
  bridge: HostBridge;
  fs: PlatformFs;
  net?: PlatformNet;
  udp?: PlatformUdp;
}

/** What a node needs: the store, the policy, and `bootShell`'s own options. Each target
 *  builds the rest from its own parts (`standUp`). An embedder whose gate is not a policy
 *  file passes `admit` in place of `policyJson`. */
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

/** A host over one platform: what a node is built from. */
export interface PlatformHost {
  /** This node's crypto, run on the engine table (sodium-engine.ts). */
  sodium: HostSodium;
  /** The realm factory (§12.3): realms on the engine table (engine-realm.ts). */
  createRealm: RealmFactory;
  /** Boot a node through `bootShell` (§12.9). The policy is parsed before anything is
   *  opened. */
  standUp(cfg: NodeSetup): Promise<NodeRuntime>;
  /** A node's TCP sockets, on a platform that has them. The platform's datagrams the
   *  transport runs its UDP paths over are lent through `standUp` (§12.7). */
  channels(): TcpChannels;
  /** A node's private modules (§4). */
  modules: PureModuleLoader;
}

/** A platform's TCP sockets, and its local ones for the control endpoint where it has them. */
export type TcpChannels = ChannelFactory & { local?: LocalChannels };

/** A deadline as the ABI carries it: `Infinity` as -1, omitted as the shared default. */
const abiMs = (ms: number | undefined): number =>
  ms === undefined ? DEFAULT_GUEST_DEADLINE_MS : ms === Infinity ? -1 : ms;

/** The driver's ChannelFactory over a platform's TCP sockets. Once per platform, since it
 *  installs the socket limits and the dispatchers events arrive through. `silentMs` is
 *  shortened only by tests. */
export function tcpChannels(net: PlatformNet, silentMs = SILENT_SOCKET_MS): TcpChannels {
  /** Open channels by socket id, and accept callbacks by bound port. */
  const chans = new Map<number, { deliver: (bytes: Uint8Array) => void; closed: () => void }>();
  const accepts = new Map<number, (id: number, remoteAddr: string) => void>();
  // Passed once. The inbound budget is TransportHost's, as is the live-socket bound
  // (`maxRawLinks`): a platform holds at most one read per socket until `resume`.
  net.install(TCP_KEEPALIVE_MS, TCP_LINGER_MS, {
    deliver: (id, bytes) => { chans.get(id)?.deliver(u8(bytes)); },
    closed: (id) => { chans.get(id)?.closed(); },
    accept: (port, id, remoteAddr) => {
      const onAccept = accepts.get(port);
      // A port no longer listened on has nothing to hand the socket to.
      if (onAccept) onAccept(id, remoteAddr);
      else net.close(id, false);
    },
  });

  function makeLink(id: number, remoteAddr?: string): RawLink {
    let onData: (bytes: Uint8Array) => void = () => {};
    let onClose: () => void = () => {};
    // A socket that never sends a byte is failed before any transport deadline can arm,
    // dialled or accepted. The first read clears it; after that idleness is the
    // transport's, and a second clock here would cut established links behind its back.
    const silent = setTimeout(() => {
      net.close(id, false);
      chans.get(id)?.closed();
    }, silentMs);
    const entry = {
      deliver: (bytes: Uint8Array) => {
        clearTimeout(silent);
        entry.deliver = (b) => onData(b);
        onData(bytes);
      },
      closed: () => { clearTimeout(silent); chans.delete(id); onClose(); },
    };
    chans.set(id, entry);
    return {
      stream: true,
      remoteAddr,
      send: (bytes) => { net.send(id, bytes); },
      buffered: () => net.buffered(id),
      // One read per resume, so only enabling needs to be passed on.
      setReadable: (enabled) => { if (enabled) net.resume(id); },
      onData: (cb) => { onData = cb; },
      onClose: (cb) => { onClose = cb; },
      // A local close never fires `closed`, so drop the entry here.
      close: (graceful) => { clearTimeout(silent); net.close(id, graceful); chans.delete(id); },
    };
  }

  return {
    // Local sockets, on a platform that has them; their listeners key below zero.
    local: net.listenLocal && net.connectLocal ? {
      listenLocal: async (path, onAccept) => {
        const key = await net.listenLocal!(path);
        accepts.set(key, (id) => onAccept(makeLink(id)));
      },
      connectLocal: (path) => makeLink(net.connectLocal!(path)),
    } : undefined,
    // The ABI has no TLS socket, so `wss://` is unroutable (§12.1).
    connect: (dest) => {
      const d = parseDest(dest);
      if (!d || d.scheme === "wss") return null;
      return makeLink(net.connect(d.host, d.port));
    },
    listen: async (addrs, onAccept) => {
      const ports: number[] = [];
      for (const a of addrs) {
        const bound = await net.listen(a.host, a.port);
        accepts.set(bound, (id, remoteAddr) => onAccept(makeLink(id, remoteAddr), { listener: a.label }));
        ports.push(bound);
      }
      return ports;
    },
    // Close the bound listeners on teardown. Every accept callback is dead then; drop them
    // so they can be collected.
    close: () => {
      net.closeListeners();
      accepts.clear();
    },
  };
}

/** The engine over a loader's table of handles (native). */
function tableEngine(t: EngineTable): SyncEngine {
  return (wasm, imports) => {
    const id = t.engineInstantiate(wasm, imports);
    return {
      exported: (name) => {
        const fn = t.engineExport(id, name);
        // A fixed arity rather than a spread, which costs the interpreted host realm.
        return (a, b, c, d, e, f, g, h, i, j, k, l) => t.engineCall(id, fn, a, b, c, d, e, f, g, h, i, j, k, l);
      },
      read: (ptr, len) => u8(t.engineRead(id, ptr, len)),
      grow: (pages) => t.engineGrow(id, pages),
      global: (name) => t.engineGlobal(id, name),
      write: (ptr, bytes) => { t.engineWrite(id, ptr, bytes); },
      dispose: () => { t.engineDispose(id); },
    };
  };
}

/** Zeros for wiping a scratch window, grown to the largest wipe. */
let zeros = new Uint8Array(0);
/** One private module on bounded engine instances, under the shared ABI: bound at
 *  install, and again on the call after a deadline closed its instance (§4.3). */
function engineModule(t: EngineTable, wasm: Uint8Array) {
  let id = 0, deadline = -1, killed = false;
  let module!: ReturnType<typeof scratchModule>;
  const bind = () => {
    id = t.engineInstantiate(wasm, moduleShims(), DEFAULT_GUEST_DEADLINE_MS);
    try {
      let fn = -1;
      try { fn = t.engineExport(id, "handle"); } catch { /* scratchModule names it */ }
      module = scratchModule({
        handle: fn < 0 ? undefined : (len) => {
          const r = t.engineCallBounded(id, fn, deadline, len);
          if (r === null) killed = true;
          return r;
        },
        global: (name) => t.engineGlobal(id, name),
        memoryBytes: () => t.engineGrow(id, 0) * WASM_PAGE_BYTES,
        read: (ptr, len) => u8(t.engineRead(id, ptr, len)),
        write: (ptr, bytes) => { t.engineWrite(id, ptr, bytes); },
        wipe: (ptr, len) => {
          if (zeros.length < len) zeros = new Uint8Array(len);
          t.engineWrite(id, ptr, zeros.subarray(0, len));
        },
      }, DEFAULT_SCRATCH_SIZE);
    } catch (err) {
      t.engineDispose(id);
      throw err;
    }
    killed = false;
  };
  bind();
  return {
    /** A trap or an overrun answers null; the next call after an overrun binds afresh. */
    call(payload: Uint8Array, deadlineMs: number): Uint8Array | null {
      if (killed) {
        t.engineDispose(id);
        try { bind(); } catch { return null; }
      }
      deadline = deadlineMs;
      try { return module.call(payload); } catch { return null; }
    },
    dispose() { t.engineDispose(id); },
  };
}
/** Private modules where the loader bounds engine calls: in the calling guest's segment,
 *  timed on its clock. A call is synchronous, so its time is already inside that segment. */
const engineModules = (t: EngineTable): PureModuleLoader => ({
  build: (mods) => moduleSet(mods, (wasm) => engineModule(t, wasm),
    (w, payload, deadlineMs) => ({ bytes: w.call(payload, abiMs(deadlineMs)), ms: 0 }),
    (w) => w.dispose()),
});

/** The freshness store (§12.4) beside the data directory. An unreadable file fails the
 *  boot instead of dropping every mark and revocation. */
export function freshnessStoreFor(files: PlatformFs, dir: string): FreshnessMarks {
  const path = freshnessPathFor(dir);
  let raw;
  // The operator's own file, so no cap.
  try {
    raw = files.read(path, Number.MAX_SAFE_INTEGER);
  } catch (e) { throw new Error(`freshness store: cannot read ${path}: ${errMessage(e)}`, { cause: e }); }
  return new FreshnessMarks(raw === null ? null : dec.decode(u8(raw)), (json) => files.write(path, enc.encode(json), true));
}

export function platformHost({ bridge, fs: files, net, udp }: Platform): PlatformHost {
  const { engine, modules } = "engine" in bridge ? bridge
    : { engine: tableEngine(bridge), modules: engineModules(bridge) };
  /** The running host blob, which carries the realm engine, this host's crypto and its
   *  default transport. */
  const hostEnv = u8(bridge.hostBlob());
  const hostParts = readHostBlob(hostEnv);
  const sodium = engineSodium(engine, hostParts.sodium, hostParts.mldsa, (n) => u8(bridge.random(n)));

  const tcp = net && tcpChannels(net);
  const channels = () => {
    if (!tcp) throw new Error("host: this platform has no sockets; pass transport.channels");
    return tcp;
  };
  const createRealm: RealmFactory = engineRealms(engine, hostParts.qjs);

  async function standUp(cfg: NodeSetup): Promise<NodeRuntime> {
    const admit = cfg.admit ?? policyFromJson(cfg.policyJson);
    return bootShell({
      sodium, identity: cfg.identity, modules, admit,
      createRealm,
      freshnessStore: freshnessStoreFor(files, cfg.dir),
      guestDeadlineMs: cfg.guestDeadlineMs,
      realmMemoryBytes: cfg.realmMemoryBytes,
      services: {
        fs: new FilesFs(files, cfg.dir),
        // The network as configured: the blob's transport over the platform's sockets,
        // unless the caller brings its own.
        transport: cfg.transport && {
          ...cfg.transport,
          bundle: cfg.transport.bundle ?? hostParts.transport,
          channels: cfg.transport.channels ?? channels(),
          datagrams: cfg.transport.datagrams ?? udp,
        },
        // The successor is this host's to vet, as an app bundle is; the loader only keeps
        // it.
        host: {
          stage: async (blob: Uint8Array) => {
            checkStagedHost(sodium, hostEnv, PLATFORM_ABI, blob);
            await bridge.stageHost(blob);
          },
        },
      },
    });
  }

  return { sodium, createRealm, standUp, channels, modules };
}
