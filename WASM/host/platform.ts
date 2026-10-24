// The host's side of the platform ABI (abi.ts, §12.9): adapts a loader's primitives
// (private modules, entropy, files, TCP and UDP sockets, the engine table that realms and
// the host's crypto run on) to what `bootShell` takes, and runs the operator flow. The same
// code runs on every target: as the host script over a loader's globals (host-main.ts),
// and in-process under the Node library (shell-node.ts). It awaits each call a platform
// may answer asynchronously.
import { policyFromJson } from "./policy.js";
import { moduleSet, type PureModuleLoader } from "./bundle.js";
import { freshnessStoreFor, runCli, type CliHost, type NodeRuntime, type NodeSetup } from "./cli.js";
import { parseDest } from "../services/peer-addr.js";
import { bootShell } from "./shell-core.js";
import { engineSodium, type HostSodium, type SyncEngine } from "./sodium-engine.js";
import type { RealmFactory } from "./realm-queue.js";
import { engineRealms } from "./engine-realm.js";
import { type ChannelFactory, type RawLink } from "../services/socket-seam.js";
import {
  MAX_INBOUND_HOLD_BYTES,
  MAX_INBOUND_HOLD_SLICES,
  SILENT_SOCKET_MS,
  TCP_KEEPALIVE_MS,
  TCP_LINGER_MS,
} from "../services/net-limits.js";
import { FilesFs } from "../services/fs-files.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_SCRATCH_SIZE, WASM_PAGE_BYTES } from "./wasm-limits.js";
import { enc, u8 } from "../services/util.js";
import { moduleShims, scratchModule } from "./pure-module.js";
import { checkStagedHost, readHostBlob } from "./host-blob.js";
import {
  PLATFORM_ABI,
  type PlatformBridge, type PlatformDispatchers, type PlatformFs, type PlatformNet,
  type PlatformUdp,
} from "./abi.js";

/** A loader's primitives, as the globals of abi.ts. A page has no sockets of its own
 *  (platform-web.ts): its channels are the ones it passes to `standUp`. */
export interface Platform {
  bridge: PlatformBridge;
  fs: PlatformFs;
  net?: PlatformNet;
  udp?: PlatformUdp;
}

/** A host over one platform: the entry its loader calls, and what a node is built from. */
export interface PlatformHost extends PlatformDispatchers {
  /** This node's crypto, run on the engine table (sodium-engine.ts). */
  sodium: HostSodium;
  /** The realm factory (§12.3): realms on the engine table (engine-realm.ts). */
  createRealm: RealmFactory;
  /** Boot a node through `bootShell` (§12.9). The policy is parsed before anything is
   *  opened. */
  standUp(cfg: NodeSetup): Promise<NodeRuntime>;
  /** A node's TCP sockets, on a platform that has them. The platform's datagrams the
   *  transport runs its UDP paths over are lent through `standUp` (§12.7). */
  channels(): ChannelFactory;
  /** A node's private modules (§4). */
  modules: PureModuleLoader;
}

/** A deadline as the ABI carries it: `Infinity` as -1, omitted as the shared default. */
const abiMs = (ms: number | undefined): number =>
  ms === undefined ? DEFAULT_GUEST_DEADLINE_MS : ms === Infinity ? -1 : ms;

/** The driver's ChannelFactory over a platform's TCP sockets. Once per platform, since it
 *  installs the socket limits and the dispatchers events arrive through. `silentMs` is
 *  shortened only by tests. */
export function tcpChannels(net: PlatformNet, silentMs = SILENT_SOCKET_MS): ChannelFactory {
  /** Open channels by socket id, and accept callbacks by bound port. */
  const chans = new Map<number, { deliver: (bytes: Uint8Array) => void; closed: () => void }>();
  const accepts = new Map<number, (id: number, remoteAddr: string) => void>();
  // Passed once; the platform applies the inbound limits to reads not yet delivered. The
  // live-socket bound is the transport's (TransportHost `maxRawLinks`).
  net.install(TCP_KEEPALIVE_MS, TCP_LINGER_MS, MAX_INBOUND_HOLD_BYTES, MAX_INBOUND_HOLD_SLICES, {
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

export function platformHost({ bridge, fs: files, net, udp }: Platform): PlatformHost {
  if (bridge.abi !== PLATFORM_ABI) {
    throw new Error(`host: this loader implements platform ABI ${bridge.abi}, the host needs ${PLATFORM_ABI}`);
  }

  /** The engine table over the platform's. */
  const engine: SyncEngine = (wasm, imports) => {
    const id = bridge.engineInstantiate(wasm, imports);
    return {
      exported: (name) => {
        const fn = bridge.engineExport(id, name);
        // A fixed arity rather than a spread, which costs the interpreted host realm.
        return (a, b, c, d, e, f, g, h, i, j, k, l) => bridge.engineCall(id, fn, a, b, c, d, e, f, g, h, i, j, k, l);
      },
      read: (ptr, len) => u8(bridge.engineRead(id, ptr, len)),
      view: bridge.engineView && ((ptr, len) => bridge.engineView!(id, ptr, len)),
      grow: (pages) => bridge.engineGrow(id, pages),
      global: (name) => bridge.engineGlobal(id, name),
      write: (ptr, bytes) => { bridge.engineWrite(id, ptr, bytes); },
      dispose: () => { bridge.engineDispose(id); },
    };
  };
  /** The running host blob, which carries the realm engine and this host's crypto. */
  const hostEnv = u8(bridge.hostBlob());
  const hostParts = readHostBlob(hostEnv);
  const sodium = engineSodium(engine, hostParts.sodium, hostParts.mldsa, (n) => u8(bridge.random(n)));

  // ── The node's parts ───────────────────────────────────────────────────────────
  /** Zeros for wiping a scratch window, grown to the largest wipe. */
  let zeros = new Uint8Array(0);
  /** One private module on bounded engine instances, under the shared ABI: bound at
   *  install, and again on the call after a deadline closed its instance (§4.3). */
  function engineModule(wasm: Uint8Array) {
    let id = 0, deadline = -1, killed = false;
    let module!: ReturnType<typeof scratchModule>;
    const bind = () => {
      id = bridge.engineInstantiate(wasm, moduleShims(), DEFAULT_GUEST_DEADLINE_MS);
      try {
        let fn = -1;
        try { fn = bridge.engineExport(id, "handle"); } catch { /* scratchModule names it */ }
        module = scratchModule({
          handle: fn < 0 ? undefined : (len) => {
            const r = bridge.engineCallBounded!(id, fn, deadline, len);
            if (r === null) killed = true;
            return r;
          },
          global: (name) => bridge.engineGlobal(id, name),
          memoryBytes: () => bridge.engineGrow(id, 0) * WASM_PAGE_BYTES,
          read: (ptr, len) => u8(bridge.engineRead(id, ptr, len)),
          write: (ptr, bytes) => { bridge.engineWrite(id, ptr, bytes); },
          wipe: (ptr, len) => {
            if (zeros.length < len) zeros = new Uint8Array(len);
            bridge.engineWrite(id, ptr, zeros.subarray(0, len));
          },
        }, DEFAULT_SCRATCH_SIZE);
      } catch (err) {
        bridge.engineDispose(id);
        throw err;
      }
      killed = false;
    };
    bind();
    return {
      /** A trap or an overrun answers null; the next call after an overrun binds afresh. */
      call(payload: Uint8Array, deadlineMs: number): Uint8Array | null {
        if (killed) {
          bridge.engineDispose(id);
          try { bind(); } catch { return null; }
        }
        deadline = deadlineMs;
        try { return module.call(payload); } catch { return null; }
      },
      dispose() { bridge.engineDispose(id); },
    };
  }
  /** Private modules where the loader bounds engine calls: in the calling guest's segment,
   *  timed on its clock. A call is synchronous, so its time is already inside that segment. */
  const engineModules: PureModuleLoader = {
    build: (mods) => moduleSet(mods, engineModule,
      async (w, payload, deadlineMs) => ({ bytes: w.call(payload, abiMs(deadlineMs)), ms: 0 }),
      (w) => w.dispose()),
  };
  // Otherwise private modules in the loader's own isolates.
  const modules = bridge.engineCallBounded ? engineModules : bridge.modules!;
  const tcp = net && tcpChannels(net);
  const channels = () => {
    if (!tcp) throw new Error("host: this platform has no sockets; pass transport.channels");
    return tcp;
  };
  const createRealm: RealmFactory = engineRealms(engine, hostParts.qjs);

  async function standUp(cfg: NodeSetup): Promise<NodeRuntime> {
    const admit = cfg.admit ?? policyFromJson(cfg.policyJson);
    return bootShell({
      sodium, identity: cfg.identity, modules, fs: new FilesFs(files, cfg.dir), admit,
      createRealm,
      freshnessStore: freshnessStoreFor(files, cfg.dir),
      // The network as configured, over the platform's sockets unless the caller brings
      // its own.
      transport: cfg.transport && {
        ...cfg.transport,
        channels: cfg.transport.channels ?? channels(),
        datagrams: cfg.transport.datagrams ?? udp,
      },
      guestDeadlineMs: cfg.guestDeadlineMs,
      realmMemoryBytes: cfg.realmMemoryBytes,
      // The successor is this host's to vet, as an app bundle is; the loader only keeps it.
      hostStaging: {
        stage: async (blob: Uint8Array) => {
          checkStagedHost(sodium, hostEnv, bridge.abi, blob);
          await bridge.stageHost(blob);
        },
      },
    });
  }

  // ── the operator flow ──────────────────────────────────────────────────────────
  /** This platform as `cli.ts` needs it; cli.ts makes every decision. */
  const cliHost = (): CliHost => ({
    read: (path, maxBytes) => files.read(path, maxBytes),
    write: (path, bytes, durable) => files.write(path, bytes, durable),
    banner: bridge.banner,
    argv: JSON.parse(bridge.argv()) as string[],
    log(line) { bridge.log(line); },
    stdout(bytes) { bridge.stdout(bytes); },
    stdin() { return u8(bridge.stdin()); },
    sodium,
    standUp,
  });

  return {
    sodium, createRealm, standUp, channels, modules,
    /** Run the operator flow. The loader reads back, as JSON bytes, whether to keep running. */
    async runMain() {
      const { serving, close } = await runCli(cliHost());
      if (!serving) close();
      return enc.encode(JSON.stringify({ serving }));
    },
  };
}
