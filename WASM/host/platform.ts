// The host's side of the platform ABI (abi.ts, §12.9): adapts a loader's primitives
// (private modules, entropy, files, TCP and UDP sockets, the engine table that realms and
// the host's crypto run on) to what `bootShell` takes, and runs the operator flow. The same
// code runs on every target: as the host script over a loader's globals (host-main.ts),
// and in-process under the Node library (shell-node.ts). It awaits each call a platform
// may answer asynchronously.
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
  SILENT_SOCKET_MS,
  TCP_LINGER_MS,
} from "../services/net-limits.js";
import { FilesFs } from "../services/fs-files.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_SCRATCH_SIZE } from "./wasm-limits.js";
import { enc, errMessage } from "../services/util.js";
import { moduleShims, scratchModule } from "./pure-module.js";
import { checkStagedHost, readHostBlob } from "./host-blob.js";
import {
  PLATFORM_ABI,
  type Bytes, type NetDispatchers, type PlatformBridge, type PlatformDispatchers, type PlatformFs, type PlatformNet,
  type PlatformUdp,
} from "./abi.js";

/** A loader's primitives, as the globals of abi.ts. */
export interface Platform {
  bridge: PlatformBridge;
  fs: PlatformFs;
  net: PlatformNet;
  udp: PlatformUdp;
}

/** A host over one platform: the dispatchers its loader calls, and what a node is built
 *  from. */
export interface PlatformHost extends PlatformDispatchers {
  /** This node's crypto, run on the engine table (sodium-engine.ts). */
  sodium: HostSodium;
  /** The realm factory (§12.3): realms on the engine table (engine-realm.ts). */
  createRealm: RealmFactory;
  /** Boot a node through `bootShell` (§12.9). The policy is parsed before anything is
   *  opened. */
  standUp(cfg: NodeSetup): Promise<NodeRuntime>;
  /** A node's sockets: TCP, and the UDP path over the platform's datagrams. A factory per
   *  node, since a UDP factory keeps the one node's accept sink. */
  channels(): ChannelFactory;
  /** The UDP path's platform over the platform's datagrams. */
  datagrams: DatagramPlatform;
  /** A node's private modules (§4). */
  modules: PureModuleLoader;
}

/** Bytes as a Uint8Array, without a copy when they already are one. */
const u8 = (b: Bytes): Uint8Array => (b instanceof Uint8Array ? b : new Uint8Array(b));

/** A deadline as the ABI carries it: `Infinity` as -1, omitted as the shared default. */
const abiMs = (ms: number | undefined): number =>
  ms === undefined ? DEFAULT_GUEST_DEADLINE_MS : ms === Infinity ? -1 : ms;

/** The driver's ChannelFactory over a platform's TCP sockets, and the dispatchers the
 *  platform delivers them through. Once per platform, since it installs the socket limits.
 *  `silentMs` is shortened only by tests. */
export function tcpChannels(net: PlatformNet, silentMs = SILENT_SOCKET_MS): ChannelFactory & NetDispatchers {
  // Limits are passed once; the platform enforces the ones that apply before JS sees a
  // socket.
  net.install(DEFAULT_MAX_RAW_LINKS, TCP_LINGER_MS, MAX_INBOUND_HOLD_BYTES, MAX_INBOUND_HOLD_SLICES);
  /** Open channels by socket id, and accept callbacks by bound port. */
  const chans = new Map<number, { deliver: (bytes: Uint8Array) => void; closed: () => void }>();
  const accepts = new Map<number, (id: number, remoteAddr: string) => void>();

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
      // A local close never fires __netClosed, so drop the entry here.
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
    __netDeliver: (id, bytes) => { chans.get(id)?.deliver(u8(bytes)); },
    __netClosed: (id) => { chans.get(id)?.closed(); },
    __netAccept: (port, id, remoteAddr) => { accepts.get(port)?.(id, remoteAddr); },
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

  const udpSockets = new Map<number, (bytes: Uint8Array, host: string, port: number) => void>();
  const datagrams: DatagramPlatform = {
    async bind() {
      const { id, port } = await udp.bind();
      let onMessage: (bytes: Uint8Array, host: string, port: number) => void = () => {};
      udpSockets.set(id, (bytes, host, from) => onMessage(bytes, host, from));
      return {
        port,
        socket: {
          send: (bytes, to, host) => { udp.send(id, host, to, bytes); },
          onMessage: (cb) => { onMessage = cb; },
          close: () => { udpSockets.delete(id); udp.close(id); },
        },
      };
    },
    addresses: () => { const s = udp.addresses(); return s === "" ? [] : s.split("\n"); },
  };

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
          memoryBytes: () => bridge.engineGrow(id, 0) * 65536,
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
   *  timed on its clock. */
  const engineModules: PureModuleLoader = {
    async build(mods) {
      const built = new Map<string, ReturnType<typeof engineModule>>();
      try {
        for (const m of mods) {
          if (built.has(m.name)) throw new Error(`table: duplicate module name ${m.name}`);
          try { built.set(m.name, engineModule(m.wasm)); } catch (err) { throw new Error(`${m.name}: ${errMessage(err)}`); }
        }
      } catch (err) {
        for (const w of built.values()) w.dispose();
        throw err;
      }
      return {
        async call(name, payload, deadlineMs) {
          const w = built.get(name);
          if (!w) return { bytes: null, ms: 0 };
          const t0 = monotonicMs();
          const bytes = w.call(payload, abiMs(deadlineMs));
          return { bytes, ms: monotonicMs() - t0 };
        },
        dispose() {
          for (const w of built.values()) w.dispose();
          built.clear();
        },
      };
    },
  };
  /** Private modules in the loader's own isolates, over opaque slot names. */
  let moduleSlotSeq = 0;
  const isolatedModules: PureModuleLoader = {
    async build(mods) {
      const slot = `slot:${++moduleSlotSeq}`;
      await bridge.buildModules!(slot, mods);
      return {
        async call(module, payload, deadlineMs) {
          const { bytes, ms } = await bridge.callModule!(slot, module, payload, abiMs(deadlineMs));
          return { bytes: bytes === null ? null : u8(bytes), ms };
        },
        dispose() { bridge.disposeModules!(slot); },
      };
    },
  };
  const modules = bridge.engineCallBounded ? engineModules : isolatedModules;
  /** `CliFiles` over the platform's operator files. A read throws for anything but a
   *  missing file; a write throws when it fails, which `FreshnessMarks` relies on to roll
   *  back. */
  const cliFiles: CliFiles = {
    readFile(path) {
      const r = bridge.readFile(path);
      return r === null ? null : u8(r);
    },
    writeFile(path, bytes, mode) { bridge.writeFile(path, bytes, mode ?? 0); },
  };
  const tcp = tcpChannels(net);
  const channels = () => combineChannels(tcp, new UdpNetwork({ datagrams }));
  const createRealm: RealmFactory = (opts) =>
    engineRealms(engine, hostParts.qjs, { billModules: modules === isolatedModules })(opts);

  async function standUp(cfg: NodeSetup): Promise<NodeRuntime> {
    const admit = policyFromJson(cfg.policyJson);
    return bootShell({
      sodium, identity: cfg.identity, modules, fs: new FilesFs(files, cfg.dir), admit,
      createRealm,
      freshnessStore: freshnessStoreFor(cliFiles, cfg.dir),
      // The network as configured, over the platform's sockets unless the caller brings
      // its own.
      transport: cfg.transport && { ...cfg.transport, channels: cfg.transport.channels ?? channels() },
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
    ...cliFiles,
    banner: bridge.banner,
    argv: JSON.parse(bridge.argv()) as string[],
    log(line) { bridge.log(line); },
    stdout(bytes) { bridge.stdout(bytes); },
    stdin() { return u8(bridge.stdin()); },
    sodium,
    standUp,
  });

  return {
    sodium, createRealm, standUp, channels, datagrams, modules,
    __netDeliver: tcp.__netDeliver,
    __netClosed: tcp.__netClosed,
    __netAccept: tcp.__netAccept,
    __udpDeliver: (id, batch) => {
      const deliver = udpSockets.get(id);
      const b = u8(batch);
      // A batch is mostly one peer's, so its address is spelled once, not once a datagram:
      // an IPv4 one is told from the last by its four bytes as a number, an IPv6 one by its
      // text.
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
    },
    /** Run the operator flow. The loader reads back, as JSON bytes, whether to keep running. */
    async runMain() {
      const { serving, close } = await runCli(cliHost());
      if (!serving) close();
      return enc.encode(JSON.stringify({ serving }));
    },
  };
}
