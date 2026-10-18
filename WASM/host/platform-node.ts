// The Node platform (§12.9): the platform ABI (abi.ts) over Node's own modules. The Node
// loader runs a host blob's script on it (loader-node.ts), and the Node library runs the
// same host in-process (shell-node.ts).

import { randomFillSync } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer, connect as tcpConnect, type Server, type Socket } from "node:net";
import { nodeRawFiles } from "../services/fs-node.js";
import { nodeDatagrams } from "../services/udp/node.js";
import { ipv6Bytes } from "../services/udp/net-udp.js";
import { errMessage } from "../services/util.js";
import { ModuleTable } from "./module-table.js";
import { syncWebEngine } from "./engine-web.js";
import type { PureModules } from "./bundle.js";
import type { CliFiles } from "./cli.js";
import type { EngineExport, EngineInstance } from "./engine-realm.js";
import type { Platform } from "./platform.js";
import { PLATFORM_ABI, type PlatformBridge, type PlatformDispatchers, type PlatformNet, type PlatformUdp } from "./abi.js";

/** Keepalive probes on every socket, as native/tcp.go sets them. */
const TCP_KEEPALIVE_MS = 30_000;

/** The process's own timer, which a loader's teardown of host timers never reaches. */
const platformSetTimeout = globalThis.setTimeout;

/** Write a whole file or none: write a temp file beside the target, then rename it over.
 *  Synchronous, because it writes state a node cannot boot without: the key file and the
 *  freshness marks. */
function writeFileAtomic(path: string, data: Uint8Array, mode?: number): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data, mode === undefined ? undefined : { mode });
  renameSync(tmp, path);
}

/** The operator's files (cli.ts `CliFiles`) on Node. Only a missing file reads as `null`,
 *  as on the native target; an unreadable one throws, or the `--key` first-boot path would
 *  overwrite it. */
export const nodeFiles: CliFiles = {
  readFile(path) {
    try { return new Uint8Array(readFileSync(path)); }
    catch (e) {
      if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return null;
      throw e;
    }
  },
  writeFile: writeFileAtomic,
};

/** What a Node platform's owner supplies: the host it delivers to, and the loader's part of
 *  the bridge. Left out, those are a library node's: no arguments, the package's own host
 *  blob, and no updates. */
export interface NodePlatformOptions {
  host(): Pick<PlatformDispatchers, "__netDeliver" | "__netClosed" | "__netAccept" | "__udpDeliver">;
  argv?(): string;
  hostBlob?(): Uint8Array;
  stageHost?(blob: Uint8Array): void;
}

/** The host blob this package was built with (scripts/build-host-blob.mjs). */
let packageHost: Uint8Array | undefined;
const packageHostBlob = () => (packageHost ??= new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url))));

/** A Node platform, and the release of everything a host holds through it: sockets,
 *  listeners, datagram sockets, modules and engines. */
export function nodePlatform(o: NodePlatformOptions): Platform & { teardown(): void } {
  // ── process, modules, engine ───────────────────────────────────────────────
  const moduleTable = new ModuleTable();
  const slots = new Map<string, PureModules>();
  const engines = new Map<number, { instance: EngineInstance; fns: EngineExport[] }>();
  let engineSeq = 0;
  const engineOf = (id: number) => {
    const e = engines.get(id);
    if (!e) throw new Error("engine: no such instance");
    return e;
  };

  const bridge: PlatformBridge = {
    abi: PLATFORM_ABI,
    banner: "seedkernel-shell",
    argv: o.argv ?? (() => "[]"),
    readFile: (path) => nodeFiles.readFile(path),
    writeFile: (path, bytes, mode) => nodeFiles.writeFile(path, bytes, mode === 0 ? undefined : mode),
    log: (line) => { console.error(line); },
    stdout: (bytes) => { process.stdout.write(bytes); },
    // Whatever was piped in, or empty. Reading fd 0 throws instead of blocking when stdin
    // is an unredirected terminal, which also means no argument.
    stdin: () => {
      try { return new Uint8Array(readFileSync(0)); } catch { return new Uint8Array(0); }
    },
    random: (n) => randomFillSync(new Uint8Array(n)),
    async buildModules(slot, mods) {
      slots.set(slot, await moduleTable.build(mods));
    },
    // Each module in a worker of its own (module-table.ts), the only way V8 stops a call.
    async callModule(slot, module, payload, deadlineMs) {
      const mods = slots.get(slot);
      return mods ? mods.call(module, payload, deadlineMs < 0 ? Infinity : deadlineMs) : { bytes: null, ms: 0 };
    },
    disposeModules(slot) {
      slots.get(slot)?.dispose();
      slots.delete(slot);
    },
    engineInstantiate(wasm, imports) {
      engines.set(++engineSeq, { instance: syncWebEngine(wasm, imports), fns: [] });
      return engineSeq;
    },
    engineExport(id, name) {
      const e = engineOf(id);
      return e.fns.push(e.instance.exported(name)) - 1;
    },
    engineCall: (id, fn, ...args) => engineOf(id).fns[fn](...args),
    engineGlobal: (id, name) => engineOf(id).instance.global(name),
    engineGrow: (id, pages) => engineOf(id).instance.grow(pages),
    engineRead: (id, ptr, len) => engineOf(id).instance.read(ptr, len),
    engineWrite: (id, ptr, bytes) => { engineOf(id).instance.write(ptr, bytes); },
    engineDispose: (id) => { engines.delete(id); },
    hostBlob: o.hostBlob ?? packageHostBlob,
    stageHost: o.stageHost ?? (() => { throw new Error("host: a library node runs its package's host and takes no updates"); }),
  };

  // ── sockets ────────────────────────────────────────────────────────────────
  const sockets = new Map<number, Socket>();
  const servers: Server[] = [];
  let socketSeq = 0;
  let limits: { maxLive: number; graceMs: number } | null = null;

  /** One socket under the ABI's rules: the first read may start at once and each later one
   *  waits for `resume`, and only a close the host did not make is reported. */
  function adopt(socket: Socket): number {
    const id = ++socketSeq;
    sockets.set(id, socket);
    // Reclaims a socket whose peer vanished without a FIN, as native's does.
    socket.setKeepAlive(true, TCP_KEEPALIVE_MS);
    socket.on("data", (chunk: Buffer) => {
      socket.pause();
      o.host().__netDeliver(id, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    });
    const gone = () => {
      // A local close dropped the entry first, so it is not reported.
      if (sockets.get(id) !== socket) return;
      sockets.delete(id);
      o.host().__netClosed(id);
    };
    socket.on("close", gone);
    socket.on("error", gone);
    return id;
  }

  const net: PlatformNet = {
    install(maxLive, graceMs, maxInboundBytes, maxInboundSlices) {
      if (limits) throw new Error("net: socket limits already installed");
      if (!(maxLive > 0 && graceMs > 0 && maxInboundBytes > 0 && maxInboundSlices > 0)) {
        throw new Error("net: invalid socket limits");
      }
      // Reads arrive on this thread one at a time, so nothing is ever staged and the
      // inbound limits hold by construction.
      limits = { maxLive, graceMs };
    },
    connect: (host, port) => adopt(tcpConnect(port, host)),
    listen: (hostname, port) => new Promise<number>((resolve, reject) => {
      const server = createServer((socket) => {
        if (sockets.size >= limits!.maxLive) {
          socket.destroy();
          return;
        }
        // The IP alone: the transport's half-open budget groups by source IP.
        const remoteAddr = socket.remoteAddress ?? "";
        const id = adopt(socket);
        o.host().__netAccept(bound, id, remoteAddr);
      });
      let bound = 0;
      server.once("error", reject);
      server.listen(port, hostname, () => {
        server.removeListener("error", reject);
        bound = (server.address() as { port: number }).port;
        // A failed accept (EMFILE and the like) loses that connection, not the listener.
        server.on("error", (err) => { console.error(`[net] accept on ${hostname}:${bound}: ${errMessage(err)}`); });
        servers.push(server);
        resolve(bound);
      });
    }),
    send: (id, bytes) => { sockets.get(id)?.write(bytes); },
    buffered: (id) => sockets.get(id)?.writableLength ?? 0,
    resume: (id) => { sockets.get(id)?.resume(); },
    close(id, graceful) {
      const socket = sockets.get(id);
      if (!socket) return;
      sockets.delete(id);
      if (!graceful) {
        socket.destroy();
        return;
      }
      // end() flushes what is queued and sends FIN; the grace covers a peer that never
      // closes its side.
      socket.end();
      platformSetTimeout(() => socket.destroy(), limits!.graceMs).unref();
    },
    closeListeners() {
      for (const server of servers.splice(0)) server.close();
    },
  };

  // ── datagrams ──────────────────────────────────────────────────────────────
  const udpSockets = new Map<number, { send(bytes: Uint8Array, port: number, host: string): void; close(): void }>();
  let udpSeq = 0;
  const udp: PlatformUdp = {
    async bind() {
      const { socket, port } = await nodeDatagrams.bind();
      const id = ++udpSeq;
      udpSockets.set(id, socket);
      socket.onMessage((bytes, from, fromPort) => {
        const ip = from.includes(":") ? ipv6Bytes(from) : Uint8Array.from(from.split(".").map(Number));
        const batch = new Uint8Array(1 + ip.length + 4 + bytes.length);
        batch[0] = ip.length;
        batch.set(ip, 1);
        const at = 1 + ip.length;
        batch[at] = fromPort >> 8;
        batch[at + 1] = fromPort & 255;
        batch[at + 2] = bytes.length >> 8;
        batch[at + 3] = bytes.length & 255;
        batch.set(bytes, at + 4);
        o.host().__udpDeliver(id, batch);
      });
      return { id, port };
    },
    send: (id, hostname, port, bytes) => { udpSockets.get(id)?.send(bytes, port, hostname); },
    close: (id) => { udpSockets.get(id)?.close(); udpSockets.delete(id); },
    addresses: () => nodeDatagrams.addresses().join("\n"),
  };

  return {
    bridge, fs: nodeRawFiles, net, udp,
    teardown() {
      for (const socket of sockets.values()) socket.destroy();
      sockets.clear();
      for (const server of servers.splice(0)) server.close();
      for (const socket of udpSockets.values()) socket.close();
      udpSockets.clear();
      for (const mods of slots.values()) mods.dispose();
      slots.clear();
      engines.clear();
      limits = null;
    },
  };
}
