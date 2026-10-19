// The Node platform (§12.9): the platform ABI (abi.ts) over Node's own modules. The Node
// loader runs a host blob's script on it (loader-node.ts), and the Node library runs the
// same host in-process (shell-node.ts).

import { randomFillSync } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer, connect as tcpConnect, type Server, type Socket } from "node:net";
import { nodeRawFiles, tempBeside } from "../services/fs-node.js";
import { nodeRawDatagrams } from "../services/datagrams-node.js";
import { errMessage } from "../services/util.js";
import { ModuleTable } from "./module-table.js";
import { syncWebEngine } from "./engine-web.js";
import type { PureModules } from "./bundle.js";
import type { CliFiles } from "./cli.js";
import type { SlotFiles } from "./slots.js";
import type { EngineExport, EngineInstance } from "./engine-realm.js";
import type { Platform } from "./platform.js";
import { PLATFORM_ABI, type NetDispatchers, type PlatformBridge, type PlatformNet } from "./abi.js";

/** The process's own timer, which a loader's teardown of host timers never reaches. */
const platformSetTimeout = globalThis.setTimeout;

/** Write a whole file or none, as `nodeRawFiles` does. Synchronous, because it writes state
 *  a node cannot boot without: the key file, the freshness marks and the host slots. */
function writeFileAtomic(path: string, data: Uint8Array, mode?: number): void {
  const tmp = tempBeside(path);
  try {
    writeFileSync(tmp, data, mode === undefined ? undefined : { mode });
    renameSync(tmp, path);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* never written */ }
    throw err;
  }
}

/** Node's synchronous files: the operator's (cli.ts `CliFiles`) and the loader's slots
 *  (slots.ts `SlotFiles`). Only a missing operator file reads as `null`, as on the native
 *  target; an unreadable one throws, or the `--key` first-boot path would overwrite it. */
export const nodeFiles: CliFiles & SlotFiles = {
  readFile(path) {
    try { return new Uint8Array(readFileSync(path)); }
    catch (e) {
      if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return null;
      throw e;
    }
  },
  writeFile: writeFileAtomic,
  mkdir: (dir) => { mkdirSync(dir, { recursive: true }); },
  read(path, maxBytes) {
    try { return statSync(path).size > maxBytes ? null : new Uint8Array(readFileSync(path)); } catch { return null; }
  },
  write: (path, bytes) => { writeFileAtomic(path, bytes); },
  remove(path) {
    try { unlinkSync(path); return true; } catch { return false; }
  },
  size(path) {
    try { return statSync(path).size; } catch { return -1; }
  },
};

/** What a Node platform's owner supplies: the loader's part of the bridge. Left out, it is
 *  a library node's: no arguments, the package's own host blob, and no updates. */
export interface NodePlatformOptions {
  argv?(): string;
  hostBlob?(): Uint8Array;
  stageHost?(blob: Uint8Array): void;
}

/** The host blob this package was built with (scripts/build-host-blob.mjs). */
let packageHost: Uint8Array | undefined;
const packageHostBlob = () => (packageHost ??= new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url))));

/** A Node platform, and the release of everything a host holds through it: sockets,
 *  listeners, datagram sockets, modules and engines. */
export function nodePlatform(o: NodePlatformOptions = {}): Platform & { teardown(): void } {
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
  let limits: { keepAliveMs: number; graceMs: number; events: NetDispatchers } | null = null;

  /** One socket under the ABI's rules: the first read may start at once and each later one
   *  waits for `resume`, and only a close the host did not make is reported. */
  function adopt(socket: Socket): number {
    const id = ++socketSeq;
    sockets.set(id, socket);
    socket.setKeepAlive(true, limits!.keepAliveMs);
    socket.on("data", (chunk: Buffer) => {
      socket.pause();
      limits!.events.deliver(id, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    });
    const gone = () => {
      // A local close dropped the entry first, so it is not reported.
      if (sockets.get(id) !== socket) return;
      sockets.delete(id);
      limits!.events.closed(id);
    };
    socket.on("close", gone);
    socket.on("error", gone);
    return id;
  }

  const net: PlatformNet = {
    install(keepAliveMs, graceMs, _maxInboundBytes, _maxInboundSlices, events) {
      // Reads arrive on this thread one at a time, so nothing is ever staged and the
      // inbound limits hold by construction.
      limits = { keepAliveMs, graceMs, events };
    },
    connect: (host, port) => adopt(tcpConnect(port, host)),
    listen: (hostname, port) => new Promise<number>((resolve, reject) => {
      const server = createServer((socket) => {
        // The IP alone: the transport's half-open budget groups by source IP.
        const remoteAddr = socket.remoteAddress ?? "";
        const id = adopt(socket);
        limits!.events.accept(bound, id, remoteAddr);
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

  const udp = nodeRawDatagrams();
  return {
    bridge, fs: nodeRawFiles, net, udp,
    teardown() {
      for (const socket of sockets.values()) socket.destroy();
      sockets.clear();
      for (const server of servers.splice(0)) server.close();
      udp.closeAll();
      for (const mods of slots.values()) mods.dispose();
      slots.clear();
      engines.clear();
      limits = null;
    },
  };
}
