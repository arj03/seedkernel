// The Node platform (§12.9): the platform ABI (abi.ts) over Node's own modules, and the
// Web APIs it shares with the browser's (platform-web.ts). The Node loader runs a host
// blob's script on it (loader-node.ts), and the Node library runs the same host in-process
// (shell-node.ts).

import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { createServer, connect as tcpConnect, type Server, type Socket } from "node:net";
import { nodeRawFiles } from "../services/fs-node.js";
import { nodeRawDatagrams } from "../services/datagrams-node.js";
import { EMPTY, errMessage } from "../services/util.js";
import { webBridge } from "./platform-web.js";
import { packageHostBlob } from "./crypto-node.js";
import type { Platform } from "./platform.js";
import { PLATFORM_ABI, type NetDispatchers, type PlatformBridge, type PlatformNet } from "./abi.js";

/** Windows' libuv has no Unix sockets, only named pipes, which live outside the file
 *  system: there a local socket's path is a file naming a random pipe, private to this user
 *  as the directory it sits in is. */
const PIPES = process.platform === "win32";
const PIPE_NAME = /^\\\\\.\\pipe\\seedkernel-[0-9a-f]{32}$/;
/** The pipe a path names, or null when there is none. Anything else there is most likely a
 *  native node's Unix socket, which this platform cannot reach, so it must never read as
 *  nobody serving: that throws. */
function localAddress(path: string): string | null {
  if (!PIPES) return path;
  let name = "";
  try { name = readFileSync(path, "utf8").trim(); } catch (e) {
    // Only a missing path is nothing: a Unix socket refuses stat and reads (EACCES).
    if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return null;
  }
  if (!PIPE_NAME.test(name)) throw new Error(`${path}: a native node's control socket, which only the native binary reaches on Windows`);
  return name;
}
/** Whether something answers at a local address, so a live socket is never replaced. */
function answers(addr: string): Promise<boolean> {
  return new Promise((resolve) => {
    const s = tcpConnect({ path: addr });
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(false));
  });
}
/** Listen on a path or pipe, the socket owner-only from the moment it is bound: a chmod
 *  after would leave a window, and a connection accepted in it would stay. */
function listenPrivate(server: Server, addr: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    const umask = PIPES ? null : process.umask(0o177);
    try {
      server.listen(addr, () => { server.removeListener("error", reject); resolve(); });
    } finally {
      if (umask !== null) process.umask(umask);
    }
  });
}

/** The process's own timer, which a loader's teardown of host timers never reaches. */
const platformSetTimeout = globalThis.setTimeout;

/** What a Node platform's owner supplies: the loader's part of the bridge. Left out, it is
 *  a library node's: no arguments, the package's own host blob, and no updates. */
export interface NodePlatformOptions {
  argv?(): string;
  hostBlob?(): Uint8Array;
  stageHost?(blob: Uint8Array): void;
}

/** A Node platform, and the release of everything a host holds through it: sockets,
 *  listeners, datagram sockets, modules and engines. */
export function nodePlatform(o: NodePlatformOptions = {}): Required<Platform> & { teardown(): void } {
  // ── process, modules, engine ───────────────────────────────────────────────
  const web = webBridge();
  const bridge: PlatformBridge = {
    abi: PLATFORM_ABI,
    banner: "seedkernel-shell",
    argv: o.argv ?? (() => "[]"),
    log: (line) => { console.error(line); },
    stdout: (bytes) => { process.stdout.write(bytes); },
    // Whatever was piped in, or empty. Reading fd 0 throws instead of blocking when stdin
    // is an unredirected terminal, which also means no argument.
    stdin: () => {
      try { return new Uint8Array(readFileSync(0)); } catch { return EMPTY; }
    },
    ...web.bridge,
    hostBlob: o.hostBlob ?? packageHostBlob,
    stageHost: o.stageHost ?? (() => { throw new Error("host: a library node runs its package's host and takes no updates"); }),
  };

  // ── sockets ────────────────────────────────────────────────────────────────
  const sockets = new Map<number, Socket>();
  const servers: Server[] = [];
  let socketSeq = 0, localSeq = 0;
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
    install(keepAliveMs, graceMs, events) {
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
    async listenLocal(path) {
      const live = localAddress(path);
      if (live !== null && await answers(live)) throw new Error(`${path}: a node already listens there`);
      const addr = PIPES ? `\\\\.\\pipe\\seedkernel-${randomBytes(16).toString("hex")}` : path;
      if (!PIPES) rmSync(path, { force: true });
      const key = -++localSeq;
      const server = createServer((socket) => { limits!.events.accept(key, adopt(socket), "local"); });
      await listenPrivate(server, addr);
      if (PIPES) writeFileSync(path, addr, { mode: 0o600 });
      server.on("error", (err) => { console.error(`[net] accept on ${path}: ${errMessage(err)}`); });
      servers.push(server);
      return key;
    },
    // A path naming no pipe still answers an id, whose socket fails and reports closed.
    connectLocal: (path) => adopt(tcpConnect({ path: localAddress(path) ?? "\\\\.\\pipe\\seedkernel-none" })),
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
      web.teardown();
      limits = null;
    },
  };
}
