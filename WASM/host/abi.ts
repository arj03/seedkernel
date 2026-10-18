// The platform ABI (§12.9): the globals a loader installs before it evaluates the host
// script, and the dispatchers the host script defines for the loader to call back. Every
// member is a raw primitive; what a node makes of them is above the ABI, in the host
// script (platform.ts), which is the same on every target and carries its own crypto and
// realm engine. The native binary implements it in Go (native/), the Node loader with
// node:net, node:dgram and node:fs (loader-node.ts).
//
// A call a platform can only answer asynchronously (a socket bind, a file read) is typed
// `Maybe`, and the host script awaits every such call, so one host serves both kinds of
// loader. Timers are the standard setTimeout and clearTimeout.

import type { EngineImports } from "./engine-realm.js";
import type { RawFiles } from "../services/fs-files.js";

/** The ABI version a loader implements and the host script requires. */
export const PLATFORM_ABI = 1;

export type Maybe<T> = T | Promise<T>;
/** Bytes a loader hands over; either form is the host's to keep. */
export type Bytes = ArrayBuffer | Uint8Array;

/** The process, private modules (§4) and the engine table. */
export interface PlatformBridge {
  /** The ABI version this loader implements (`PLATFORM_ABI`). */
  readonly abi: number;
  /** The first word of the console banner, which names the loader. */
  readonly banner: string;
  /** Whether a module call runs inside the calling guest's execution segment, which then
   *  already counts it; otherwise the host bills it to the caller. */
  readonly modulesInSegment: boolean;

  /** Process arguments after the program name, as a JSON array. */
  argv(): string;
  /** Read a whole file; `null` only when absent. Other read failures throw. */
  readFile(path: string): Bytes | null;
  /** Write a whole file atomically; `mode` 0 keeps the platform default. */
  writeFile(path: string, bytes: Uint8Array, mode: number): void;
  /** One diagnostic line on stderr; stdout is the data channel. */
  log(line: string): void;
  /** Raw bytes on stdout. */
  stdout(bytes: Uint8Array): void;
  /** Raw bytes from stdin, or empty when nothing was piped in. */
  stdin(): Bytes;
  /** `n` bytes from the platform CSPRNG. */
  random(n: number): Bytes;

  /** Build a bundle's private modules under an opaque slot name, all or none. */
  buildModules(slot: string, mods: { name: string; wasm: Uint8Array }[], scratchDefault: number,
    bindDeadlineMs: number): Maybe<void>;
  /** One module call under a deadline (-1 for none): its answer, or `null` when it failed.
   *  A loader that runs it elsewhere answers asynchronously, with the module's own time. */
  callModule(slot: string, module: string, payload: Uint8Array, deadlineMs: number):
    Bytes | null | Promise<{ bytes: Bytes | null; ms: number }>;
  disposeModules(slot: string): unknown;

  /** The engine table: a wasm instance from bytes, its import handlers by module and name
   *  as WebAssembly's importObject. Numbers cross as numbers; i64 does not cross. */
  engineInstantiate(wasm: Uint8Array, imports: EngineImports): number;
  /** An export's handle, for engineCall. */
  engineExport(id: number, name: string): number;
  /** Call an export with up to twelve numbers; any past its parameters are ignored. A trap
   *  throws. */
  engineCall(id: number, fn: number, ...args: number[]): number;
  /** Grow an instance's memory by `pages` of 64 KiB: its size in pages before, or -1 when
   *  it cannot grow. 0 pages reads the size. */
  engineGrow(id: number, pages: number): number;
  /** An exported global's value, or `null` when the instance exports none by that name. */
  engineGlobal(id: number, name: string): number | null;
  engineRead(id: number, ptr: number, len: number): Bytes;
  engineWrite(id: number, ptr: number, bytes: Uint8Array): void;
  engineDispose(id: number): void;
  /** The running host blob (host-blob.ts), which carries the realm engine and the host's
   *  crypto. */
  hostBlob(): Bytes;
  /** Keep a host blob, which the running host has checked (host-blob.ts
   *  `checkStagedHost`), as the one to try next, under the operator's --host-updates; a
   *  refusal throws its reason. */
  stageHost(blob: Uint8Array): Maybe<void>;
}

/** Whole files by path, which the node's store (services/fs-files.ts) is kept in. */
export type PlatformFs = RawFiles;

/** Byte streams (§12.1). Reads arrive through `__netDeliver`, one per `resume`. */
export interface PlatformNet {
  /** Host-owned socket limits, installed once before any channel opens. */
  install(maxLiveChannels: number, closeGraceMs: number,
    maxInboundReadBytes: number, maxInboundReadSlices: number): void;
  /** An outbound duplex (id never 0) that buffers sends until it connects. */
  connect(host: string, port: number): number;
  /** Bind a listener and answer its port; a failure throws the OS's reason. Accepts arrive
   *  through `__netAccept`. */
  listen(host: string, port: number): Maybe<number>;
  send(id: number, bytes: Uint8Array): void;
  /** Bytes sent but not yet handed to the socket. */
  buffered(id: number): number;
  /** Allow the next read. */
  resume(id: number): void;
  /** A local close; never fires `__netClosed`. */
  close(id: number, graceful?: boolean): void;
  closeListeners(): void;
}

/** Datagrams (§12.7). Reads arrive through `__udpDeliver`. */
export interface PlatformUdp {
  /** A socket on a port the OS picks, dual-stack where the machine has IPv6. */
  bind(): Maybe<{ id: number; port: number }>;
  /** One datagram; a failure is a lost one. A name rather than an address resolves. */
  send(id: number, host: string, port: number, bytes: Uint8Array): void;
  close(id: number): void;
  /** This machine's addresses, `\n`-separated: the outward IPv4 ones, or loopback, then
   *  IPv6 but for loopback and link-local. */
  addresses(): string;
}

/** How a platform delivers socket events. */
export interface NetDispatchers {
  /** A socket read. */
  __netDeliver(id: number, bytes: Bytes): void;
  /** A channel failed or closed remotely. */
  __netClosed(id: number): void;
  /** A socket was accepted on listener `port`. */
  __netAccept(port: number, id: number, remoteAddr: string): void;
}

/** What the host script defines for the loader to call. */
export interface PlatformDispatchers extends NetDispatchers {
  /** Datagrams as `[n u8][ip n][port u16][len u16][bytes]` each, n 4 for IPv4 and 16 for
   *  IPv6. */
  __udpDeliver(id: number, batch: Bytes): void;
  /** Run the operator flow; answers `{"serving": bool}` as JSON bytes, and the loader keeps
   *  running while serving. */
  runMain(): Promise<Uint8Array>;
}
