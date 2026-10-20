// The platform ABI (§12.9): the globals a loader installs before it evaluates the host
// script, and the entry the host script defines for the loader to call. Socket events
// arrive at the callbacks the host hands over (`install`, `bind`). Every member is a raw
// primitive; what a node makes of them is above the ABI, in the host
// script (platform.ts), which is the same on every target and carries its own crypto and
// realm engine. The native binary implements it in Go (native/), the Node loader with
// node:net, node:dgram and node:fs (loader-node.ts).
//
// A call a platform can only answer asynchronously (a socket bind, a file read) is typed
// `Maybe`, and the host script awaits every such call, so one host serves both kinds of
// loader. Timers are the standard setTimeout and clearTimeout.

import type { EngineImports } from "./engine-realm.js";
import type { RawFiles } from "../services/fs-files.js";
import type { RawDatagrams } from "../services/datagrams.js";

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

  // Private modules (§4) run one of two ways, and a loader offers exactly one. One that can
  // end a synchronous wasm call at a deadline offers bounded engine instances
  // (`engineCallBounded`), and the host runs the module ABI over them in the calling
  // guest's segment (host/pure-module.ts). One that cannot runs each module in an isolate
  // of its own and offers the three calls below, which answer asynchronously with the
  // module's own time, billed to the caller.

  /** Build a bundle's private modules under an opaque slot name, all or none. */
  buildModules?(slot: string, mods: { name: string; wasm: Uint8Array }[]): Promise<void>;
  /** One module call under a deadline (-1 for none): its answer, or `null` when it failed. */
  callModule?(slot: string, module: string, payload: Uint8Array, deadlineMs: number):
    Promise<{ bytes: Bytes | null; ms: number }>;
  disposeModules?(slot: string): void;

  /** The engine table: a wasm instance from bytes, its import handlers by module and name
   *  as WebAssembly's importObject. Numbers cross as numbers, and only integral ones (an
   *  f64 is an id or a duration in ns), which is all a loader need carry; i64 does not
   *  cross. A
   *  `bindDeadlineMs` (-1 for none) asks for a bounded instance, on a loader that offers
   *  `engineCallBounded`; its instantiation runs under that deadline. */
  engineInstantiate(wasm: Uint8Array, imports: EngineImports, bindDeadlineMs?: number): number;
  /** An export's handle, for engineCall. */
  engineExport(id: number, name: string): number;
  /** Call an export with up to twelve numbers; any past its parameters are ignored. A trap
   *  throws. */
  engineCall(id: number, fn: number, ...args: number[]): number;
  /** `engineCall` on a bounded instance under a deadline in ms (-1 for none). Past it the
   *  instance is closed and the call answers `null`; a trap still throws. */
  engineCallBounded?(id: number, fn: number, deadlineMs: number, ...args: number[]): number | null;
  /** Grow an instance's memory by `pages` of 64 KiB: its size in pages before, or -1 when
   *  it cannot grow. 0 pages reads the size. */
  engineGrow(id: number, pages: number): number;
  /** An exported global's value, or `null` when the instance exports none by that name. */
  engineGlobal(id: number, name: string): number | null;
  engineRead(id: number, ptr: number, len: number): Bytes;
  /** `engineRead` without the copy, valid until the instance next runs, on a loader whose
   *  engine memory the host script can reach. */
  engineView?(id: number, ptr: number, len: number): Uint8Array;
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

/** Byte streams (§12.1). Reads arrive through `events.deliver`, one per `resume`. */
export interface PlatformNet {
  /** Host-owned socket settings and limits, and the dispatchers socket events arrive
   *  through, installed once before any channel opens. */
  install(keepAliveMs: number, closeGraceMs: number,
    maxInboundReadBytes: number, maxInboundReadSlices: number, events: NetDispatchers): void;
  /** An outbound duplex (id never 0) that buffers sends until it connects. */
  connect(host: string, port: number): number;
  /** Bind a listener and answer its port; a failure throws the OS's reason. Accepts arrive
   *  through `events.accept`. */
  listen(host: string, port: number): Maybe<number>;
  send(id: number, bytes: Uint8Array): void;
  /** Bytes sent but not yet handed to the socket. */
  buffered(id: number): number;
  /** Allow the next read. */
  resume(id: number): void;
  /** A local close; never fires `events.closed`. */
  close(id: number, graceful?: boolean): void;
  closeListeners(): void;
}

/** How a platform delivers socket events. */
export interface NetDispatchers {
  /** A socket read. */
  deliver(id: number, bytes: Bytes): void;
  /** A channel failed or closed remotely. */
  closed(id: number): void;
  /** A socket was accepted on listener `port`. */
  accept(port: number, id: number, remoteAddr: string): void;
}

/** Datagrams (§12.7), each socket's reads arriving at the `deliver` it was bound with. */
export type PlatformUdp = RawDatagrams;

/** What the host script defines for the loader to call. */
export interface PlatformDispatchers {
  /** Run the operator flow; answers `{"serving": bool}` as JSON bytes, and the loader keeps
   *  running while serving. */
  runMain(): Promise<Uint8Array>;
}
