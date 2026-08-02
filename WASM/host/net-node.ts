// The Node platform binding for the TCP/WS socket seam — node↔node over TCP and
// browser↔node over WebSocket. It implements ChannelFactory (transport-seam.ts):
// it knows how to open node:net sockets and wrap them as RawChannels, and nothing
// else. The transport itself — the PeerLink handshake, link routing, the
// request/response layer — now runs in the transport bundle's guest program,
// driven by the shared TransportHost (transport-host.ts), which the shell stands
// up when a bundle claiming the transport role is admitted. This file is what
// remains of the old NodeNetworkCore wiring: the factory the driver's DIAL
// actions and listeners go through, and the peer-spec parsing for the CLI.
//
// WebSocket exists only because browsers cannot speak raw TCP, so it is handled as
// a wire codec *over a raw TCP listener*: the RFC 6455 opening handshake and
// framing run in ws.wasm (ws-codec.ts), identically on Node and Bun — no
// dependency on node:http and no Bun-native fast path, one WS code path everywhere.
import { createServer as createTcpServer, connect as tcpConnect, type Server as TcpServer, type Socket } from "node:net";
// From the core, never from the transport bundle: this file holds the descriptor,
// so it must not take its flood bound from the module it is bounding (net-limits.ts).
import { MAX_FRAME_BYTES, MAX_HANDSHAKE_FRAME_BYTES } from "../core/net-limits.js";
import { BufferedChannel } from "../core/net-channel.js";
import { WsServerChannel, WsClientChannel } from "./net-frame.js";
import { installWasmWsBackend } from "./ws/ws-wasm-backend.js";
import { writeU32BE, readU32BE, ByteQueue } from "../core/util.js";
import { type PeerAddr, type RawChannel, type TransportCrypto, type RawByteStream } from "../core/socket-seam.js";

export interface NodeChannelFactoryOptions {
    sodium: TransportCrypto;
}

export { parsePeerSpec } from "../core/socket-seam.js";
// The WS codec (net-frame.ts) runs over the WebAssembly ws.wasm on this target.
installWasmWsBackend();
// ── RawChannel: length-prefixed frames over a TCP socket ──────────────────────
//   [len u32 BE][bytes]   one PeerLink message per record.
// BufferedChannel (net-channel.ts) carries the shared adapter machinery; this adds
// the length-prefix framing on write and its reassembly on receive. node:net buffers
// writes issued before connect, so the channel is writable from birth — open() is
// called straight away and the base's pre-open queue stays unused.
/** How long a gracefully-closed socket may linger waiting for its FIN to flush
 *  before it is destroyed outright. */
const TCP_LINGER_MS = 5_000;
class TcpChannel extends BufferedChannel {
    private readonly socket: Socket;
    q = new ByteQueue();
    /** The peer's IP, for the per-source half-open cap only (§12.6.1). Captured at
     *  construction because `socket.remoteAddress` reads undefined once the socket is
     *  destroyed, and the limiter must be able to release the same bucket it took.
     *  Unauthenticated and spoofable at the IP level — never an identity. */
    readonly remoteAddr: string | undefined;
    constructor(socket: Socket) {
        super();
        this.socket = socket;
        this.remoteAddr = socket.remoteAddress ?? undefined;
        this.open();
        socket.on("data", (chunk: Uint8Array) => this.onData(new Uint8Array(chunk)));
        socket.on("close", () => this.fail());
        socket.on("error", () => this.fail());
    }
    write(bytes: Uint8Array) {
        const out = new Uint8Array(4 + bytes.length);
        writeU32BE(out, 0, bytes.length);
        out.set(bytes, 4);
        this.socket.write(out);
    }
    // A graceful stop must FLUSH. `destroy()` drops whatever is still in the socket's
    // write buffer, which for the transport means the end-of-stream record it just
    // wrote is silently discarded and the peer reads a clean shutdown as a truncation.
    // `end()` writes the queued bytes and then sends FIN. The linger timer is the
    // backstop: a peer that never FINs back must not hold the socket open forever.
    stop(graceful: boolean) {
        if (!graceful) {
            this.socket.destroy();
            return;
        }
        try {
            this.socket.end();
            const t = setTimeout(() => this.socket.destroy(), TCP_LINGER_MS);
            t.unref?.();
        }
        catch {
            this.socket.destroy();
        }
    }
    frameCap = MAX_HANDSHAKE_FRAME_BYTES;
    allowLargeFrames() { this.frameCap = MAX_FRAME_BYTES; }
    onData(chunk: Uint8Array) {
        if (this.dead)
            return;
        this.q.push(chunk);
        for (;;) {
            const head = this.q.peek(4);
            if (!head)
                break;
            const len = readU32BE(head, 0);
            // Pre-auth this is the small handshake cap, not MAX_FRAME_BYTES: a stranger who
            // knows only host:port must not be able to reserve megabytes by declaring a frame
            // and then dribbling it. The transport guest raises the cap on authentication.
            if (len > this.frameCap) {
                this.fail();
                return;
            }
            if (this.q.length < 4 + len)
                break;
            this.q.drop(4);
            this.deliver(this.q.take(len)!);
        }
    }
}
// ── RawByteStream over a node:net socket ──────────────────────────────────────
// The transport the shared WS codec (net-frame.ts) runs on: raw bytes in/out, no
// framing. node:net buffers writes issued before connect, so the WS client's
// upgrade request can be written the moment the channel is constructed.
function nodeRawStream(socket: Socket): RawByteStream {
    return {
        write: (bytes: Uint8Array) => { socket.write(bytes); },
        onData: (cb: (chunk: Uint8Array) => void) => { socket.on("data", (chunk: Uint8Array) => cb(new Uint8Array(chunk))); },
        // error and close both mean "gone"; WsChannelBase.fail() is idempotent.
        onClose: (cb: () => void) => { socket.on("close", cb); socket.on("error", cb); },
        close: () => { socket.destroy(); },
    };
}
function listenOn(server: TcpServer, opt: { host: string; port: number }): Promise<number> {
    return new Promise<number>((resolve, reject) => {
        server.once("error", reject);
        server.listen(opt.port, opt.host, () => {
            const a = server.address() as { port: number } | null;
            resolve(a && typeof a === "object" ? a.port : 0);
        });
    });
}
// The node:net / ws.wasm ChannelFactory: every socket the transport driver opens
// or accepts is created here, behind the RawChannel shape.
export class NodeChannelFactory {
    sodium;
    private tcpServer: TcpServer | null = null;
    private wsServer: TcpServer | null = null;
    constructor(sodium: TransportCrypto) {
        this.sodium = sodium;
    }
    connect(addr: PeerAddr): RawChannel {
        return addr.transport === "ws"
            ? new WsClientChannel(nodeRawStream(tcpConnect(addr.port, addr.host)), addr.host, addr.port, this.sodium)
            : new TcpChannel(tcpConnect(addr.port, addr.host));
    }
    async listen(tcp: {
        host: string;
        port: number;
    } | undefined, ws: {
        host: string;
        port: number;
    } | undefined, onAccept: (channel: RawChannel) => void): Promise<{
        port: number;
        wsPort: number;
    }> {
        let port = 0, wsPort = 0;
        const tasks: Promise<void>[] = [];
        if (tcp) {
            const server = createTcpServer((socket) => onAccept(new TcpChannel(socket)));
            this.tcpServer = server;
            tasks.push(listenOn(server, tcp).then((p) => { port = p; }));
        }
        if (ws) {
            const server = createTcpServer((socket) => onAccept(new WsServerChannel(nodeRawStream(socket))));
            this.wsServer = server;
            tasks.push(listenOn(server, ws).then((p) => { wsPort = p; }));
        }
        await Promise.all(tasks);
        return { port, wsPort };
    }
    close(): void {
        this.tcpServer?.close();
        this.tcpServer = null;
        this.wsServer?.close();
        this.wsServer = null;
    }
}
