// The Node platform binding for the TCP/WS socket seam — node↔node over TCP and
// browser↔node over WebSocket. It implements ChannelFactory (core/socket-seam.ts):
// it knows how to open node:net sockets and wrap them as RawLinks, and nothing
// else. The transport itself — the PeerLink handshake, link routing, the
// request/response layer — now runs in the transport bundle's guest program,
// driven by the shared TransportHost (transport-host.ts), which the shell stands
// up when a bundle claiming the transport role is admitted. This file is what
// remains of the old NodeNetworkCore wiring: the factory the driver's DIAL
// actions and listeners go through, and the peer-spec parsing for the CLI.
//
// WebSocket exists only because browsers cannot speak raw TCP, so it is handled as
// a wire codec *over a raw TCP listener*: this file binds the listener and says which
// codec applies, and the RFC 6455 handshake and framing themselves run in the
// transport bundle (transport/guest.js over its own ws.wasm module). No dependency on
// node:http and no Bun-native fast path — one WS code path, and it is not host code.
import { createServer as createTcpServer, connect as tcpConnect, type Server as TcpServer, type Socket } from "node:net";

import { FRAMING, type Framing, type PeerAddr, type RawLink } from "../core/socket-seam.js";


export { parsePeerSpec } from "./transport-host.js";
// ── An unframed RawLink over a node:net socket ────────────────────────────────
// Raw bytes in and out, no boundaries: node↔node TCP is handed to the transport
// bundle exactly like this, and a WS link is the same socket with a different codec
// declared on it. node:net buffers writes issued before connect, so the
// link is writable from birth — the transport can send its HELLO (or the WS client
// its upgrade request) the moment it is constructed.
/** How long a gracefully-closed socket may linger waiting for its FIN to flush
 *  before it is destroyed outright. */
const TCP_LINGER_MS = 5_000;
function nodeRawStream(socket: Socket, framing: Framing, authority?: string): RawLink {
    return {
        framing,
        authority,
        // The peer's IP, for the per-source half-open cap only (§12.6.1). Captured now
        // because `socket.remoteAddress` reads undefined once the socket is destroyed,
        // and the limiter must be able to release the same bucket it took.
        // Unauthenticated and spoofable at the IP level — never an identity.
        remoteAddr: socket.remoteAddress ?? undefined,
        send: (bytes: Uint8Array) => { socket.write(bytes); },
        onData: (cb: (chunk: Uint8Array) => void) => { socket.on("data", (chunk: Uint8Array) => cb(new Uint8Array(chunk))); },
        // error and close both mean "gone"; the caller's teardown is idempotent.
        onClose: (cb: () => void) => { socket.on("close", cb); socket.on("error", cb); },
        // A graceful stop must FLUSH. `destroy()` drops whatever is still in the socket's
        // write buffer, which for the transport means the end-of-stream record it just
        // wrote is silently discarded and the peer reads a clean shutdown as a truncation.
        // `end()` writes the queued bytes and then sends FIN. The linger timer is the
        // backstop: a peer that never FINs back must not hold the socket open forever.
        close: (graceful?: boolean) => {
            if (!graceful) { socket.destroy(); return; }
            try {
                socket.end();
                const t = setTimeout(() => socket.destroy(), TCP_LINGER_MS);
                t.unref?.();
            }
            catch { socket.destroy(); }
        },
        buffered: () => socket.writableLength,
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
// The node:net ChannelFactory: every socket the transport driver opens
// or accepts is created here, behind the RawLink shape.
export class NodeChannelFactory {
    private tcpServer: TcpServer | null = null;
    private wsServer: TcpServer | null = null;
    /** Takes no crypto. The WebSocket client key and the frame masks are the transport
     *  bundle's, which reaches entropy through the `RANDOM` op like any other authority.
     *  This factory opens sockets and says which codec applies, and that is all of it. */
    constructor() {}
    connect(addr: PeerAddr): RawLink {
        const socket = tcpConnect(addr.port, addr.host);
        return addr.transport === "ws"
            ? nodeRawStream(socket, FRAMING.WS_CLIENT, addr.host + ":" + addr.port)
            : nodeRawStream(socket, FRAMING.LENGTH);
    }
    async listen(tcp: {
        host: string;
        port: number;
    } | undefined, ws: {
        host: string;
        port: number;
    } | undefined, onAccept: (channel: RawLink) => void): Promise<{
        port: number;
        wsPort: number;
    }> {
        let port = 0, wsPort = 0;
        const tasks: Promise<void>[] = [];
        if (tcp) {
            const server = createTcpServer((socket) => onAccept(nodeRawStream(socket, FRAMING.LENGTH)));
            this.tcpServer = server;
            tasks.push(listenOn(server, tcp).then((p) => { port = p; }));
        }
        if (ws) {
            const server = createTcpServer((socket) => onAccept(nodeRawStream(socket, FRAMING.WS_SERVER)));
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
