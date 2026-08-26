// The Node platform binding for the TCP/WS socket seam: a `ChannelFactory`
// (core/socket-seam.ts) that opens node:net sockets and wraps them as RawLinks, and
// nothing else. The handshake, link routing and request/response layer run in the transport
// bundle's guest, driven by TransportHost.
//
// WebSocket is handled as a wire codec *over a raw TCP listener*: this file binds the
// listener and says which codec applies, while the RFC 6455 handshake and framing run in
// the transport bundle over its own ws.wasm — one WS code path, and no node:http here.
import { createServer as createTcpServer, connect as tcpConnect, type Server as TcpServer, type Socket } from "node:net";

import { FRAMING, type Framing, type PeerAddr, type RawLink } from "../core/socket-seam.js";
import { TCP_LINGER_MS } from "../core/net-limits.js";


// The peer-spec grammar is the operator's (peer-addr.ts), re-exported because `./net-node` is
// where a caller holding a `pk[.secret]@host:port` string looks for the parser.
export { parsePeerSpec, parsePeerRef, parseHostPort } from "./peer-addr.js";
export { isHex64 } from "../core/util.js";
// ── An unframed RawLink over a node:net socket ────────────────────────────────
// Raw bytes in and out, no boundaries; a WS link is the same socket with a different codec
// declared on it. node:net buffers writes issued before connect, so the link is writable
// from birth — the transport can send its HELLO the moment it is constructed.
function nodeRawStream(socket: Socket, framing: Framing, authority?: string): RawLink {
    return {
        framing,
        authority,
        // The peer's IP, for the per-source half-open cap only (§12.6.1) — unauthenticated
        // and never an identity. Captured now because `socket.remoteAddress` reads undefined
        // once destroyed, and the limiter must release the bucket it took.
        remoteAddr: socket.remoteAddress ?? undefined,
        send: (bytes: Uint8Array) => { socket.write(bytes); },
        onData: (cb: (chunk: Uint8Array) => void) => { socket.on("data", (chunk: Uint8Array) => cb(new Uint8Array(chunk))); },
        // error and close both mean "gone"; the caller's teardown is idempotent.
        onClose: (cb: () => void) => { socket.on("close", cb); socket.on("error", cb); },
        // A graceful stop must FLUSH: `destroy()` drops the write buffer, so the
        // end-of-stream record the transport just wrote is discarded and the peer reads a
        // clean shutdown as a truncation. `end()` writes the queued bytes then FINs; the
        // linger timer is the backstop for a peer that never FINs back.
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
// The node:net ChannelFactory: every socket the transport driver opens or accepts is
// created here, behind the RawLink shape.
export class NodeChannelFactory {
    private tcpServer: TcpServer | null = null;
    private wsServer: TcpServer | null = null;
    /** Takes no crypto: the WebSocket client key and the frame masks are the transport
     *  bundle's, which reaches entropy through `node/random` like any other authority. */
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
