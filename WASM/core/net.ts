export type PeerId = string;
/** A node's attachment to a Network: an endpoint is bound to one local id, so
 *  `send` names only the destination — the sender is implicit.
 *
 *  There is no inbound sink here. Attribution is the transport's output, so inbound
 *  content arrives as *attributed* traffic through the transport slot's own seam
 *  (guest-seam `TransportSink`) and never as raw frames on this shape. The `onFrame`
 *  member this interface used to carry was the last of the pre-split arrangement: a
 *  field the driver wrote and nothing ever read. */
export interface Endpoint {
    /** Unicast `frame` to peer `to`. The sender is this endpoint's own id. */
    send(to: PeerId, frame: Uint8Array): void;
    /** Detach from the fabric: stop delivering; a real transport also tears down. */
    close(): void;
}
/** The delivery fabric. It vends a per-node {@link Endpoint} for a local id. A
 *  real transport (the transport bundle's driver) is a single-identity fabric
 *  that vends only its own endpoint. */
export interface Network {
    endpoint(id: PeerId): Endpoint;
}
/** The app-facing request handler the driver's `onRequest` accepts — the
 *  shell's dispatch. May return a Promise (the driver answers when it settles). */
export type RequestHandler = (from: PeerId, proto: string, payload: Uint8Array) => Uint8Array | Promise<Uint8Array> | null;
