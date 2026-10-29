// Driver bounds (§12.6). Host-owned: the socket side of a link, never its framing.
/** Hard cap on one read handed to the link occupant, checked before it is copied into a
 *  realm. A platform-framed transport's frame cap must fit under it. The windows below
 *  are sized in multiples of it. */
export const MAX_LINK_READ_BYTES = 2 * 1024 * 1024; // 2 MiB

/** Inbound bytes one driver admits across dispatched and held reads, for the whole driver,
 *  not per link; a read past it fails the arriving link (§12.6). Seedstore's holder ingest
 *  bench, the worst case, peaks at ~6 MiB. */
export const MAX_INBOUND_HOLD_BYTES = 8 * MAX_LINK_READ_BYTES;

/** Count companion to `MAX_INBOUND_HOLD_BYTES`, against floods of tiny reads. */
export const MAX_INBOUND_HOLD_SLICES = 4096;

/** Bytes one link may retain for writes not yet on the wire; a write past it fails the
 *  link. */
export const MAX_OUTBOUND_QUEUE_BYTES = 8 * MAX_LINK_READ_BYTES;

/** Count companion to `MAX_OUTBOUND_QUEUE_BYTES`, against floods of tiny writes. */
export const MAX_OUTBOUND_QUEUE_SLICES = 4096;

/** Outbound allowance shared by every link in one driver, so per-link ceilings do not
 *  multiply by `DEFAULT_MAX_RAW_LINKS`. */
export const MAX_NODE_OUTBOUND_QUEUE_BYTES = 4 * MAX_OUTBOUND_QUEUE_BYTES;
export const MAX_NODE_OUTBOUND_QUEUE_SLICES = 4 * MAX_OUTBOUND_QUEUE_SLICES;

/** Live raw sockets one host holds. */
export const DEFAULT_MAX_RAW_LINKS = 4096;

/** Keepalive probes on every TCP socket, which reclaim one whose peer vanished without a
 *  FIN. */
export const TCP_KEEPALIVE_MS = 30_000;

/** Datagram sockets the link occupant holds at once (services/link.ts). A hard NAT's
 *  birthday punch opens hundreds (§12.7); the transport bounds its own below this. */
export const MAX_UDP_SOCKETS = 2048;

/** Datagram bytes held for the link occupant while it reads earlier ones, for every socket
 *  together. Past it a datagram is dropped, as a full socket buffer drops one. Native's
 *  readers charge it again, across every socket, to what they hold for the loop (udp.go):
 *  no read token gates them as TCP's are, so its bound is 2x. */
export const MAX_UDP_HELD_BYTES = 8 * MAX_LINK_READ_BYTES;

/** The kernel receive and send buffers asked for on each datagram socket: a peer may put a
 *  whole stream credit on the wire in a burst, and a kernel charges a datagram well past
 *  its payload, so a smaller buffer drops the burst's tail. Windows' default is far below. */
export const UDP_SOCKET_BUFFER_BYTES = 4 * 1024 * 1024;

/** How long a TCP socket may stay silent before its first byte (host/platform.ts
 *  `tcpChannels`): the slowloris bound, which costs an attacker a SYN and this side a
 *  socket and its reader until it fires. */
export const SILENT_SOCKET_MS = 30_000;

/** How long a gracefully closed TCP socket may linger while queued bytes flush. */
export const TCP_LINGER_MS = 5_000;
