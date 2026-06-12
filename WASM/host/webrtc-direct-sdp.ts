// Browser-safe WebRTC-Direct SDP helpers — no node, no werift imports, so the
// SAME logic runs in the console listener/dialer (host/webrtc-direct.ts) and in a
// browser tab dialing a console node (browser/p2p.html). Pure string/byte work.

/** Decode the dial token's certhash to the colon-hex sha-256 the browser bakes
 *  into the fabricated answer's `a=fingerprint:` line. The token is multibase
 *  ("u" base64url) of multihash(sha2-256=0x12, len=0x20, digest). */
export function certhashToFingerprint(certhash: string): string {
  const bytes = base64urlDecode(certhash.startsWith("u") ? certhash.slice(1) : certhash);
  const digest = bytes.subarray(2); // strip the 0x12 0x20 multihash prefix
  return [...digest].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
}

/** A random value used as BOTH ice-ufrag and ice-pwd (WebRTC-Direct shares one
 *  value so the console can derive the integrity key from the STUN USERNAME). It
 *  MUST be ≥22 chars: browsers enforce RFC 5245's ice-pwd minimum on the fabricated
 *  answer (werift does not, which is why a short one slips through Node tests). */
export function randomUfrag(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return "sk" + [...b].map((x) => x.toString(16).padStart(2, "0")).join(""); // 34 chars
}

/** Turn the dialer's own offer into the console's answer: identical structure for
 *  a data-channel-only session, so we only swap the ICE credentials (one shared
 *  `ufrag` used for both ice-ufrag and ice-pwd), the fingerprint (= the token's
 *  certhash), and the DTLS role (passive ⇒ the console is the DTLS server that
 *  holds the named cert), then append the console's host candidate. */
export function fabricateAnswerSdp(
  offerSdp: string,
  opts: { ufrag: string; fingerprint: string; host: string; port: number },
): string {
  const out: string[] = [];
  for (let line of offerSdp.split(/\r?\n/)) {
    if (!line) continue;
    if (line.startsWith("a=ice-ufrag:")) line = "a=ice-ufrag:" + opts.ufrag;
    else if (line.startsWith("a=ice-pwd:")) line = "a=ice-pwd:" + opts.ufrag;
    else if (line.startsWith("a=fingerprint:")) line = "a=fingerprint:sha-256 " + opts.fingerprint;
    else if (line.startsWith("a=setup:")) line = "a=setup:passive";
    out.push(line);
  }
  out.push(`a=candidate:1 1 UDP 2130706431 ${opts.host} ${opts.port} typ host`);
  out.push("a=end-of-candidates");
  return out.join("\r\n") + "\r\n";
}

/** A dial token string ⇄ its parts. Format (carried in the page URL #fragment):
 *  `/ip4/<host>/udp/<port>/certhash/<multibase>/p2p/<nodePubkeyHex>` — host+port+
 *  certhash bring up DTLS; the pubkey lets the dialer pin PeerLink's expectPeerId. */
export interface DialToken { host: string; port: number; certhash: string; peerId: string }

export function encodeDialToken(t: DialToken): string {
  return `/ip4/${t.host}/udp/${t.port}/certhash/${t.certhash}/p2p/${t.peerId}`;
}

export function parseDialToken(token: string): DialToken {
  const m = /^\/ip4\/([^/]+)\/udp\/(\d+)\/certhash\/([^/]+)\/p2p\/([0-9a-fA-F]+)$/.exec(token.trim());
  if (!m) throw new Error("bad dial token");
  return { host: m[1], port: Number(m[2]), certhash: m[3], peerId: m[4].toLowerCase() };
}

// base64url → bytes, using atob (a global in browsers and Node ≥16 / Bun).
function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
