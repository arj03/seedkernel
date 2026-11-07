// An in-process relay speaking the relay wire the transport bundle speaks (transport/src/
// relay.js; the real server is seedrelay): a node's relay link runs the channel handshake
// with the relay as its responder, pinned to the relay's key, and the relay wire travels
// in its records; then calls, splices and tells. Its links are whole-message `RawLink`s,
// as a browser WebSocket's are. The handshake here is written out apart from the
// transport's, from libsodium and the ML-KEM module, so a transport that drifts from the
// documented construction (docs/TRANSPORT.md, Handshake) fails here as it would against
// seedrelay.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
const { DOMAIN_LINK_SCOPE } = await imp("build/host/domains.js");
const { loadCrypto } = await imp("build/host/crypto-node.js");
const { ModuleTable } = await imp("build/host/module-table.js");
const sodium = await loadCrypto();
const kem = await new ModuleTable().build([{ name: "mlkem", wasm: readFileSync(join(root, "browser/mlkem768.wasm")) }]);

const utf8 = (s) => new TextEncoder().encode(s);
const cat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
const hex = (b) => Buffer.from(b).toString("hex");
const H = (...parts) => sodium.crypto_generichash(32, cat(...parts), null);
const ZERO32 = new Uint8Array(32), NONCE0 = new Uint8Array(12);
const X25519_BASE = Uint8Array.of(9, ...new Uint8Array(31));

const DOMAIN_CHANNEL = utf8("seedkernel-channel-id-v1\0");
const LABEL = {
  probe: utf8("seedkernel-c-probe-v1\0"), m2: utf8("seedkernel-c-msg2-v1\0"), m3: utf8("seedkernel-c-msg3-v1\0"),
  i2r: utf8("seedkernel-session-i->r-v1\0"), r2i: utf8("seedkernel-session-r->i-v1\0"),
  rekey: utf8("seedkernel-session-rekey-v1\0"),
};
const SUITE = 0x03, M1_LEN = 1233, M3_LEN = 112, KEM_PK_LEN = 1184;
/** The public network's root: every relay link is on it, whatever the node's network. */
const ROOT = H(DOMAIN_CHANNEL, ZERO32);
const R_REGISTERED = 0x01, R_CALL = 0x05, R_UNREACHABLE = 0x06, R_TELL = 0x08;

const seal = (key, nonce, pt) => sodium.crypto_aead_chacha20poly1305_ietf_encrypt(pt, null, null, nonce, key);
function open(key, nonce, ct) {
  try { return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ct, null, nonce, key); }
  catch { return null; }
}
function recordNonce(epoch, ctr) {
  const n = new Uint8Array(12);
  const v = new DataView(n.buffer);
  v.setUint32(0, epoch);
  v.setUint32(8, ctr);
  return n;
}
/** One direction of a record stream: the implicit (epoch, counter) nonce, ratcheting the
 *  key every `rekeyAfterFrames` records as the transport does. */
function direction(key, rekeyAfterFrames) {
  let epoch = 0, ctr = 0;
  const step = () => {
    if (++ctr < rekeyAfterFrames) return;
    key = H(key, LABEL.rekey);
    epoch++;
    ctr = 0;
  };
  return {
    seal(pt) {
      const ct = seal(key, recordNonce(epoch, ctr), pt);
      step();
      return ct;
    },
    open(ct) {
      const pt = open(key, recordNonce(epoch, ctr), ct);
      if (pt) step();
      return pt;
    },
  };
}

/** A relay's identity, a function of its authority so a test can name its URL before
 *  making it (`relayUrl`). */
const relayIdentity = (authority) => sodium.crypto_sign_seed_keypair(H(utf8("fake-relay\0"), utf8(authority)));

/** The URL a node registers with on the FakeRelay at `authority`,
 *  `ws://<key>[.<secret>]@authority`; `relay+` and it is a peer's address behind it. */
export function relayUrl(authority = "relay", secret = null) {
  return `ws://${hex(relayIdentity(authority).publicKey)}${secret ? "." + hex(secret) : ""}@${authority}`;
}

export class FakeRelay {
  /** `authority` is the host[:port] the relay's URLs name. With a `secret` (32 bytes) it is
   *  a private relay: its contact secret, which a node's msg1 must open under. */
  constructor(authority = "relay", { secret = null, rekeyAfterFrames = 1 << 24 } = {}) {
    this.authority = authority;
    this.secret = secret ?? ZERO32;
    this.rekeyAfterFrames = rekeyAfterFrames;
    this.identity = relayIdentity(authority);
    this.key = hex(this.identity.publicKey);
    this.controls = new Set();
    this.registered = new Map(); // key hex to its control
    this.pending = new Map();    // ticket hex to { ends: [] }
    this.splices = [];           // joined pairs, for tests to inspect
    this.calls = 0;
    this.spliceBytes = 0;        // bytes forwarded through splices
    this.refuseSplices = false;  // a relay that takes calls but joins nothing
    this.callerName = null;      // a lying relay: the key hex it names every caller as
    this.controlWire = [];       // every message a relay link carried, either way
    this.tells = [];             // [key hex, bytes] for every tell a node sent
    this.onTell = null;          // (keyHex, bytes) for a test that answers them
    // A relay too slow to forward anything: splice bytes wait here, counted, until resume().
    this.paused = false;
    this.pausedBytes = 0;
    this.stalled = [];
  }

  /** The URL a node registers with (`relayUrl`). */
  url(secret = null) { return relayUrl(this.authority, secret); }

  factory() {
    return {
      connect: (dest) => this.connect(dest),
      listen: async (addrs) => addrs.map(() => 0),
      close() {},
    };
  }

  connect(dest) {
    const m = /^wss?:\/\/([^/?#]+)\/v1\/(?:\?splice=([0-9a-f]{32}))?$/.exec(dest);
    if (!m || m[1] !== this.authority) return null;
    return m[2] ? this.spliceEnd(m[2]) : this.control();
  }

  /** A whole-message link: `deliver` hands it bytes, `delay` ms late for a slow path, and
   *  `kill` drops it from this side. */
  link(onSend) {
    const end = { msg: null, cls: null, dead: false, queued: [], delay: 0 };
    end.deliver = (b) => {
      const run = () => { if (end.dead) return; if (end.msg) end.msg(Uint8Array.from(b)); else end.queued.push(b); };
      if (end.delay > 0) setTimeout(run, end.delay); else queueMicrotask(run);
    };
    end.kill = () => { if (end.dead) return; end.dead = true; end.gone?.(); queueMicrotask(() => end.cls?.()); };
    end.raw = {
      send: (b) => { if (!end.dead) onSend(Uint8Array.from(b)); },
      onData(cb) { end.msg = cb; for (const b of end.queued.splice(0)) end.deliver(b); },
      onClose(cb) { end.cls = cb; },
      close() { if (end.dead) return; end.dead = true; end.gone?.(); },
      buffered: () => 0,
    };
    return end;
  }

  /** A node's relay link: the handshake, then records, each message taken in order. A
   *  record is read as it arrives once nothing waits before it, as seedrelay reads its
   *  links, so a call is heard before the splice socket the node opens behind it. */
  control() {
    const c = { key: null, hs: null, recv: null, send: null, work: Promise.resolve(), waiting: 0 };
    c.end = this.link((b) => {
      this.controlWire.push(b);
      if (c.recv && c.waiting === 0) { this.onRecord(c, b); return; }
      c.waiting++;
      c.work = c.work.then(() => this.onControl(c, b)).catch(() => c.end.kill()).finally(() => { c.waiting--; });
    });
    c.end.gone = () => this.leave(c);
    this.controls.add(c);
    return c.end.raw;
  }

  /** One record of the relay wire, on a registered link. */
  record(c, ...parts) { this.put(c, c.send.seal(cat(...parts))); }

  /** One message to a node on its relay link. */
  put(c, bytes) {
    this.controlWire.push(bytes);
    c.end.deliver(bytes);
  }

  /** Tell a registered node `bytes`, as a relay service would. */
  tell(keyHex, bytes) {
    const c = this.registered.get(keyHex);
    if (c) this.record(c, Uint8Array.of(R_TELL), bytes);
  }

  onControl(c, b) {
    if (c.recv) return this.onRecord(c, b);
    return c.hs ? this.onMsg3(c, b) : this.onMsg1(c, b);
  }

  /** msg1: silence for anything that does not open under the relay's contact secret. */
  async onMsg1(c, w1) {
    if (w1.length !== M1_LEN || w1[0] !== SUITE) return;
    const eph = w1.subarray(1, 33), kemPk = w1.subarray(33, 33 + KEM_PK_LEN);
    const probe = H(this.secret, H(ROOT, w1.subarray(0, 1), eph, kemPk), LABEL.probe);
    if (!open(probe, NONCE0, w1.subarray(33 + KEM_PK_LEN))) return;
    const sk = sodium.randombytes_buf(32);
    const ee = sodium.crypto_scalarmult(sk, eph);
    const r = (await kem.call("mlkem", cat(Uint8Array.of(1), kemPk, sodium.randombytes_buf(32)))).bytes;
    if (r[0] !== 1) return;
    const head = cat(sodium.crypto_scalarmult(sk, X25519_BASE), r.subarray(1, 1089));
    const pq = r.subarray(1089);
    const h1 = H(ROOT, w1);
    const hs = H(h1, head);
    const sig = sodium.crypto_sign_detached(cat(DOMAIN_LINK_SCOPE, DOMAIN_CHANNEL, ROOT, hs, this.identity.publicKey), this.identity.privateKey);
    const w2 = cat(head, seal(H(ee, pq, this.secret, hs, LABEL.m2), NONCE0, sig));
    c.hs = { ee, pq, th: H(h1, w2) };
    this.put(c, w2);
  }

  /** msg3: the node names itself, which registers it. */
  onMsg3(c, w3) {
    const { ee, pq, th } = c.hs;
    if (w3.length !== M3_LEN) return;
    const plain = open(H(ee, pq, this.secret, th, LABEL.m3), NONCE0, w3);
    if (!plain) return;
    const id = plain.subarray(0, 32), sig = plain.subarray(32, 96);
    if (!sodium.crypto_sign_verify_detached(sig, cat(DOMAIN_LINK_SCOPE, DOMAIN_CHANNEL, ROOT, th, id), id)) return;
    const h3 = H(th, w3);
    c.recv = direction(H(ee, pq, this.secret, h3, LABEL.i2r), this.rekeyAfterFrames);
    c.send = direction(H(ee, pq, this.secret, h3, LABEL.r2i), this.rekeyAfterFrames);
    c.hs = null;
    c.key = hex(id);
    this.registered.set(c.key, c);
    this.record(c, Uint8Array.of(R_REGISTERED));
  }

  onRecord(c, ct) {
    const m = c.recv.open(ct);
    // A bad record, or the node's goodbye, ends the link.
    if (!m || m.length === 0) { c.end.kill(); return; }
    if (m[0] === R_CALL && m.length === 49) {
      this.calls++;
      const to = m.subarray(1, 33), ticket = m.subarray(33);
      const callee = this.registered.get(hex(to));
      if (!callee || callee.key === c.key || this.pending.has(hex(ticket))) {
        this.record(c, Uint8Array.of(R_UNREACHABLE), to, ticket);
        return;
      }
      this.pending.set(hex(ticket), { ends: [] });
      this.record(callee, Uint8Array.of(R_CALL), Buffer.from(this.callerName ?? c.key, "hex"), ticket);
    } else if (m[0] === R_TELL) {
      this.tells.push([c.key, m.subarray(1)]);
      this.onTell?.(c.key, m.subarray(1));
    } else {
      c.end.kill();
    }
  }

  leave(c) {
    this.controls.delete(c);
    if (!c.key || this.registered.get(c.key) !== c) return;
    this.registered.delete(c.key);
    for (const o of this.controls) if (o.key === c.key) this.registered.set(c.key, o);
  }

  spliceEnd(ticket) {
    const p = this.pending.get(ticket);
    if (!p || p.ends.length >= 2 || this.refuseSplices) return null;
    const end = this.link((b) => {
      if (!end.peer) { end.early.push(b); return; }
      if (this.paused) { this.pausedBytes += b.length; this.stalled.push(() => end.peer.deliver(b)); return; }
      this.spliceBytes += b.length;
      end.peer.deliver(b);
    });
    end.early = [];
    // A closing end takes its peer down behind what it already sent, as a relay forwards
    // a socket's last bytes before it closes the other one. A node may write its goodbye
    // and close in one turn.
    end.gone = () => { queueMicrotask(() => end.peer?.kill()); };
    p.ends.push(end);
    if (p.ends.length === 2) {
      this.pending.delete(ticket);
      const [a, b] = p.ends;
      a.peer = b; b.peer = a;
      this.splices.push(p.ends);
      for (const e of p.ends) for (const m of e.early.splice(0)) { this.spliceBytes += m.length; e.peer.deliver(m); }
    }
    return end.raw;
  }

  /** Forward what a pause held, in order, and stop holding. */
  resume() {
    this.paused = false;
    for (const f of this.stalled.splice(0)) f();
  }

  /** Drop every socket, as a relay restart would. */
  restart() {
    for (const c of [...this.controls]) c.end.kill();
    for (const pair of this.splices) for (const e of pair) e.kill();
    this.pending.clear();
  }
}
