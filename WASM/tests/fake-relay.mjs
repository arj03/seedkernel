// An in-process relay speaking the relay wire the transport bundle speaks (transport/src/
// relay.js; the real server is seedrelay): signed registration, calls and splices. Its
// links are whole-message `RawLink`s, as a browser WebSocket's are. It checks registrations
// against the host's signing domain, so a wrong format fails here as it would against
// seedrelay.

import { createPublicKey, randomBytes, verify } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { DOMAIN_LINK_SCOPE } = await import(pathToFileURL(join(root, "build/services/domains.js")).href);

const DOMAIN_RELAY = Buffer.from("seedkernel-relay-register-v1\0");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const T_CHALLENGE = 0x00, T_REGISTER = 0x01, T_CALL = 0x05, T_UNREACHABLE = 0x06;

export class FakeRelay {
  /** `authority` is the host[:port] the relay's URLs name, which registrations sign;
   *  `signedFor` makes it check them against another. */
  constructor(authority = "relay", { signedFor = authority } = {}) {
    this.authority = authority;
    this.signedFor = signedFor;
    this.controls = new Set();
    this.registered = new Map(); // key hex to its control
    this.pending = new Map();    // ticket hex to { ends: [] }
    this.splices = [];           // joined pairs, for tests to inspect
    this.calls = 0;
    this.spliceBytes = 0;        // bytes forwarded through splices
    this.refuseSplices = false;  // a relay that takes calls but joins nothing
  }

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

  /** A whole-message link: `deliver` hands it bytes, `kill` drops it from this side. */
  link(onSend) {
    const end = { msg: null, cls: null, dead: false, queued: [] };
    end.deliver = (b) => queueMicrotask(() => { if (end.dead) return; if (end.msg) end.msg(Uint8Array.from(b)); else end.queued.push(b); });
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

  control() {
    const c = { key: null, nonce: randomBytes(32) };
    c.end = this.link((b) => this.onControl(c, Buffer.from(b)));
    c.end.gone = () => this.leave(c);
    this.controls.add(c);
    c.end.deliver(Buffer.concat([Buffer.of(T_CHALLENGE), c.nonce]));
    return c.end.raw;
  }

  onControl(c, b) {
    if (b[0] === T_REGISTER && b.length === 97 && !c.key) {
      const pk = b.subarray(1, 33), sig = b.subarray(33);
      const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, pk]), format: "der", type: "spki" });
      const msg = Buffer.concat([DOMAIN_LINK_SCOPE, DOMAIN_RELAY, Buffer.from(this.signedFor), c.nonce]);
      if (!verify(null, msg, key, sig)) { c.end.kill(); return; }
      c.key = pk.toString("hex");
      this.registered.set(c.key, c);
      c.end.deliver(Buffer.of(T_REGISTER));
    } else if (b[0] === T_CALL && b.length === 49 && c.key) {
      this.calls++;
      const to = b.subarray(1, 33), ticket = b.subarray(33);
      const callee = this.registered.get(to.toString("hex"));
      if (!callee || callee.key === c.key || this.pending.has(ticket.toString("hex"))) {
        c.end.deliver(Buffer.concat([Buffer.of(T_UNREACHABLE), to, ticket]));
        return;
      }
      this.pending.set(ticket.toString("hex"), { ends: [] });
      callee.end.deliver(Buffer.concat([Buffer.of(T_CALL), Buffer.from(c.key, "hex"), ticket]));
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
      this.spliceBytes += b.length;
      end.peer.deliver(b);
    });
    end.early = [];
    end.gone = () => { end.peer?.kill(); };
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

  /** Drop every socket, as a relay restart would. */
  restart() {
    for (const c of [...this.controls]) c.end.kill();
    for (const pair of this.splices) for (const e of pair) e.kill();
    this.pending.clear();
  }
}
