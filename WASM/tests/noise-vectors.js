// noise-vectors.js — just enough of the Noise Protocol Framework (rev 34) to replay the
// published Noise_XX / Noise_XXpsk3 _25519_ChaChaPoly_BLAKE2b vectors
// (tests/fixtures/noise-xx-vectors.json), written against nothing but the guest-visible
// `crypto/` names. It is a test of those names, not a Noise library: a replacement transport
// is a bundle only while a standard handshake can be built on them (services/domains.ts,
// HOST_TRANSFORM_NAMES). BLAKE2b-512 carries the hash and HMAC, the handshake hash rides the
// AEAD's associated data, and the transport messages use it empty — all three through the
// host. A plain script, so the JS suite (tests/realm-guest.test.mjs) and the native one
// (native/guestseam_test.go) run these same bytes against their own seam.
"use strict";

/** `call(name, bytes)` → Promise<Uint8Array>, the seam. Answers `{ ran, failures }`. */
globalThis.runNoiseVectors = async function (call, vectors) {
  const XX = [["e"], ["e", "ee", "s", "es"], ["s", "se"]];
  const EMPTY = new Uint8Array(0);
  const fromHex = (h) => Uint8Array.from(h.match(/../g) || [], (b) => parseInt(b, 16));
  const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const cat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  };
  const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };

  // The three host names, in the argument framing RUNTIME §12.2 gives them.
  const hash = (data) => call("crypto/blake2b", cat(Uint8Array.of(64, 0), data));
  async function dh(sk, pk) {
    const r = await call("crypto/x25519/dh", cat(sk, pk));
    if (r[0] !== 1) throw new Error("x25519 refused the point");
    return r.subarray(1);
  }
  // ChaChaPoly's nonce is 32 zero bits, then the counter as a 64-bit little-endian integer.
  const nonce = (n) => { const b = new Uint8Array(12); new DataView(b.buffer).setUint32(4, n, true); return b; };
  const seal = (k, n, ad, pt) =>
    call("crypto/chacha20poly1305-ietf/seal", cat(nonce(n), k, u32(ad.length), ad, pt));
  async function open(k, n, ad, ct) {
    const r = await call("crypto/chacha20poly1305-ietf/open", cat(nonce(n), k, u32(ad.length), ad, ct));
    if (r[0] !== 1) throw new Error("a message did not open");
    return r.subarray(1);
  }

  // HMAC-BLAKE2b (BLOCKLEN 128; every key here is a 64-byte hash) and Noise's HKDF.
  async function hmac(key, data) {
    const pad = (x) => { const b = new Uint8Array(128).fill(x); for (let i = 0; i < key.length; i++) b[i] ^= key[i]; return b; };
    return hash(cat(pad(0x5c), await hash(cat(pad(0x36), data))));
  }
  async function hkdf(ck, ikm, n) {
    const temp = await hmac(ck, ikm);
    const out = [await hmac(temp, Uint8Array.of(1))];
    for (let i = 2; i <= n; i++) out.push(await hmac(temp, cat(out[i - 2], Uint8Array.of(i))));
    return out;
  }

  /** One side's HandshakeState, its SymmetricState inline — XX's tokens and `psk`, no more. */
  async function party(v, initiator, name, pskMode) {
    const side = initiator ? "init" : "resp";
    const base = new Uint8Array(32); base[0] = 9;
    const p = {
      s: fromHex(v[side + "_static"]), e: fromHex(v[side + "_ephemeral"]),
      psks: (v[side + "_psks"] || []).map(fromHex), rs: null, re: null, k: null, n: 0,
    };
    p.sPub = await dh(p.s, base);
    p.ePub = await dh(p.e, base);
    const proto = new TextEncoder().encode(name);
    p.h = proto.length <= 64 ? cat(proto, new Uint8Array(64 - proto.length)) : await hash(proto);
    p.ck = p.h;
    const mixHash = async (d) => { p.h = await hash(cat(p.h, d)); };
    const mixKey = async (ikm) => { const [ck, k] = await hkdf(p.ck, ikm, 2); p.ck = ck; p.k = k.subarray(0, 32); p.n = 0; };
    const mixKeyAndHash = async (ikm) => {
      const [ck, th, k] = await hkdf(p.ck, ikm, 3);
      p.ck = ck; await mixHash(th); p.k = k.subarray(0, 32); p.n = 0;
    };
    const encryptAndHash = async (pt) => { const ct = p.k ? await seal(p.k, p.n++, p.h, pt) : pt; await mixHash(ct); return ct; };
    const decryptAndHash = async (ct) => { const pt = p.k ? await open(p.k, p.n++, p.h, ct) : ct; await mixHash(ct); return pt; };
    const mixDh = async (token) => {
      if (token === "ee") return mixKey(await dh(p.e, p.re));
      // es: the initiator's ephemeral with the responder's static; se the other way round.
      const mine = (token === "es") === initiator ? p.e : p.s;
      const theirs = (token === "es") === initiator ? p.rs : p.re;
      return mixKey(await dh(mine, theirs));
    };
    await mixHash(fromHex(v[side + "_prologue"]));

    p.write = async (tokens, payload) => {
      const out = [];
      for (const t of tokens) {
        if (t === "e") { out.push(p.ePub); await mixHash(p.ePub); if (pskMode) await mixKey(p.ePub); }
        else if (t === "s") out.push(await encryptAndHash(p.sPub));
        else if (t === "psk") await mixKeyAndHash(p.psks.shift());
        else await mixDh(t);
      }
      out.push(await encryptAndHash(payload));
      return cat(...out);
    };
    p.read = async (tokens, msg) => {
      let at = 0;
      for (const t of tokens) {
        if (t === "e") { p.re = msg.subarray(at, at += 32); await mixHash(p.re); if (pskMode) await mixKey(p.re); }
        else if (t === "s") { const len = p.k ? 48 : 32; p.rs = await decryptAndHash(msg.subarray(at, at += len)); }
        else if (t === "psk") await mixKeyAndHash(p.psks.shift());
        else await mixDh(t);
      }
      return decryptAndHash(msg.subarray(at));
    };
    p.split = async () => (await hkdf(p.ck, EMPTY, 2)).map((k) => k.subarray(0, 32));
    return p;
  }

  const failures = [];
  for (const v of vectors) {
    const name = v.protocol_name;
    const m = /^Noise_XX(?:psk(\d))?_25519_ChaChaPoly_BLAKE2b$/.exec(name);
    if (!m) { failures.push(`${name}: not an XX vector this harness replays`); continue; }
    const pattern = XX.map((tokens) => tokens.slice());
    if (m[1] !== undefined) {
      const at = Number(m[1]);
      if (at === 0) pattern[0].unshift("psk"); else pattern[at - 1].push("psk");
    }
    try {
      const pskMode = m[1] !== undefined;
      const init = await party(v, true, name, pskMode);
      const resp = await party(v, false, name, pskMode);
      // After the handshake, [initiator→responder, responder→initiator] with their nonces.
      let keys = null;
      const counters = [0, 0];
      for (let i = 0; i < v.messages.length; i++) {
        const payload = fromHex(v.messages[i].payload);
        const [tx, rx] = i % 2 === 0 ? [init, resp] : [resp, init];
        let wire, got;
        if (i < pattern.length) {
          wire = await tx.write(pattern[i], payload);
          got = await rx.read(pattern[i], wire);
          if (i === pattern.length - 1) {
            if (toHex(init.h) !== v.handshake_hash || toHex(resp.h) !== v.handshake_hash) {
              failures.push(`${name}: handshake hash differs`);
            }
            keys = await init.split();
            const theirs = await resp.split();
            if (toHex(cat(...keys)) !== toHex(cat(...theirs))) failures.push(`${name}: the two ends split different keys`);
          }
        } else {
          const dir = i % 2, n = counters[dir]++;
          wire = await seal(keys[dir], n, EMPTY, payload);
          got = await open(keys[dir], n, EMPTY, wire);
        }
        if (toHex(wire) !== v.messages[i].ciphertext) failures.push(`${name}: message ${i} ciphertext differs`);
        if (toHex(got) !== v.messages[i].payload) failures.push(`${name}: message ${i} payload differs`);
      }
    } catch (e) {
      failures.push(`${name}: ${e && e.message ? e.message : e}`);
    }
  }
  return { ran: vectors.length, failures };
};
