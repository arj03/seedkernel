package main

// The UDP path on the native binary (§12.7): two nodes meet through a relay, the transport
// moves them to a UDP path over Go's datagram primitive (udp.go), and requests cross it.
// The relay is an in-realm fake speaking the relay wire over whole-message links, as the
// shared JS suite's fake-relay.mjs does: the handshake as the relay link's responder, then
// calls in records. Its STUN address does not resolve, so the path is punched between this
// machine's own addresses.
//
// The benchmarks are BenchmarkNetRoundTrip, BenchmarkNetFetch64K and BenchmarkNetUpload1M
// (net_bench_test.go) over the UDP path instead of a dialed TCP link: the same app, the
// same requests, the same transport above the socket.
//
//	go test -run x -bench 'BenchmarkNet|BenchmarkUdp' -benchmem ./...

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// udpPairHarness sets up nodes C and D in the realm, both behind the fake relay and with
// the UDP path in their sockets; D reaches C through the relay, and the setup returns once
// each reads the other as direct. udpPingN/udpFetchN/udpUploadN then send from D to C as
// net_bench_test.go's do from B to A, and udpCheck asks for a block and sends one, both
// intact and neither through the relay.
//
// The four %q holes, in order: the ML-KEM module hex, the app bundle hex, the app author's
// hex id, and the protocol id D sends under.
const udpPairHarness = `
	globalThis.__udpRelay = (() => {
	  const T_REGISTERED = 1, T_CALL = 5, T_UNREACHABLE = 6;
	  const registered = new Map(), pending = new Map();
	  const stats = { spliceBytes: 0 };
	  const cat = (...parts) => {
	    let n = 0;
	    for (const p of parts) n += p.length;
	    const out = new Uint8Array(n);
	    let at = 0;
	    for (const p of parts) { out.set(p, at); at += p.length; }
	    return out;
	  };
	  // A whole-message link: deliver hands it bytes on a later turn, kill drops it.
	  const link = (onSend) => {
	    const end = { msg: null, cls: null, dead: false, queued: [] };
	    end.deliver = (b) => queueMicrotask(() => { if (end.dead) return; if (end.msg) end.msg(b.slice()); else end.queued.push(b); });
	    end.kill = () => { if (end.dead) return; end.dead = true; if (end.gone) end.gone(); queueMicrotask(() => { if (end.cls) end.cls(); }); };
	    end.raw = {
	      send: (b) => { if (!end.dead) onSend(b.slice()); },
	      onData(cb) { end.msg = cb; for (const b of end.queued.splice(0)) end.deliver(b); },
	      onClose(cb) { end.cls = cb; },
	      close() { if (end.dead) return; end.dead = true; if (end.gone) end.gone(); },
	      buffered: () => 0,
	    };
	    return end;
	  };
	  // The relay's side of a relay link: the channel handshake as its responder, on the
	  // public network's root, then the relay wire in records (fake-relay.mjs has the same).
	  const enc = (s) => new TextEncoder().encode(s);
	  const H = (...parts) => sodium.crypto_generichash(32, cat(...parts), null);
	  const DOMAIN_LINK_SCOPE = enc("seedkernel-link-scope-v1\0"), DOMAIN_CHANNEL = enc("seedkernel-channel-id-v1\0");
	  const L = (s) => enc("seedkernel-" + s + "-v1\0");
	  const ROOT = H(DOMAIN_CHANNEL, new Uint8Array(32)), NONCE0 = new Uint8Array(12), SECRET = new Uint8Array(32);
	  const relayId = sodium.crypto_sign_keypair();
	  const kem = platformModules.build([{ name: "mlkem", wasm: fromHex(%q) }]);
	  const aead = {
	    seal: (k, n, m) => sodium.crypto_aead_chacha20poly1305_ietf_encrypt(m, null, null, n, k),
	    open: (k, n, c) => { try { return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, c, null, n, k); } catch { return null; } },
	  };
	  const nonce = (ctr) => { const n = new Uint8Array(12); n[8] = ctr >>> 24; n[9] = (ctr >>> 16) & 255; n[10] = (ctr >>> 8) & 255; n[11] = ctr & 255; return n; };
	  const onMsg1 = async (c, w1) => {
	    if (w1.length !== 1233 || w1[0] !== 3) return;
	    const eph = w1.subarray(1, 33), kemPk = w1.subarray(33, 1217);
	    if (!aead.open(H(SECRET, H(ROOT, w1.subarray(0, 1), eph, kemPk), L("c-probe")), NONCE0, w1.subarray(1217))) return;
	    const sk = sodium.randombytes_buf(32);
	    const r = (await (await kem).call("mlkem", cat(Uint8Array.of(1), kemPk, sodium.randombytes_buf(32)))).bytes;
	    const ee = sodium.crypto_scalarmult(sk, eph), pq = r.subarray(1089);
	    const head = cat(sodium.crypto_scalarmult(sk, Uint8Array.of(9, ...new Uint8Array(31))), r.subarray(1, 1089));
	    const h1 = H(ROOT, w1), hs = H(h1, head);
	    const sig = sodium.crypto_sign_detached(cat(DOMAIN_LINK_SCOPE, DOMAIN_CHANNEL, ROOT, hs, relayId.publicKey), relayId.privateKey);
	    const w2 = cat(head, aead.seal(H(ee, pq, SECRET, hs, L("c-msg2")), NONCE0, sig));
	    c.hs = { ee, pq, th: H(h1, w2) };
	    c.end.deliver(w2);
	  };
	  const onMsg3 = (c, w3) => {
	    const { ee, pq, th } = c.hs;
	    const plain = w3.length === 112 ? aead.open(H(ee, pq, SECRET, th, L("c-msg3")), NONCE0, w3) : null;
	    if (!plain) return;
	    const h3 = H(th, w3);
	    c.recv = { key: H(ee, pq, SECRET, h3, L("session-i->r")), ctr: 0 };
	    c.send = { key: H(ee, pq, SECRET, h3, L("session-r->i")), ctr: 0 };
	    c.hs = null;
	    c.key = toHex(plain.subarray(0, 32));
	    registered.set(c.key, c);
	    record(c, Uint8Array.of(T_REGISTERED));
	  };
	  const record = (c, ...parts) => c.end.deliver(aead.seal(c.send.key, nonce(c.send.ctr++), cat(...parts)));
	  const onRecord = (c, ct) => {
	    const b = aead.open(c.recv.key, nonce(c.recv.ctr), ct);
	    if (!b || b.length === 0) { c.end.kill(); return; }
	    c.recv.ctr++;
	    if (b[0] === T_CALL && b.length === 49) {
	      const callee = registered.get(toHex(b.subarray(1, 33))), ticket = b.subarray(33);
	      if (!callee || callee === c) { record(c, Uint8Array.of(T_UNREACHABLE), b.subarray(1)); return; }
	      pending.set(toHex(ticket), { ends: [] });
	      record(callee, Uint8Array.of(T_CALL), fromHex(c.key), ticket);
	    } else {
	      c.end.kill();
	    }
	  };
	  // Records are read as they come once nothing waits before them, so a call is heard
	  // before the splice socket opened behind it.
	  const control = () => {
	    const c = { key: null, hs: null, recv: null, send: null, work: Promise.resolve(), waiting: 0 };
	    c.end = link((b) => {
	      if (c.recv && c.waiting === 0) { onRecord(c, b); return; }
	      c.waiting++;
	      c.work = c.work.then(() => (c.recv ? onRecord(c, b) : c.hs ? onMsg3(c, b) : onMsg1(c, b)))
	        .catch(() => c.end.kill()).finally(() => { c.waiting--; });
	    });
	    c.end.gone = () => { if (c.key && registered.get(c.key) === c) registered.delete(c.key); };
	    return c.end.raw;
	  };
	  const spliceEnd = (ticket) => {
	    const p = pending.get(ticket);
	    if (!p || p.ends.length >= 2) return null;
	    const end = link((b) => {
	      if (!end.peer) { end.early.push(b); return; }
	      stats.spliceBytes += b.length;
	      end.peer.deliver(b);
	    });
	    end.early = [];
	    end.gone = () => queueMicrotask(() => { if (end.peer) end.peer.kill(); });
	    p.ends.push(end);
	    if (p.ends.length === 2) {
	      pending.delete(ticket);
	      const [a, b] = p.ends;
	      a.peer = b; b.peer = a;
	      for (const e of p.ends) for (const m of e.early.splice(0)) { stats.spliceBytes += m.length; e.peer.deliver(m); }
	    }
	    return end.raw;
	  };
	  return {
	    stats,
	    url: "ws://" + toHex(relayId.publicKey) + "@relay",
	    factory: () => ({
	      connect(dest) {
	        const m = /^ws:\/\/relay\/v1\/(?:\?splice=([0-9a-f]{32}))?$/.exec(dest);
	        if (!m) return null;
	        return m[1] ? spliceEnd(m[1]) : control();
	      },
	      listen: async (addrs) => addrs.map(() => 0),
	      close() {},
	    }),
	  };
	})();
	globalThis.idC = sodium.crypto_sign_keypair();
	globalThis.idD = sodium.crypto_sign_keypair();
	globalThis.cId = toHex(idC.publicKey);
	globalThis.dId = toHex(idD.publicKey);
	globalThis.__udpAppBlob = fromHex(%q);
	globalThis.__udpPolicy = JSON.stringify({ authors: [%q] });
	globalThis.__udpSetup = (async () => {
	  const opFrame = (name, args) => {
	    const out = new Uint8Array(1 + name.length + args.length);
	    out[0] = name.length;
	    for (let i = 0; i < name.length; i++) out[1 + i] = name.charCodeAt(i);
	    out.set(args, 1 + name.length);
	    return out;
	  };
	  const blob = (b) => {
	    const out = new Uint8Array(4 + b.length);
	    out[0] = b.length >>> 24; out[1] = (b.length >>> 16) & 255; out[2] = (b.length >>> 8) & 255; out[3] = b.length & 255;
	    out.set(b, 4);
	    return out;
	  };
	  const node = (identity) => standUp({ dir: __dir, policyJson: __udpPolicy, identity,
	    transport: { channels: combineChannels(__udpRelay.factory(), platformChannels()) } });
	  const c = await node(idC), d = await node(idD);
	  globalThis.udpC = c;
	  globalThis.udpD = d;
	  await c.shell.install(__udpAppBlob);
	  const dApp = await d.shell.install(__udpAppBlob);
	  for (const n of [c, d]) {
	    const r = await n.shell.call("_net", opFrame("relay", blob(new TextEncoder().encode(__udpRelay.url))));
	    if (r[0] !== 1) throw new Error("udp: not registered on the relay");
	  }
	  await teachAddr(d.shell, cId, "relay+" + __udpRelay.url, await contactOf(c.shell));

	  // The transport's 'send' op argument: [noReply u8][to blob][proto blob][payload blob].
	  const proto = new TextEncoder().encode(%q);
	  const sendArgs = (payload) => {
	    const parts = [Uint8Array.of(0), blob(fromHex(cId)), blob(proto), blob(payload)];
	    let n = 0;
	    for (const p of parts) n += p.length;
	    const out = new Uint8Array(n);
	    let at = 0;
	    for (const p of parts) { out.set(p, at); at += p.length; }
	    return out;
	  };
	  const req = async (args) => {
	    const r = await dApp.invoke(opFrame("send", args));
	    if (r[0] !== 1) throw new Error("udp: request failed");
	    return r.slice(1);
	  };
	  // The first request dials through the relay; the transport then moves the pair off it.
	  const ping = sendArgs(new Uint8Array([10, 20, 30]));
	  await req(ping);
	  const direct = async (n, peer) => {
	    const r = await n.shell.call("_net", opFrame("routes", new Uint8Array(0)));
	    for (let at = 0; at + 33 <= r.length; at += 33) if (toHex(r.subarray(at, at + 32)) === peer) return r[at + 32] === 1;
	    return false;
	  };
	  const until = Date.now() + 10000;
	  while (!((await direct(c, dId)) && (await direct(d, cId)))) {
	    if (Date.now() > until) throw new Error("udp: the pair never moved off the relay");
	    await new Promise((r) => setTimeout(r, 20));
	  }

	  const fid = sendArgs(new Uint8Array([7, ...new Array(31).fill(0)]));
	  const big = new Uint8Array(1 + (1 << 20)); big.fill(0x5a); big[0] = 9;
	  const upload = sendArgs(big);
	  const uploadAck = ((1 << 20) ^ 0x5a) & 255;
	  globalThis.udpPingN = async (n) => { for (let i = 0; i < n; i++) await req(ping); return new Uint8Array(0); };
	  globalThis.udpFetchN = async (n) => { let acc = 0; for (let i = 0; i < n; i++) { const r = await req(fid); acc ^= r[0]; } return new Uint8Array([acc & 255]); };
	  globalThis.udpUploadN = async (n) => { for (let i = 0; i < n; i++) { const r = await req(upload); if (r[0] !== uploadAck) throw new Error("udp: upload ack " + r[0]); } return new Uint8Array(0); };
	  globalThis.udpCheck = async () => {
	    const before = __udpRelay.stats.spliceBytes;
	    const block = await req(fid);
	    if (block.length !== 65536 || block.some((x) => x !== 0x5a)) throw new Error("udp: the block came back wrong, " + block.length + " bytes");
	    await udpUploadN(1);
	    if (__udpRelay.stats.spliceBytes !== before) throw new Error("udp: bulk crossed the relay");
	    return new Uint8Array(0);
	  };
	})();
`

// setupUdpPair evaluates the harness once per realm and waits for the pair to be direct.
func setupUdpPair(tb testing.TB) {
	tb.Helper()
	v, err := qc.Eval("udp-pair-installed.js", `typeof udpPingN`)
	if err != nil {
		tb.Fatal("harness probe:", err)
	}
	if v.String() == "function" {
		return
	}
	author := testAuthor(tb)
	blob := signedBundleBytes(tb, author, benchProto, 1, netBenchGuestSource, []string{"_net"})
	mlkem, err := os.ReadFile(filepath.Join("..", "WASM", "browser", "mlkem768.wasm"))
	if err != nil {
		tb.Fatal("mlkem768.wasm:", err)
	}
	src := fmt.Sprintf(udpPairHarness, hex.EncodeToString(mlkem), hex.EncodeToString(blob), hex.EncodeToString(author.id()), benchProto)
	if _, err := qc.Eval("udp-pair-harness.js", src); err != nil {
		tb.Fatal("harness:", err)
	}
	awaitOK(tb, "__udpSetup", `__udpSetup`, 20*time.Second)
}

func TestUdpPathNative(t *testing.T) {
	bootRealm(t)
	setupUdpPair(t)
	// Each end's negotiation holds one Go socket.
	uh.mu.Lock()
	socks := len(uh.socks)
	uh.mu.Unlock()
	if socks < 2 {
		t.Fatalf("want a UDP socket at each end, Go holds %d", socks)
	}
	awaitOK(t, "udpCheck", `udpCheck()`, 20*time.Second)
}

// A native socket is dual-stack: it hears IPv4 and IPv6 alike, and names each sender in the
// batch as the platform ABI writes it, IPv4 as its 4 bytes though the socket hears it
// IPv4-mapped, IPv6 as its 16.
func TestUdpDualStackNative(t *testing.T) {
	bootRealm(t)
	got := awaitOK(t, "dual-stack", `(async () => {
	  const heard = [];
	  const read = (batch) => {
	    const b = new Uint8Array(batch);
	    for (let at = 0; at < b.length;) {
	      const n = b[at], ip = b.subarray(at + 1, at + 1 + n);
	      const port = (b[at + 1 + n] << 8) | b[at + 2 + n], len = (b[at + 3 + n] << 8) | b[at + 4 + n];
	      heard.push((n === 4 ? ip.join(".") : ip.join("") === "0".repeat(15) + "1" ? "::1" : "?") + " " + (port === a.port) + " " + b[at + 5 + n]);
	      at += 5 + n + len;
	    }
	  };
	  const a = __udp.bind(() => {}, 1 << 16, 1 << 22), b = __udp.bind(read, 1 << 16, 1 << 22);
	  // [socket u32][n u8][ip n][port u16][len u16][bytes], as link/udpSend carries it.
	  const one = (ip, x) => Uint8Array.of(0, 0, 0, a.id, ip.length, ...ip, b.port >> 8, b.port & 255, 0, 1, x);
	  const loop6 = new Array(16).fill(0);
	  loop6[15] = 1;
	  __udp.send(new Uint8Array([...one([127, 0, 0, 1], 4), ...one(loop6, 6)]));
	  const until = Date.now() + 5000;
	  while (heard.length < 2 && Date.now() < until) await new Promise((r) => setTimeout(r, 10));
	  __udp.close(a.id);
	  __udp.close(b.id);
	  return new TextEncoder().encode(heard.sort().join(","));
	})()`, 10*time.Second)
	if want := "127.0.0.1 true 4,::1 true 6"; string(got) != want {
		t.Fatalf("heard %q, want %q", got, want)
	}
}

func BenchmarkUdpRoundTrip(b *testing.B) {
	ensureBooted(b)
	setupUdpPair(b)
	benchAwait(b, "udpPingN(1)")
	b.ResetTimer()
	benchAwait(b, fmt.Sprintf("udpPingN(%d)", b.N))
	b.StopTimer()
}

func BenchmarkUdpFetch64K(b *testing.B) {
	ensureBooted(b)
	setupUdpPair(b)
	b.SetBytes(blockBytes)
	benchAwait(b, "udpFetchN(1)")
	b.ResetTimer()
	benchAwait(b, fmt.Sprintf("udpFetchN(%d)", b.N))
	b.StopTimer()
}

func BenchmarkUdpUpload1M(b *testing.B) {
	ensureBooted(b)
	setupUdpPair(b)
	b.SetBytes(1 << 20)
	benchAwait(b, "udpUploadN(1)")
	b.ResetTimer()
	benchAwait(b, fmt.Sprintf("udpUploadN(%d)", b.N))
	b.StopTimer()
}

// TestUdpHeldBudgetShared: what the sockets hold for the loop is one budget across all of
// them (MAX_UDP_HELD_BYTES, passed at bind), not one per socket.
func TestUdpHeldBudgetShared(t *testing.T) {
	bootRealm(t)
	const budget = 3000
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	payload := make([]byte, 1000)
	for i := 0; i < 2; i++ {
		port, err := strconv.Atoi(evalString(t, fmt.Sprintf(`__udp.bind(() => {}, 65536, %d).port`, budget)))
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 4; j++ {
			client.WriteToUDP(payload, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		}
	}
	// No loop turn runs here, so nothing is delivered: what is held only grows, to the budget.
	entry := int64(5 + 4 + len(payload))
	deadline := time.Now().Add(2 * time.Second)
	for uh.held.Load() < 2*entry && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if held := uh.held.Load(); held != 2*entry {
		t.Fatalf("two sockets hold %d bytes under a shared budget of %d, want the %d bytes of the two datagrams that fit", held, budget, 2*entry)
	}
}
