package main

// The UDP path on the native binary (§12.7): two nodes meet through a relay, the transport
// moves them to a UDP path over Go's datagram primitive (udp.go), and requests cross it.
// The relay is an in-realm fake speaking the relay wire over whole-message links, as the
// shared JS suite's fake-relay.mjs does; it checks no signatures, since only the move off
// it is under test. Its STUN address does not resolve, so the path is punched between this
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
	"testing"
	"time"
)

// udpPairHarness sets up nodes C and D in the realm, both behind the fake relay and with
// the UDP path in their sockets; D reaches C through the relay, and the setup returns once
// each reads the other as direct. udpPingN/udpFetchN/udpUploadN then send from D to C as
// net_bench_test.go's do from B to A, and udpCheck asks for a block and sends one, both
// intact and neither through the relay.
//
// The three %q holes, in order: the app bundle hex, the app author's hex id, and the
// protocol id D sends under.
const udpPairHarness = `
	globalThis.__udpRelay = (() => {
	  const T_CHALLENGE = 0, T_REGISTER = 1, T_CALL = 5, T_UNREACHABLE = 6;
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
	  const control = () => {
	    const c = { key: null };
	    c.end = link((b) => {
	      if (b[0] === T_REGISTER && !c.key) {
	        c.key = toHex(b.subarray(1, 33));
	        registered.set(c.key, c);
	        c.end.deliver(Uint8Array.of(T_REGISTER));
	      } else if (b[0] === T_CALL && b.length === 49 && c.key) {
	        const callee = registered.get(toHex(b.subarray(1, 33))), ticket = b.subarray(33);
	        if (!callee || callee === c) { c.end.deliver(cat(Uint8Array.of(T_UNREACHABLE), b.subarray(1))); return; }
	        pending.set(toHex(ticket), { ends: [] });
	        callee.end.deliver(cat(Uint8Array.of(T_CALL), fromHex(c.key), ticket));
	      } else {
	        c.end.kill();
	      }
	    });
	    c.end.gone = () => { if (c.key && registered.get(c.key) === c) registered.delete(c.key); };
	    c.end.deliver(cat(Uint8Array.of(T_CHALLENGE), sodium.randombytes_buf(32)));
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
	    const r = await n.shell.call("_net", opFrame("relay", blob(new TextEncoder().encode("ws://relay"))));
	    if (r[0] !== 1) throw new Error("udp: not registered on the relay");
	  }
	  await teachAddr(d.shell, cId, "relay+ws://relay");

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
	src := fmt.Sprintf(udpPairHarness, hex.EncodeToString(blob), hex.EncodeToString(author.id()), benchProto)
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

// A native socket is dual-stack: it hears IPv4 and IPv6 alike, and names each sender as
// the seam writes it, IPv4 dotted though the socket hears it IPv4-mapped, IPv6 as RFC 5952
// writes it.
func TestUdpDualStackNative(t *testing.T) {
	bootRealm(t)
	got := awaitOK(t, "dual-stack", `(async () => {
	  const a = await platformDatagrams.bind(), b = await platformDatagrams.bind();
	  const heard = [];
	  b.socket.onMessage((bytes, host, port) => heard.push(host + " " + (port === a.port) + " " + bytes[0]));
	  a.socket.send(Uint8Array.of(4), b.port, "127.0.0.1");
	  a.socket.send(Uint8Array.of(6), b.port, "::1");
	  const until = Date.now() + 5000;
	  while (heard.length < 2 && Date.now() < until) await new Promise((r) => setTimeout(r, 10));
	  a.socket.close();
	  b.socket.close();
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
