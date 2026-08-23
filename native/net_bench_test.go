package main

// Networking round-trip perf for the Go loader: the transport bundle's request/response
// over a real loopback socket — dial/accept, the AKE + record layer (amortized: the warmup
// request establishes the link), routing, the TCP framing (net.go), the Go↔JS
// frame-delivery boundary (sock.go), and the correlation/timeout layer. This is the
// wall-clock wrapping the crypto/RS arithmetic the other benches cover.
//
//   - BenchmarkNetRoundTrip — a tiny control-plane request (HAVE/OFFER-shaped); ns/op is
//     the per-request latency, 1e9/ns ≈ serial req/s.
//   - BenchmarkNetFetch64K — a FETCH-shaped op: small request, ~64 KB response (§27, the
//     GET bulk read), so bytes/op surfaces the framing + boundary-copy cost on a real
//     block rather than just the round-trip floor.
//
// b.N requests run as one JS-side await loop (benchPingN/benchFetchN) so the per-op
// el.await harness cost isn't folded into every iteration — only the socket round-trips
// are timed. Built on the shared benchmark realm (bench_test.go).
//
//	go test -run x -bench BenchmarkNet -benchmem ./...

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"seedloader/qjs"
)

// benchProto is the protocol id the bench app claims, and the id B addresses A by. An
// ordinary id, deliberately: `_`-led ids are the runtime's reservation and no ordinary
// bundle may spell one (§12.10).
const benchProto = "netbench"

// netBenchGuestSource is the bench APP — both ends of it. There is no host-side request
// facade, so the thing being benchmarked has to be an app, which is the point: this is the
// path a deployment uses.
//
//	handle — one entrypoint, both ends. A remote peer's frame is keyed on the first
//	         payload byte: type 7 is FETCH-shaped (a fixed 64 KB block), type 9 is
//	         UPLOAD-shaped (a 1-byte ack folding in the length and last byte, so the
//	         bench can prove the payload arrived whole), and anything else echoes — the
//	         control-plane round trip. A local loopback (the host's zero caller id) carries
//	         this app's own op framing: `send` is the transport's send op behind the name
//	         this side writes, `echo` is the bare realm hop. The framing is content — the
//	         kernel never reads it.
const netBenchGuestSource = `
  function readOp(b) {
    const n = b.length > 0 ? b[0] : -1;
    let op = "";
    for (let i = 0; i < n; i++) op += String.fromCharCode(b[1 + i]);
    return { op, args: b.subarray(1 + n) };
  }
  function writeOp(op, args) {
    const out = new Uint8Array(1 + op.length + args.length);
    out[0] = op.length;
    for (let i = 0; i < op.length; i++) out[1 + i] = op.charCodeAt(i) & 255;
    out.set(args, 1 + op.length);
    return out;
  }
  const block64k = new Uint8Array(65536); block64k.fill(0x5a);
  function handle(arg) {
    const c = arg.subarray(0, 32);
    let fromHost = true;
    for (let i = 0; i < 32; i++) { if (c[i] !== 0) { fromHost = false; break; } }
    const p = arg.subarray(32);
    if (fromHost) {
      const { op, args } = readOp(p);
      if (op === "send") return host.call("_net", writeOp("send", args));
      return args;
    }
    if (p.length > 0 && p[0] === 7) return block64k;
    if (p.length > 0 && p[0] === 9) return new Uint8Array([(p.slice(1).length ^ p[p.length - 1]) & 255]);
    return p;
  }
`

// netBenchHarness wires two nodes in one realm: A listens and answers, B requests. Both
// load the SAME signed app — one guest serves both ends — so the bundle is built once,
// in Go, and handed in as hex. benchPingN/benchFetchN/benchUploadN issue n sequential
// requests over the one link, each as an `invoke` of the `send` op into B's app.
//
// The nodes are stood up by makeTransportNode — the factory bootNode uses — and the
// policy has to admit the artifact's own transport author (for `link`) and the bench
// app's author (for the app) before either node has a network at all: the shared bench
// realm boots deny-all (ensureBooted).
//
// The four %q holes, in order: the app bundle hex, the app key invoke addresses, the
// app author's hex id, and the protocol id B sends under.
const netBenchHarness = `
	globalThis.idA = sodium.crypto_sign_keypair();
	globalThis.idB = sodium.crypto_sign_keypair();
	globalThis.aId = toHex(idA.publicKey);
	globalThis.bId = toHex(idB.publicKey);
	globalThis.__appBlob = fromHex(%q);
	globalThis.__appKey = %q;
	setPolicy(JSON.stringify({ authors: [embeddedTransportAuthor, %q],
	                           grants: { link: [embeddedTransportAuthor] } }));
	globalThis.__netSetup = (async () => {
	  const a = await makeTransportNode({ identity: idA, listen: { host: "127.0.0.1", port: 0 }, timeoutMs: 2000 });
	  const b = await makeTransportNode({ identity: idB, timeoutMs: 2000 });
	  globalThis.netA = a.transport;
	  globalThis.netB = b.transport;
	  // A claims the protocol so inbound frames route to its guest; B holds the same app
	  // because the request goes out THROUGH it.
	  await a.shell.loadBundleBlob(__appBlob);
	  await b.shell.loadBundleBlob(__appBlob);

	  // The transport's 'send' op argument order (transport/src/core.js):
	  // [noReply u8][deadline u32][to blob][proto blob][payload blob].
	  const proto = new TextEncoder().encode(%q);
	  const to = fromHex(aId);
	  const sendArgs = (payload) => {
	    const out = new Uint8Array(1 + 4 + 4 + to.length + 4 + proto.length + 4 + payload.length);
	    let off = 0;
	    out[off++] = 0;
	    const u32 = (v) => { out[off] = v >>> 24; out[off + 1] = (v >>> 16) & 255; out[off + 2] = (v >>> 8) & 255; out[off + 3] = v & 255; off += 4; };
	    u32(0);                                  // deadline: the node's default
	    u32(to.length); out.set(to, off); off += to.length;
	    u32(proto.length); out.set(proto, off); off += proto.length;
	    u32(payload.length); out.set(payload, off);
	    return out;
	  };
	  // The lane's own op framing: the app's handle reads [opLen][op][args] after the
	  // shell's caller id - the shell never interprets it.
	  const opFrame = (name, args) => {
	    const out = new Uint8Array(1 + name.length + args.length);
	    out[0] = name.length;
	    for (let i = 0; i < name.length; i++) out[1 + i] = name.charCodeAt(i);
	    out.set(args, 1 + name.length);
	    return out;
	  };
	  // One request out of B, answered by A's app. The [ok u8][response] answer shape is
	  // the transport's; a 0 means unreachable, a deadline, or a refusal.
	  const req = async (args) => {
	    const r = await b.shell.invoke(opFrame("send", args), __appKey);
	    if (r[0] !== 1) throw new Error("net: request failed");
	    return r.slice(1);
	  };

	  const ping = sendArgs(new Uint8Array([10, 20, 30]));
	  const fid = sendArgs(new Uint8Array([7, ...new Array(31).fill(0)]));      // type=7 fetch id
	  const big = new Uint8Array(1 << 20); big.fill(0x5a);                      // 1 MiB upload payload (a STORE group)
	  const big9 = new Uint8Array(1 + big.length); big9[0] = 9; big9.set(big, 1); // type=9 upload
	  const upload = sendArgs(big9);
	  globalThis.benchPingN = async (n) => { for (let i = 0; i < n; i++) await req(ping); return new Uint8Array(0); };
	  globalThis.benchFetchN = async (n) => { let acc = 0; for (let i = 0; i < n; i++) { const r = await req(fid); acc ^= r[0]; } return new Uint8Array([acc & 255]); };
	  globalThis.benchUploadN = async (n) => { const want = ((1 << 20) ^ 0x5a) & 255; for (let i = 0; i < n; i++) { const r = await req(upload); if (r[0] !== want) throw new Error("upload ack " + r[0] + " != " + want); } return new Uint8Array(0); };
	  // The realm hop ALONE: one invocation of the app's guest, no socket in the path.
	  // Two of these sit inside every round trip above (the sender's app and the
	  // receiver's), so it is what says whether a round-trip number is the wire or the
	  // guest boundary.
	  const localArg = new Uint8Array(34);
	  globalThis.benchLocalN = async (n) => { for (let i = 0; i < n; i++) await b.shell.invoke(opFrame("echo", localArg), __appKey); return new Uint8Array(0); };
	  netB.addPeerAddr(aId, { host: "127.0.0.1", port: netA.port, transport: "tcp" });
	})();
`

// setupNetBench stands up the harness in the shared benchmark realm: A's listeners are
// bound inside __netSetup (makeTransportNode awaits start()), both nodes load the bench
// app, and B is pointed at A's bound port. The returned loop drives
// benchPingN/benchFetchN/benchUploadN.
func setupNetBench(b *testing.B) *eventLoop {
	ensureBooted(b)
	// Once per REALM, not once per call. The realm is shared across benchmarks
	// (ensureBooted) and the framework re-enters each benchmark to grow b.N, so a second
	// eval of the harness would redeclare its top-level consts and fail as a SyntaxError.
	// Asking the realm what it already holds keeps this correct however the benchmarks are
	// ordered or filtered — a Go-side "did I do this" flag would drift from the realm.
	v, err := qc.Eval("net-bench-installed.js", qjs.Code(`typeof benchPingN`))
	if err != nil {
		b.Fatal("harness probe:", err)
	}
	if v.String() != "function" {
		// The app is signed HERE, by the Go-side writer, for the same reason the tests'
		// probe app is: the realm holds no signing key and the loader deliberately cannot
		// sign (mldsa.go binds verify only, §12.4).
		author := testAuthor(b)
		blob := signedBundleBytes(b, author, benchProto, 1, netBenchGuestSource, []string{"_net"})
		src := fmt.Sprintf(netBenchHarness,
			hex.EncodeToString(blob),
			appKeyFor(author.id(), benchProto),
			hex.EncodeToString(author.id()),
			benchProto)
		if _, err := qc.Eval("net-bench-harness.js", qjs.Code(src)); err != nil {
			b.Fatal("harness:", err)
		}
		if kind, _, msg, err := el.await(`__netSetup`, 8*time.Second); err != nil || kind != 0 {
			b.Fatalf("__netSetup: kind=%d msg=%q err=%v", kind, msg, err)
		}
	}
	return el // already wired: listeners bound, app loaded, peer addressed
}

// benchAwait drives one JS request loop to completion and fails the bench if it rejects
// (so a number is only ever reported for round-trips that actually succeeded). The
// timeout scales with b.N as a safety net — it bounds a hang, not the real run.
func benchAwait(b *testing.B, el *eventLoop, expr string) {
	b.Helper()
	kind, _, msg, err := el.await(expr, time.Duration(b.N)*5*time.Millisecond+10*time.Second)
	if err != nil {
		b.Fatal(err)
	}
	if kind != 0 {
		b.Fatalf("%s rejected: %s", expr, msg)
	}
}

// BenchmarkGuestDispatch times ONE guest entrypoint invocation with no socket in the
// path — the Go↔QuickJS boundary, the per-realm FIFO queue (§12.3) and the guest's own
// `handle`, and nothing else. Every network round trip above crosses two of these (the
// sending app's realm on the way out, the receiving app's on the way in), so this is the
// floor a round-trip number is measured against: it says whether a regression is the
// wire, the record layer, or the guest boundary.
func BenchmarkGuestDispatch(b *testing.B) {
	el := setupNetBench(b)
	benchAwait(b, el, "benchLocalN(1)") // warmup: the realm is built lazily
	b.ResetTimer()
	benchAwait(b, el, fmt.Sprintf("benchLocalN(%d)", b.N))
	b.StopTimer()
}

func BenchmarkNetRoundTrip(b *testing.B) {
	el := setupNetBench(b)
	benchAwait(b, el, "benchPingN(1)") // warmup: dial + PeerLink handshake (amortized out)
	b.ResetTimer()
	benchAwait(b, el, fmt.Sprintf("benchPingN(%d)", b.N))
	b.StopTimer()
}

func BenchmarkNetFetch64K(b *testing.B) {
	el := setupNetBench(b)
	b.SetBytes(blockBytes)
	benchAwait(b, el, "benchFetchN(1)") // warmup
	b.ResetTimer()
	benchAwait(b, el, fmt.Sprintf("benchFetchN(%d)", b.N))
	b.StopTimer()
}

// BenchmarkNetUpload1M is the twin of BenchmarkNetFetch64K for the OPPOSITE direction:
// B sends a 1 MiB payload to A and A returns a 1-byte ack, so bytes/op surfaces the
// cost of A's RECEIVE path (socket read → frame reassembly → Go↔JS boundary → request
// dispatch) — the path a PUT hits at the holder, which no other bench exercises (Fetch
// has A *send* the bulk and *receive* a tiny request).
func BenchmarkNetUpload1M(b *testing.B) {
	el := setupNetBench(b)
	b.SetBytes(1 << 20)
	benchAwait(b, el, "benchUploadN(1)") // warmup
	b.ResetTimer()
	benchAwait(b, el, fmt.Sprintf("benchUploadN(%d)", b.N))
	b.StopTimer()
}
