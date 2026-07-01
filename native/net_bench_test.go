package main

// Networking round-trip perf for the Go loader — the net twin of BenchmarkKernelDispatch.
// Where that bench times the kernel pipeline, this one times the full Transport
// request/response over a real loopback socket: dial/accept, the PeerLink handshake
// (amortized — the warmup request establishes the link, steady-state requests reuse it),
// routing, the [len][bytes] TCP framing (net.go), the Go↔JS frame-delivery boundary
// (sock.go: reader goroutine → el.post → __netDeliver → pump), and the correlation /
// timeout layer (net.ts) — none of which is Go logic, all driven by one loop. This is
// the wall-clock that wraps the crypto/RS arithmetic the other benches already cover.
//
//   - BenchmarkNetRoundTrip — a tiny control-plane request (HAVE/OFFER-shaped); ns/op is
//     the per-request latency, 1e9/ns ≈ serial req/s.
//   - BenchmarkNetFetch64K — a FETCH-shaped op: small request, ~64 KB response (§27, the
//     GET bulk read), so bytes/op surfaces the framing + boundary-copy cost on a real
//     block rather than just the round-trip floor.
//
// b.N requests run as one JS-side await loop (benchPingN/benchFetchN) so the per-op
// el.await harness cost isn't folded into every iteration — only the socket round-trips
// are timed. Built on transport_test.go's netRouteNode harness.
//
//	go test -run x -bench BenchmarkNet -benchmem ./...

import (
	"fmt"
	"testing"
	"time"

	"seedloader/qjs"
)

// netBenchHarness wires two nodes in one realm: A listens and answers (type 7 → a fixed
// 64 KB block for the FETCH bench; anything else → an echo of [type, ...payload]), B is
// the requester. benchPingN/benchFetchN issue n sequential requests over the one link.
const netBenchHarness = `
	globalThis.idA = sodium.crypto_sign_keypair();
	globalThis.idB = sodium.crypto_sign_keypair();
	globalThis.aId = toHex(idA.publicKey);
	globalThis.bId = toHex(idB.publicKey);
	globalThis.netA = makeNetwork(idA, { host: "127.0.0.1", port: 0 }, undefined);
	globalThis.netB = makeNetwork(idB, undefined, undefined);
	globalThis.tA = new Transport(aId, netA, 2000);
	globalThis.tB = new Transport(bId, netB, 2000);

	const block64k = new Uint8Array(65536); block64k.fill(0x5a);
	tA.onRequest((from, type, payload) => {
	  if (type === 7) return block64k;                       // FETCH-shaped: bulk response
	  if (type === 9) return new Uint8Array([(payload.length ^ payload[payload.length - 1]) & 255]); // UPLOAD-shaped: 1-byte ack folding in length + last byte, so a short/torn receive changes it
	  const out = new Uint8Array(payload.length + 1);        // control-plane: echo [type, ...payload]
	  out[0] = type; out.set(payload, 1);
	  return out;
	});

	globalThis.__ping = new Uint8Array([10, 20, 30]);
	globalThis.__fid = new Uint8Array(32);
	globalThis.__big = new Uint8Array(1 << 20); __big.fill(0x5a); // 1 MiB upload payload (a STORE group)
	globalThis.benchPingN = async (n) => { for (let i = 0; i < n; i++) await tB.request(aId, 5, __ping); return new Uint8Array(0); };
	globalThis.benchFetchN = async (n) => { let acc = 0; for (let i = 0; i < n; i++) { const r = await tB.request(aId, 7, __fid); acc ^= r[0]; } return new Uint8Array([acc & 255]); };
	globalThis.benchUploadN = async (n) => { const want = ((1 << 20) ^ 0x5a) & 255; for (let i = 0; i < n; i++) { const r = await tB.request(aId, 9, __big); if (r[0] !== want) throw new Error("upload ack " + r[0] + " != " + want); } return new Uint8Array(0); };
`

// setupNetBench stands up the harness, binds A's listener, and points B at it. The
// returned loop drives benchPingN/benchFetchN; done() tears both runtimes down.
func setupNetBench(b *testing.B) (*eventLoop, func()) {
	el, qc, done := netRouteNode(b)
	if _, err := qc.Eval("net-bench-harness.js", qjs.Code(netBenchHarness)); err != nil {
		done()
		b.Fatal("harness:", err)
	}
	if kind, _, msg, err := el.await(`(async () => { await netA.start(); return new Uint8Array(0); })()`, 8*time.Second); err != nil || kind != 0 {
		done()
		b.Fatalf("netA.start: kind=%d msg=%q err=%v", kind, msg, err)
	}
	if _, err := qc.Eval("net-bench-peer.js", qjs.Code(`netB.addPeerAddr(aId, { host: "127.0.0.1", port: netA.port, transport: "tcp" });`)); err != nil {
		done()
		b.Fatal("addPeerAddr:", err)
	}
	return el, done
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

func BenchmarkNetRoundTrip(b *testing.B) {
	el, done := setupNetBench(b)
	defer done()
	benchAwait(b, el, "benchPingN(1)") // warmup: dial + PeerLink handshake (amortized out)
	b.ResetTimer()
	benchAwait(b, el, fmt.Sprintf("benchPingN(%d)", b.N))
	b.StopTimer()
}

func BenchmarkNetFetch64K(b *testing.B) {
	el, done := setupNetBench(b)
	defer done()
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
	el, done := setupNetBench(b)
	defer done()
	b.SetBytes(1 << 20)
	benchAwait(b, el, "benchUploadN(1)") // warmup
	b.ResetTimer()
	benchAwait(b, el, fmt.Sprintf("benchUploadN(%d)", b.N))
	b.StopTimer()
}
