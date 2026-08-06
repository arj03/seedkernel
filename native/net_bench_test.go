package main

// Networking round-trip perf for the Go loader. Where the crypto and RS benches time
// individual primitives, this one times the transport bundle's
// request/response over a real loopback socket: dial/accept, the AKE + record layer
// (amortized — the warmup request establishes the link, steady-state requests reuse it),
// routing, the [len][bytes] TCP framing (net.go), the Go↔JS frame-delivery boundary
// (sock.go: reader goroutine → el.post → __netDeliver → pump), and the correlation /
// timeout layer (transport-host.ts + the transport guest) — none of which is Go logic,
// all driven by one loop. This is the wall-clock that wraps the crypto/RS arithmetic the
// other benches already cover.
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
	"fmt"
	"testing"
	"time"

	"seedloader/qjs"
)

// netBenchHarness wires two nodes in one realm: A listens and answers (type 7 → a fixed
// 64 KB block for the FETCH bench; anything else → an echo of payload), B is
// the requester. benchPingN/benchFetchN issue n sequential requests over the one link.
// The nodes are stood up by makeTransportNode — the factory bootNode uses — and the
// policy has to admit the artifact's own transport author before either has a network
// at all (the shared bench realm boots deny-all, ensureBooted).
const netBenchHarness = `
	globalThis.idA = sodium.crypto_sign_keypair();
	globalThis.idB = sodium.crypto_sign_keypair();
	globalThis.aId = toHex(idA.publicKey);
	globalThis.bId = toHex(idB.publicKey);
	setPolicy(JSON.stringify({ authors: [embeddedTransportAuthor],
	                           roles: { transport: [embeddedTransportAuthor] } }));
	globalThis.__netSetup = (async () => {
	  const a = await makeTransportNode({ identity: idA, listen: { host: "127.0.0.1", port: 0 }, timeoutMs: 2000 });
	  const b = await makeTransportNode({ identity: idB, timeoutMs: 2000 });
	  globalThis.netA = a.net;
	  globalThis.netB = b.net;

	  const block64k = new Uint8Array(65536); block64k.fill(0x5a);
	  netA.onRequest((from, proto, payload) => {
	    if (payload.length > 0 && payload[0] === 7) return block64k;     // FETCH-shaped: bulk response (type=7 in payload[0])
	    if (payload.length > 0 && payload[0] === 9) return new Uint8Array([(payload.slice(1).length ^ payload[payload.length - 1]) & 255]); // UPLOAD-shaped: 1-byte ack folding in length + last byte
	    return payload;                                                   // control-plane: echo
	  });

	  globalThis.__ping = new Uint8Array([10, 20, 30]);
	  globalThis.__fid = new Uint8Array([7, ...new Array(31).fill(0)]);      // type=7 fetch id (type byte inside payload)
	  globalThis.__big = new Uint8Array(1 << 20); __big.fill(0x5a);          // 1 MiB upload payload (a STORE group)
	  globalThis.__big9 = new Uint8Array(1 + __big.length); __big9[0] = 9; __big9.set(__big, 1); // type=9 upload (type byte inside payload)
	  globalThis.benchPingN = async (n) => { for (let i = 0; i < n; i++) await netB.request(aId, new TextEncoder().encode("_test"), __ping); return new Uint8Array(0); };
	  globalThis.benchFetchN = async (n) => { let acc = 0; for (let i = 0; i < n; i++) { const r = await netB.request(aId, new TextEncoder().encode("_test"), __fid); acc ^= r[0]; } return new Uint8Array([acc & 255]); };
	  globalThis.benchUploadN = async (n) => { const want = ((1 << 20) ^ 0x5a) & 255; for (let i = 0; i < n; i++) { const r = await netB.request(aId, new TextEncoder().encode("_test"), __big9); if (r[0] !== want) throw new Error("upload ack " + r[0] + " != " + want); } return new Uint8Array(0); };
	  netB.addPeerAddr(aId, { host: "127.0.0.1", port: netA.port, transport: "tcp" });
	})();
`

// setupNetBench stands up the harness in the shared benchmark realm: A's listeners are
// bound inside __netSetup (makeTransportNode awaits start()), and B is pointed at A's
// bound port. The returned loop drives benchPingN/benchFetchN/benchUploadN.
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
		if _, err := qc.Eval("net-bench-harness.js", qjs.Code(netBenchHarness)); err != nil {
			b.Fatal("harness:", err)
		}
		if kind, _, msg, err := el.await(`__netSetup`, 8*time.Second); err != nil || kind != 0 {
			b.Fatalf("__netSetup: kind=%d msg=%q err=%v", kind, msg, err)
		}
	}
	return el // already wired: listeners bound, peer addressed
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
