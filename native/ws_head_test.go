package main

import (
	"strconv"
	"testing"
	"time"

	"seedloader/qjs"
)

// ── what a stranger's upgrade head costs this realm ──────────────────────────
//
// An accepting WebSocket link buffers bytes until it sees `\r\n\r\n`, and
// `WsFramer.scanHead` is what looks for it as each slice arrives. The sender picks the
// slice size, so the same 16 KiB of head is one scan or sixteen thousand of them — and the
// difference is work this node does for a peer it has not authenticated, on the one realm
// every other link shares.

// wsHeadJS evaluates the signed transport bundle's own guest program in a function scope,
// under the config it ships with, and feeds one accepting WsFramer a head one byte under
// the ceiling with no terminator in it — the most it will hold for a peer that has not said
// who it is — in slices of `chunk` bytes. A head that never completes never reaches
// ws.wasm, so the framer's host has nothing to answer.
const wsHeadJS = `
"use strict";
{
  const blob = transportBundleBytes();
  const src = new TextDecoder().decode(unpackBundle(blob)["guest.js"]);
  const APP = verifyBundle(sodium, blob).manifest.guest.config;
  const LOCAL = { networkKey: "00".repeat(32), peers: [], admitPeers: [] };
  const host = { call: (name) => { throw new Error("ws head probe: the framer called " + name); } };
  const F = new Function("APP", "LOCAL", "host", src +
    "\nreturn { WsFramer, MAX_WS_HANDSHAKE };")(APP, LOCAL, host);
  globalThis.__wsHead = async (chunk) => {
    const head = new Uint8Array(F.MAX_WS_HANDSHAKE - 1).fill(0x41);
    const framer = new F.WsFramer(() => Promise.resolve(), false, "");
    for (let off = 0; off < head.length; off += chunk) {
      if (!(await framer.push(head.subarray(off, off + chunk), () => {}))) {
        throw new Error("the head was refused at byte " + off);
      }
    }
    return new Uint8Array(0);
  };
}
`

func wsHeadRealm(tb testing.TB) {
	tb.Helper()
	bootRealm(tb)
	if _, err := qc.Eval("ws-head.js", qjs.Code(wsHeadJS)); err != nil {
		tb.Fatal("transport guest scope:", err)
	}
}

// wsHead feeds the head in slices of chunk bytes.
func wsHead(tb testing.TB, chunk int) {
	tb.Helper()
	if _, err := callRealm("__wsHead", 120*time.Second, qc.NewInt64(int64(chunk))); err != nil {
		tb.Fatal(err)
	}
}

// wsHeadWhole is the head's ceiling (MAX_WS_HANDSHAKE), so one push carries all of it.
const wsHeadWhole = 16 * 1024

// wsHeadAmplificationBound is how much more a 16 KiB head may cost dribbled one byte at a
// time than delivered whole. A scan that restarts at the front costs n²/2 byte steps and
// measured ~6800× (25 s against 3.7 ms); a scan that resumes leaves only per-push overhead,
// which is linear in the number of pushes and measures ~40× for 16384 of them against one.
// The bound sits an order of magnitude above what a resumed scan costs and more than an
// order below what a restarted one does.
const wsHeadAmplificationBound = 500

// TestWsHandshakeHeadScansOnce asserts a RATIO — the same head, both ways, in the same
// realm on the same machine — so machine speed cancels out of both sides and what is left
// is the shape of the scan: the head is scanned once, however it arrives.
func TestWsHandshakeHeadScansOnce(t *testing.T) {
	wsHeadRealm(t)
	// Best of three. The realm is shared and this machine moves work between cores, so the
	// fastest run is the one least contaminated by that — and a floor is the right summary
	// when the assertion is an upper bound.
	feed := func(chunk int) time.Duration {
		best := time.Duration(0)
		for i := 0; i < 3; i++ {
			start := time.Now()
			wsHead(t, chunk)
			if d := time.Since(start); best == 0 || d < best {
				best = d
			}
		}
		return best
	}
	whole, dribbled := feed(wsHeadWhole), feed(1)
	if ratio := float64(dribbled) / float64(whole); ratio > wsHeadAmplificationBound {
		t.Fatalf("an upgrade head costs %v whole and %v one byte at a time — %.0f×, past the %d× a scan that resumes allows. The head-end scan is being restarted per slice, which is n²/2 byte steps of the one realm every link shares, bought by a stranger with one upgrade head.",
			whole, dribbled, ratio, wsHeadAmplificationBound)
	}
}

// BenchmarkWsHandshakeHead holds the head fixed and varies only the chunking, so the
// number it prints IS the amplification.
func BenchmarkWsHandshakeHead(b *testing.B) {
	wsHeadRealm(b)
	for _, chunk := range []int{wsHeadWhole, 1024, 64, 8, 1} {
		b.Run("chunk="+strconv.Itoa(chunk), func(b *testing.B) {
			for b.Loop() {
				wsHead(b, chunk)
			}
		})
	}
}
