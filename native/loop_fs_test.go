package main

import (
	"testing"
	"time"

	"seedloader/qjs"
)

// A guest that chains fs ops must keep advancing with NOTHING else driving the loop —
// the holder's shape, and the one case the pump ordering cannot carry on its own. A guest
// continuation that issues `await host.call("fs/*")` parks, and its settlement is a
// HOST-realm microtask queued after el.c was already drained this round, so without the
// wake in __host_call the chain advances one fs call per externally-provoked round and
// then stops dead.
//
// A holder serving from local disk generates no I/O of its own, which is why it strands:
// while a peer keeps sending frames the loop is woken incidentally, so the stall only
// shows once the inbound burst ends. This test removes that traffic entirely — no net, no
// timers, just a chain of fs awaits.
func TestGuestRealmChainedFsCallsAdvanceWithNothingElseDrivingTheLoop(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildGuestSeam(["fs/put", "fs/get", "fs/size"], __id, null);
	`)); err != nil {
		t.Fatal("build seam:", err)
	}

	// Each iteration is PUT then GET then SIZE — three parked ops, so a 24-block run is
	// 72 chained host-realm settlements with no other source of loop activity.
	newTestRealm(t, "{}", `
		function keyBytes(i) {
			const s = "blk" + i + ".dat";
			const b = new Uint8Array(s.length);
			for (let j = 0; j < s.length; j++) b[j] = s.charCodeAt(j);
			return b;
		}
		async function handle(arg) {
			// The mock composes this guest's local "chain" op; the payload is one byte.
			const n = arg[33 + arg[32]];
			let seen = 0;
			for (let i = 0; i < n; i++) {
				const k = keyBytes(i);
				const body = new Uint8Array(4 + k.length + 16);
				// [klen u32 BE][key][bytes]
				body[0] = 0; body[1] = 0; body[2] = (k.length >>> 8) & 255; body[3] = k.length & 255;
				body.set(k, 4);
				await host.call("fs/put", body);
				const got = await host.call("fs/get", k);
				if (got[0] === 1) seen++;
				await host.call("fs/size", k);
			}
			return new Uint8Array([seen]);
		}
	`)

	const blocks = 24
	start := time.Now()
	out, err := realmCall("chain", []byte{blocks})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("chained fs calls failed after %s: %v", elapsed, err)
	}
	if len(out) != 1 || out[0] != blocks {
		t.Fatalf("chain read back %v blocks, want %d", out, blocks)
	}
	// The harness gives up at 30s. A stranded chain burns the whole budget; a driven one
	// is milliseconds. Anything past a second means rounds are not being scheduled.
	if elapsed > 5*time.Second {
		t.Fatalf("chained fs calls took %s — the loop is not scheduling a round per parked op", elapsed)
	}
}
