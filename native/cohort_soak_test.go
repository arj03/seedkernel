package main

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

	"seedloader/qjs"
)

// TestCohortSoakNoLeak is the cohort-scale leak guard: the in-process twin of
// scripts/loader-interop.sh, but a `go test` that asserts steady-state memory instead
// of one-shot wire parity. A cohort of independent nodes — each its own wazero+qjs
// runtime, event loop, confined guest, fs dir, and goroutine, cross-connected over
// real loopback TCP — drives seedstore-style store/fetch traffic at every peer until a
// byte budget has moved, then asserts each node's wasm linear memory and callback
// registry returned to steady state. It is the full-stack aggregate of the targeted
// leak tests (qjs string/CString, net chan registry, await callback): anything that
// accumulates per request/response/serve over thousands of real round-trips forces a
// wasm heap grow or a callback-count climb, which this catches where a single-surface
// test would not.
//
// What it exercises: PeerLink handshake + framing (sock.go/net.go), Transport
// correlation/timeout (net-route bundle), the holder serve path (wireHolder →
// guest.serveHandle → fs), and the QuickJS marshal hot paths on both realms. The
// initiator side here is host JS (transport.request); the guest-*initiated* net path
// (awaitNetCall / __host_call blocking) is the one surface this does not drive — that
// is covered deterministically by net_leak_test + loop_leak_test.
//
// Why memory is "stable" despite moving ~GiB: blocks ride through wasm linear memory as
// transient buffers (the holder persists them to a disk fs, not memory). Storing over a
// small rotating keyset keeps the disk working set bounded too, so a flat steady state —
// not unbounded growth — is the correct outcome. Skipped under -short (it stands up a
// whole cohort and runs for tens of seconds).
func TestCohortSoakNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cohort soak in -short mode")
	}

	const (
		cohortSize   = 6
		valSize      = 128 << 10 // per-block payload pushed through the pipeline
		keyset       = 8         // rotating keys per node ⇒ bounded disk working set
		warmupCycles = 16        // warm allocator pools + establish every peer link
		memSlack     = 32 << 20  // per-realm wasm-heap headroom; a real per-op leak is >>this
	)
	// Total bytes to move across the cohort before sampling the steady state. Default is
	// enough to dwarf memSlack (a leak that fails to free one block per op would grow the
	// heap by the full budget); override with SEEDKERNEL_SOAK_MIB for a heavier soak
	// (e.g. 1024 for the ~1 GiB run).
	budget := int64(256) << 20
	if v := os.Getenv("SEEDKERNEL_SOAK_MIB"); v != "" {
		if mib, err := strconv.ParseInt(v, 10, 64); err == nil && mib > 0 {
			budget = mib << 20
		}
	}

	val := bytes.Repeat([]byte{0x5e}, valSize) // fixed payload; content variety is irrelevant to a leak

	nodes := make([]*soakNode, cohortSize)
	for i := range nodes {
		nodes[i] = buildSoakNode(t, t.TempDir(), val)
	}
	defer func() {
		for _, n := range nodes {
			n.close()
		}
	}()

	// Cross-connect: teach every node how to reach every other (request-on-demand dials
	// the link on first contact). The cap-bridge peers list is irrelevant here — the
	// holder guest only touches fs — so only the network address map needs the peers.
	for i, n := range nodes {
		for j, p := range nodes {
			if i == j {
				continue
			}
			if _, err := n.qc.Eval("<peer>", qjs.Code(fmt.Sprintf(`__addPeer(%q)`, p.addr))); err != nil {
				t.Fatalf("node %d addPeer %d: %v", i, j, err)
			}
		}
	}

	base := make([]soakSample, cohortSize)
	final := make([]soakSample, cohortSize)
	var moved int64           // bytes stored across the whole cohort (atomic)
	var firstErr atomic.Value // first per-node failure, if any

	var doneInitiating, serving sync.WaitGroup
	doneInitiating.Add(cohortSize)
	serving.Add(cohortSize)

	for i := range nodes {
		i := i
		go func() {
			defer serving.Done()
			n := nodes[i]
			peers := make([]string, 0, cohortSize-1)
			for j, p := range nodes {
				if j != i {
					peers = append(peers, p.pk)
				}
			}

			// req drives one transport op with retry: the network is best-effort (a frame
			// lost to dial glare or a not-yet-formed link is the Transport's to time out and
			// the app's to resend), so a transient rejection is retried on the now-stable
			// link before it counts as a failure. The await budget exceeds the Transport
			// timeout so a real miss rejects cleanly (not via the loop safety net). Store and
			// fetch are both idempotent here (overwrite / read), so a re-send is harmless.
			req := func(stage, expr string) ([]byte, bool) {
				const tries = 8
				var last error
				for a := 0; a < tries; a++ {
					kind, got, msg, err := n.el.await(expr, 6*time.Second)
					if err == nil && kind == 0 {
						return got, true
					}
					last = orMsg2(kind, err, msg)
				}
				firstErr.CompareAndSwap(nil, fmt.Errorf("node %d %s (after %d tries): %w", i, stage, tries, last))
				return nil, false
			}
			// One store+fetch round-trip to peer, over rotating key "soak<r%keyset>".
			cycle := func(r int) bool {
				peer := peers[r%len(peers)]
				key := fmt.Sprintf("soak%d", r%keyset)
				if _, ok := req("store", fmt.Sprintf(`__soakOp(%q,1,%q)`, peer, key)); !ok {
					return false
				}
				got, ok := req("fetch", fmt.Sprintf(`__soakOp(%q,2,%q)`, peer, key))
				if !ok {
					return false
				}
				if len(got) != 1+valSize || got[0] != 1 {
					firstErr.CompareAndSwap(nil, fmt.Errorf("node %d fetch bad response: %d bytes, flag %d", i, len(got), firstByte(got)))
					return false
				}
				atomic.AddInt64(&moved, valSize)
				return true
			}

			// Form the full mesh before driving traffic: every node dials every peer and
			// waits for the handshakes (glare resolved by the deterministic double-connect
			// rule), so the soak runs over stable links instead of paying a dial on each
			// first contact. Best-effort — a residual race is caught by req's retry.
			n.el.await(`__nodeReady()`, 15*time.Second)

			for r := 0; r < warmupCycles; r++ {
				if !cycle(r) {
					doneInitiating.Done()
					return
				}
			}
			// Steady-state baseline, sampled on this goroutine between awaits (the only safe
			// point to read live wasm state), after the pools are warm and every link is up.
			base[i] = n.sample()

			for r := warmupCycles; atomic.LoadInt64(&moved) < budget; r++ {
				if !cycle(r) {
					doneInitiating.Done()
					return
				}
			}
			doneInitiating.Done()

			// Keep serving the cohort until every node has finished initiating, so a peer's
			// late request never finds this node idle (and times out). The test goroutine
			// posts the stop once all are done.
			n.el.stopped = false
			n.el.run()
			final[i] = n.sample()
		}()
	}

	doneInitiating.Wait()
	for _, n := range nodes {
		n.el.post(func() { n.el.stopped = true })
	}
	serving.Wait()

	if err := firstErr.Load(); err != nil {
		t.Fatal(err.(error))
	}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	for i := range nodes {
		b, f := base[i], final[i]
		if grew := int64(f.memHost) - int64(b.memHost); grew > memSlack {
			t.Errorf("node %d host wasm heap grew %d bytes over the soak — leak in the serve/transport path?", i, grew)
		}
		if grew := int64(f.memGuest) - int64(b.memGuest); grew > memSlack {
			t.Errorf("node %d guest wasm heap grew %d bytes over the soak — leak in serveHandle/fs?", i, grew)
		}
		if f.cbHost != b.cbHost {
			t.Errorf("node %d host callback registry %d → %d — per-request callback leak?", i, b.cbHost, f.cbHost)
		}
		if f.cbGuest != b.cbGuest {
			t.Errorf("node %d guest callback registry %d → %d — per-serve callback leak?", i, b.cbGuest, f.cbGuest)
		}
		t.Logf("node %d: host mem %d→%d (+%d) cb %d  guest mem %d→%d (+%d) cb %d  timers %d byID %d",
			i, b.memHost, f.memHost, int64(f.memHost)-int64(b.memHost), f.cbHost,
			b.memGuest, f.memGuest, int64(f.memGuest)-int64(b.memGuest), f.cbGuest, f.timers, f.byID)
	}
	t.Logf("cohort soak: %d nodes moved %d MiB; Go HeapInuse=%d MiB after GC",
		cohortSize, atomic.LoadInt64(&moved)>>20, ms.HeapInuse>>20)
}

// soakNode is one fully-assembled cohort node: the production engine-host realm
// (installEngineHost), a confined holder guest, and its own loop — the same wiring
// main.go boots, minus the kernel/bundle path (which uses process-global singletons and
// adds nothing to the leak surface under test).
type soakNode struct {
	wrt  wazero.Runtime
	rt   *qjs.Runtime
	qc   *qjs.Context
	el   *eventLoop
	g    *guestRealm
	pk   string // node pubkey hex (the transport.request destination id)
	addr string // "<pk>@127.0.0.1:<port>" peer spec
}

// soakSample is the leak-relevant state of a node at one instant, read on the node's
// own goroutine. wasm memory only grows, so a flat host/guest size across the soak is
// the leak signal; the callback counts must be exactly flat.
type soakSample struct {
	memHost, memGuest uint32
	cbHost, cbGuest   int
	timers, byID      int
}

func (n *soakNode) sample() soakSample {
	return soakSample{
		memHost:  n.rt.MemorySize(),
		memGuest: n.g.rt.MemorySize(),
		cbHost:   n.rt.CallbackCount(),
		cbGuest:  n.g.rt.CallbackCount(),
		timers:   len(n.el.timers),
		byID:     len(n.el.byID),
	}
}

func (n *soakNode) close() {
	if n.g != nil {
		n.g.close()
	}
	if n.rt != nil {
		n.rt.Close()
	}
	if n.wrt != nil {
		n.wrt.Close(ctx)
	}
}

// buildSoakNode stands up one node listening on a loopback port: engine host + identity
// + bound network/transport + cap-bridge + a confined holder guest wired to serve the
// cohort. The holder answers store (type 1) / fetch (type 2) from local fs only — the
// seedstore holder shape (README §13.7), identical to serveAsHolder's guest.
func buildSoakNode(t *testing.T, dir string, val []byte) *soakNode {
	t.Helper()
	n := &soakNode{}
	n.wrt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd := bootSodium(n.wrt)

	rt, err := qjs.New()
	if err != nil {
		n.close()
		t.Fatal(err)
	}
	n.rt = rt
	n.qc = rt.Context()
	n.el = newEventLoop(n.qc)
	if err := installEngineHost(n.qc, n.el, sd, dir); err != nil {
		n.close()
		t.Fatal("host:", err)
	}

	skHex, err := n.qc.Eval("<mint>", qjs.Code(
		`(function(){ const kp = sodium.crypto_sign_keypair(); return Array.from(kp.privateKey, b => b.toString(16).padStart(2,"0")).join(""); })()`,
	))
	if err != nil {
		n.close()
		t.Fatal("mint:", err)
	}
	pkVal, err := n.qc.Eval("<identity>", qjs.Code(fmt.Sprintf(`__setIdentity(%q)`, skHex.String())))
	if err != nil {
		n.close()
		t.Fatal("identity:", err)
	}
	n.pk = pkVal.String()

	// Transport per-request timeout 3s: short enough that a frame lost to a dial-glare
	// resolution (two nodes dialing each other; the losing link drops its queued frames)
	// is retried promptly, and — being shorter than the await budget below — the Transport
	// rejects (clearing its pending entry + timer) before the loop's safety net fires, so a
	// retried request leaks no transport state.
	if _, _, _, err := n.el.await(`__startNode({ host: "127.0.0.1", port: 0 }, undefined, 3000)`, 8*time.Second); err != nil {
		n.close()
		t.Fatal("start:", err)
	}
	ports, err := qjs.JsTypedArrayToGo(mustEvalQc(n.qc, `__nodePorts()`))
	if err != nil {
		n.close()
		t.Fatal("ports:", err)
	}
	port := int(ports[0])<<8 | int(ports[1])
	n.addr = fmt.Sprintf("%s@127.0.0.1:%d", n.pk, port)

	if _, err := n.qc.Eval("<bridge>", qjs.Code(`__buildNodeBridge(["crypto","fs"])`)); err != nil {
		n.close()
		t.Fatal("cap-bridge:", err)
	}

	// The holder guest: store ([klen u32][key][bytes] already framed for FS_PUT) and
	// fetch (key → [0] | [1][bytes]) from local fs — no app-specific host code.
	const holderSource = `
		register("handle", (arg) => {
		  const type = arg[0];
		  const payload = arg.slice(1);
		  if (type === 1) { host.call(CAP_FS_PUT, payload); return new Uint8Array([1]); }
		  if (type === 2) { return host.call(CAP_FS_GET, payload); }
		  return new Uint8Array(0);
		});
	`
	g, err := newGuestRealm(n.el, "{}", holderSource)
	if err != nil {
		n.close()
		t.Fatal("guest:", err)
	}
	n.g = g
	wireHolder(n.qc, g)

	// The initiator helper: frame a store/fetch and send it to a peer over the node's
	// transport. The block bytes are a fixed buffer set once (__soakVal) so each store
	// reuses it — the per-op copies through the pipeline are what the soak exercises, not
	// fresh-data generation.
	n.qc.Global().SetPropertyStr("__soakVal", n.qc.NewArrayBuffer(val))
	if _, err := n.qc.Eval("<soak-op>", qjs.Code(`
		globalThis.__soakOp = async (peerHex, type, keyStr) => {
		  const key = new TextEncoder().encode(keyStr);
		  let payload;
		  if (type === 1) {
		    const v = new Uint8Array(__soakVal);
		    payload = new Uint8Array(4 + key.length + v.length);
		    new DataView(payload.buffer).setUint32(0, key.length);
		    payload.set(key, 4);
		    payload.set(v, 4 + key.length);
		  } else {
		    payload = key;
		  }
		  return await __transport.request(peerHex, type, payload);
		};
	`)); err != nil {
		n.close()
		t.Fatal("soak-op:", err)
	}
	return n
}

// mustEvalQc is mustEval against an explicit context (the package mustEval targets the
// global qc, which the soak cohort does not use).
func mustEvalQc(qc *qjs.Context, code string) *qjs.Value {
	v, err := qc.Eval("<eval>", qjs.Code(code))
	if err != nil {
		panic(fmt.Sprintf("eval %q: %v", code, err))
	}
	return v
}

// orMsg folds an await's error + a non-empty settle message into one error.
func orMsg(err error, msg string) error {
	if err != nil {
		return err
	}
	if msg != "" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// orMsg2 also treats a rejected settle (kind != 0) as a failure.
func orMsg2(kind int, err error, msg string) error {
	if e := orMsg(err, msg); e != nil {
		return e
	}
	if kind != 0 {
		return fmt.Errorf("rejected (kind %d)", kind)
	}
	return nil
}

func firstByte(b []byte) int {
	if len(b) == 0 {
		return -1
	}
	return int(b[0])
}
