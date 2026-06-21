package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"seedloader/qjs"
)

// TestDeliberateCloseNoChanLeak guards the deliberate-close registry-drop. A
// channel's n.chans entry (and the JS shim's chans Map entry) was dropped only from
// onClose, which fires only from fail() — but a deliberate close() sets dead WITHOUT
// firing onClose (the owner asked for it), and the readLoop error chasing it
// short-circuits in fail() on dead. So before the fix every locally-initiated close
// leaked its slot: a peer that connects and is dropped in a loop (net-link.ts closes
// on each rejected handshake) grows the map without bound — an attacker-triggerable
// memory exhaustion. After the fix the close handler drops the entry itself, so the
// registry returns to empty.
//
// Pre-fix the count stays at `count` after closing; post-fix it is 0.
func TestDeliberateCloseNoChanLeak(t *testing.T) {
	rt, err := qjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	qc := rt.Context()
	el := newEventLoop(qc)
	n := exposeNet(qc, el) // installs __net + the netConnect/netListen shim globals

	// A bare TCP listener that accepts and HOLDS every connection (never closes it):
	// the only teardown is then the deliberate close() under test, not a remote EOF —
	// an EOF would route through fail()→onClose and drop the entry anyway, hiding the
	// leak. Each accept is handed back so the test can wait for live links before
	// closing, exercising the connected-then-closed path the leak hides behind.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	accepted := make(chan net.Conn, 256)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	const count = 50
	connect := fmt.Sprintf(`(async () => {
	  globalThis.__chs = [];
	  for (let i = 0; i < %d; i++) __chs.push(netConnect("127.0.0.1", %d));
	  return new Uint8Array(0);
	})()`, count, port)
	if kind, _, msg, err := el.await(connect, 5*time.Second); err != nil || kind != 0 {
		t.Fatalf("connect: kind=%d msg=%q err=%v", kind, msg, err)
	}
	if got := chanCount(n); got != count {
		t.Fatalf("after connecting %d channels the registry holds %d, want %d", count, got, count)
	}

	// Wait until all dials are live (accepted) so each close races a real readLoop —
	// the precise scenario where fail() short-circuits on dead and never drops the entry.
	held := make([]net.Conn, 0, count)
	timeout := time.After(5 * time.Second)
	for len(held) < count {
		select {
		case c := <-accepted:
			held = append(held, c) // keep alive (and closeable) for the whole test
		case <-timeout:
			t.Fatalf("only %d/%d connections accepted within timeout", len(held), count)
		}
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	closeAll := `(async () => { for (const c of __chs) c.close(); __chs = []; return new Uint8Array(0); })()`
	if kind, _, msg, err := el.await(closeAll, 5*time.Second); err != nil || kind != 0 {
		t.Fatalf("close: kind=%d msg=%q err=%v", kind, msg, err)
	}
	if got := chanCount(n); got != 0 {
		t.Fatalf("after deliberately closing %d channels the registry still holds %d — n.chans leak on close()", count, got)
	}
	t.Logf("registry drained to 0 across %d connect/close cycles", count)
}

func chanCount(n *netHost) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.chans)
}
