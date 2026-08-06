package main

// sock_test.go — the direct tests for sockChannel (net.go/sock.go): the queue
// limit, the close-vs-fail split, and the dial lifecycle. Until these existed the
// channel was only exercised end-to-end through the transport tests, which can't
// reach a 4 MiB unacked queue, a deliberate close mid-flush, or the dial races.
//
// net.Pipe gives each test a real net.Conn with deadlines but no ports: a channel
// wraps one end and the test plays the peer on the other.

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitOn(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out: " + what)
	}
}

// TestSockChannelRoundTrip pushes bytes both ways over one pipe: peer → readLoop →
// onMsg, and send → writer → peer. It pins the raw-byte-duplex contract (no framing,
// ownership of delivered slices, queue-then-flush order).
func TestSockChannelRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	in := make(chan []byte, 1)
	c := newInboundChannel(c1, func(b []byte) { in <- b }, func() {})
	go c.readLoop()

	if _, err := c2.Write([]byte("inbound")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-in:
		if string(b) != "inbound" {
			t.Fatalf("inbound frame = %q, want %q", b, "inbound")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inbound frame was never delivered to onMsg")
	}

	c.send([]byte("outbound"))
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatal("outbound frame never reached the peer:", err)
	}
	if string(buf[:n]) != "outbound" {
		t.Fatalf("outbound frame = %q, want %q", buf[:n], "outbound")
	}
	c.close()
}

// TestSockChannelCloseFlushesQueuedSends pins the deliberate-close contract: queued
// sends drain to the peer before the socket closes, and close() never fires onClose.
func TestSockChannelCloseFlushesQueuedSends(t *testing.T) {
	c1, c2 := net.Pipe()
	var onClosed atomic.Int32
	c := newInboundChannel(c1, func([]byte) {}, func() { onClosed.Add(1) })
	c.send([]byte("first"))
	c.send([]byte("second"))
	c.close()

	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	buf := make([]byte, 64)
	for {
		n, err := c2.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF || err == io.ErrClosedPipe {
				break
			}
			t.Fatal("drain:", err)
		}
	}
	if string(got) != "firstsecond" {
		t.Fatalf("close() must flush queued sends, peer got %q", got)
	}
	if onClosed.Load() != 0 {
		t.Fatal("a deliberate close() must not fire onClose")
	}
}

// TestSockChannelSendQueueLimitFails trips the bounded-queue fail path: a send past
// sendQueueLimit fails the channel (onClose fires) instead of buffering without
// bound, and the channel stays dead — later sends are dropped and a second fail is
// silent.
func TestSockChannelSendQueueLimitFails(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	onClosed := make(chan struct{}, 1)
	c := newInboundChannel(c1, func([]byte) {}, func() {
		select {
		case onClosed <- struct{}{}:
		default:
		}
	})
	// One send past the cap trips the fail path before anything reaches the socket;
	// the writer is parked on wake and never sees the payload.
	c.send(make([]byte, sendQueueLimit+1))
	waitOn(t, onClosed, "a queue overflowing the send limit must fail the channel")
	c.send([]byte("after-fail")) // dead: dropped, not queued, no panic
	c.fail()                     // idempotent: the dead flag short-circuits it
	if len(onClosed) != 0 {
		t.Fatal("fail() fired onClose twice")
	}
}

// TestSockChannelDialFailureFiresOnClose covers the dial-error path: a background
// dial that cannot connect fails the channel, and onClose is how the owner learns.
func TestSockChannelDialFailureFiresOnClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // now nothing listens: the dial must fail

	onClosed := make(chan struct{}, 1)
	c := newDialChannel(addr, func([]byte) {}, func() { onClosed <- struct{}{} })
	waitOn(t, onClosed, "a failed dial must fire onClose")
	c.send([]byte("x")) // dead: dropped without a panic
}

// TestSockChannelCloseWhileDialing pins the pre-connect close: whichever side wins
// the race — close() before the dial lands (queued sends dropped, fresh conn closed
// unopened) or after (writer flushes then closes) — a deliberate close never fires
// onClose and the conn the dial produced always ends up closed.
func TestSockChannelCloseWhileDialing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var onClosed atomic.Int32
	c := newDialChannel(ln.Addr().String(), func([]byte) {}, func() { onClosed.Add(1) })
	c.send([]byte("queued")) // buffers pre-connect; flushed only if the dial lands first
	c.close()

	conn, err := ln.Accept() // the dial lands, sees dead, and closes the fresh conn
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, err := conn.Read(make([]byte, 16))
		if err == io.EOF || err == io.ErrClosedPipe {
			break
		}
		if err != nil {
			t.Fatal("the conn the channel dialed must end up closed after close():", err)
		}
	}
	if onClosed.Load() != 0 {
		t.Fatal("a deliberate close() while dialing must not fire onClose")
	}
}

// TestSockChannelPeerCloseFiresOnClose covers the error-teardown path: the read loop
// hitting an error on the socket fails the channel, and onClose fires exactly once.
func TestSockChannelPeerCloseFiresOnClose(t *testing.T) {
	c1, c2 := net.Pipe()
	onClosed := make(chan struct{}, 1)
	c := newInboundChannel(c1, func([]byte) {}, func() { onClosed <- struct{}{} })
	go c.readLoop()
	c2.Close() // the peer tears down
	waitOn(t, onClosed, "a peer close must fire onClose")
	c.fail() // idempotent
	if len(onClosed) != 0 {
		t.Fatal("fail() fired onClose twice")
	}
}

// TestSockChannelCloseFailRace hammers the close/fail split from many goroutines:
// the dead flag must settle the channel once — at most one onClose, no panic, no
// hang — no matter how the races interleave.
func TestSockChannelCloseFailRace(t *testing.T) {
	c1, c2 := net.Pipe()
	var onClosed atomic.Int32
	c := newInboundChannel(c1, func([]byte) {}, func() { onClosed.Add(1) })
	go c.readLoop()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); c.close() }()
		go func() { defer wg.Done(); c.fail() }()
	}
	wg.Wait()

	c2.Close() // a read-loop error lands after the race; it must not add an onClose
	for i := 0; i < 50 && onClosed.Load() < 1; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := onClosed.Load(); n > 1 {
		t.Fatalf("onClose fired %d times across close/fail races", n)
	}
	c.mu.Lock()
	dead := c.dead
	c.mu.Unlock()
	if !dead {
		t.Fatal("the channel must be dead after close/fail")
	}
}
