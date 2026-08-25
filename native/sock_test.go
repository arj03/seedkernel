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
	c.close(false)
}

// TestSockChannelCloseFlushesQueuedSends pins the deliberate-close contract: queued
// sends drain to the peer before the socket closes, and close() never fires onClose.
func TestSockChannelCloseFlushesQueuedSends(t *testing.T) {
	c1, c2 := net.Pipe()
	var onClosed atomic.Int32
	c := newInboundChannel(c1, func([]byte) {}, func() { onClosed.Add(1) })
	c.send([]byte("first"))
	c.send([]byte("second"))
	c.close(true)

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

// TestSockChannelNonGracefulCloseDropsQueuedSends is the other close mode: bytes still
// blocked in the writer are discarded and the socket closes immediately.
func TestSockChannelNonGracefulCloseDropsQueuedSends(t *testing.T) {
	c1, c2 := net.Pipe()
	var onClosed atomic.Int32
	c := newInboundChannel(c1, func([]byte) {}, func() { onClosed.Add(1) })
	c.send([]byte("must-not-flush"))
	c.close(false)

	c2.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	n, err := c2.Read(buf)
	if n != 0 || (err != io.EOF && err != io.ErrClosedPipe) {
		t.Fatalf("non-graceful close delivered %q, err=%v; want no bytes and EOF", buf[:n], err)
	}
	if onClosed.Load() != 0 {
		t.Fatal("a deliberate non-graceful close must not fire onClose")
	}
}

// TestSockChannelBufferedReportsQueue pins the fact the native RawLink exposes to the
// transport's stall clock. No writer is started, so every byte remains deterministically
// queued until a non-graceful close drops it.
func TestSockChannelBufferedReportsQueue(t *testing.T) {
	c := &sockChannel{wake: make(chan struct{}, 1)}
	c.send([]byte("first"))
	c.send([]byte("second"))
	if got := c.buffered(); got != len("firstsecond") {
		t.Fatalf("buffered = %d, want %d queued bytes", got, len("firstsecond"))
	}
	c.close(false)
	if got := c.buffered(); got != 0 {
		t.Fatalf("buffered after non-graceful close = %d, want 0", got)
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

// TestSockChannelCloseWhileDialing pins the pre-connect non-graceful close: whichever
// side wins the race, queued sends are dropped, a deliberate close never fires onClose,
// and the connection the dial produced always ends up closed.
func TestSockChannelCloseWhileDialing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var onClosed atomic.Int32
	c := newDialChannel(ln.Addr().String(), func([]byte) {}, func() { onClosed.Add(1) })
	c.send([]byte("queued")) // buffers pre-connect; the non-graceful close drops it
	c.close(false)

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

// TestSockChannelSilentPeerTimesOut pins the pre-auth bound (silentReadTimeout): a
// connection that opens and never sends a byte is failed and reclaimed on its own,
// without the transport guest ever having to notice it — the slowloris shape, which
// costs the attacker a SYN and costs this side two goroutines and a 64 KiB buffer.
func TestSockChannelSilentPeerTimesOut(t *testing.T) {
	defer func(d time.Duration) { silentReadTimeout = d }(silentReadTimeout)
	silentReadTimeout = 50 * time.Millisecond

	c1, c2 := net.Pipe()
	defer c2.Close()
	onClosed := make(chan struct{}, 1)
	c := newInboundChannel(c1, func([]byte) {}, func() { onClosed <- struct{}{} })
	go c.readLoop()
	waitOn(t, onClosed, "a connection that never spoke must be reclaimed")
}

// TestSockChannelSpokenForSurvives is the other half of the same rule: the deadline is
// cleared by the FIRST byte, so a link that has spoken is never killed for going quiet
// afterwards. How long an established link may idle is the transport's policy (its own
// idle clock), and a blind second clock here would cut established links behind it.
func TestSockChannelSpokenForSurvives(t *testing.T) {
	defer func(d time.Duration) { silentReadTimeout = d }(silentReadTimeout)
	silentReadTimeout = 50 * time.Millisecond

	c1, c2 := net.Pipe()
	defer c2.Close()
	in := make(chan struct{}, 1)
	onClosed := make(chan struct{}, 1)
	c := newInboundChannel(c1, func([]byte) { in <- struct{}{} }, func() { onClosed <- struct{}{} })
	go c.readLoop()

	if _, err := c2.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	waitOn(t, in, "the first frame must be delivered")
	time.Sleep(5 * silentReadTimeout) // long past the deadline the first read cleared
	select {
	case <-onClosed:
		t.Fatal("a link that had spoken was killed for idling")
	default:
	}
	c.close(false)
}

// TestNetHostAcceptCeiling pins the accept bound (maxLiveChannels): past the ceiling an
// inbound socket is closed on the spot, without an id, a channel or a goroutine — and
// the listener keeps serving, so the node recovers as live channels drain rather than
// going deaf.
func TestNetHostAcceptCeiling(t *testing.T) {
	defer func(m int) { maxLiveChannels = m }(maxLiveChannels)
	maxLiveChannels = 2

	n := &netHost{chans: map[int64]rawChannel{}}
	for i := 0; i < maxLiveChannels; i++ {
		id, ok := n.allocInbound()
		if !ok {
			t.Fatalf("connection %d refused under the ceiling", i)
		}
		n.chans[id] = nil // a live channel, as the accept loop registers it
	}
	if _, ok := n.allocInbound(); ok {
		t.Fatal("a connection over the ceiling was admitted")
	}
	// One drains (a peer hung up, a link closed): the next connection is admitted again.
	for id := range n.chans {
		delete(n.chans, id)
		break
	}
	if _, ok := n.allocInbound(); !ok {
		t.Fatal("the ceiling did not release as channels drained")
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
		go func() { defer wg.Done(); c.close(false) }()
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
