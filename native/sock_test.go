package main

// sock_test.go — the direct tests for sockChannel (net.go/sock.go): the queue
// limit, the close-vs-fail split, and the dial lifecycle. Until these existed the
// channel was only exercised end-to-end through the transport tests, which can't
// reach the outbound queue ceilings, a deliberate close mid-flush, or the dial races.
//
// net.Pipe gives each test a real net.Conn with deadlines but no ports: a channel
// wraps one end and the test plays the peer on the other.

import (
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testCloseGrace = time.Second

func newTestInboundChannel(conn net.Conn, onMsg func([]byte), onClose func()) *sockChannel {
	return newInboundChannel(conn, func(b []byte) bool {
		onMsg(append([]byte(nil), b...))
		return true
	}, onClose, testCloseGrace)
}

func newTestDialChannel(addr string, onMsg func([]byte), onClose func()) *sockChannel {
	return newDialChannel(addr, func(b []byte) bool {
		onMsg(append([]byte(nil), b...))
		return true
	}, onClose, testCloseGrace)
}

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
	c := newTestInboundChannel(c1, func(b []byte) { in <- b }, func() {})
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

// TestSockChannelReadBackpressure pins the native half of the realm-queue bound: one
// delivered read pauses the socket until the JS driver has finished that realm turn and
// explicitly resumes it. The second write must remain in net.Pipe, not become another host
// event queued behind the first.
func TestSockChannelReadBackpressure(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	in := make(chan string, 2)
	c := newTestInboundChannel(c1, func(b []byte) { in <- string(b) }, func() {})
	go c.readLoop()

	if _, err := c2.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-in:
		if got != "first" {
			t.Fatalf("first read = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first read was never delivered")
	}

	secondWrite := make(chan error, 1)
	go func() { _, err := c2.Write([]byte("second")); secondWrite <- err }()
	select {
	case got := <-in:
		t.Fatalf("read %q arrived before resume", got)
	case <-time.After(100 * time.Millisecond):
	}

	c.resume()
	select {
	case got := <-in:
		if got != "second" {
			t.Fatalf("second read = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second read was never delivered after resume")
	}
	if err := <-secondWrite; err != nil {
		t.Fatal(err)
	}
	c.close(false)
}

// TestSockChannelCloseFlushesQueuedSends pins the deliberate-close contract: queued
// sends drain to the peer before the socket closes, and close() never fires onClose.
func TestSockChannelCloseFlushesQueuedSends(t *testing.T) {
	c1, c2 := net.Pipe()
	var onClosed atomic.Int32
	c := newTestInboundChannel(c1, func([]byte) {}, func() { onClosed.Add(1) })
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
	c := newTestInboundChannel(c1, func([]byte) {}, func() { onClosed.Add(1) })
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
// host's outbound custody owner. No writer is started, so every byte remains deterministically
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

// TestSockChannelBufferedIncludesBlockedWrite pins the handoff edge: popping a slice from
// the Go queue does not release its driver-visible bytes while conn.Write still retains it.
func TestSockChannelBufferedIncludesBlockedWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	c := newTestInboundChannel(c1, func([]byte) {}, func() {})
	payload := []byte("blocked")
	c.send(payload)

	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		popped := len(c.queue) == 0
		c.mu.Unlock()
		if popped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writer never popped the queued slice")
		}
		time.Sleep(time.Millisecond)
	}
	if got := c.buffered(); got != len(payload) {
		t.Fatalf("buffered during blocked Write = %d, want %d", got, len(payload))
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c2, buf); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for c.buffered() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("completed Write did not release buffered bytes")
		}
		time.Sleep(time.Millisecond)
	}
	c.close(false)
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
	c := newTestDialChannel(addr, func([]byte) {}, func() { onClosed <- struct{}{} })
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
	c := newTestDialChannel(ln.Addr().String(), func([]byte) {}, func() { onClosed.Add(1) })
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
	c := newTestInboundChannel(c1, func([]byte) {}, func() { onClosed <- struct{}{} })
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
	c := newTestInboundChannel(c1, func([]byte) {}, func() { onClosed <- struct{}{} })
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
	c := newTestInboundChannel(c1, func([]byte) { in <- struct{}{} }, func() { onClosed <- struct{}{} })
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
	n := &netHost{chans: map[int64]rawChannel{}, maxLiveChannels: 2}
	for i := 0; i < n.maxLiveChannels; i++ {
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

// TestNetHostInboundReadAllowance pins the native side of the driver-wide inbound meter:
// shared across links (not one allowance per sockChannel), admitted up to the exact byte
// and slice ceilings, and fully returned after delivery.
func TestNetHostInboundReadAllowance(t *testing.T) {
	n := &netHost{maxInboundReadBytes: 8, maxInboundReadSlices: 2}
	if !n.reserveInboundRead(5) || !n.reserveInboundRead(3) {
		t.Fatal("reads at the exact aggregate byte/slice ceilings must be admitted")
	}
	if n.reserveInboundRead(9) {
		t.Fatal("a read larger than the whole window must be refused, never waited on")
	}
	if got := n.inboundReadBytes; got != 8 {
		t.Fatalf("refusal changed staged bytes: got %d, want 8", got)
	}
	n.releaseInboundRead(5)
	n.releaseInboundRead(3)
	if n.inboundReadBytes != 0 || n.inboundReadSlices != 0 {
		t.Fatalf("native staging custody leaked: %d bytes, %d slices",
			n.inboundReadBytes, n.inboundReadSlices)
	}
}

// TestNetHostInboundReadWaitsForSpace is the backpressure half: a full window parks the
// reader goroutine — where stalling is free and the socket's receive window carries it to
// the peer — instead of failing an honest link well below MAX_RAW_LINKS.
func TestNetHostInboundReadWaitsForSpace(t *testing.T) {
	n := &netHost{maxInboundReadBytes: 4, maxInboundReadSlices: 1}
	if !n.reserveInboundRead(4) {
		t.Fatal("failed to occupy the test allowance")
	}
	admitted := make(chan struct{})
	go func() {
		n.reserveInboundRead(2)
		close(admitted)
	}()
	select {
	case <-admitted:
		t.Fatal("a read was admitted while the staging window was full")
	case <-time.After(50 * time.Millisecond):
	}
	n.releaseInboundRead(4)
	select {
	case <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("released staging capacity did not wake the waiting reader")
	}
	n.releaseInboundRead(2)
	if n.inboundReadBytes != 0 || n.inboundReadSlices != 0 {
		t.Fatalf("native staging custody leaked: %d bytes, %d slices",
			n.inboundReadBytes, n.inboundReadSlices)
	}
}

// TestNetHostOnMsgChargesBeforePost covers the exact pre-meter edge: the copy into the
// event-loop queue happens only after custody is charged. A nil QuickJS context is
// intentional — touching the delivery path would panic the test.
func TestNetHostOnMsgChargesBeforePost(t *testing.T) {
	el := &eventLoop{tasks: make(chan func(), 1)}
	n := &netHost{el: el, maxInboundReadBytes: 4, maxInboundReadSlices: 1}
	if n.onMsg(1)([]byte("toolong")) {
		t.Fatal("onMsg admitted a read larger than the whole staging window")
	}
	if len(el.tasks) != 0 || n.inboundReadSlices != 0 {
		t.Fatal("a refused read was charged or posted toward QuickJS")
	}
	if !n.onMsg(1)([]byte("ok")) {
		t.Fatal("onMsg refused a read the staging window had room for")
	}
	if n.inboundReadBytes != 2 || n.inboundReadSlices != 1 || len(el.tasks) != 1 {
		t.Fatalf("accepted read was not charged before post: %d bytes, %d slices, %d tasks",
			n.inboundReadBytes, n.inboundReadSlices, len(el.tasks))
	}
	// Do not execute the task against this test's intentionally nil QuickJS context.
	// Discard its retained closure and mirror the defer it would run after delivery.
	<-el.tasks
	n.releaseInboundRead(2)
}

// TestSockChannelReadAdmissionRefusalIsTerminal ensures a peer cannot keep retrying a read
// the staging meter can never admit: it closes the socket and reports the link down once.
func TestSockChannelReadAdmissionRefusalIsTerminal(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	closed := make(chan struct{}, 1)
	var attempts atomic.Int32
	c := newInboundChannel(c1, func([]byte) bool {
		attempts.Add(1)
		return false
	}, func() { closed <- struct{}{} }, testCloseGrace)
	go c.readLoop()

	if _, err := c2.Write([]byte("refused")); err != nil {
		t.Fatal(err)
	}
	waitOn(t, closed, "an over-budget native read must fail its link")
	if attempts.Load() != 1 {
		t.Fatalf("read admission attempted %d times, want exactly once", attempts.Load())
	}
}

// TestSockChannelCloseFailRace hammers the close/fail split from many goroutines:
// the dead flag must settle the channel once — at most one onClose, no panic, no
// hang — no matter how the races interleave.
func TestSockChannelCloseFailRace(t *testing.T) {
	c1, c2 := net.Pipe()
	var onClosed atomic.Int32
	c := newTestInboundChannel(c1, func([]byte) {}, func() { onClosed.Add(1) })
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

// A reader parked on a full staging window waits for custody the event loop hands back.
// Teardown means no loop, so close() must refuse it rather than leave the goroutine parked
// for the life of the process.
func TestNetHostCloseReleasesParkedReaders(t *testing.T) {
	n := &netHost{chans: map[int64]rawChannel{}, maxInboundReadBytes: 4, maxInboundReadSlices: 1}
	if !n.reserveInboundRead(4) {
		t.Fatal("failed to occupy the test allowance")
	}
	answered := make(chan bool, 1)
	go func() { answered <- n.reserveInboundRead(2) }()
	select {
	case <-answered:
		t.Fatal("a read was admitted while the staging window was full")
	case <-time.After(50 * time.Millisecond):
	}
	n.close()
	select {
	case admitted := <-answered:
		if admitted {
			t.Fatal("a read was admitted after teardown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close() left a reader parked on the staging window")
	}
	if n.reserveInboundRead(1) {
		t.Fatal("a fresh read was admitted after teardown")
	}
}

// boot() is idempotent — each one releases the previous one's engines. The network is not
// an engine but outlives one just as badly: a listener nothing closes keeps its fd and its
// accept goroutine, and the readers behind it post into a loop that no longer runs.
func TestShutdownClosesTheNetwork(t *testing.T) {
	before := runtime.NumGoroutine()
	const boots = 3
	for i := 0; i < boots; i++ {
		bootRealm(t)
		// Through __net itself, so the accept goroutine under test is the real one.
		evalString(t, `String(__net.listen("127.0.0.1", 0))`)
	}
	shutdown()
	// The accept goroutines end when Accept() returns ErrClosed, which is not synchronous
	// with the Close() that causes it.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("shutdown left %d goroutines running (%d before %d boots, %d after)",
			after-before, before, boots, after)
	}
}
