// The socket primitive exposed to QuickJS as `__net`. Reader goroutines hand each read to
// el.post, and the loop delivers it through the deliver/closed/accept dispatchers
// host/platform.ts hands over at install.
package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"seedkernel/qjs"
)

// acceptErrBackoff paces the accept loop after a non-fatal error such as EMFILE.
const acceptErrBackoff = 20 * time.Millisecond

type netHost struct {
	el *eventLoop
	qc *qjs.Context

	mu        sync.Mutex
	chans     map[int64]*sockChannel
	nextID    int64
	listeners []net.Listener
	// Set by close, releasing readers parked on the staging allowance.
	closed bool

	// Installed by host/platform.ts before any socket opens.
	keepAlive            time.Duration
	closeGrace           time.Duration
	maxInboundReadBytes  int
	maxInboundReadSlices int
	fnDeliver            *qjs.Value
	fnClosed             *qjs.Value
	fnAccept             *qjs.Value

	// Staging custody: reads posted to the loop but not yet handed to TransportHost.
	inboundReadBytes  int
	inboundReadSlices int
	readSpace         *sync.Cond // signalled as staging custody is released
}

// newNetHost is a netHost with nothing installed yet.
func newNetHost(el *eventLoop, qc *qjs.Context) *netHost {
	n := &netHost{el: el, qc: qc, chans: map[int64]*sockChannel{}}
	n.readSpace = sync.NewCond(&n.mu)
	return n
}

// exposeNet installs `__net`, shaped into RawLinks by host/platform.ts.
func exposeNet(qc *qjs.Context, el *eventLoop) *netHost {
	n := newNetHost(el, qc)
	o := qc.NewObject()

	o.SetPropertyStr("install", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.keepAlive = time.Duration(args[0].Int64()) * time.Millisecond
		n.closeGrace = time.Duration(args[1].Int64()) * time.Millisecond
		n.maxInboundReadBytes = int(args[2].Int64())
		n.maxInboundReadSlices = int(args[3].Int64())
		n.fnDeliver = args[4].GetPropertyStr("deliver")
		n.fnClosed = args[4].GetPropertyStr("closed")
		n.fnAccept = args[4].GetPropertyStr("accept")
		return nil, nil
	}))

	o.SetPropertyStr("connect", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		addr := net.JoinHostPort(args[0].String(), strconv.Itoa(int(args[1].Int32())))
		return qc.NewInt64(n.dial(addr)), nil
	}))
	o.SetPropertyStr("listen", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		bound, err := n.listen(args[0].String(), int(args[1].Int32()))
		if err != nil {
			return nil, err
		}
		return qc.NewInt32(int32(bound)), nil
	}))
	// No answer: the driver has already charged these bytes (sockChannel.send).
	o.SetPropertyStr("send", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		if ch := n.get(args[0].Int64()); ch != nil {
			// A copy, not a View: the bytes outlive this turn in the send queue.
			if b, err := args[1].Bytes(); err == nil {
				ch.send(b)
			}
		}
		return nil, nil
	}))
	o.SetPropertyStr("buffered", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		if ch := n.get(args[0].Int64()); ch != nil {
			return qc.NewInt64(int64(ch.buffered())), nil
		}
		return qc.NewInt64(0), nil
	}))
	o.SetPropertyStr("resume", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		if ch := n.get(args[0].Int64()); ch != nil {
			ch.resume()
		}
		return nil, nil
	}))
	o.SetPropertyStr("closeListeners", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		n.closeListeners()
		return nil, nil
	}))
	o.SetPropertyStr("close", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// A deliberate close never fires onClose, so the entry is dropped here.
		if ch := n.take(args[0].Int64()); ch != nil {
			ch.close(len(args) >= 2 && args[1].Int32() != 0)
		}
		return nil, nil
	}))
	qc.Global().SetPropertyStr("__net", o)
	return n
}

func (n *netHost) get(id int64) *sockChannel {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.chans[id]
}

// take removes a channel from the table and answers it, or nil if it is gone.
func (n *netHost) take(id int64) *sockChannel {
	n.mu.Lock()
	defer n.mu.Unlock()
	ch := n.chans[id]
	delete(n.chans, id)
	return ch
}

// reserveInboundRead charges a read to the staging allowance (§16.1) before it is posted.
// A full window parks the reader, so backpressure reaches the peer through TCP; only a
// read that can never fit is refused.
func (n *netHost) reserveInboundRead(length int) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if length > n.maxInboundReadBytes {
		return false
	}
	for !n.closed && (n.inboundReadSlices >= n.maxInboundReadSlices ||
		length > n.maxInboundReadBytes-n.inboundReadBytes) {
		n.readSpace.Wait()
	}
	if n.closed {
		return false
	}
	n.inboundReadSlices++
	n.inboundReadBytes += length
	return true
}

func (n *netHost) releaseInboundRead(length int) {
	n.mu.Lock()
	n.inboundReadSlices--
	n.inboundReadBytes -= length
	n.readSpace.Broadcast()
	n.mu.Unlock()
}

// dial opens an outbound byte duplex that JS can send on before it connects.
func (n *netHost) dial(addr string) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextID++
	id := n.nextID
	n.chans[id] = newDialChannel(addr, n.keepAlive, n.onMsg(id), n.onClose(id), n.closeGrace)
	return id
}

// listen accepts inbound byte duplexes. Each reader starts only after `accept` has
// made the JS channel it delivers to.
func (n *netHost) listen(host string, port int) (int, error) {
	lc := net.ListenConfig{KeepAlive: n.keepAlive}
	ln, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	bound := ln.Addr().(*net.TCPAddr).Port
	n.mu.Lock()
	n.listeners = append(n.listeners, ln)
	n.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// Descriptor exhaustion or an early reset: pause and keep serving.
				time.Sleep(acceptErrBackoff)
				continue
			}
			// The IP alone: the transport's half-open budget groups by source IP.
			remoteAddr := conn.RemoteAddr().(*net.TCPAddr).IP.String()
			n.mu.Lock()
			n.nextID++
			id := n.nextID
			ch := newInboundChannel(conn, n.onMsg(id), n.onClose(id), n.closeGrace)
			n.chans[id] = ch
			n.mu.Unlock()
			n.el.post(func() {
				n.invoke(n.fnAccept, n.qc.NewInt32(int32(bound)), n.qc.NewInt64(id), n.qc.NewString(remoteAddr))
				go ch.readLoop()
			})
		}
	}()
	return bound, nil
}

// closeListeners closes every bound listener, ending its accept goroutine.
func (n *netHost) closeListeners() {
	n.mu.Lock()
	lns := n.listeners
	n.listeners = nil
	n.mu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
}

// close tears the network down with its realm: every listener and channel, hard, without
// firing onClose.
func (n *netHost) close() {
	n.closeListeners()
	n.mu.Lock()
	chans := n.chans
	n.chans = map[int64]*sockChannel{}
	n.mu.Unlock()
	// Kill channels before releasing parked readers, so a woken reader finds its own dead.
	for _, ch := range chans {
		ch.close(false)
	}
	n.mu.Lock()
	n.closed = true
	n.readSpace.Broadcast()
	n.mu.Unlock()
}

// onMsg/onClose run on a reader goroutine and hand the work to the loop goroutine.
func (n *netHost) onMsg(id int64) func([]byte) bool {
	return func(b []byte) bool {
		if !n.reserveInboundRead(len(b)) {
			return false
		}
		// b is the reader's buffer, borrowed: the spent read token keeps the next read
		// from overwriting it before the task copies it.
		n.el.post(func() {
			// Staging custody ends once `deliver` has handed off, however it returns.
			defer n.releaseInboundRead(len(b))
			n.invoke(n.fnDeliver, n.qc.NewInt64(id), n.qc.NewArrayBuffer(b))
		})
		return true
	}
}

func (n *netHost) onClose(id int64) func() {
	return func() {
		n.el.post(func() {
			// Dropped first, so a close from the JS handler is a no-op.
			n.take(id)
			n.invoke(n.fnClosed, n.qc.NewInt64(id))
		})
	}
}

// invoke calls a retained JS dispatcher and frees the arguments.
func (n *netHost) invoke(fn *qjs.Value, args ...*qjs.Value) {
	dispatch(n.qc, "netHost: dispatcher error", fn, args...)
}
