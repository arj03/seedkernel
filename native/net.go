// The socket primitive exposed to QuickJS as `__net`. Reader goroutines hand each read to
// el.post, and the loop delivers it through the deliver/closed/accept dispatchers
// host/platform.ts hands over at install.
//
// A socket has at most one read on its way to the realm (sockChannel.readGate), held in
// the reader's own buffer until the loop copies it in, so what waits here is bounded by
// the sockets and costs nothing they do not already hold. The driver-wide inbound budget
// is the transport host's, as on Node.
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

	// Installed by host/platform.ts before any socket opens.
	keepAlive  time.Duration
	closeGrace time.Duration
	fnDeliver  *qjs.Value
	fnClosed   *qjs.Value
	fnAccept   *qjs.Value
}

// newNetHost is a netHost with nothing installed yet.
func newNetHost(el *eventLoop, qc *qjs.Context) *netHost {
	return &netHost{el: el, qc: qc, chans: map[int64]*sockChannel{}}
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
		n.fnDeliver = args[2].GetPropertyStr("deliver")
		n.fnClosed = args[2].GetPropertyStr("closed")
		n.fnAccept = args[2].GetPropertyStr("accept")
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
	for _, ch := range chans {
		ch.close(false)
	}
}

// onMsg/onClose run on a reader goroutine and hand the work to the loop goroutine.
func (n *netHost) onMsg(id int64) func([]byte) {
	return func(b []byte) {
		// b is the reader's buffer, borrowed: the spent read token keeps the next read
		// from overwriting it before the task copies it.
		n.el.post(func() {
			n.invoke(n.fnDeliver, n.qc.NewInt64(id), n.qc.NewArrayBuffer(b))
		})
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
