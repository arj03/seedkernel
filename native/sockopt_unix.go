//go:build !windows

package main

import "syscall"

// controlSocketBuffers sets SO_RCVBUF/SO_SNDBUF on a raw socket fd before it is
// bound (listener) or connected (dialer), so the TCP window scale is negotiated for
// the large buffer at the handshake. Best-effort: the kernel clamps the value to
// net.core.{r,w}mem_max and a failed setsockopt is ignored (never fatal to the link).
func controlSocketBuffers(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, tcpSocketBuffer)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, tcpSocketBuffer)
	})
}
