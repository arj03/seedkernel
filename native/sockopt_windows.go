//go:build windows

package main

import "syscall"

// controlSocketBuffers — Windows twin of the unix version. setsockopt takes a
// syscall.Handle here rather than an int fd; otherwise identical (best-effort).
func controlSocketBuffers(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, tcpSocketBuffer)
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, tcpSocketBuffer)
	})
}
