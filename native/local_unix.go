//go:build unix

package main

import (
	"net"
	"syscall"
)

// listenPrivate binds a Unix domain socket that is owner-only from the moment it exists: a
// chmod after would leave a window, and a connection accepted in it would stay. The umask
// is process-wide, so anything created meanwhile is only more private.
func listenPrivate(path string) (net.Listener, error) {
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}

// checkLocalPath has nothing to check where every node makes a Unix socket.
func checkLocalPath(string, bool) error { return nil }
