//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// listenPrivate binds a Unix domain socket. Windows has no mode bits: the socket takes the
// ACL of the directory it is in, so that directory is what keeps it private.
func listenPrivate(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

// Node on Windows has no Unix sockets, so its control "socket" is a file naming a named
// pipe (host/platform-node.ts). That is a node this binary cannot reach, so it must never
// read as nobody serving there.
var nodePipe = regexp.MustCompile(`^\\\\\.\\pipe\\seedkernel-[0-9a-f]{32}$`)

// checkLocalPath refuses a path holding a Node node's pipe file: always when connecting,
// and when listening while that pipe still answers. A stale one is removed.
func checkLocalPath(path string, listening bool) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	b, err := os.ReadFile(path)
	name := strings.TrimSpace(string(b))
	if err != nil || !nodePipe.MatchString(name) {
		return fmt.Errorf("%s: not a control socket", path)
	}
	if !listening {
		return fmt.Errorf("%s: a Node node's control pipe, which only a Node client reaches on Windows", path)
	}
	if f, err := os.OpenFile(name, os.O_RDWR, 0); err == nil {
		f.Close()
		return fmt.Errorf("%s: a Node node already listens there", path)
	}
	return os.Remove(path)
}
