//go:build linux

package main

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// Linux sends a run of equal datagrams to one address as one buffer, cut into datagrams
// below the socket (UDP_SEGMENT, GSO), and hands a reader a run of one flow's datagrams as
// one buffer it cuts (UDP_GRO): a syscall and a pass through the stack a run, not a
// datagram.
const (
	solUDP     = 17
	udpSegment = 103
	udpGRO     = 104
)

func sockopt(conn *net.UDPConn, set bool, opt int) bool {
	rc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	rc.Control(func(fd uintptr) {
		if set {
			ok = syscall.SetsockoptInt(int(fd), solUDP, opt, 1) == nil
		} else {
			_, err := syscall.GetsockoptInt(int(fd), solUDP, opt)
			ok = err == nil
		}
	})
	return ok
}

// gsoCapable answers whether the kernel takes UDP_SEGMENT on conn.
func gsoCapable(conn *net.UDPConn) bool { return sockopt(conn, false, udpSegment) }

// enableGRO asks the kernel to coalesce what conn reads, answering whether it will.
func enableGRO(conn *net.UDPConn) bool { return sockopt(conn, true, udpGRO) }

// gsoOOB is the control message sending a buffer as datagrams of size bytes, in oob.
func gsoOOB(oob []byte, size int) []byte {
	oob = oob[:syscall.CmsgSpace(2)]
	clear(oob)
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level, h.Type = solUDP, udpSegment
	h.SetLen(syscall.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&oob[syscall.CmsgLen(0)])) = uint16(size)
	return oob
}

// groSize is the datagram size a coalesced read was cut from, or 0 when it is one datagram:
// UDP_GRO's message, the only control message a socket asks for.
func groSize(oob []byte) int {
	if len(oob) < syscall.CmsgLen(4) {
		return 0
	}
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
	if h.Level != solUDP || h.Type != udpGRO {
		return 0
	}
	return int(*(*int32)(unsafe.Pointer(&oob[syscall.CmsgLen(0)])))
}

// gsoRefused: the device cannot checksum segments (EIO), or the kernel will not cut this
// buffer (EINVAL); the socket sends one datagram a syscall from then on.
func gsoRefused(err error) bool {
	return errors.Is(err, syscall.EIO) || errors.Is(err, syscall.EINVAL)
}
