package main

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// Windows sends a run of equal datagrams to one address as one buffer, cut below the
// socket (UDP_SEND_MSG_SIZE, USO): a socket call a run, not a datagram. Its receive side
// (URO) coalesces nothing on loopback here, so reads stay one datagram each.
const (
	ipprotoUDP     = 17
	udpSendMsgSize = 2
)

// gsoCapable answers whether the stack takes UDP_SEND_MSG_SIZE on conn.
func gsoCapable(conn *net.UDPConn) bool {
	rc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	rc.Control(func(fd uintptr) {
		var v uint32
		n := int32(4)
		ok = syscall.Getsockopt(syscall.Handle(fd), ipprotoUDP, udpSendMsgSize, (*byte)(unsafe.Pointer(&v)), &n) == nil
	})
	return ok
}

func enableGRO(*net.UDPConn) bool { return false }

// gsoOOB is the control message sending a buffer as datagrams of size bytes, in oob: a
// WSACMSGHDR (SIZE_T length, level, type) and a DWORD.
func gsoOOB(oob []byte, size int) []byte {
	const head = int(unsafe.Sizeof(uintptr(0))) + 8
	oob = oob[:head+8]
	clear(oob)
	*(*uintptr)(unsafe.Pointer(&oob[0])) = uintptr(head + 4)
	*(*int32)(unsafe.Pointer(&oob[head-8])) = ipprotoUDP
	*(*int32)(unsafe.Pointer(&oob[head-4])) = udpSendMsgSize
	*(*uint32)(unsafe.Pointer(&oob[head])) = uint32(size)
	return oob
}

func groSize([]byte) int { return 0 }

// gsoRefused: the stack will not cut this buffer (WSAEINVAL, WSAEOPNOTSUPP); the socket
// sends one datagram a call from then on.
func gsoRefused(err error) bool {
	return errors.Is(err, syscall.Errno(10022)) || errors.Is(err, syscall.Errno(10045))
}
