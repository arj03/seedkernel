//go:build !linux && !windows

package main

import "net"

// Elsewhere every datagram is its own syscall (udp_linux.go, udp_windows.go).
func gsoCapable(*net.UDPConn) bool    { return false }
func enableGRO(*net.UDPConn) bool     { return false }
func gsoOOB(oob []byte, _ int) []byte { return oob }
func groSize([]byte) int              { return 0 }
func gsoRefused(error) bool           { return false }
