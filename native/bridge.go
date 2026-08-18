// bridge.go — shared helpers for installing Go-backed functions on the bridge objects
// (bridge, __net, __fs, __sodium).
package main

import "seedloader/qjs"

// bridgeFn wraps a Go handler as a QuickJS function for installation on a bridge
// object (qc is the realm the function belongs to).
func bridgeFn(qc *qjs.Context, g func(*qjs.This) (*qjs.Value, error)) *qjs.Value {
	return qc.Function(g)
}

// argBytes reads the i-th bridge argument as bytes; a missing or non-bytes
// argument yields nil, which the handlers treat as absent.
func argBytes(t *qjs.This, i int) []byte {
	b, _ := qjs.JsTypedArrayToGo(t.Args()[i])
	return b
}

// argString reads the i-th bridge argument as a string.
func argString(t *qjs.This, i int) string { return t.Args()[i].String() }

// bytesAB wraps b as a fresh ArrayBuffer in the caller's realm.
func bytesAB(t *qjs.This, b []byte) *qjs.Value { return t.Context().NewArrayBuffer(b) }
