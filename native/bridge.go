// bridge.go — shared helpers for installing Go-backed functions on the bridge objects
// (bridge, __net, __fs, __sodium).
package main

import "seedloader/qjs"

// argBytes reads the i-th bridge argument as bytes; a missing or non-bytes
// argument yields nil, which the handlers treat as absent.
func argBytes(t *qjs.This, i int) []byte {
	b, _ := qjs.JsTypedArrayToGo(t.Args()[i])
	return b
}

// bytesAB wraps b as a fresh ArrayBuffer in the caller's realm.
func bytesAB(t *qjs.This, b []byte) *qjs.Value { return t.Context().NewArrayBuffer(b) }
