package qjs

import (
	"os"
	"testing"
)

// engine is the checked-in qjs.wasm, which the bridge's own tests run on; the binary runs
// the copy in its host blob.
func engine(t testing.TB) []byte {
	t.Helper()
	wasm, err := os.ReadFile("qjs.wasm")
	if err != nil {
		t.Fatal("qjs.wasm:", err)
	}
	return wasm
}
