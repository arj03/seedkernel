package main

import (
	"bytes"
	"testing"

	"github.com/tetratelabs/wazero"

	"seedloader/qjs"
)

// The shared cap-bridge.ts runs in the host realm over the Go
// primitives (sodium + fs), reused verbatim. Each op is exercised through the
// single `__capBridge(op, bytes)` funnel and checked against the underlying
// primitive, plus the cap-domain gate (an undeclared op is refused).

func capBridgeRealm(t *testing.T) (*qjs.Context, *eventLoop, func()) {
	t.Helper()
	wrt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd := bootSodium(wrt)
	rt, err := qjs.New()
	if err != nil {
		wrt.Close(ctx)
		t.Fatal(err)
	}
	qc := rt.Context()
	installPolyfills(qc)
	exposeSodium(qc, sd)
	if err := exposeFs(qc, t.TempDir()); err != nil {
		rt.Close()
		wrt.Close(ctx)
		t.Fatal("fs:", err)
	}
	el := newEventLoop(qc)
	exposeCapBridge(qc)
	return qc, el, func() { rt.Close(); wrt.Close(ctx) }
}

func TestCapBridgeOps(t *testing.T) {
	qc, _, done := capBridgeRealm(t)
	defer done()

	// Grant crypto + fs + clock (not net/module) and an identity from sodium.
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildCapBridge(["crypto", "fs", "clock"], __id, null, []);
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}

	call := func(op int, payload []byte) (*qjs.Value, error) {
		fn := qc.Global().GetPropertyStr("__callBridge")
		return qc.Invoke(fn, qc.NewUndefined(), qc.NewInt32(int32(op)), qc.NewArrayBuffer(payload))
	}
	callBytes := func(op int, payload []byte) []byte {
		t.Helper()
		v, err := call(op, payload)
		if err != nil {
			t.Fatalf("op %d: %v", op, err)
		}
		b, err := qjs.JsTypedArrayToGo(v)
		if err != nil {
			t.Fatalf("op %d result: %v", op, err)
		}
		return b
	}

	// The node pubkey, read once via .slice() (JsTypedArrayToGo neuters its arg, so a
	// copy keeps __id.publicKey intact for the bridge's own use).
	pk := jsBytes(t, qc, `__id.publicKey.slice()`)

	// CAP.HASH (1): 32-byte generic hash, must equal sodium.crypto_generichash.
	h := callBytes(1, []byte("hello seedkernel"))
	if len(h) != 32 {
		t.Fatalf("HASH len = %d, want 32", len(h))
	}
	want := jsBytes(t, qc, `sodium.crypto_generichash(32, new TextEncoder().encode("hello seedkernel"))`)
	if !bytes.Equal(h, want) {
		t.Fatalf("HASH = %x, want %x", h, want)
	}

	// CAP.IDENTITY (5): this node's public key.
	if id := callBytes(5, nil); !bytes.Equal(id, pk) {
		t.Fatalf("IDENTITY = %x, want node pubkey %x", id, pk)
	}

	// CAP.SIGN (3) + CAP.VERIFY (4): sign as this identity, verify with its pubkey.
	msg := []byte("a message to sign")
	sig := callBytes(3, msg)
	if len(sig) != 64 {
		t.Fatalf("SIGN len = %d, want 64", len(sig))
	}
	verifyArg := append(append(append([]byte{}, pk...), sig...), msg...) // [pk 32][sig 64][msg]
	if v := callBytes(4, verifyArg); len(v) != 1 || v[0] != 1 {
		t.Fatalf("VERIFY = %v, want [1]", v)
	}

	// CAP.FS_PUT (11) then CAP.FS_GET (10): content-addressed round trip.
	key := []byte("blk")
	value := []byte("a content-addressed block")
	put := make([]byte, 4+len(key)+len(value)) // [klen u32][key][bytes]
	putU32BE(put, 0, uint32(len(key)))
	copy(put[4:], key)
	copy(put[4+len(key):], value)
	callBytes(11, put)
	got := callBytes(10, key) // [1][bytes] on hit
	if len(got) == 0 || got[0] != 1 || !bytes.Equal(got[1:], value) {
		t.Fatalf("FS_GET = %v, want [1] ++ %q", got, value)
	}

	// CAP.CLOCK (17): 8-byte big-endian millis, nonzero.
	if clk := callBytes(17, nil); len(clk) != 8 || (clk[0]|clk[1]|clk[2]|clk[3]|clk[4]|clk[5]|clk[6]|clk[7]) == 0 {
		t.Fatalf("CLOCK = %v, want nonzero u64", clk)
	}

	// Gate: CAP.NET_SEND (7) is not in the declared caps → refused.
	if _, err := call(7, make([]byte, 33)); err == nil {
		t.Fatal("NET_SEND resolved despite not being a declared cap")
	}
}

// jsBytes evaluates a JS expression that yields a Uint8Array and returns its bytes.
func jsBytes(t *testing.T, qc *qjs.Context, expr string) []byte {
	t.Helper()
	v, err := qc.Eval("<jsBytes>", qjs.Code(expr))
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	b, err := qjs.JsTypedArrayToGo(v)
	if err != nil {
		t.Fatalf("bytes of %q: %v", expr, err)
	}
	return b
}
