// wsframe.go — the WebSocket wire codec primitive: the embedded ws.wasm (RFC 6455
// framing + handshake, the no-cap module built from assembly/ws/index.ts) driven
// over wazero and exposed to QuickJS as `__ws`. This is the Go twin of the
// node/browser WebAssembly backend (host/ws/ws-wasm-backend.ts): the SAME ws.wasm,
// so framing is byte-identical across targets — the whole point of the runtime
// split ("WebSocket framing is ws.wasm, not host code").
//
// The codec itself (the handshake state machine, masking, the residual receive
// buffer) is the shared host JS (net-frame.ts + ws-codec.ts, bundled as
// host-ws.gen.js) running in QuickJS over a raw Go byte stream (sock.go
// connectRaw/listenRaw). This file only does the byte transforms: it stages a
// request at ws.wasm's `scratch` offset, calls handle(), and copies the response
// out — the 4-op ABI ws-codec.ts drives (assembly/ws/index.ts).
//
// ws.wasm imports only env.abort and reserves a 16 MB scratch heap at start, so it
// is instantiated lazily (in its own wazero runtime) on first WS use — a pure
// node↔node TCP deployment never pays for it.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"sync"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed wasm/ws.wasm
var wsWasm []byte

// wsCodec is the instantiated ws.wasm: one shared scratch region means a request is
// a write/call/read sequence that must not interleave, so every call takes the lock
// (the framing runs on the loop goroutine, but the lock also makes the process-wide
// singleton safe for the per-test realms in `go test`).
type wsCodec struct {
	mod     api.Module
	mem     api.Memory
	handle  api.Function
	scratch uint32
	mu      sync.Mutex
}

var (
	wsc     *wsCodec  // lazily instantiated on first __ws.handle
	wscOnce sync.Once // serializes that init so parallel go-test realms can't race the global
)

// wsCodecInstance returns the process-wide ws.wasm codec, booting it once on first use.
func wsCodecInstance() *wsCodec {
	wscOnce.Do(func() { wsc = bootWsCodec() })
	return wsc
}

// bootWsCodec instantiates the embedded ws.wasm in a dedicated wazero runtime. It
// imports only env.abort (AS's 4-arg abort); the start runs heap.alloc(scratch).
func bootWsCodec() *wsCodec {
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) {}).Export("abort")
	if _, err := env.Instantiate(ctx); err != nil {
		panic(fmt.Sprintf("ws.wasm imports: %v", err))
	}
	cm, err := rt.CompileModule(ctx, wsWasm)
	if err != nil {
		panic(fmt.Sprintf("ws.wasm compile: %v", err))
	}
	mod, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName("ws"))
	if err != nil {
		panic(fmt.Sprintf("ws.wasm instantiate: %v", err))
	}
	g := mod.ExportedGlobal("scratch")
	h := mod.ExportedFunction("handle")
	if g == nil || h == nil {
		panic("ws.wasm: missing scratch/handle export")
	}
	return &wsCodec{mod: mod, mem: mod.Memory(), handle: h, scratch: uint32(g.Get())}
}

// call runs one op: stage req at scratch, handle(len), read the response (nil when
// the module reports an error / needs more — handle returns ≤ 0).
func (w *wsCodec) call(req []byte) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.mem.Write(w.scratch, req) {
		panic("ws.wasm: scratch write out of range")
	}
	r, err := w.handle.Call(ctx, uint64(len(req)))
	if err != nil {
		panic(fmt.Sprintf("ws.wasm handle: %v", err))
	}
	n := int32(uint32(r[0]))
	if n <= 0 {
		return nil
	}
	out, _ := w.mem.Read(w.scratch, uint32(n))
	return append([]byte(nil), out...)
}

// exposeWs installs `__ws.handle(Uint8Array) -> Uint8Array`, instantiating ws.wasm
// lazily on the first call.
func exposeWs(qc *qjs.Context) {
	o := qc.NewObject()
	o.SetPropertyStr("handle", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		req, err := qjs.JsTypedArrayToGo(t.Args()[0])
		if err != nil {
			return t.Context().NewArrayBuffer(nil), nil
		}
		return t.Context().NewArrayBuffer(wsCodecInstance().call(req)), nil
	}))
	qc.Global().SetPropertyStr("__ws", o)
}

// installWsCodec wires the WebSocket layer into a realm that already holds __net +
// sodium: the shared WS codec bundle (host-ws.gen.js: ws-codec + net-frame), the
// __ws primitive, and the glue (engineWsJS) that points the codec at __ws and
// exposes netConnectWS/netListenWS — WS RawChannels over a raw Go byte stream.
func installWsCodec(qc *qjs.Context) error {
	if _, err := qc.Eval("host-ws.gen.js", qjs.Code(hostWsJS)); err != nil {
		return fmt.Errorf("ws bundle: %w", err)
	}
	exposeWs(qc)
	if _, err := qc.Eval("engine-ws.js", qjs.Code(engineWsJS)); err != nil {
		return fmt.Errorf("ws glue: %w", err)
	}
	return nil
}

const engineWsJS = `
"use strict";
(function () {
  // Drive the canonical ws.wasm framing (host-ws bundle) through the Go __ws
  // primitive — the same 4-op ABI the node/bun WebAssembly backend uses, so the
  // RFC 6455 codec is byte-identical across targets.
  setWsHandle((req) => new Uint8Array(__ws.handle(req)));

  // WS RawChannels for the routing core (engineNetworkJS, sock.go): a WebSocket
  // over a raw Go byte stream (netConnectRaw/netListenRaw), framed in JS by the
  // shared net-frame classes. The browser uses its platform WebSocket; this is the
  // node-dialing-a-WS-endpoint / node-accepting-a-browser side.
  globalThis.netConnectWS = (host, port) => new WsClientChannel(netConnectRaw(host, port), host, port, sodium);
  globalThis.netListenWS = (host, port, onAccept) =>
    netListenRaw(host, port, (stream) => onAccept(new WsServerChannel(stream)));
})();
`
