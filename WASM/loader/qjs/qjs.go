// Package qjs is a thin, in-repo bridge to the quickjs-ng engine running on
// wazero. It is the Go counterpart of sodium.go's raw-wasm-over-wazero pattern:
// the engine is the prebuilt qjs.wasm blob (quickjs-ng + a small C shim exposing
// a flat QJS_* C ABI), and this package drives it directly over wazero linear
// memory with a single host import (env.jsFunctionProxy) for JS→Go callbacks.
//
// It replaces github.com/fastschema/qjs, which pinned an old wazero and carried a
// reflection/generics marshaling layer we don't need (it was never a binary-size
// cost — the ~7.5 MiB stripped floor is wazero's compiler backend, not this). We
// only ever need a small, synchronous slice of the API (objects, strings,
// ArrayBuffers, function callbacks, eval, invoke), so this bridge mirrors exactly
// that surface — and the exact call/free sequences fastschema used against this same
// wasm — and nothing more. The qjs.wasm blob and its C sources are vendored under
// this directory; see README.md.
//
// JSValue ABI: the wasm is built with NaN-boxed JSValues, so every QJS_* function
// takes and returns a single i64 (uint64). A *Value is just a wrapper around that
// uint64 handle. "Packed pointer" returns (QJS_ToCString, QJS_GetArrayBuffer) are a
// pointer to an 8-byte cell holding (addr<<32 | size) in little-endian.
package qjs

import (
	"context"
	_ "embed"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	wasi "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed qjs.wasm
var wasmBytes []byte

const (
	// eval flags (quickjs JS_EVAL_*): global scope + strict mode, matching the
	// fastschema default used to eval the host shims.
	evalTypeGlobal = 0
	evalFlagStrict = 1 << 3
)

// goFunc is a Go function exposed to JS via (*Context).Function.
type goFunc = func(*This) (*Value, error)

// Runtime owns the wazero runtime, the instantiated qjs module and the QuickJS
// runtime/context handles. It is single-threaded: the loader drives the realm from
// one goroutine (the main thread), so no locking around engine calls is needed.
type Runtime struct {
	ctx    context.Context
	wrt    wazero.Runtime
	mod    api.Module
	malloc api.Function
	free   api.Function
	mem    api.Memory
	qjs    uint64 // QJSRuntime*
	ctxt   *Context
	reg    *registry
}

// registry maps callback ids to Go funcs for the env.jsFunctionProxy dispatcher.
type registry struct {
	mu   sync.RWMutex
	next uint64
	m    map[uint64]goFunc
}

func newRegistry() *registry { return &registry{m: map[uint64]goFunc{}} }

func (r *registry) register(fn goFunc) uint64 {
	id := atomic.AddUint64(&r.next, 1)
	r.mu.Lock()
	r.m[id] = fn
	r.mu.Unlock()
	return id
}

func (r *registry) get(id uint64) goFunc {
	r.mu.RLock()
	fn := r.m[id]
	r.mu.RUnlock()
	return fn
}

// CallbackCount returns the number of registered Go callbacks. The registry has no
// unregister (a function proxy lives for its context), so this is exposed for leak
// diagnostics: a count that climbs with work signals callbacks created per-call
// instead of reused (see the loader's persistent __settle / __signal).
func (r *Runtime) CallbackCount() int {
	r.reg.mu.RLock()
	defer r.reg.mu.RUnlock()
	return len(r.reg.m)
}

// New instantiates a fresh QuickJS runtime + context.
func New() (rt *Runtime, err error) {
	ctx := context.Background()
	rt = &Runtime{ctx: ctx, reg: newRegistry()}

	// On any failure — a panic or an error return — after the wazero runtime is
	// created but before the module is live, close it so a failed New leaks nothing
	// (the runtime holds this instance's compiled machine code).
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("qjs.New: %v", r)
		}
		if err != nil {
			if rt != nil && rt.wrt != nil {
				rt.wrt.Close(ctx)
			}
			rt = nil
		}
	}()
	// A shared compilation cache makes the per-runtime CompileModule cheap when
	// several runtimes are created (e.g. across tests); a CompiledModule is bound
	// to the runtime that compiled it, so each runtime must compile its own.
	rt.wrt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(sharedCache()))

	if _, err := wasi.Instantiate(ctx, rt.wrt); err != nil {
		return rt, fmt.Errorf("instantiate WASI: %w", err)
	}

	// The single host import the wasm needs: the JS→Go callback dispatcher. The C
	// trampoline packs argv as [fnID, ctxID, isAsync, promise, ...realArgs].
	if _, err := rt.wrt.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(rt.jsFunctionProxy).
		Export("jsFunctionProxy").
		Instantiate(ctx); err != nil {
		return rt, fmt.Errorf("host module: %w", err)
	}

	code, err := rt.wrt.CompileModule(ctx, wasmBytes)
	if err != nil {
		return rt, fmt.Errorf("compile qjs.wasm: %w", err)
	}

	rt.mod, err = rt.wrt.InstantiateModule(ctx, code, wazero.
		NewModuleConfig().
		WithStartFunctions(""). // qjs.wasm is a reactor; New_QJS does the init
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep())
	if err != nil {
		return rt, fmt.Errorf("instantiate module: %w", err)
	}

	rt.malloc = rt.mod.ExportedFunction("malloc")
	rt.free = rt.mod.ExportedFunction("free")
	rt.mem = rt.mod.Memory()
	// New_QJS(memoryLimit, maxStackSize, maxExecutionTime, gcThreshold); 0 = default.
	// maxStackSize is load-bearing: qjs.wasm has only a ~161 KiB shadow stack
	// (--stack-first), but QuickJS's default limit is 256 KiB — larger than the stack
	// that actually exists. With the default, the overflow guard never trips, so deep
	// JS recursion (QuickJS burns several KiB of C stack per frame) runs the shadow
	// stack off the end of linear memory and traps as an OOB *crash* instead of a
	// catchable "stack overflow". Capping below the real stack makes the guard fire
	// first (a throw), but the guard also needs the stack top calibrated to the wasm
	// SP — see QJS_UpdateStackTop below. Headroom left for the C frames between the
	// check and the deepest alloca.
	rt.qjs = rt.call("New_QJS", 0, maxStackSize, 0, 0)
	rt.ctxt = &Context{rt: rt, handle: rt.call("QJS_GetContext", rt.qjs)}
	// Calibrate QuickJS's stack_top to the actual wasm shadow-SP. JS_NewRuntime
	// captured it deep inside New_QJS; recording it here (a shallow Go→wasm entry, the
	// same depth every top-level QJS_Call/QJS_Eval re-enters at, since wazero restores
	// __stack_pointer between calls) makes stack_limit = stack_top - maxStackSize land
	// in the real stack region. Done ONCE — never per-call: a re-entrant Invoke (a host
	// callback that calls back into JS) must measure against this top, not reset to its
	// own deeper SP.
	rt.call("QJS_UpdateStackTop", rt.qjs)
	return rt, nil
}

// maxStackSize caps the QuickJS C stack below qjs.wasm's ~161 KiB shadow stack
// (__stack_pointer init = 165408, --stack-first) so an overflow throws instead of
// trapping as an OOB memory access. See New.
const maxStackSize = 147456 // 144 KiB; ~18 KiB headroom under the 161 KiB shadow stack

var (
	cacheOnce sync.Once
	cache     wazero.CompilationCache
)

// sharedCache returns a process-wide compilation cache so repeated runtime
// creation reuses compiled machine code.
func sharedCache() wazero.CompilationCache {
	cacheOnce.Do(func() { cache = wazero.NewCompilationCache() })
	return cache
}

// Context returns the runtime's JS execution context.
func (r *Runtime) Context() *Context { return r.ctxt }

// Close tears down the engine. It closes both the module instance and the wazero
// runtime that compiled it — the runtime holds this instance's compiled machine
// code, so closing only the module would leak it (matters when many runtimes are
// created and dropped, e.g. across tests). The compilation cache is process-wide
// (sharedCache) and is intentionally left open.
func (r *Runtime) Close() {
	if r == nil || r.mod == nil {
		return
	}
	r.mod.Close(r.ctx)
	r.mod = nil
	if r.wrt != nil {
		r.wrt.Close(r.ctx)
		r.wrt = nil
	}
}

// ── low-level engine plumbing ─────────────────────────────────────────────────

// call invokes an exported wasm function and returns its single i64 result (0 if
// the function is void). Panics on a wasm trap — the loader treats engine faults
// as fatal, same as the rest of main.go.
func (r *Runtime) call(name string, args ...uint64) uint64 {
	// Resolve per call, NOT cached: wazero's api.Function lazily allocates and then
	// reuses a per-instance execution stack, so a single cached instance corrupts under
	// re-entrancy (a host import calling back into JS→wasm) — the bridge is re-entrant,
	// so a fresh instance per call is what keeps nested calls independent.
	fn := r.mod.ExportedFunction(name)
	if fn == nil {
		panic(fmt.Errorf("qjs: missing wasm export %q", name))
	}
	res, err := fn.Call(r.ctx, args...)
	if err != nil {
		panic(fmt.Errorf("qjs: call %s: %w", name, err))
	}
	if len(res) == 0 {
		return 0
	}
	return res[0]
}

func (r *Runtime) mallocN(n int) uint64 {
	res, err := r.malloc.Call(r.ctx, uint64(n))
	if err != nil {
		panic(fmt.Errorf("qjs: malloc: %w", err))
	}
	if res[0] == 0 {
		panic(fmt.Errorf("qjs: malloc(%d) returned NULL (out of wasm memory)", n))
	}
	return res[0]
}

func (r *Runtime) freeAt(ptr uint64) {
	if _, err := r.free.Call(r.ctx, ptr); err != nil {
		panic(fmt.Errorf("qjs: free: %w", err))
	}
}

// writeCStr allocates a NUL-terminated copy of s in wasm memory and returns the
// pointer. Caller owns it (the QJS_* string entry points copy the bytes).
func (r *Runtime) writeCStr(s string) uint64 {
	ptr := r.mallocN(len(s) + 1)
	r.mem.Write(uint32(ptr), []byte(s))
	r.mem.WriteByte(uint32(ptr)+uint32(len(s)), 0)
	return ptr
}

// writeBytes allocates a copy of b in wasm memory and returns (ptr, len).
func (r *Runtime) writeBytes(b []byte) (uint64, uint64) {
	if len(b) == 0 {
		return 0, 0
	}
	ptr := r.mallocN(len(b))
	r.mem.Write(uint32(ptr), b)
	return ptr, uint64(len(b))
}

// unpackPtr reads the 8-byte (addr<<32 | size) cell at packedPtr.
func (r *Runtime) unpackPtr(packedPtr uint64) (addr, size uint32) {
	if packedPtr == 0 {
		return 0, 0
	}
	v, _ := r.mem.ReadUint64Le(uint32(packedPtr))
	return uint32(v >> 32), uint32(v)
}

// readPackedString reads a string described by a packed pointer (addr<<32 | size)
// and releases both the string and the packed cell. size is the JS_ToCString result's
// strlen — it excludes the NUL terminator — so the read is exact (no trailing \x00).
//
// addr is NOT a malloc block: it points into a refcounted JSString whose ref count
// QJS_ToCString (via JS_ToCString) incremented. The only correct release is
// JS_FreeCString, which recovers the JSString header from addr and drops that ref — a
// plain free(addr) would corrupt the heap. (Contrast QJS_GetArrayBuffer's addr, which
// is live ArrayBuffer storage that must NOT be freed — see toByteArray.) Without this
// call every JS→Go string read leaked a JSString; fastschema had the same bug. We pass
// r.ctxt because the bridge is one-context-per-runtime and every QJS_ToCString here ran
// in that context.
func (r *Runtime) readPackedString(packedPtr uint64) string {
	if packedPtr == 0 {
		return ""
	}
	addr, size := r.unpackPtr(packedPtr)
	if addr == 0 {
		r.freeAt(packedPtr)
		return ""
	}
	buf, _ := r.mem.Read(addr, size)
	s := string(buf)                                       // copy out before freeing
	r.call("JS_FreeCString", r.ctxt.handle, uint64(addr)) // drop the JSString ref ToCString took
	r.freeAt(packedPtr)                                    // free the malloc'd packed cell
	return s
}

// jsFunctionProxy is the env.jsFunctionProxy host import. The C trampoline lays
// argv out as [fnID, ctxID, isAsync, promise, ...realArgs]; we dispatch fnID and
// pass the real args (borrowed handles, valid only for the call — the loader's
// callbacks read them synchronously and never retain them).
func (r *Runtime) jsFunctionProxy(_ context.Context, _ api.Module, _ uint32, thisVal uint64, argc, argv uint32) (rs uint64) {
	c := r.ctxt
	// Registered before any arg processing so a panic below (a malformed argv, an
	// out-of-range index, a panicking callback) surfaces as a catchable JS exception
	// rather than an uncaught host-side wasm trap that would kill the node.
	defer func() {
		if rec := recover(); rec != nil {
			rs = c.throwError(fmt.Errorf("%v", rec))
		}
	}()

	args := make([]uint64, argc)
	for i := uint32(0); i < argc; i++ {
		v, _ := r.mem.ReadUint64Le(argv + i*8)
		args[i] = v
	}
	fn := r.reg.get(args[0])
	if fn == nil {
		return c.throwError(fmt.Errorf("qjs: unknown callback id %d", args[0]))
	}
	callArgs := make([]*Value, 0, len(args)-4)
	for _, h := range args[4:] {
		callArgs = append(callArgs, c.value(h))
	}
	this := &This{Value: c.value(thisVal), context: c, args: callArgs}

	res, err := fn(this)
	if err != nil {
		return c.throwError(err)
	}
	if res == nil {
		return c.NewUndefined().Raw()
	}
	return res.Raw()
}
