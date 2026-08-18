// Package qjs is a thin, in-repo bridge to the quickjs-ng engine running on wazero — the
// Go counterpart of sodium.go's raw-wasm-over-wazero pattern. The engine is the prebuilt
// qjs.wasm blob (quickjs-ng plus a small C shim exposing a flat QJS_* ABI, forked under
// csrc/ and built by build-qjs.sh; see README.md), driven directly over wazero linear
// memory with one host import, env.jsFunctionProxy, for JS→Go callbacks.
//
// The loader needs only a small synchronous slice of the API — objects, strings,
// ArrayBuffers, function callbacks, eval, invoke — so this mirrors exactly that surface
// and nothing more.
//
// JSValue ABI: the wasm is built with NaN-boxed JSValues, so every QJS_* function takes
// and returns a single i64, and a *Value wraps that handle. "Packed pointer" returns
// (QJS_ToCString, QJS_GetArrayBuffer) point at an 8-byte little-endian cell holding
// (addr<<32 | size).
package qjs

import (
	"context"
	_ "embed"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	wasi "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed qjs.wasm
var wasmBytes []byte

const (
	// eval flags (quickjs JS_EVAL_*): global scope + strict mode.
	evalTypeGlobal = 0
	evalFlagStrict = 1 << 3
)

// goFunc is a Go function exposed to JS via (*Context).Function.
type goFunc = func(*This) (*Value, error)

// Runtime owns the wazero runtime, the instantiated qjs module and the QuickJS
// runtime/context handles. Single-threaded: the loader drives the realm from one
// goroutine, so engine calls need no locking.
type Runtime struct {
	ctx           context.Context
	wrt           wazero.Runtime
	mod           api.Module
	malloc        api.Function
	free          api.Function
	mem           api.Memory
	qjs           uint64 // QJSRuntime*
	ctxt          *Context
	reg           *registry
	fnPool        map[string][]api.Function // per-name free list of resolved exports; see call
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

// Option configures a Runtime at creation. Options exist for limits that QuickJS can
// only take at JS_NewRuntime time, so they cannot be applied to a live runtime.
type Option func(*config)

type config struct {
	memoryLimit uint64 // bytes; 0 = engine default (unbounded)
}

// WithMemoryLimit caps the runtime's total heap. An allocation past the cap fails
// inside QuickJS and surfaces as a catchable JS "out of memory" error, so a runaway
// realm hits its own ceiling instead of the host's. Used for the confined guest realm
// (guest.go), which mirrors safe-js.ts's setMemoryLimit on the node/browser target.
func WithMemoryLimit(bytes uint64) Option {
	return func(c *config) { c.memoryLimit = bytes }
}

// Budget bounds the wall time of guest execution on this runtime until the returned
// restore func runs, by arming QuickJS's own interrupt handler (QJS_SetDeadline in the
// shim), which the interpreter consults every ~10k bytecodes and then throws.
//
// So the kill is an ordinary catchable JS exception and the runtime stays USABLE: the
// caller sees an error from the call that overran, and the next call works. The
// alternative — wazero's WithCloseOnContextDone — had to close the module to stop it, and
// cost ~2.3x on a guest realm dispatch and ~2x on every network round trip for a bound
// that also destroyed the realm it enforced.
//
// A non-positive d leaves the runtime unbounded.
func (r *Runtime) Budget(d time.Duration) func() {
	if d <= 0 {
		return func() {}
	}
	// The module resolves the deadline against its own monotonic clock, so the host
	// never has to share a clock origin with it — it passes a duration, not an instant.
	r.call("QJS_SetDeadline", uint64(d.Nanoseconds()))
	return func() {
		if r.Alive() {
			r.call("QJS_SetDeadline", 0)
		}
	}
}

// TookInterrupt reports whether the Budget deadline fired since it was last asked, and
// clears the flag. It is the only way to know: an interrupt throws into whatever guest
// frame was running, and when that frame is a promise-reaction job the job loop consumes
// the exception — so the host's call (a pump) returns success and a guest that ran out of
// budget is indistinguishable from one that finished. Every entry into guest code asks.
func (r *Runtime) TookInterrupt() bool {
	if !r.Alive() {
		return false
	}
	return r.call("QJS_TakeInterrupted") != 0
}

// Alive reports whether the underlying module is still usable — false only once the
// runtime has been closed. A Budget overrun no longer ends it: the engine throws and
// the runtime keeps running.
func (r *Runtime) Alive() bool { return r.mod != nil && !r.mod.IsClosed() }

// New instantiates a fresh QuickJS runtime + context.
func New(opts ...Option) (rt *Runtime, err error) {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}
	ctx := context.Background()
	rt = &Runtime{ctx: ctx, reg: newRegistry(), fnPool: map[string][]api.Function{}}

	// On any failure after the wazero runtime is created but before the module is live,
	// close it: the runtime holds this instance's compiled machine code.
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
	// A CompiledModule is bound to the runtime that compiled it, so each runtime compiles
	// its own; the shared cache is what keeps that cheap when several are created.
	//
	// Nothing here arms an execution bound — the engine carries its own (see Budget) — so
	// the compiled code pays no termination check.
	wcfg := wazero.NewRuntimeConfig().WithCompilationCache(sharedCache())
	rt.wrt = wazero.NewRuntimeWithConfig(ctx, wcfg)

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
	// maxStackSize is load-bearing: QuickJS's default limit (256 KiB) is larger than
	// qjs.wasm's ~161 KiB shadow stack, so the overflow guard never trips and deep JS
	// recursion runs the stack off the end of linear memory, trapping as an OOB crash
	// instead of a catchable "stack overflow". Capping below the real stack makes the
	// guard fire first — but only once the stack top is calibrated, below.
	rt.qjs = rt.call("New_QJS", cfg.memoryLimit, maxStackSize, 0, 0)
	rt.ctxt = &Context{rt: rt, handle: rt.call("QJS_GetContext", rt.qjs)}
	// Calibrate QuickJS's stack_top to the actual wasm shadow-SP, which JS_NewRuntime
	// captured deep inside New_QJS. Recording it from this shallow entry — the depth every
	// top-level QJS_Call/QJS_Eval re-enters at, since wazero restores __stack_pointer
	// between calls — makes stack_limit land in the real stack region. ONCE, never
	// per-call: a re-entrant Invoke must measure against this top, not its own deeper SP.
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

// Close tears down the engine: both the module instance and the wazero runtime that
// compiled it, since the runtime holds this instance's compiled machine code. The
// process-wide compilation cache is intentionally left open.
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
	// wazero's api.Function lazily allocates and reuses a per-instance execution stack, so
	// one cached instance corrupts under re-entrancy (a host import calling back into
	// JS→wasm), while resolving fresh per call pays a lookup and an allocation every time.
	// The per-name free list keeps both: each in-flight (possibly nested) call pops its own
	// instance and returns it after. Single-threaded, so the pool needs no locking.
	fn := r.acquireFn(name)
	res, err := fn.Call(r.ctx, args...)
	r.releaseFn(name, fn)
	if err != nil {
		panic(fmt.Errorf("qjs: call %s: %w", name, err))
	}
	if len(res) == 0 {
		return 0
	}
	return res[0]
}

// acquireFn hands out a resolved export instance for name: a pooled one if free, so a
// nested re-entrant call gets a distinct instance from the one in flight.
func (r *Runtime) acquireFn(name string) api.Function {
	if pool := r.fnPool[name]; len(pool) > 0 {
		fn := pool[len(pool)-1]
		r.fnPool[name] = pool[:len(pool)-1]
		return fn
	}
	fn := r.mod.ExportedFunction(name)
	if fn == nil {
		panic(fmt.Errorf("qjs: missing wasm export %q", name))
	}
	return fn
}

// releaseFn returns an instance to its free list for a later call to reuse.
func (r *Runtime) releaseFn(name string, fn api.Function) {
	r.fnPool[name] = append(r.fnPool[name], fn)
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
	if !r.Alive() { // see Value.Free
		return
	}
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

// unpackPtr reads the 8-byte (addr<<32 | size) cell at packedPtr.
func (r *Runtime) unpackPtr(packedPtr uint64) (addr, size uint32) {
	if packedPtr == 0 {
		return 0, 0
	}
	v, _ := r.mem.ReadUint64Le(uint32(packedPtr))
	return uint32(v >> 32), uint32(v)
}

// readPackedString reads a string described by a packed pointer and releases both the
// string and the packed cell. size is strlen, excluding the NUL, so the read is exact.
//
// addr is NOT a malloc block: it points into a refcounted JSString whose count
// QJS_ToCString incremented, and the only correct release is JS_FreeCString, which
// recovers the header from addr and drops that ref — a plain free(addr) corrupts the heap.
// (Contrast QJS_GetArrayBuffer's addr, live storage that must NOT be freed; see
// toByteArray.) Without this every JS→Go string read leaks a JSString.
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
	s := string(buf)                                      // copy out before freeing
	r.call("JS_FreeCString", r.ctxt.handle, uint64(addr)) // drop the JSString ref ToCString took
	r.freeAt(packedPtr)                                   // free the malloc'd packed cell
	return s
}

// jsFunctionProxy is the env.jsFunctionProxy host import. The C trampoline lays argv out
// as [fnID, ctxID, isAsync, promise, ...realArgs]; the real args are borrowed handles,
// valid only for the call.
func (r *Runtime) jsFunctionProxy(_ context.Context, _ api.Module, _ uint32, thisVal uint64, argc, argv uint32) (rs uint64) {
	c := r.ctxt
	// Registered before any arg processing, so a panic below (a malformed argv, a panicking
	// callback) surfaces as a catchable JS exception rather than a wasm trap killing the node.
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
