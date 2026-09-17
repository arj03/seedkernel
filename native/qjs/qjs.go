// Package qjs is a thin, in-repo bridge to the quickjs-ng engine running on wazero — the
// Go counterpart of sodium.go's raw-wasm-over-wazero pattern. The engine is qjs.wasm:
// quickjs-ng plus csrc/shim.c, a flat QJS_* ABI (README.md), driven directly over wazero
// linear memory with one host import, env.callGo, for JS→Go calls.
//
// The loader needs only a small synchronous slice of the API — objects, strings,
// ArrayBuffers, function callbacks, eval, invoke — so this mirrors exactly that surface
// and nothing more.
//
// JSValue ABI: the wasm is built with NaN-boxed JSValues, so every JSValue crosses as one
// i64 and a *Value wraps that handle. An export that answers an address and a length packs
// both into its i64 result as (addr<<32 | len).
package qjs

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed qjs.wasm
var wasmBytes []byte

// goFunc is a Go function exposed to JS via (*Context).Function. It indexes the arguments
// it requires straight out of This.Args: a call short of one panics, and callGo answers
// the panic as a JS exception.
type goFunc = func(*This) (*Value, error)

// Runtime owns one engine: the wazero runtime, the instantiated qjs module, and the QuickJS
// runtime and context inside it. Single-threaded: the loader drives every realm from one
// goroutine, so engine calls need no locking.
type Runtime struct {
	ctx     context.Context
	wrt     wazero.Runtime
	mod     api.Module
	malloc  api.Function
	free    api.Function
	mem     api.Memory
	ctxt    *Context
	funcs   []goFunc           // exposed Go funcs, indexed by callback id; see Function
	fnPools map[string]*fnPool // per-name free list of resolved exports; see call
}

// fnPool is one export's free list of resolved instances. A POINTER in the map, not a
// slice value: a slice value has to be read and written back to pop and again to push, so
// every engine call — and a *Value operation is one — hashed the name four times. Through
// the pointer it is one lookup, and the pop and the push mutate in place.
type fnPool struct{ free []api.Function }

// Option configures a Runtime at creation, for what QuickJS takes only when it creates the
// runtime.
type Option func(*config)

type config struct {
	memoryLimit     uint64       // bytes; 0 = unbounded
	trackRejections bool         // TrackRejections
	wasiProbe       func(string) // set by package tests only; records WASI import calls
}

// WithMemoryLimit caps the runtime's total heap. An allocation past the cap fails
// inside QuickJS and surfaces as a catchable JS "out of memory" error, so a runaway
// realm hits its own ceiling instead of the host's. Used for the confined guest realm
// (guest.go), which mirrors safe-js.ts's setMemoryLimit on the node/browser target.
func WithMemoryLimit(bytes uint64) Option {
	return func(c *config) { c.memoryLimit = bytes }
}

// TrackRejections makes Pump fail on a promise that was rejected with no handler and still
// has none once the job queue is empty — Node's rule for an unhandled rejection, which ends
// a Node process. It is for the trusted host realm, where one is a host bug; a guest's own
// rejections are its business.
func TrackRejections() Option {
	return func(c *config) { c.trackRejections = true }
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
// runtime has been closed. A Budget overrun does not end it: the engine throws and the
// runtime keeps running.
func (r *Runtime) Alive() bool { return r.mod != nil && !r.mod.IsClosed() }

// New instantiates a fresh QuickJS runtime and context: the engine's ECMAScript intrinsics
// and nothing else — no quickjs-libc, no module loader, and WASI imports that answer only the
// clock (instantiateWASI). Whatever else a realm can reach, its creator installs.
func New(opts ...Option) (rt *Runtime, err error) {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}
	ctx := context.Background()
	rt = &Runtime{ctx: ctx, fnPools: map[string]*fnPool{}}

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

	if _, err := rt.wrt.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(rt.callGo).
		Export("callGo").
		Instantiate(ctx); err != nil {
		return rt, fmt.Errorf("host module: %w", err)
	}

	code, err := rt.wrt.CompileModule(ctx, wasmBytes)
	if err != nil {
		return rt, fmt.Errorf("compile qjs.wasm: %w", err)
	}
	if err := instantiateWASI(ctx, rt.wrt, cfg.wasiProbe, code.ImportedFunctions()); err != nil {
		return rt, fmt.Errorf("instantiate WASI: %w", err)
	}

	// A reactor: _initialize sets wasi-libc up once, before any other export runs.
	rt.mod, err = rt.wrt.InstantiateModule(ctx, code, wazero.
		NewModuleConfig().
		WithStartFunctions("_initialize"))
	if err != nil {
		return rt, fmt.Errorf("instantiate module: %w", err)
	}

	rt.malloc = rt.mod.ExportedFunction("malloc")
	rt.free = rt.mod.ExportedFunction("free")
	rt.mem = rt.mod.Memory()
	track := uint64(0)
	if cfg.trackRejections {
		track = 1
	}
	handle := rt.call("QJS_New", cfg.memoryLimit, track)
	if handle == 0 {
		return rt, errors.New("qjs.New: the engine could not create a runtime")
	}
	rt.ctxt = &Context{rt: rt, handle: handle}
	// The engine's stack limit — its default, under the shadow stack csrc/qjswasm.cmake
	// sizes — is measured down from a stack top it read inside QJS_New, a few frames deep.
	// Read it again from here, the depth every top-level call enters at (each call leaves
	// the stack pointer where it found it), so deep recursion throws a RangeError before it
	// can run off the shadow stack into a trap that leaves the engine unusable. ONCE, never
	// per call: a re-entrant call must count against this top, not its own deeper one.
	rt.call("QJS_UpdateStackTop", handle)
	return rt, nil
}

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

// ── WASI ──────────────────────────────────────────────────────────────────────

const wasiModule = "wasi_snapshot_preview1"

// WASI preview1 errno values the stubs answer with. They are the spec's numbers
// (ENOSYS 52, EINVAL 28, EFAULT 21), not the host OS's: a stub writes the result stack
// directly, so it must not route through wazero's POSIX-to-WASI mapping.
const (
	wasiErrnoFault = 21
	wasiErrnoInval = 28
	wasiErrnoNosys = 52
)

// monotonicEpoch is the origin a realm's CLOCK_MONOTONIC reads from.
var monotonicEpoch = time.Now()

// instantiateWASI builds the wasi_snapshot_preview1 module the engine imports, holding no
// host authority: every import refuses, except clock_time_get, which stays real because the
// engine's own clock reads it — js__hrtime_ns drives the Budget interrupt and
// performance.now, and Date and the Math.random seed read the wall clock. The signatures
// come from the compiled module's imports, so an import a future build adds is refused by
// construction rather than linked to a real host module.
func instantiateWASI(ctx context.Context, r wazero.Runtime, probe func(string), imports []api.FunctionDefinition) error {
	b := r.NewHostModuleBuilder(wasiModule)
	for _, fn := range imports {
		mod, name, ok := fn.Import()
		if !ok || mod != wasiModule {
			continue
		}
		b.NewFunctionBuilder().
			WithGoModuleFunction(wasiFunc(name, len(fn.ResultTypes()) > 0, probe), fn.ParamTypes(), fn.ResultTypes()).
			Export(name)
	}
	_, err := b.Instantiate(ctx)
	return err
}

// wasiFunc is one syscall, chosen once per import: clock_time_get is implemented, every
// other import refuses with ENOSYS. A void import (proc_exit) panics instead of returning,
// so an exit that somehow reached the host can never look like a successful one. probe,
// when set, wraps the choice as the package tests' witness of which imports JS reaches;
// production calls pay nothing for it.
func wasiFunc(name string, hasResult bool, probe func(string)) api.GoModuleFunc {
	var fn api.GoModuleFunc
	switch {
	case name == "clock_time_get":
		fn = clockTimeGet
	case !hasResult:
		fn = func(context.Context, api.Module, []uint64) {
			panic("qjs: realm called void WASI import " + name)
		}
	default:
		fn = func(_ context.Context, _ api.Module, stack []uint64) { stack[0] = wasiErrnoNosys }
	}
	if probe == nil {
		return fn
	}
	return func(ctx context.Context, mod api.Module, stack []uint64) {
		probe(name)
		fn(ctx, mod, stack)
	}
}

// clockTimeGet implements clock_time_get against Go's clocks: CLOCK_REALTIME (0) from the
// wall clock, CLOCK_MONOTONIC (1) from a process-stable origin. js__hrtime_ns aborts the
// engine on any failure, so a bad id is EINVAL and an unwritable result cell EFAULT —
// never a success with untouched memory.
func clockTimeGet(_ context.Context, mod api.Module, stack []uint64) {
	clockID := api.DecodeU32(stack[0])
	out := api.DecodeU32(stack[2])
	var ns uint64
	switch clockID {
	case 0: // CLOCK_REALTIME
		ns = uint64(time.Now().UnixNano())
	case 1: // CLOCK_MONOTONIC
		ns = uint64(time.Since(monotonicEpoch).Nanoseconds())
	default:
		stack[0] = wasiErrnoInval
		return
	}
	if !mod.Memory().WriteUint64Le(out, ns) {
		stack[0] = wasiErrnoFault
		return
	}
	stack[0] = 0
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
	p := r.pool(name)
	fn := p.acquire(r, name)
	res, err := fn.Call(r.ctx, args...)
	p.free = append(p.free, fn)
	if err != nil {
		panic(fmt.Errorf("qjs: call %s: %w", name, err))
	}
	if len(res) == 0 {
		return 0
	}
	return res[0]
}

// pool returns name's free list, minting it on first use. The one map lookup an engine
// call makes.
func (r *Runtime) pool(name string) *fnPool {
	p := r.fnPools[name]
	if p == nil {
		p = &fnPool{}
		r.fnPools[name] = p
	}
	return p
}

// acquire hands out a resolved export instance: a pooled one if free, so a nested
// re-entrant call gets a distinct instance from the one in flight.
func (p *fnPool) acquire(r *Runtime, name string) api.Function {
	if n := len(p.free); n > 0 {
		fn := p.free[n-1]
		p.free = p.free[:n-1]
		return fn
	}
	fn := r.mod.ExportedFunction(name)
	if fn == nil {
		panic(fmt.Errorf("qjs: missing wasm export %q", name))
	}
	return fn
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

// readString reads a string QJS_ToCString packed, and releases it. The address is not a
// malloc block: it points into a refcounted JSString that QJS_ToCString retained, and the
// only correct release is JS_FreeCString — a plain free corrupts the heap, and no release
// leaks the string.
func (r *Runtime) readString(packed uint64) string {
	if packed == 0 {
		return ""
	}
	addr, size := uint32(packed>>32), uint32(packed)
	buf, _ := r.mem.Read(addr, size)
	s := string(buf) // copy out before releasing
	r.call("JS_FreeCString", r.ctxt.handle, uint64(addr))
	return s
}

// callGo is the env.callGo host import: a JS call to the Go function registered under id.
// The arguments are borrowed handles, valid only for the call.
func (r *Runtime) callGo(_ context.Context, _ api.Module, _ uint32, thisVal uint64, argc, argv, id uint32) (rs uint64) {
	c := r.ctxt
	// Deferred before any arg processing, so a panic below (a malformed argv, a panicking
	// callback) surfaces as a catchable JS exception rather than a wasm trap killing the node.
	defer func() {
		if rec := recover(); rec != nil {
			rs = c.throwError(fmt.Errorf("%v", rec))
		}
	}()

	fn := r.funcs[id]
	args := make([]*Value, argc)
	for i := range args {
		h, _ := r.mem.ReadUint64Le(argv + uint32(i)*8)
		args[i] = c.value(h)
	}
	res, err := fn(&This{Value: c.value(thisVal), context: c, args: args})
	if err != nil {
		return c.throwError(err)
	}
	if res == nil {
		return c.NewUndefined().Raw()
	}
	return res.Raw()
}
