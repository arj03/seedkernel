// Package qjs is a thin bridge to quickjs-ng running on wazero: qjs.wasm is quickjs-ng
// plus csrc/shim.c, a flat QJS_* ABI (README.md), with one host import, env.callGo, for
// JS→Go calls. It covers only the synchronous surface the native host uses.
//
// JSValues are NaN-boxed, so each crosses as one i64 that a *Value wraps. An export
// returning an address and a length packs them as (addr<<32 | len).
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

// goFunc is a Go function exposed to JS via (*Context).Function. A call short of an
// argument it indexes panics, which callGo turns into a JS exception.
type goFunc = func(*Context, []*Value) (*Value, error)

// Runtime owns one engine: the wazero runtime, the qjs module, and the QuickJS runtime and
// context inside it. Single-threaded.
type Runtime struct {
	ctx     context.Context
	wrt     wazero.Runtime
	mod     api.Module
	mem     api.Memory
	ctxt    *Context
	funcs   []goFunc           // exposed Go funcs, indexed by callback id; see Function
	fnPools map[string]*fnPool // per-name free list of resolved exports; see call

	// JS_UNDEFINED and JS_NULL as this engine encodes them: immediates, so handling one
	// needs no engine call.
	undefined, null uint64
}

// fnPool is one export's free list of resolved instances, held by pointer so an engine
// call does one map lookup.
type fnPool struct {
	free      []pooledFn
	params    int
	hasResult bool
}

// pooledFn is one resolved instance and its own value stack, reused by CallWithStack.
type pooledFn struct {
	fn    api.Function
	stack []uint64
}

// Option configures a Runtime at creation.
type Option func(*config)

type config struct {
	memoryLimit     uint64       // bytes; 0 = unbounded
	trackRejections bool         // TrackRejections
	wasiProbe       func(string) // tests only: records WASI import calls
}

// WithMemoryLimit caps the runtime's total heap; past it, allocation throws a catchable
// "out of memory".
func WithMemoryLimit(bytes uint64) Option {
	return func(c *config) { c.memoryLimit = bytes }
}

// TrackRejections makes Pump fail on a rejection still unhandled once the job queue is
// empty, Node's rule. For the host realm.
func TrackRejections() Option {
	return func(c *config) { c.trackRejections = true }
}

// Budget bounds execution wall time until the returned restore func runs, through
// QuickJS's interrupt handler. An overrun is a catchable JS exception and the runtime
// stays usable. A non-positive d is unbounded.
func (r *Runtime) Budget(d time.Duration) func() {
	if d <= 0 {
		return func() {}
	}
	r.call("QJS_SetDeadline", uint64(d.Nanoseconds()))
	return func() {
		if r.Alive() {
			r.call("QJS_SetDeadline", 0)
		}
	}
}

// TookInterrupt reports and clears whether the Budget deadline fired. A pump can swallow
// the exception inside a job, so this is the only reliable signal.
func (r *Runtime) TookInterrupt() bool {
	if !r.Alive() {
		return false
	}
	return r.call("QJS_TakeInterrupted") != 0
}

// Alive reports whether the runtime has not been closed.
func (r *Runtime) Alive() bool { return r.mod != nil && !r.mod.IsClosed() }

// New instantiates a QuickJS runtime and context holding only ECMAScript intrinsics; WASI
// answers only the clock (instantiateWASI).
func New(opts ...Option) (rt *Runtime, err error) {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}
	ctx := context.Background()
	rt = &Runtime{ctx: ctx, fnPools: map[string]*fnPool{}}

	// On failure, close the wazero runtime and its compiled code.
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
	// Each runtime compiles its own module; the shared cache keeps that cheap.
	wcfg := wazero.NewRuntimeConfig().WithCompilationCache(sharedCache())
	rt.wrt = wazero.NewRuntimeWithConfig(ctx, wcfg)

	// A GoModuleFunc: WithFunc's reflection cost ~1µs per JS→Go call.
	i32, i64 := api.ValueTypeI32, api.ValueTypeI64
	if _, err := rt.wrt.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(rt.callGo),
			[]api.ValueType{i32, i64, i32, i32, i32}, []api.ValueType{i64}).
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

	rt.mem = rt.mod.Memory()
	rt.undefined, rt.null = rt.call("QJS_Undefined"), rt.call("QJS_Null")
	track := uint64(0)
	if cfg.trackRejections {
		track = 1
	}
	handle := rt.call("QJS_New", cfg.memoryLimit, track)
	if handle == 0 {
		return rt, errors.New("qjs.New: the engine could not create a runtime")
	}
	rt.ctxt = &Context{rt: rt, handle: handle}
	// Re-read the stack top at the depth every top-level call enters at, so deep recursion
	// throws a RangeError before it overruns the shadow stack. Once, not per call, so
	// re-entrant calls count against it.
	rt.call("QJS_UpdateStackTop", handle)
	return rt, nil
}

var (
	cacheOnce sync.Once
	cache     wazero.CompilationCache
)

// sharedCache returns the process-wide compilation cache.
func sharedCache() wazero.CompilationCache {
	cacheOnce.Do(func() { cache = wazero.NewCompilationCache() })
	return cache
}

// ── WASI ──────────────────────────────────────────────────────────────────────

const wasiModule = "wasi_snapshot_preview1"

// WASI preview1 errno values, the spec's numbers rather than the host OS's.
const (
	wasiErrnoFault = 21
	wasiErrnoInval = 28
	wasiErrnoNosys = 52
)

// monotonicEpoch is the origin a realm's CLOCK_MONOTONIC reads from.
var monotonicEpoch = time.Now()

// instantiateWASI builds the WASI module the engine imports: every import refuses except
// clock_time_get, which the Budget interrupt, performance.now and Date read. Signatures
// come from the module's own imports, so a new import is refused by construction.
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

// wasiFunc is one syscall: clock_time_get, ENOSYS, or a panic for a void import
// (proc_exit). probe, when set, records the call.
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

// clockTimeGet implements clock_time_get for CLOCK_REALTIME and CLOCK_MONOTONIC.
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

// Close tears down the module and its wazero runtime; the shared cache stays open.
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

// call invokes an export and returns its i64 result (0 if void). Panics on a trap.
func (r *Runtime) call(name string, args ...uint64) uint64 {
	// An api.Function reuses one execution stack, so each in-flight (possibly nested)
	// call takes its own instance from the pool.
	p := r.pool(name)
	if len(args) != p.params {
		panic(fmt.Errorf("qjs: call %s: %d arguments for %d parameters", name, len(args), p.params))
	}
	f := p.acquire(r, name)
	copy(f.stack, args)
	err := f.fn.CallWithStack(r.ctx, f.stack)
	res := f.stack[0]
	p.free = append(p.free, f)
	if err != nil {
		panic(fmt.Errorf("qjs: call %s: %w", name, err))
	}
	if !p.hasResult {
		return 0
	}
	return res
}

// pool returns name's free list, minting it on first use.
func (r *Runtime) pool(name string) *fnPool {
	p := r.fnPools[name]
	if p == nil {
		fn := r.mod.ExportedFunction(name)
		if fn == nil {
			panic(fmt.Errorf("qjs: missing wasm export %q", name))
		}
		def := fn.Definition()
		p = &fnPool{params: len(def.ParamTypes()), hasResult: len(def.ResultTypes()) > 0}
		p.free = append(p.free, p.instance(fn))
		r.fnPools[name] = p
	}
	return p
}

// instance pairs a resolved export with a stack wide enough for its params and result.
func (p *fnPool) instance(fn api.Function) pooledFn {
	return pooledFn{fn: fn, stack: make([]uint64, max(p.params, 1))}
}

// acquire hands out a free instance, or resolves a new one.
func (p *fnPool) acquire(r *Runtime, name string) pooledFn {
	if n := len(p.free); n > 0 {
		f := p.free[n-1]
		p.free = p.free[:n-1]
		return f
	}
	return p.instance(r.mod.ExportedFunction(name))
}

func (r *Runtime) mallocN(n int) uint64 {
	ptr := r.call("malloc", uint64(n))
	if ptr == 0 {
		panic(fmt.Errorf("qjs: malloc(%d) returned NULL (out of wasm memory)", n))
	}
	return ptr
}

func (r *Runtime) freeAt(ptr uint64) {
	if !r.Alive() { // see Value.Free
		return
	}
	r.call("free", ptr)
}

// writeCStr allocates a NUL-terminated copy of s in wasm memory; the caller frees it.
func (r *Runtime) writeCStr(s string) uint64 {
	ptr := r.mallocN(len(s) + 1)
	r.mem.Write(uint32(ptr), []byte(s))
	r.mem.WriteByte(uint32(ptr)+uint32(len(s)), 0)
	return ptr
}

// readString copies out a string QJS_ToCString packed and releases it with
// JS_FreeCString, never free: it points into a retained JSString.
func (r *Runtime) readString(packed uint64) string {
	if packed == 0 {
		return ""
	}
	addr, size := uint32(packed>>32), uint32(packed)
	buf, _ := r.mem.Read(addr, size)
	s := string(buf)
	r.call("JS_FreeCString", r.ctxt.handle, uint64(addr))
	return s
}

// callGo is the env.callGo import, (ctx i32, this i64, argc i32, argv i32, id i32) → i64:
// a JS call to the Go function registered under id. The arguments are borrowed for the
// call; `this` is ignored.
func (r *Runtime) callGo(_ context.Context, _ api.Module, stack []uint64) {
	c := r.ctxt
	// A panic becomes a JS exception rather than a trap.
	defer func() {
		if rec := recover(); rec != nil {
			stack[0] = c.throwError(fmt.Errorf("%v", rec))
		}
	}()

	argc, argv, id := api.DecodeU32(stack[2]), api.DecodeU32(stack[3]), api.DecodeU32(stack[4])
	fn := r.funcs[id]
	vals := make([]Value, argc)
	args := make([]*Value, argc)
	for i := range args {
		h, _ := r.mem.ReadUint64Le(argv + uint32(i)*8)
		vals[i] = Value{c: c, raw: h}
		args[i] = &vals[i]
	}
	res, err := fn(c, args)
	switch {
	case err != nil:
		stack[0] = c.throwError(err)
	case res == nil:
		stack[0] = c.NewUndefined().Raw()
	default:
		stack[0] = res.Raw()
	}
}
