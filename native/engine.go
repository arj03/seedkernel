// The engine table (the platform ABI's engine calls): instantiate a wasm module from bytes,
// call its exports with numbers, and read and write its memory. It knows nothing of what
// runs inside; the shared realm driver (host/engine-realm.ts) builds guest realms on it
// from qjs.wasm. An import outside WASI calls the JS function the instantiation names for
// it, as WebAssembly's importObject does. WASI is answered only for an unbounded instance,
// the realm engine, as a realm's is (qjs.go): the clock and nothing else. A private module
// imports only the runtime shims (host/wasm-limits.ts), so it is handed no WASI here either.
//
// A bounded instance is the one a private module runs on (§4.3): its runtime compiles in
// the check that lets a deadline end a call mid-loop, instantiation runs under its own
// deadline, and engineCallBounded arms one per call. The module ABI itself is the host's
// (host/pure-module.ts).
package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"seedkernel/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

var (
	// engines are the live instances, keyed by a handle this map mints.
	engines   = map[int64]*engineInstance{}
	engineSeq int64
)

type engineInstance struct {
	rt      wazero.Runtime
	mod     api.Module
	mem     api.Memory
	imports []*qjs.Value    // retained import handlers, freed on dispose
	exports []*engineExport // by export handle (engineExport)
}

// engineExport is one export's signature, and a resolved function with its own stack per
// nesting depth: a call can re-enter the same export through an import, and each call in
// flight needs its own stack.
type engineExport struct {
	name            string
	params, results []api.ValueType
	fns             []api.Function
	stacks          [][]uint64
	depth           int
}

func installEngineBridge(qc *qjs.Context, b *qjs.Value) {
	b.SetPropertyStr("engineInstantiate", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		bytes, err := args[0].Bytes()
		if err != nil {
			return nil, err
		}
		// A third argument, the bind deadline in ms (-1 for none), makes it bounded.
		bounded := len(args) > 2 && !args[2].IsUndefined()
		bind := time.Duration(-1)
		if bounded {
			bind = time.Duration(args[2].Int64()) * time.Millisecond
		}
		e, err := newEngineInstance(qc, bytes, args[1], bounded, bind)
		if err != nil {
			return nil, err
		}
		engineSeq++
		engines[engineSeq] = e
		return qc.NewInt64(engineSeq), nil
	}))
	// The rest name an instance first.
	on := func(name string, f func(e *engineInstance, args []*qjs.Value) (*qjs.Value, error)) {
		b.SetPropertyStr(name, qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
			e := engines[args[0].Int64()]
			if e == nil {
				return nil, errors.New("engine: no such instance")
			}
			return f(e, args[1:])
		}))
	}
	on("engineExport", func(e *engineInstance, args []*qjs.Value) (*qjs.Value, error) {
		h, err := e.export(args[0].String())
		if err != nil {
			return nil, err
		}
		return qc.NewInt32(int32(h)), nil
	})
	on("engineCall", func(e *engineInstance, args []*qjs.Value) (*qjs.Value, error) {
		return e.call(qc, ctx, args[0].Int64(), args[1:])
	})
	// A call under a deadline in ms (-1 for none): past it the instance is closed and the
	// call answers null, while a trap still throws.
	on("engineCallBounded", func(e *engineInstance, args []*qjs.Value) (*qjs.Value, error) {
		callCtx := ctx
		if d := args[1].Int64(); d >= 0 {
			callCtx = armModuleDeadline(time.Duration(d) * time.Millisecond)
			defer disarmModuleDeadline()
		}
		r, err := e.call(qc, callCtx, args[0].Int64(), args[2:])
		if err != nil && e.mod != nil && e.mod.IsClosed() {
			return qc.NewNull(), nil
		}
		return r, err
	})
	on("engineRead", func(e *engineInstance, args []*qjs.Value) (*qjs.Value, error) {
		view, ok := e.mem.Read(uint32(args[0].Int64()), uint32(args[1].Int64()))
		if !ok {
			return nil, errors.New("engine: read out of bounds")
		}
		return qc.NewArrayBuffer(view), nil
	})
	on("engineWrite", func(e *engineInstance, args []*qjs.Value) (*qjs.Value, error) {
		ptr := uint32(args[0].Int64())
		// Borrowed last (qjs.Value.View).
		bytes, err := args[1].View()
		if err != nil {
			return nil, err
		}
		if !e.mem.Write(ptr, bytes) {
			return nil, errors.New("engine: write out of bounds")
		}
		return nil, nil
	})
	on("engineGlobal", func(e *engineInstance, args []*qjs.Value) (*qjs.Value, error) {
		g := e.mod.ExportedGlobal(args[0].String())
		if g == nil {
			return qc.NewNull(), nil
		}
		return numberToJS(qc, g.Type(), g.Get()), nil
	})
	on("engineGrow", func(e *engineInstance, args []*qjs.Value) (*qjs.Value, error) {
		before, ok := e.mem.Grow(uint32(args[0].Int64()))
		if !ok {
			return qc.NewInt32(-1), nil
		}
		return qc.NewInt64(int64(before)), nil
	})
	b.SetPropertyStr("engineDispose", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		id := args[0].Int64()
		if e := engines[id]; e != nil {
			delete(engines, id)
			e.close()
		}
		return nil, nil
	}))
}

// newEngineInstance compiles and instantiates bytes, wiring each non-WASI import to
// importObject[module][name], a JS function of numbers.
func newEngineInstance(qc *qjs.Context, bytes []byte, importObject *qjs.Value, bounded bool, bind time.Duration) (_ *engineInstance, err error) {
	e := &engineInstance{}
	// The process-wide cache the host realm compiled qjs.wasm into, so every realm runs
	// one copy of the engine's machine code.
	cfg := wazero.NewRuntimeConfig()
	if bounded {
		// WithCloseOnContextDone compiles in the check that enforces the §4.3 bound.
		cfg = wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(true)
	}
	e.rt = wazero.NewRuntimeWithConfig(ctx, cfg.WithCompilationCache(qjs.SharedCache()))
	defer func() {
		if err != nil {
			e.close()
		}
	}()
	code, err := e.rt.CompileModule(ctx, bytes)
	if err != nil {
		return nil, fmt.Errorf("engine: compile: %w", err)
	}
	imports := code.ImportedFunctions()
	if !bounded {
		if err := qjs.InstantiateWASI(ctx, e.rt, imports); err != nil {
			return nil, fmt.Errorf("engine: WASI: %w", err)
		}
	}
	builders := map[string]wazero.HostModuleBuilder{}
	for _, def := range imports {
		module, name, _ := def.Import()
		if module == "wasi_snapshot_preview1" && !bounded {
			continue
		}
		ns := importObject.GetPropertyStr(module)
		if !ns.IsObject() {
			ns.Free()
			return nil, fmt.Errorf("engine: no handlers for import module %s", module)
		}
		fn := ns.GetPropertyStr(name)
		ns.Free()
		if !fn.IsObject() {
			fn.Free()
			return nil, fmt.Errorf("engine: import %s.%s has no handler", module, name)
		}
		e.imports = append(e.imports, fn)
		b := builders[module]
		if b == nil {
			b = e.rt.NewHostModuleBuilder(module)
			builders[module] = b
		}
		b.NewFunctionBuilder().
			WithGoModuleFunction(importHandler(qc, fn, def.ParamTypes(), def.ResultTypes()),
				def.ParamTypes(), def.ResultTypes()).
			Export(name)
	}
	for module, b := range builders {
		if _, err := b.Instantiate(ctx); err != nil {
			return nil, fmt.Errorf("engine: imports %s: %w", module, err)
		}
	}
	// A reactor runs `_initialize` once, before any other export.
	mcfg := wazero.NewModuleConfig().WithName("")
	if code.ExportedFunctions()["_initialize"] != nil {
		mcfg = mcfg.WithStartFunctions("_initialize")
	}
	// Instantiation runs the start section, so a bounded instance binds under its deadline.
	instCtx, cancel := ctx, func() {}
	if bind >= 0 {
		instCtx, cancel = context.WithTimeout(ctx, bind)
	}
	e.mod, err = e.rt.InstantiateModule(instCtx, code, mcfg)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("engine: instantiate: %w", err)
	}
	e.mem = e.mod.Memory()
	if e.mem == nil {
		return nil, errors.New("engine: module exports no memory")
	}
	return e, nil
}

// importHandler calls a JS handler with the import's arguments as numbers, and hands its
// number back. A handler that throws traps the call, and with it the export that made it.
func importHandler(qc *qjs.Context, fn *qjs.Value, params, results []api.ValueType) api.GoModuleFunc {
	return func(_ context.Context, _ api.Module, stack []uint64) {
		args := make([]*qjs.Value, len(params))
		for i, t := range params {
			args[i] = numberToJS(qc, t, stack[i])
		}
		res, err := qc.Invoke(fn, qc.NewUndefined(), args...)
		for _, a := range args {
			a.Free()
		}
		if err != nil {
			panic(fmt.Errorf("engine: import handler: %w", err))
		}
		if len(results) > 0 {
			stack[0] = numberFromJS(results[0], res)
		}
		res.Free()
	}
}

func numberToJS(qc *qjs.Context, t api.ValueType, v uint64) *qjs.Value {
	switch t {
	case api.ValueTypeI32:
		return qc.NewInt32(api.DecodeI32(v))
	case api.ValueTypeF64:
		return qc.NewFloat64(api.DecodeF64(v))
	default:
		// An i64 would need a BigInt on every target, and nothing crosses an f32.
		panic("engine: only i32 and f64 values cross the engine table")
	}
}

// numberFromJS reads a JS number as wasm type t. Values that cross are integers or ids, so
// the integer conversion is exact.
func numberFromJS(t api.ValueType, v *qjs.Value) uint64 {
	switch t {
	case api.ValueTypeI32:
		return api.EncodeI32(v.Int32())
	case api.ValueTypeF64:
		return api.EncodeF64(float64(v.Int64()))
	default:
		panic("engine: only i32 and f64 values cross the engine table")
	}
}

// export resolves an export to the handle engineCall takes.
func (e *engineInstance) export(name string) (int, error) {
	fn := e.mod.ExportedFunction(name)
	if fn == nil {
		return 0, fmt.Errorf("engine: no export %q", name)
	}
	def := fn.Definition()
	e.exports = append(e.exports, &engineExport{name: name, params: def.ParamTypes(), results: def.ResultTypes()})
	return len(e.exports) - 1, nil
}

// call runs export `handle` with numeric arguments and answers its result as a number.
// Arguments past the export's parameters are ignored, so a caller can pass a fixed count.
func (e *engineInstance) call(qc *qjs.Context, callCtx context.Context, handle int64, args []*qjs.Value) (*qjs.Value, error) {
	if e.mod == nil || e.mod.IsClosed() {
		return nil, errors.New("engine: instance is closed")
	}
	if handle < 0 || handle >= int64(len(e.exports)) {
		return nil, errors.New("engine: no such export handle")
	}
	x := e.exports[handle]
	if len(args) < len(x.params) {
		return nil, fmt.Errorf("engine: %s takes %d arguments, not %d", x.name, len(x.params), len(args))
	}
	if x.depth == len(x.fns) {
		x.fns = append(x.fns, e.mod.ExportedFunction(x.name))
		x.stacks = append(x.stacks, make([]uint64, max(len(x.params), len(x.results), 1)))
	}
	fn, stack := x.fns[x.depth], x.stacks[x.depth]
	for i, t := range x.params {
		stack[i] = numberFromJS(t, args[i])
	}
	x.depth++
	err := fn.CallWithStack(callCtx, stack)
	x.depth--
	if err != nil {
		return nil, fmt.Errorf("engine: %s trapped: %w", x.name, err)
	}
	if len(x.results) == 0 {
		return nil, nil
	}
	return numberToJS(qc, x.results[0], stack[0]), nil
}

func (e *engineInstance) close() {
	for _, fn := range e.imports {
		fn.Free()
	}
	e.imports = nil
	if e.rt != nil {
		_ = e.rt.Close(ctx)
		e.rt = nil
	}
	e.mod = nil
}

// moduleDeadline is the context a bounded call runs under (§4.3): a reusable one, since a
// context.WithTimeout per call cost more than the calls it bounded. Its channel closes
// only on an overrun, which ends the instance anyway, so a spent one is replaced then.
// Loop goroutine only.
type moduleDeadline struct {
	done  chan struct{}
	timer *time.Timer
	fired atomic.Bool
}

func (d *moduleDeadline) Deadline() (time.Time, bool) { return time.Time{}, false }
func (d *moduleDeadline) Done() <-chan struct{}       { return d.done }
func (d *moduleDeadline) Value(any) any               { return nil }
func (d *moduleDeadline) Err() error {
	if d.fired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

// moduleCall is the deadline the next bounded call arms.
var moduleCall = newModuleDeadline()

func newModuleDeadline() *moduleDeadline {
	d := &moduleDeadline{done: make(chan struct{})}
	// An expiry racing a replacement must not close twice.
	d.timer = time.AfterFunc(time.Hour, func() {
		if d.fired.CompareAndSwap(false, true) {
			close(d.done)
		}
	})
	d.timer.Stop()
	return d
}

// armModuleDeadline starts the shared deadline and returns the context to call under.
func armModuleDeadline(after time.Duration) context.Context {
	moduleCall.timer.Reset(after)
	return moduleCall
}

// disarmModuleDeadline stops it, replacing one that fired or is firing: a closed Done
// stays closed. Deferred by the caller, so an engine panic cannot skip it.
func disarmModuleDeadline() {
	if !moduleCall.timer.Stop() {
		moduleCall = newModuleDeadline()
	}
}
