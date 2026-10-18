// The engine table (the platform ABI's engine calls): instantiate a wasm module from bytes,
// call its exports with numbers, and read and write its memory. It knows nothing of what
// runs inside; the shared realm driver (host/engine-realm.ts) builds guest realms on it
// from qjs.wasm. An import outside WASI calls the JS function the instantiation names for
// it, as WebAssembly's importObject does. WASI is answered as a realm's is (qjs.go): the
// clock and nothing else.
package main

import (
	"context"
	"errors"
	"fmt"

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
	imports []*qjs.Value // retained import handlers, freed on dispose
	pools   []*enginePool // by export handle (engineExport)
}

// enginePool is one export's free list of resolved functions and their stacks: a call can
// re-enter the same export through an import, and each in-flight call needs its own stack.
type enginePool struct {
	name    string
	free    []engineFn
	params  []api.ValueType
	results []api.ValueType
}

type engineFn struct {
	fn    api.Function
	stack []uint64
}

func installEngineBridge(qc *qjs.Context, b *qjs.Value) {
	b.SetPropertyStr("engineInstantiate", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		bytes, err := args[0].Bytes()
		if err != nil {
			return nil, err
		}
		e, err := newEngineInstance(qc, bytes, args[1])
		if err != nil {
			return nil, err
		}
		engineSeq++
		engines[engineSeq] = e
		return qc.NewInt64(engineSeq), nil
	}))
	b.SetPropertyStr("engineExport", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		e := engines[args[0].Int64()]
		if e == nil {
			return nil, errors.New("engine: no such instance")
		}
		h, err := e.export(args[1].String())
		if err != nil {
			return nil, err
		}
		return qc.NewInt32(int32(h)), nil
	}))
	b.SetPropertyStr("engineCall", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		e := engines[args[0].Int64()]
		if e == nil {
			return nil, errors.New("engine: no such instance")
		}
		return e.call(qc, args[1].Int64(), args[2:])
	}))
	b.SetPropertyStr("engineRead", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		e := engines[args[0].Int64()]
		if e == nil {
			return nil, errors.New("engine: no such instance")
		}
		view, ok := e.mem.Read(uint32(args[1].Int64()), uint32(args[2].Int64()))
		if !ok {
			return nil, errors.New("engine: read out of bounds")
		}
		return qc.NewArrayBuffer(view), nil
	}))
	b.SetPropertyStr("engineWrite", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		e := engines[args[0].Int64()]
		if e == nil {
			return nil, errors.New("engine: no such instance")
		}
		ptr := uint32(args[1].Int64())
		// Borrowed last (qjs.Value.View).
		bytes, err := args[2].View()
		if err != nil {
			return nil, err
		}
		if !e.mem.Write(ptr, bytes) {
			return nil, errors.New("engine: write out of bounds")
		}
		return nil, nil
	}))
	b.SetPropertyStr("engineGlobal", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		e := engines[args[0].Int64()]
		if e == nil {
			return nil, errors.New("engine: no such instance")
		}
		g := e.mod.ExportedGlobal(args[1].String())
		if g == nil {
			return qc.NewNull(), nil
		}
		return numberToJS(qc, g.Type(), g.Get()), nil
	}))
	b.SetPropertyStr("engineGrow", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		e := engines[args[0].Int64()]
		if e == nil {
			return nil, errors.New("engine: no such instance")
		}
		before, ok := e.mem.Grow(uint32(args[1].Int64()))
		if !ok {
			return qc.NewInt32(-1), nil
		}
		return qc.NewInt64(int64(before)), nil
	}))
	// The wasm the host script runs on the table: the running host blob's own.
	for name, wasm := range map[string]func() []byte{
		"qjsWasm":    func() []byte { return host.qjs },
		"sodiumWasm": func() []byte { return host.sodium },
		"mldsaWasm":  func() []byte { return host.mldsa },
	} {
		b.SetPropertyStr(name, qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
			return qc.NewArrayBuffer(wasm()), nil
		}))
	}
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
func newEngineInstance(qc *qjs.Context, bytes []byte, importObject *qjs.Value) (_ *engineInstance, err error) {
	e := &engineInstance{}
	// The process-wide cache the host realm compiled qjs.wasm into, so every realm runs
	// one copy of the engine's machine code.
	e.rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(qjs.SharedCache()))
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
	if err := qjs.InstantiateWASI(ctx, e.rt, imports); err != nil {
		return nil, fmt.Errorf("engine: WASI: %w", err)
	}
	builders := map[string]wazero.HostModuleBuilder{}
	for _, def := range imports {
		module, name, _ := def.Import()
		if module == "wasi_snapshot_preview1" {
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
	cfg := wazero.NewModuleConfig().WithName("")
	if code.ExportedFunctions()["_initialize"] != nil {
		cfg = cfg.WithStartFunctions("_initialize")
	}
	if e.mod, err = e.rt.InstantiateModule(ctx, code, cfg); err != nil {
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
	case api.ValueTypeF32:
		return qc.NewFloat64(float64(api.DecodeF32(v)))
	default:
		// An i64 would need a BigInt on every target; the ABI has none.
		panic("engine: i64 values do not cross the engine table")
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
	case api.ValueTypeF32:
		return api.EncodeF32(float32(v.Int64()))
	default:
		panic("engine: i64 values do not cross the engine table")
	}
}

// export resolves an export to the handle engineCall takes.
func (e *engineInstance) export(name string) (int, error) {
	fn := e.mod.ExportedFunction(name)
	if fn == nil {
		return 0, fmt.Errorf("engine: no export %q", name)
	}
	def := fn.Definition()
	p := &enginePool{name: name, params: def.ParamTypes(), results: def.ResultTypes()}
	p.free = append(p.free, p.newFn(fn))
	e.pools = append(e.pools, p)
	return len(e.pools) - 1, nil
}

// call runs export `handle` with numeric arguments and answers its result as a number.
// Arguments past the export's parameters are ignored, so a caller can pass a fixed count.
func (e *engineInstance) call(qc *qjs.Context, handle int64, args []*qjs.Value) (*qjs.Value, error) {
	if e.mod == nil || e.mod.IsClosed() {
		return nil, errors.New("engine: instance is closed")
	}
	if handle < 0 || handle >= int64(len(e.pools)) {
		return nil, errors.New("engine: no such export handle")
	}
	p := e.pools[handle]
	if len(args) < len(p.params) {
		return nil, fmt.Errorf("engine: %s takes %d arguments, not %d", p.name, len(p.params), len(args))
	}
	var f engineFn
	if n := len(p.free); n > 0 {
		f, p.free = p.free[n-1], p.free[:n-1]
	} else {
		f = p.newFn(e.mod.ExportedFunction(p.name))
	}
	for i, t := range p.params {
		f.stack[i] = numberFromJS(t, args[i])
	}
	err := f.fn.CallWithStack(ctx, f.stack)
	res := f.stack[0]
	p.free = append(p.free, f)
	if err != nil {
		return nil, fmt.Errorf("engine: %s trapped: %w", p.name, err)
	}
	if len(p.results) == 0 {
		return nil, nil
	}
	return numberToJS(qc, p.results[0], res), nil
}

func (p *enginePool) newFn(fn api.Function) engineFn {
	return engineFn{fn: fn, stack: make([]uint64, max(len(p.params), len(p.results), 1))}
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
