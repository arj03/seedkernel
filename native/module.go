// The private module table (§3): the wazero runtime app modules run on, the opaque slots
// holding their instances, and the calls host/native-shim.ts makes into them. Modules are
// pure transforms (§4.3) and cannot call back.
package main

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"seedkernel/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type boundModule struct {
	mod     api.Module
	cmod    wazero.CompiledModule
	fn      api.Function
	scratch uint32 // §4.1 scratch offset
	size    uint32 // bytes reserved there: scratchSize, or the default
}

var (
	// rt holds every installed app module and the env shims they import.
	rt          wazero.Runtime
	moduleSlots = map[string]map[string]*boundModule{}
	// modSeq names wazero instances (h1, h2, …) so two installs never collide.
	modSeq = 0
)

// moduleDeadline is the context a module call runs under (§4.3): a reusable one, since a
// context.WithTimeout per call cost more than the calls it bounded. Its channel closes
// only on an overrun, which ends the module anyway, so a spent instance is replaced then.
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

// disarmModuleDeadline stops it, replacing an instance that fired or is firing: a closed
// Done stays closed. Deferred by the caller, so an engine panic cannot skip it.
func disarmModuleDeadline() {
	if !moduleCall.timer.Stop() {
		moduleCall = newModuleDeadline()
	}
}

// bootModuleTable stands up the app module runtime and the imports it resolves.
func bootModuleTable() error {
	// WithCloseOnContextDone compiles in the check that enforces the §4.3 bound.
	rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().
		WithCloseOnContextDone(true))
	// AssemblyScript's three imports, as the JS host resolves them. `seed` is a constant
	// (§4.2), `trace` drops its args (§4.3), and `abort` traps.
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, line, col uint32) {
		panic(fmt.Sprintf("module abort at %d:%d", line, col))
	}).Export("abort")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module) float64 { return 0 }).Export("seed")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, float64, float64, float64, float64, float64) {}).Export("trace")
	if _, err := env.Instantiate(ctx); err != nil {
		return fmt.Errorf("module imports: %w", err)
	}
	return nil
}

// closeModuleTable releases the runtime, every instance and the slot map.
func closeModuleTable() {
	if rt != nil {
		_ = rt.Close(ctx)
		rt = nil
	}
	moduleSlots = map[string]map[string]*boundModule{}
}

// replaceModuleSlot replaces one handle's module set, closing the old one.
func replaceModuleSlot(slot string, mods map[string]*boundModule) {
	disposeModuleSlot(slot)
	moduleSlots[slot] = mods
}

// closeModule releases a module's wasm instance and compiled code. nil-safe.
func closeModule(w *boundModule) {
	if w == nil {
		return
	}
	_ = w.mod.Close(ctx)
	_ = w.cmod.Close(ctx)
}

// disposeModuleSlot releases every instance behind one opaque handle.
func disposeModuleSlot(slot string) int {
	mods := moduleSlots[slot]
	for _, w := range mods {
		closeModule(w)
	}
	delete(moduleSlots, slot)
	return len(mods)
}

// callModule invokes one app's module by name (§4), returning its response, or nil if
// nothing is bound or the call failed. A negative `deadline` is unbounded.
func callModule(slot, module string, payload []byte, deadline time.Duration) []byte {
	w := moduleSlots[slot][module]
	if w == nil {
		return nil
	}
	// §4: write input at scratch, call handle(input_len), read the response back, both
	// clamped to the reserved size (§4.1).
	mem := w.mod.Memory()
	if uint64(len(payload)) > uint64(w.size) || mem == nil || !mem.Write(w.scratch, payload) {
		return nil
	}
	// The instance is long-lived, so wipe the request and response once copied out.
	wipeLen := len(payload)
	defer func() {
		if b, ok := mem.Read(w.scratch, uint32(wipeLen)); ok {
			clear(b)
		}
	}()
	callCtx := ctx
	if deadline >= 0 {
		callCtx = armModuleDeadline(deadline)
		defer disarmModuleDeadline()
	}
	r, err := w.fn.Call(callCtx, uint64(len(payload)))
	if err != nil {
		// A trap leaves the module alive; a deadline closed it, so evict it.
		if w.mod.IsClosed() {
			closeModule(w)
			delete(moduleSlots[slot], module)
		}
		return nil
	}
	// An empty response is a non-nil slice, distinct from failure (nil).
	if len(r) == 0 {
		return nil
	}
	outLen := int32(r[0])
	if outLen < 0 || uint32(outLen) > w.size {
		return nil
	}
	if int(outLen) > wipeLen {
		wipeLen = int(outLen)
	}
	out := make([]byte, outLen)
	if len(out) > 0 {
		b, ok := mem.Read(w.scratch, uint32(len(out)))
		if !ok {
			return nil
		}
		copy(out, b)
	}
	return out
}

// buildModuleSlot builds one slot's modules, all or none (§3.1).
func buildModuleSlot(slot string, names []string, wasms [][]byte, scratchDefault uint32, bindDeadline time.Duration) error {
	// bundle.ts refuses duplicates already; a duplicate here would leak an instance.
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("duplicate module name %q", name)
		}
		seen[name] = struct{}{}
	}
	built := make(map[string]*boundModule, len(wasms))
	for i, wasm := range wasms {
		w, err := instantiateWasm(wasm, scratchDefault, bindDeadline)
		if err != nil {
			for _, h := range built {
				closeModule(h)
			}
			return fmt.Errorf("%s: %w", names[i], err)
		}
		built[names[i]] = w
	}
	// Nothing above touched the table and nothing below can fail.
	replaceModuleSlot(slot, built)
	return nil
}

// instantiateWasm compiles, instantiates and validates module bytes against the §4 ABI.
func instantiateWasm(wasm []byte, scratchDefault uint32, bindDeadline time.Duration) (*boundModule, error) {
	cm, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	modSeq++
	// Instantiation runs the start section, bound like module-table.ts bounds its load.
	instCtx, cancel := ctx, func() {}
	if bindDeadline >= 0 {
		instCtx, cancel = context.WithTimeout(ctx, bindDeadline)
	}
	m, err := rt.InstantiateModule(instCtx, cm, wazero.NewModuleConfig().WithName(fmt.Sprintf("h%d", modSeq)))
	cancel()
	if err != nil {
		_ = cm.Close(ctx)
		return nil, fmt.Errorf("instantiate: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = m.Close(ctx)
			_ = cm.Close(ctx)
		}
	}()
	g, fn := m.ExportedGlobal("scratch"), m.ExportedFunction("handle")
	if g == nil || fn == nil || m.Memory() == nil {
		return nil, fmt.Errorf("missing exports: memory=%v scratch=%v handle=%v", m.Memory() != nil, g != nil, fn != nil)
	}
	// §4.1: the module reserves [scratch, scratch+size); an exported `scratchSize` must be
	// in bounds and at least the default.
	mem, s := uint64(m.Memory().Size()), uint32(g.Get())
	if s == 0 || uint64(s)+uint64(scratchDefault) > mem {
		return nil, fmt.Errorf("scratch offset %d out of bounds (mem %d)", s, mem)
	}
	size := scratchDefault
	if sg := m.ExportedGlobal("scratchSize"); sg != nil {
		d := uint32(sg.Get())
		if d < scratchDefault {
			return nil, fmt.Errorf("scratchSize %d is below the %d default", d, scratchDefault)
		}
		if uint64(s)+uint64(d) > mem {
			return nil, fmt.Errorf("scratchSize %d overflows memory (scratch %d, mem %d)", d, s, mem)
		}
		size = d
	}
	ok = true
	return &boundModule{m, cm, fn, s, size}, nil
}

// installModuleBridge adds the module-table calls to `bridge`.
func installModuleBridge(qc *qjs.Context, b *qjs.Value) {
	b.SetPropertyStr("buildModules", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		slot := args[0].String()
		mods := args[1]
		lenv := mods.GetPropertyStr("length")
		n := int(lenv.Int64())
		lenv.Free()
		names := make([]string, n)
		wasms := make([][]byte, n)
		for i := 0; i < n; i++ {
			m := mods.GetPropertyStr(strconv.Itoa(i))
			nv := m.GetPropertyStr("name")
			names[i] = nv.String()
			nv.Free()
			wv := m.GetPropertyStr("wasm")
			wb, err := wv.Bytes()
			wv.Free()
			m.Free()
			if err != nil {
				return nil, fmt.Errorf("buildModuleSlot: %s: %w", names[i], err)
			}
			wasms[i] = wb
		}
		bindDeadline := time.Duration(args[3].Int64()) * time.Millisecond
		if err := buildModuleSlot(slot, names, wasms, uint32(args[2].Int64()), bindDeadline); err != nil {
			return nil, err
		}
		return qc.NewNull(), nil
	}))
	b.SetPropertyStr("callModule", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		slot, module := args[0].String(), args[1].String()
		deadline := time.Duration(args[3].Int64()) * time.Millisecond
		// Borrowed last (qjs.Value.View).
		pl, err := args[2].View()
		if err != nil {
			return qc.NewNull(), nil
		}
		resp := callModule(slot, module, pl, deadline)
		if resp == nil {
			return qc.NewNull(), nil
		}
		return qc.NewArrayBuffer(resp), nil
	}))
	b.SetPropertyStr("disposeModules", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewInt64(int64(disposeModuleSlot(args[0].String()))), nil
	}))
}
