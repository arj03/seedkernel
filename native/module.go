// module.go — the private module table (§3): the wazero runtime every installed app
// module is instantiated on, the opaque slots holding those instances, and the three
// calls host/native-shim.ts makes into them. Modules are pure transforms bounded by
// §4.3 — they import nothing but AssemblyScript's three inert shims and cannot call
// back, so the table is plumbing, never shell identity or routing state.
package main

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type boundModule struct {
	mod     api.Module
	cmod    wazero.CompiledModule // retained so an upgrade can release the old compiled code
	fn      api.Function
	scratch uint32 // §4.1 scratch offset, read once at instantiation
	size    uint32 // bytes reserved there: the declared scratchSize, or the default
}

var (
	// rt holds every installed app module and the env shims they import: the untrusted
	// code the module-call bound arms (bootModuleTable).
	rt wazero.Runtime
	// Native module instances live behind opaque slot handles. This map is target
	// plumbing, not shell identity or routing state.
	moduleSlots = map[string]map[string]*boundModule{}
	// modSeq only names wazero instances (h1, h2, …) so two installs never share a
	// module name; it is not an identity anything resolves through.
	modSeq = 0
)

// The §4.1 scratch default arrives from the shared host (core/wasm-limits.ts
// DEFAULT_SCRATCH_SIZE) with every slot build, so Go owns no copy that could drift from
// the JS table's. A module needing more exports a `scratchSize` global.

// ── the call deadline (§4.3) ────────────────────────────────────────────────────
//
// moduleDeadline is the context one module call runs under, and the whole of what wazero
// reads from it: Done() to watch and Err() to say why. A `context.WithTimeout` per call
// measured at ~580 ns and 5 allocations — 60% of the ~970 ns an armed call costs on this
// machine — and ws.wasm is a module call per WebSocket frame, so the bound was costing more
// than the calls it bounds.
//
// One instance serves every call because the channel closes only when a call actually
// OVERRUNS, and an overrun already ends the module: wazero closed it and callModule evicts
// it below. So a spent instance is replaced on that rare path rather than rebuilt on the
// hot one. Sharing is safe for the same reason `moduleSlots` needs no lock — this file runs
// only on the event-loop goroutine, and a call is synchronous.
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
	// The CAS is belt to disarm's braces: an expiry that races a replacement must not
	// close an already-closed channel.
	d.timer = time.AfterFunc(time.Hour, func() {
		if d.fired.CompareAndSwap(false, true) {
			close(d.done)
		}
	})
	d.timer.Stop()
	return d
}

// armModuleDeadline starts the shared deadline and answers the context to call under.
func armModuleDeadline(after time.Duration) context.Context {
	moduleCall.timer.Reset(after)
	return moduleCall
}

// disarmModuleDeadline stops it, replacing the instance once it has fired — a closed Done
// channel stays closed, so re-arming a spent one would kill the next call the instant it
// began. Stop answering false covers "already firing" as well as "already fired", which is
// why the replacement is keyed on it rather than on the flag. DEFERRED by the caller, so a
// panic out of the engine cannot leave a spent instance armed for the next call.
func disarmModuleDeadline() {
	if !moduleCall.timer.Stop() {
		moduleCall = newModuleDeadline()
	}
}

// bootModuleTable stands the table up: the runtime every installed app module is
// instantiated on, plus the import shims those modules resolve against. Both belong here
// rather than in boot(), which owns engines the table has nothing to do with.
func bootModuleTable() error {
	// WithCloseOnContextDone arms the termination check compiled into every loop of every
	// app module, which is what gives the §4.3 bound teeth. Calls carry the calling guest's
	// own remaining segment.
	rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().
		WithCloseOnContextDone(true))
	// AssemblyScript's three imports, exactly the set the JS host resolves (a subset would
	// make "does this module load" a property of the target). None grants I/O: `seed` is a
	// constant (§4.2) and `trace` drops args (§4.3). `abort` TRAPS — AssemblyScript calls it
	// where the module has declared itself broken, so returning would let it run on past that
	// point, and the same module would fail on the JS targets and continue here.
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

// closeModuleTable releases the table whole: closing the runtime frees every instance and
// its compiled code, and the slot map naming them goes with it. Paired with the above so
// the table's state has ONE teardown — state added beside `rt` and `moduleSlots` is
// released here, not by remembering to add a line to shutdown().
func closeModuleTable() {
	if rt != nil {
		_ = rt.Close(ctx)
		rt = nil
	}
	moduleSlots = map[string]map[string]*boundModule{}
}

// replaceModuleSlot replaces one opaque handle's whole module set. wazero frees neither
// instances nor compiled code, so dropping the map value alone leaks per re-install.
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

// callModule invokes one app's module by logical name (README §4), returning its response
// or nil if nothing is bound there. `deadline` is the calling guest's remaining segment;
// a negative value denotes an unbounded guest. Modules are pure transforms and cannot
// call back, so there is no re-entrancy to guard.
func callModule(slot, module string, payload []byte, deadline time.Duration) []byte {
	w := moduleSlots[slot][module]
	if w == nil {
		return nil
	}
	// §4: write input at scratch, call handle(input_len), read the response back. Both
	// copies are clamped to what the module reserved (§4.1) — writing past it would
	// scribble whatever it keeps beyond scratch.
	mem := w.mod.Memory()
	if uint32(len(payload)) > w.size || mem == nil || !mem.Write(w.scratch, payload) {
		return nil
	}
	// The module instance is long-lived. Once the response has been copied out, erase both
	// the staged request and any longer response (for example an ML-KEM private key).
	wipeLen := len(payload)
	defer func() {
		if b, ok := mem.Read(w.scratch, uint32(wipeLen)); ok {
			clear(b)
		}
	}()
	// The runtime is armed with WithCloseOnContextDone, which is what gives the §4.3
	// bound teeth: a module that never returns is interrupted at its next loop back-edge.
	callCtx := ctx
	if deadline >= 0 {
		callCtx = armModuleDeadline(deadline)
		defer disarmModuleDeadline()
	}
	r, err := w.fn.Call(callCtx, uint64(len(payload)))
	if err != nil {
		// A trap leaves the module alive (retriable); a context-done termination closed
		// it. Evict the wedged one so a reinstall recovers it.
		if w.mod.IsClosed() {
			closeModule(w)
			delete(moduleSlots[slot], module)
		}
		return nil
	}
	// handle returns output_len ≥ 0 (README §4); a 0-length result is a valid EMPTY
	// response and returns a non-nil slice, which is how a caller distinguishes it from
	// "no module / trap" (nil).
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
		// A length past the module's memory is as bogus as an oversized payload — fail
		// rather than return zero-filled bytes.
		b, ok := mem.Read(w.scratch, uint32(len(out)))
		if !ok {
			return nil
		}
		copy(out, b)
	}
	return out
}

// buildModuleSlot constructs one opaque slot's modules, all or none (README §3.1),
// reached from JS as bridge.buildModules. The transaction is here because this is the
// side holding the half-built instances, which a rejected bundle must close itself.
func buildModuleSlot(slot string, names []string, wasms [][]byte, scratchDefault uint32, bindDeadline time.Duration) error {
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
// No slot effect: the result is an intermediate of buildModuleSlot's transaction.
func instantiateWasm(wasm []byte, scratchDefault uint32, bindDeadline time.Duration) (*boundModule, error) {
	cm, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	modSeq++
	// Instantiation runs the module's start section, so a never-returning initializer
	// is bound at BIND the same way module-table.ts bounds its load, at the one place a
	// call-time deadline cannot reach. The context bounds only this invocation.
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
	// Every refusal below has to release the instance *and* its compiled code.
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
	// §4.1: the module reserves [scratch, scratch+size); an exported `scratchSize` is
	// honored only if in-bounds and never below the default. A negative i32 arrives as a
	// huge uint32 the bounds refuse.
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

// installModuleBridge hangs the module half of `bridge` on b, beside the table it drives
// rather than in exposeBridge — the same shape installRealmBridge uses (guest.go).
func installModuleBridge(qc *qjs.Context, b *qjs.Value) {
	// One transactional build of an opaque slot's module set. The §4.1 scratch default
	// arrives from the shared host rather than Go owning a copy of it.
	b.SetPropertyStr("buildModules", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		slot := t.Args()[0].String()
		mods := t.Args()[1]
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
			wb, err := qjs.JsTypedArrayToGo(wv)
			wv.Free()
			m.Free()
			if err != nil {
				return nil, fmt.Errorf("buildModuleSlot: %s: %w", names[i], err)
			}
			wasms[i] = wb
		}
		bindDeadline := time.Duration(t.Args()[3].Int64()) * time.Millisecond
		if err := buildModuleSlot(slot, names, wasms, uint32(t.Args()[2].Int64()), bindDeadline); err != nil {
			return nil, err
		}
		return t.Context().NewNull(), nil
	}))
	b.SetPropertyStr("callModule", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		pl, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return t.Context().NewNull(), nil
		}
		deadline := time.Duration(t.Args()[3].Int64()) * time.Millisecond
		resp := callModule(t.Args()[0].String(), t.Args()[1].String(), pl, deadline)
		if resp == nil {
			return t.Context().NewNull(), nil
		}
		return t.Context().NewArrayBuffer(resp), nil
	}))
	b.SetPropertyStr("disposeModules", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewInt64(int64(disposeModuleSlot(t.Args()[0].String()))), nil
	}))
}
