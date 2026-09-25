// The driver for the no-import ML-DSA wasm module: instantiate, cross-check its widths,
// and bump-allocate from its linear memory, rewound at the start of each op. Ops are
// serialized by mu.
package main

import (
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// wasmModule is a no-import wasm module plus the bump allocator over its memory.
type wasmModule struct {
	mod      api.Module
	mem      api.Memory
	heapBase uint32
	top      uint32 // bump pointer over the module's own heap, valid only while mu is held
	mu       sync.Mutex
	name     string
}

// newWasmModule instantiates wasm under name and checks each width export, so a module
// built for another parameter set fails at boot.
func newWasmModule(rt wazero.Runtime, name string, wasm []byte, widths map[string]uint64) *wasmModule {
	cm, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		panic(fmt.Sprintf("%s: compile: %v", name, err))
	}
	mod, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName(name).WithStartFunctions())
	if err != nil {
		panic(fmt.Sprintf("%s: instantiate: %v", name, err))
	}
	m := &wasmModule{mod: mod, mem: mod.Memory(), name: name}
	for export, want := range widths {
		f := mod.ExportedFunction(export)
		if f == nil {
			panic(fmt.Sprintf("%s: missing export %q", name, export))
		}
		r, err := f.Call(ctx)
		if err != nil || len(r) != 1 || r[0] != want {
			panic(fmt.Sprintf("%s: %s reported %v, expected %d", name, export, r, want))
		}
	}
	hb := mod.ExportedGlobal("__heap_base")
	if hb == nil {
		panic(fmt.Sprintf("%s: missing __heap_base", name))
	}
	m.heapBase = uint32(hb.Get())
	return m
}

// reset rewinds the bump pointer. Call once at the top of every op, under mu.
func (m *wasmModule) reset() { m.top = m.heapBase }

// alloc sub-allocates n 16-aligned bytes, growing linear memory if needed.
func (m *wasmModule) alloc(n int) uint32 {
	// Widened, so neither the align nor the add can wrap.
	p := (uint64(m.top) + 15) &^ 15
	if n < 0 || p > uint64(^uint32(0)) || uint64(n) > uint64(^uint32(0))-p {
		panic(fmt.Sprintf("%s: allocation out of range", m.name))
	}
	top := p + uint64(n)
	// Size wraps at 4 GiB; the page count returned by Grow(0) does not.
	pages, _ := m.mem.Grow(0)
	if size := uint64(pages) * 0x10000; top > size {
		if _, ok := m.mem.Grow(uint32((top - size + 0xffff) / 0x10000)); !ok {
			panic(fmt.Sprintf("%s: out of memory", m.name))
		}
	}
	m.top = uint32(top)
	return uint32(p)
}

// put is alloc plus a copy of b into the sub-allocation.
func (m *wasmModule) put(b []byte) uint32 {
	p := m.alloc(len(b))
	if !m.mem.Write(p, b) {
		panic(fmt.Sprintf("%s: memory write out of range", m.name))
	}
	return p
}
