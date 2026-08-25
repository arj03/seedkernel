// wasmmod.go — the driver for the no-import ML-DSA wasm module: instantiate the artifact,
// cross-check its constant-width exports, and hand out buffers from its own linear memory
// with a bump pointer. The module does not allocate or retain anything across a call, so
// a rewind at the start of each op is the whole memory manager and there is no free list
// to corrupt. Ops are serialized by mu — held for one
// call, never across a callback into JS or Go.
package main

import (
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// wasmModule is a no-import wasm module plus the bump allocator over its memory.
// name feeds the error messages ("mldsa65").
type wasmModule struct {
	mod      api.Module
	mem      api.Memory
	heapBase uint32
	top      uint32 // bump pointer over the module's own heap, valid only while mu is held
	mu       sync.Mutex
	name     string
}

// newWasmModule compiles and instantiates wasm under name (no imports, no start functions)
// and cross-checks the constant-width exports against want. A module built for another
// parameter set would otherwise look like a working implementation until a real bundle
// arrived, so it fails at boot instead.
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
		if err != nil || r[0] != want {
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

// alloc sub-allocates n 16-aligned bytes from the module's own heap, growing
// linear memory if needed.
func (m *wasmModule) alloc(n int) uint32 {
	p := (m.top + 15) &^ 15
	m.top = p + uint32(n)
	if need := int64(m.top) - int64(m.mem.Size()); need > 0 {
		if _, ok := m.mem.Grow(uint32(need/0x10000) + 1); !ok {
			panic(fmt.Sprintf("%s: out of memory", m.name))
		}
	}
	return p
}

// put is alloc plus a copy of b into the sub-allocation.
func (m *wasmModule) put(b []byte) uint32 {
	p := m.alloc(len(b))
	if !m.mem.Write(p, b) {
		panic(fmt.Sprintf("%s: memory write out of range", m.name))
	}
	return p
}
