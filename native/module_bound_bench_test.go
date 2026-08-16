package main

// module_bound_bench_test.go — what the §4.3 module-call bound COSTS, which is what
// decided it should be a default (SECURITY §14.1). Arming a wazero runtime with
// WithCloseOnContextDone compiles a termination check into every loop of every module on
// it, and this file prices that check on real module-shaped wasm: libsodium's XChaCha20
// and Ed25519 (the TCB's own crypto, for comparison against the numbers in
// sodium_bench_test.go) and, opt-in, seedstore's Reed–Solomon codec — an installed app
// module, which is the code the bound actually exists to stop.
//
//	go test -run x -bench BenchmarkBound -benchtime 2s -count 5 ./...
//	SEEDSTORE_CODEC=/path/to/seedstore/WASM/build/codec.wasm go test -run x -bench BenchmarkBound ./...
//
// Both configurations run in one process so a comparison is not across two builds:
// `unarmed` is a stock runtime (what an unbounded deployment runs), `armed` is the same
// wasm on a runtime with the bound armed. The ratio between them is the number
// SECURITY §14.1 quotes, and the one to re-measure after any wazero bump — the loader
// runs a patched wazero whose back-edge check is inline rather than an exit into Go,
// keeping only a rare unconditional exit as the loop's GC safepoint (see the go.mod
// replace), and that patch is exactly what this bench keeps honest.

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// boundConfigs are the two runtimes every benchmark below runs on.
var boundConfigs = []struct {
	name  string
	armed bool
}{{"unarmed", false}, {"armed", true}}

func boundRuntime(b *testing.B, armed bool) wazero.Runtime {
	b.Helper()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(armed))
	b.Cleanup(func() { rt.Close(context.Background()) })
	return rt
}

func BenchmarkBoundXChaCha20_640K(b *testing.B) {
	data := bytes.Repeat([]byte{0x11}, 640*1024)
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x24}, 24)
	for _, c := range boundConfigs {
		b.Run(c.name, func(b *testing.B) {
			s := bootSodium(boundRuntime(b, c.armed))
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.streamXor(data, nonce, key)
			}
		})
	}
}

func BenchmarkBoundEd25519Verify(b *testing.B) {
	for _, c := range boundConfigs {
		b.Run(c.name, func(b *testing.B) {
			s := bootSodium(boundRuntime(b, c.armed))
			pk, sk := s.signSeedKeypair(bytes.Repeat([]byte{7}, 32))
			sig := s.signDetached(benchMsg, sk)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !s.verifyDetached(sig, benchMsg, pk) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

// boundModuleCaller instantiates one §4 pure transform on its own runtime and returns a
// caller with callModule's shape. Deliberately not callModule itself: this bench needs
// two runtimes alive at once (armed and not), which boot()'s single table cannot hold.
func boundModuleCaller(b *testing.B, wasmBytes []byte, armed bool) func(payload []byte) []byte {
	b.Helper()
	rt := boundRuntime(b, armed)
	// The AssemblyScript shims boot() resolves, same set and same inertness.
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) {}).Export("abort")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module) float64 { return 0 }).Export("seed")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, float64, float64, float64, float64, float64) {}).Export("trace")
	if _, err := env.Instantiate(ctx); err != nil {
		b.Fatalf("env imports: %v", err)
	}
	m, err := rt.Instantiate(ctx, wasmBytes)
	if err != nil {
		b.Fatalf("instantiate: %v", err)
	}
	scratch, size := uint32(m.ExportedGlobal("scratch").Get()), uint32(m.ExportedGlobal("scratchSize").Get())
	fn, mem := m.ExportedFunction("handle"), m.Memory()
	return func(payload []byte) []byte {
		if uint32(len(payload)) > size || !mem.Write(scratch, payload) {
			b.Fatalf("payload %d B does not fit scratch %d B", len(payload), size)
		}
		r, err := fn.Call(ctx, uint64(len(payload)))
		if err != nil {
			b.Fatalf("handle: %v", err)
		}
		out := make([]byte, int32(r[0]))
		got, _ := mem.Read(scratch, uint32(len(out)))
		copy(out, got)
		return out
	}
}

// boundRSRequests stages the same RS(10,6) encode and single-loss decode setupRS does,
// without a bundle — and checks the decode actually reconstructs the lost block, so a
// configuration that changed the ANSWER could not be reported as a rate.
func boundRSRequests(b *testing.B, call func([]byte) []byte) (enc, dec []byte) {
	b.Helper()
	data := make([]byte, rsK*rsBS)
	for i := range data {
		data[i] = byte(i*1103515245 + 12345)
	}
	enc = make([]byte, 7+len(data))
	enc[0], enc[1], enc[2] = 1, rsK, rsM // OP_ENCODE
	binary.BigEndian.PutUint32(enc[3:7], rsBS)
	copy(enc[7:], data)
	parity := call(enc)
	if len(parity) != rsM*rsBS {
		b.Fatalf("encode returned %d B, want %d", len(parity), rsM*rsBS)
	}

	cnt := rsK
	dec = make([]byte, 8+cnt+cnt*rsBS)
	dec[0], dec[1], dec[2] = 2, rsK, rsM // OP_DECODE, data block 0 lost
	binary.BigEndian.PutUint32(dec[3:7], rsBS)
	dec[7] = byte(cnt)
	rows, blocks := dec[8:8+cnt], dec[8+cnt:]
	for r := 0; r < rsK-1; r++ { // surviving data rows 1..k-1
		rows[r] = byte(r + 1)
		copy(blocks[r*rsBS:], data[(r+1)*rsBS:(r+2)*rsBS])
	}
	rows[rsK-1] = byte(rsK) // first parity row
	copy(blocks[(rsK-1)*rsBS:], parity[:rsBS])
	if out := call(dec); len(out) != rsK*rsBS || !bytes.Equal(out[:rsBS], data[:rsBS]) {
		b.Fatalf("decode did not reconstruct block 0 (%d B out)", len(out))
	}
	return enc, dec
}

func benchBoundRS(b *testing.B, decode bool) {
	path := os.Getenv("SEEDSTORE_CODEC")
	if path == "" {
		b.Skip("seedstore codec not configured (set SEEDSTORE_CODEC to a built codec.wasm)")
	}
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("SEEDSTORE_CODEC=%s: %v", path, err)
	}
	for _, c := range boundConfigs {
		b.Run(c.name, func(b *testing.B) {
			call := boundModuleCaller(b, wasmBytes, c.armed)
			enc, dec := boundRSRequests(b, call)
			req := enc
			if decode {
				req = dec
			}
			b.SetBytes(rsK * rsBS)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				call(req)
			}
		})
	}
}

func BenchmarkBoundRSEncode(b *testing.B) { benchBoundRS(b, false) }
func BenchmarkBoundRSDecode(b *testing.B) { benchBoundRS(b, true) }

// BenchmarkBoundCallOverhead prices the OTHER half of the default (main.go
// defaultModuleCallDeadline): the per-call `context.WithTimeout` that a bound deadline
// makes callModule build, where an unbound one took a no-op branch. The benchmarks
// above measure the compiled checks, which are billed per back-edge and so are
// invisible on a call that barely loops; this one measures what every call pays no
// matter how little it does, on the smallest real module there is (the forwarder,
// which copies its input back) and a 32-byte payload — the shape of a control frame,
// where a fixed cost has nothing to hide behind.
//
// Both arms run against ONE boot, so the runtime is armed in both and only the context
// differs. That is deliberate: it isolates the context, which is the part the loader
// controls. wazero spawns a watchdog goroutine and channel per call whenever the
// runtime is armed, whatever context it is handed (internal/wasm module_instance.go
// CloseModuleOnCanceledOrTimeout), so that cost is in both arms and is not what this
// measures. Measured ~345 ns → ~950 ns, 6 → 11 allocs: a fixed ~600 ns that a bound
// deployment pays per call, against ~30 µs for the hop the JS targets pay per call for
// the same bound, and against ~400 µs for the RS calls it actually sits in front of.
// If a genuinely chatty module ever lands, the fix is to stop rebuilding the timeout
// per call rather than to give the bound up.
func BenchmarkBoundCallOverhead(b *testing.B) {
	bootRealm(b)
	key := appKeyFor(bytes.Repeat([]byte{0x5b}, 32), "callcost")
	if err := bindAll(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000); err != nil {
		b.Fatalf("bindAll refused: %v", err)
	}
	payload := bytes.Repeat([]byte{0x7e}, 32)
	saved := moduleCallDeadline
	b.Cleanup(func() { moduleCallDeadline = saved })

	for _, c := range []struct {
		name     string
		deadline time.Duration
	}{{"noCallDeadline", 0}, {"callDeadline", defaultModuleCallDeadline}} {
		b.Run(c.name, func(b *testing.B) {
			moduleCallDeadline = c.deadline
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if r := callModule(key, "fwd", payload); len(r) != len(payload) {
					b.Fatalf("forwarder returned %d B, want %d", len(r), len(payload))
				}
			}
		})
	}
}
