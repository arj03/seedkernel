package main

// What the §4.3 module-call bound costs, which decided it should be on by default (§14.1).
// Arming a runtime compiles a termination check into every loop of every module on it,
// and this measures that check on real wasm: the host's ML-DSA-65 verifier and, opt-in,
// seedstore's Reed-Solomon codec, an installed app module and so the kind of code the bound
// exists for.
//
//	go test -run x -bench BenchmarkBound -benchtime 2s -count 5 ./...
//	SEEDSTORE_CODEC=/path/to/seedstore/WASM/build/codec.wasm go test -run x -bench BenchmarkBound ./...
//
// Both configurations run in one process, so the comparison is not across two builds. The
// ratio between them is the number §14.1 quotes, and the one to re-measure after any wazero
// upgrade: the native binary runs a patched wazero whose termination check is inline instead
// of an exit into Go (see the go.mod replace), and this bench checks that patch still pays.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

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

func BenchmarkBoundMlDsaVerify(b *testing.B) {
	msg := bytes.Repeat([]byte{0x5a}, 4096)
	for _, c := range boundConfigs {
		b.Run(c.name, func(b *testing.B) {
			s := newMlDsaSigner(b, boundRuntime(b, c.armed))
			pk, sk := s.keypair(b, bytes.Repeat([]byte{7}, 32))
			sig := s.signDetached(b, msg, sk)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !s.verifyCtx(b, sig, msg, nil, pk) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

// boundModuleCaller instantiates one §4 pure transform on its own runtime and returns a
// caller with callModule's signature. Not callModule itself, because this bench needs two
// runtimes alive at once (armed and not), which boot()'s single table cannot hold.
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

// boundRSRequests builds the same RS(10,6) encode and single-loss decode setupRS does,
// without a bundle, and checks the decode actually reconstructs the lost block, so a
// configuration that changed the answer could not be reported as a rate.
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

// BenchmarkBoundCallOverhead measures the other half of the bound: what one module call
// costs on the host's own path, the shared §4 ABI (host/pure-module.ts) over the bounded
// engine table, with the shared deadline (engine.go moduleDeadline) a finite guest
// deadline makes engineCallBounded arm and disarm, and without one. The benchmarks above
// measure the compiled checks, which cost per back-edge and so vanish on a call that barely
// loops; this one measures what every call pays however little it does, on the smallest
// real module (the forwarder, which copies its input back) and a 32-byte payload, the size
// of a control frame, where a fixed cost is most visible.
func BenchmarkBoundCallOverhead(b *testing.B) {
	ensureBooted(b)
	if err := buildModules(b, "callcost", []string{"fwd"}, forwarderWasm); err != nil {
		b.Fatalf("the forwarder was refused: %v", err)
	}
	evalString(b, `globalThis.__callCost = async (n, deadlineMs) => {
		const set = __modSets.get("callcost"), payload = new Uint8Array(32).fill(0x7e);
		for (let i = 0; i < n; i++) {
			const r = await set.call("fwd", payload, deadlineMs);
			if (r.bytes === null || r.bytes.length !== 32) throw new Error("forwarder answered wrong");
		}
		return new Uint8Array(0);
	}, ""`)
	for _, c := range []struct{ name, deadline string }{{"noCallDeadline", "Infinity"}, {"callDeadline", "5000"}} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			benchAwait(b, fmt.Sprintf("__callCost(%d, %s)", b.N, c.deadline))
		})
	}
}
