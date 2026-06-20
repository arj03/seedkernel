package main

// Kernel-pipeline perf for the Go loader: time the full signed-envelope dispatch
// path — parse → match → verify the Ed25519 wrapper (libsodium) → re-dispatch the
// inner envelope → reach the handler. This is the Go counterpart to the "kernel
// pipeline" half of node's testPerf10k (WASM/tests/run.mjs): same 49-byte payloads,
// same `message #N: …` shape, so µs/msg lines up runtime-to-runtime. The "plain
// Ed25519" half is BenchmarkSodiumEd25519Verify; the overhead ratio node prints is
// just BenchmarkKernelDispatch ns/op ÷ that one.
//
//	go test -run x -bench 'BenchmarkKernelDispatch|BenchmarkSodiumEd25519Verify' -benchmem ./...

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
)

// dispatchPoolSize matches node's N=10_000: a distinct signed envelope per slot, so
// the dispatch loop cycles a 10k working set (cache behaviour ~ node) rather than
// re-running one hot message.
const dispatchPoolSize = 10_000

var (
	dispatchOnce sync.Once
	dispatchPool [][]byte // dispatchPoolSize distinct signed chat.text envelopes
	dispatchHits int      // handler invocations, asserted to equal b.N (pipeline ran)
)

// bootOnce shares a single shell boot across every benchmark in the package (boot()
// is a global singleton; re-running it would leak a runtime and reset the kernel's
// handler table out from under already-registered handlers).
var bootOnce sync.Once

func ensureBooted() { bootOnce.Do(boot) }

// setupDispatch wires a chat.text handler onto the booted shell and pre-signs the 10k
// envelope pool. Run via sync.Once so the testing framework's repeated bench
// invocations share one setup.
func setupDispatch() {
	ensureBooted()
	chat := name("chat.text")
	registerNative("chat.text", func([]byte) []byte { dispatchHits++; return nil })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dispatchPool = make([][]byte, dispatchPoolSize)
	for i := range dispatchPool {
		payload := []byte(fmt.Sprintf("message #%d: hello world benchmark payload data", i))
		dispatchPool[i] = sign(priv, pub, chat, payload)
	}
}

func BenchmarkKernelDispatch(b *testing.B) {
	dispatchOnce.Do(setupDispatch)
	before := dispatchHits
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dispatch(dispatchPool[i%dispatchPoolSize])
	}
	b.StopTimer()
	if got := dispatchHits - before; got != b.N {
		b.Fatalf("handler reached %d times, want %d (pipeline dropped messages?)", got, b.N)
	}
}
