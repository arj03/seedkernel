package main

// Perf benchmarks for the Go loader's crypto primitives, to compare runtime-to-runtime
// against node. Ed25519 verify and XChaCha20 run on loader/wasm/libsodium.wasm under
// wazero — the same wasm node runs under V8; BLAKE2b is native Go (see sodium.go). The
// node counterparts that time the same primitives are the "plain Ed25519" line of
// WASM/tests/run.mjs (testPerf10k) and seedstore's WASM/tests/bench.mjs (which times
// BLAKE2b + XChaCha20 alongside its Reed–Solomon throughput).
//
//	go test -run x -bench BenchmarkSodium -benchmem ./...

import (
	"bytes"
	"testing"

	"github.com/tetratelabs/wazero"
)

// benchSodium stands up an isolated libsodium for a benchmark (mirrors newSodium in
// sodium_test.go, but takes a *testing.B).
func benchSodium(b *testing.B) *libsodium {
	b.Helper()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	b.Cleanup(func() { rt.Close(ctx) })
	return bootSodium(rt)
}

// benchMsg is ~49 B, matching the payload the 10k-signature bench signs/verifies.
var benchMsg = []byte("message #4242: hello world benchmark payload data")

func BenchmarkSodiumEd25519Verify(b *testing.B) {
	s := benchSodium(b)
	pk, sk := s.signSeedKeypair(bytes.Repeat([]byte{7}, 32))
	sig := s.signDetached(benchMsg, sk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !s.verifyDetached(sig, benchMsg, pk) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkSodiumBlake2b64K(b *testing.B) {
	s := benchSodium(b)
	block := bytes.Repeat([]byte{0x5a}, 64*1024)
	b.SetBytes(int64(len(block)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.genericHash(32, block)
	}
}

func BenchmarkSodiumXChaCha20_640K(b *testing.B) {
	s := benchSodium(b)
	data := bytes.Repeat([]byte{0x11}, 640*1024)
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x24}, 24)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.streamXor(data, nonce, key)
	}
}
