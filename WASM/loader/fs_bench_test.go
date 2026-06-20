package main

// fs.* perf for the Go loader — the storage hot path. A seedstore holder turns every
// FETCH into store.get → fs.get → os.ReadFile and every STORE into a content-hash
// check + store.put → fs.put → os.WriteFile (storage-node.ts handleRequest), one ~64 KB
// block at a time (§27). These benches time that block I/O at two levels, mirroring how
// the crypto benches split the raw primitive from the dispatch pipeline:
//
//   - BenchmarkNodeFs{Get,Put}64K — the bare Go nodeFs (disk + the fsKeySafe regex).
//     Report MB/s so it lines up next to the BLAKE2b/XChaCha20 rates: that comparison
//     is what tells you whether GET is disk-bound or crypto-bound.
//   - BenchmarkFs{Get,Put}JS64K — the same op through the QuickJS shim (fs.go exposeFs),
//     so the delta over the bare Go number is the per-block ArrayBuffer copy the storage
//     guest actually pays on the JS↔Go boundary.
//
// Plus BenchmarkNodeFsOpenScan: FsBlobStore rebuilds its in-memory index at open by
// listing the fs once and stat-ing every block (store-fs.ts) — has/list/stat then never
// touch the backend, so this O(N) scan is a node-startup cost, not per-request. The
// sweep over directory size shows that scaling.
//
// These are loader-internal numbers: node uses node:fs, so unlike the crypto/RS benches
// there's no byte-identical cross-runtime twin to compare against.
//
//	go test -run x -bench 'BenchmarkNodeFs|BenchmarkFs' -benchmem ./...

import (
	"bytes"
	"fmt"
	"testing"

	"seedloader/qjs"
)

// blockBytes is the §27 block size every fs bench moves per op.
const blockBytes = 64 * 1024

func benchBlock() []byte { return bytes.Repeat([]byte{0x5a}, blockBytes) }

// ── bare Go nodeFs ─────────────────────────────────────────────────────────

func BenchmarkNodeFsPut64K(b *testing.B) {
	fs, err := newNodeFs(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	block := benchBlock()
	b.SetBytes(blockBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := fs.put("benchblk", block); err != nil { // overwrite: steady-state write throughput
			b.Fatal(err)
		}
	}
}

func BenchmarkNodeFsGet64K(b *testing.B) {
	fs, err := newNodeFs(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	block := benchBlock()
	if err := fs.put("benchblk", block); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(blockBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := fs.get("benchblk"); len(got) != blockBytes { // reads back through the OS page cache (hot block)
			b.Fatalf("get returned %d bytes, want %d", len(got), blockBytes)
		}
	}
}

// ── through the QuickJS shim (the storage guest's actual fs surface) ─────────

func BenchmarkFsPutJS64K(b *testing.B) {
	put := setupFsJS(b)
	und := qc.NewUndefined()
	b.SetBytes(blockBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := qc.Invoke(put, und)
		if err != nil {
			b.Fatal(err)
		}
		r.Free()
	}
}

func BenchmarkFsGetJS64K(b *testing.B) {
	_ = setupFsJS(b)
	get := qc.Global().GetPropertyStr("__benchGet")
	und := qc.NewUndefined()
	b.SetBytes(blockBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := qc.Invoke(get, und) // each call rebuilds a Uint8Array from the Go bytes
		if err != nil {
			b.Fatal(err)
		}
		r.Free()
	}
}

// setupFsJS boots the shared shell, wires fs.go's `fs` object onto a fresh data dir,
// seeds one block, and returns the retained __benchPut function (callers fetch
// __benchGet themselves). The boot is shared via ensureBooted, like the dispatch bench.
func setupFsJS(b *testing.B) *qjs.Value {
	ensureBooted()
	if err := exposeFs(qc, b.TempDir()); err != nil {
		b.Fatal(err)
	}
	if _, err := qc.Eval("fs-bench-setup.js", qjs.Code(`
		globalThis.__benchBlock = new Uint8Array(65536); __benchBlock.fill(0x5a);
		fs.put("benchblk", __benchBlock);
		globalThis.__benchGet = () => fs.get("benchblk");
		globalThis.__benchPut = () => fs.put("benchblk", __benchBlock);
	`)); err != nil {
		b.Fatal(err)
	}
	return qc.Global().GetPropertyStr("__benchPut")
}

// ── node-open index scan (FsBlobStore constructor: one ReadDir + N stats) ────

func BenchmarkNodeFsOpenScan(b *testing.B) {
	for _, n := range []int{1_000, 10_000} { // 100k shows the cliff but is slow to seed on NTFS
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			fs, err := newNodeFs(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			for i := 0; i < n; i++ { // seed n block files (hex stem + .blk, like store-fs.ts)
				if err := fs.put(fmt.Sprintf("%064x.blk", i), []byte("x")); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				keys := fs.list("") // the open scan: list the dir, then stat every entry
				used := 0
				for _, k := range keys {
					used += fs.size(k)
				}
				if len(keys) != n {
					b.Fatalf("listed %d keys, want %d", len(keys), n)
				}
			}
		})
	}
}
