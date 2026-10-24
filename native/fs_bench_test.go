package main

// fs.* performance on the native binary: the storage hot path, where a seedstore holder
// turns every FETCH into fs.get and every STORE into fs.put, one ~64 KB block at a time,
// through the shared key store (services/fs-files.ts) over fs.go's file primitive, which is
// the storage guest's actual fs surface. The difference from a bare os.ReadFile is the
// per-block ArrayBuffer copy across JS and Go and the store's own bookkeeping.
//
// Plus BenchmarkFsOpenScan: the store sums its directory at open (one list, then a size per
// file), so that O(N) scan is a startup cost, not a per-request one. The sweep over
// directory size shows its scaling.
//
//	go test -run x -bench BenchmarkFs -benchmem ./...

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// blockBytes is the block size every fs bench moves per op (seedstore's block size).
const blockBytes = 64 * 1024

// The store is synchronous; running b.N ops in one JS loop keeps the el.await cost out of
// the per-op number, as the net benches do.

func BenchmarkFsPut64K(b *testing.B) {
	setupFsJS(b)
	b.SetBytes(blockBytes)
	b.ResetTimer()
	benchAwait(b, fmt.Sprintf("__benchPut(%d)", b.N))
	b.StopTimer()
}

func BenchmarkFsGet64K(b *testing.B) {
	setupFsJS(b)
	b.SetBytes(blockBytes)
	b.ResetTimer()
	benchAwait(b, fmt.Sprintf("__benchGet(%d)", b.N))
	b.StopTimer()
}

// setupFsJS boots the shared shell, uses the process-wide benchmark data dir and writes one
// block, leaving __benchPut/__benchGet ready to run on the shared loop.
func setupFsJS(b *testing.B) {
	ensureBooted(b)
	// Do not re-point the process-wide realm at b.TempDir(): Go removes that directory
	// when this benchmark ends, while later benchmarks still use the same store.
	if _, err := qc.Eval("fs-bench-setup.js", `
		globalThis.__benchBlock = new Uint8Array(65536); __benchBlock.fill(0x5a);
		globalThis.__benchPut = (n) => { for (let i = 0; i < n; i++) fs.put("benchblk", __benchBlock); return new Uint8Array(0); };
		globalThis.__benchGet = (n) => { let acc = 0; for (let i = 0; i < n; i++) { const r = fs.get("benchblk"); if (r && r.length) acc ^= r[0]; } return new Uint8Array([acc & 255]); };
	`); err != nil {
		b.Fatal(err)
	}
	awaitOK(b, "seed put", `__benchPut(1)`, 8*time.Second)
}

// ── the open scan ─────────────────────────────────────────────────────────────

func BenchmarkFsOpenScan(b *testing.B) {
	ensureBooted(b)
	for _, n := range []int{1_000, 10_000} { // 100k shows the cliff but is slow to seed on NTFS
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			dir := b.TempDir()
			for i := 0; i < n; i++ { // n block files (hex stem + .blk, like store-fs.ts)
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%064x.blk", i)), []byte("x"), 0o644); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			benchAwait(b, fmt.Sprintf(`(() => {
				for (let i = 0; i < %d; i++) {
					const s = new FilesFs(__fs, %s).stat();
					if (s.used !== %d) throw new Error("used " + s.used);
				}
				return new Uint8Array(0);
			})()`, b.N, jsonString(dir), n))
		})
	}
}
