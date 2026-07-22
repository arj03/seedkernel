package main

// Reed–Solomon codec perf for the Go loader. RS isn't a libsodium primitive — it
// lives in the seedstore repo's codec.wasm (AssemblyScript GF(2^8) erasure coding) —
// but the loader runs that same wasm through the installed `seedstore:codec` handler,
// so its encode/decode throughput is comparable runtime-to-runtime against the node
// numbers from seedstore/WASM/tests/bench.mjs. Same shape as that bench: RS(10,6),
// 64 KB blocks, 640 KB of data per chunk; throughput is reported over data bytes
// (b.SetBytes(k*bs)), matching bench.mjs's rate() which divides by the data size.
//
// RS lives in the seedstore repo, so this bench is opt-in: point SEEDSTORE_BUNDLE at a
// built seedstore bundle BLOB to run it; with the var unset the benchmarks Skip. The
// loader itself has no seedstore dependency (its own tests use a minimal in-repo bundle).
//
//	SEEDSTORE_BUNDLE=/path/to/seedstore/WASM/bundle/seedstore.skb go test -run x -bench 'BenchmarkRS' -benchmem ./...
//
// NB: with the var SET, every failure below is fatal rather than a Skip. This bench spent
// a while reporting nothing because it still expected the old directory-form bundle: it
// read `<dir>/manifest.bundle`, got an error, and silently skipped. An opt-in the operator
// explicitly asked for must not quietly decline.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

const (
	rsK  = 10        // data blocks  (RS(10,6), the seedstore default §4.1)
	rsM  = 6         // parity blocks
	rsBS = 64 * 1024 // block size → 640 KB data / 384 KB parity per chunk
)

var (
	rsOnce      sync.Once
	rsCodecName string
	rsEncodeReq []byte // [OP_ENCODE][k][m][bs BE][640 KB data]
	rsDecodeReq []byte // [OP_DECODE][k][m][bs BE][cnt][rowIdx][blocks] — block 0 lost
	rsReady     bool
	rsSetupErr  error // non-nil ⇒ SEEDSTORE_BUNDLE was set but unusable: fail, don't skip
)

// bundleAuthor pulls the manifest author key out of a packed bundle blob (§12.4). The
// container is [magic 4][count u16] then per file [nameLen u16][name][dataLen u32][data],
// and the manifest envelope inside it leads with a suite byte: [suite 1][author_pk 32]
// [sig 64][json]. Mirrors packBundle/verifyManifest in bundle.ts. The bench only needs the
// key to allow-list — loadBundle still verifies the signature against it, so a wrong key
// here fails the load rather than weakening it.
func bundleAuthor(blob []byte) ([]byte, error) {
	if len(blob) < 6 {
		return nil, fmt.Errorf("bundle blob too short (%d B)", len(blob))
	}
	for o := 6; o+2 <= len(blob); {
		nameLen := int(binary.BigEndian.Uint16(blob[o:]))
		o += 2
		if o+nameLen+4 > len(blob) {
			break
		}
		name := string(blob[o : o+nameLen])
		o += nameLen
		dataLen := int(binary.BigEndian.Uint32(blob[o:]))
		o += 4
		if o+dataLen > len(blob) {
			break
		}
		if name == "manifest.bundle" {
			if dataLen < 33 {
				return nil, fmt.Errorf("manifest envelope too short (%d B)", dataLen)
			}
			return blob[o+1 : o+33], nil // +1 skips the suite byte
		}
		o += dataLen
	}
	return nil, fmt.Errorf("no manifest.bundle entry in the container")
}

// setupRS loads the seedstore bundle (installing seedstore:codec) and stages a fixed
// encode request plus a "one data block lost" decode request — the §21 single-loss
// read path, identical to bench.mjs's decode case (surviving data rows 1..k-1 plus
// the first parity row). Both requests are validated once before timing.
func setupRS() {
	ensureBooted()
	path := os.Getenv("SEEDSTORE_BUNDLE")
	if path == "" {
		return // opt-in only: no seedstore bundle configured → rsReady stays false → Skip
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		rsSetupErr = fmt.Errorf("SEEDSTORE_BUNDLE=%s: %w", path, err)
		return
	}
	// The booted default policy is deny-all, which would refuse the bundle. The bench is
	// pointed at a bundle the operator chose, so authorize its own manifest author.
	author, err := bundleAuthor(blob)
	if err != nil {
		rsSetupErr = fmt.Errorf("SEEDSTORE_BUNDLE=%s: %w", path, err)
		return
	}
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(author) + `"]}`); err != nil {
		rsSetupErr = fmt.Errorf("applyPolicy: %w", err)
		return
	}
	if status := loadBundle(path); !strings.HasPrefix(status, "seedstore v") {
		rsSetupErr = fmt.Errorf("loadBundle(%s): %s", path, status)
		return
	}
	// Where the loader bound the bundle's `codec` module: derived from the manifest's
	// signed (author, app, name) triple (§5.1), not declared anywhere. `author` is the
	// key we just authorized, so this is the name that bundle's module landed at.
	rsCodecName = kernelNameFor(author, "seedstore", "codec")

	// 640 KB of deterministic data (content is irrelevant to RS timing; this is the
	// same cheap fill bench.mjs uses).
	data := make([]byte, rsK*rsBS)
	for i := range data {
		data[i] = byte(i*1103515245 + 12345)
	}

	rsEncodeReq = make([]byte, 7+len(data))
	rsEncodeReq[0], rsEncodeReq[1], rsEncodeReq[2] = 1, rsK, rsM // OP_ENCODE
	binary.BigEndian.PutUint32(rsEncodeReq[3:7], rsBS)
	copy(rsEncodeReq[7:], data)

	parity := callHandler(rsCodecName, rsEncodeReq)
	if len(parity) != rsM*rsBS {
		rsSetupErr = fmt.Errorf("encode via %s returned %d B, want %d", rsCodecName, len(parity), rsM*rsBS)
		return
	}

	// Decode with data block 0 missing: rows 1..k-1 (surviving data) + row k (first
	// parity) = k rows, the minimum basis the codec needs to rebuild all k data rows.
	cnt := rsK
	rsDecodeReq = make([]byte, 8+cnt+cnt*rsBS)
	rsDecodeReq[0], rsDecodeReq[1], rsDecodeReq[2] = 2, rsK, rsM // OP_DECODE
	binary.BigEndian.PutUint32(rsDecodeReq[3:7], rsBS)
	rsDecodeReq[7] = byte(cnt)
	rows := rsDecodeReq[8 : 8+cnt]
	blocks := rsDecodeReq[8+cnt:]
	for r := 0; r < rsK-1; r++ { // surviving data rows 1..k-1
		rows[r] = byte(r + 1)
		copy(blocks[r*rsBS:], data[(r+1)*rsBS:(r+2)*rsBS])
	}
	rows[rsK-1] = byte(rsK) // first parity row (index k)
	copy(blocks[(rsK-1)*rsBS:], parity[:rsBS])

	out := callHandler(rsCodecName, rsDecodeReq)
	if len(out) != rsK*rsBS || !bytes.Equal(out[:rsBS], data[:rsBS]) {
		// Don't report a bogus rate for a codec that didn't rebuild the lost block.
		rsSetupErr = fmt.Errorf("decode via %s did not reconstruct block 0 (%d B out)", rsCodecName, len(out))
		return
	}
	rsReady = true
}

func BenchmarkRSEncode(b *testing.B) {
	rsOnce.Do(setupRS)
	if rsSetupErr != nil {
		b.Fatalf("SEEDSTORE_BUNDLE is set but the bench could not run: %v", rsSetupErr)
	}
	if !rsReady {
		b.Skip("seedstore bundle not built (set SEEDSTORE_BUNDLE)")
	}
	b.SetBytes(rsK * rsBS)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callHandler(rsCodecName, rsEncodeReq)
	}
}

func BenchmarkRSDecode(b *testing.B) {
	rsOnce.Do(setupRS)
	if rsSetupErr != nil {
		b.Fatalf("SEEDSTORE_BUNDLE is set but the bench could not run: %v", rsSetupErr)
	}
	if !rsReady {
		b.Skip("seedstore bundle not built (set SEEDSTORE_BUNDLE)")
	}
	b.SetBytes(rsK * rsBS)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callHandler(rsCodecName, rsDecodeReq)
	}
}
