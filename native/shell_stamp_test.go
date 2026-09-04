package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ── is the artifact under test the tree beside it? ───────────────────────────
//
// host-shell.gen.js is generated, gitignored and never pruned, and everything this target
// runs goes through it: the shared host TS, and — inside the signed transport blob it
// embeds — the transport guest and ws.wasm. So a checkout whose npm build has not been
// re-run tests a program that is no longer in the repository, with every suite green.
//
// The fuzz targets are where that costs the most, because they reach their subject THROUGH
// the artifact on purpose: a bundle's own signed content is the thing worth fuzzing, and
// lifting it out of the blob the host embeds is what makes the framers and the handshake
// under test the ones that ship. The same indirection is what let FuzzByteParts spend a
// corpus on a `findHeadEnd` that framing.js had already replaced with `WsFramer.scanHead`,
// and pass.
//
// bundle-loader.mjs stamps the sources it generated from into the artifact
// (scripts/source-stamp.mjs); this re-hashes them. The file list comes OUT of the artifact,
// so nothing here restates the build's own set — a source added to the bundle is described
// by the next artifact generated, and every source already in one is checked byte for byte.

// shellSourceMarker introduces the stamp line bundle-loader.mjs writes.
const shellSourceMarker = "//@sources "

var shellStamp struct {
	sync.Once
	err error
}

// requireFreshShell fails the caller when host-shell.gen.js was generated from sources that
// have since changed. Once per process: fuzzing re-enters a target thousands of times, and
// the tree does not move under a running worker.
func requireFreshShell(tb testing.TB) {
	tb.Helper()
	shellStamp.Do(func() { shellStamp.err = shellSourceDrift() })
	if shellStamp.err != nil {
		tb.Fatalf("%v\n\nRegenerate it:  (cd WASM && npm run build:loader)", shellStamp.err)
	}
}

// shellSourceDrift reports which stamped sources no longer hash to what they did when
// host-shell.gen.js was written, or nil when the artifact is current.
func shellSourceDrift() error {
	at := strings.Index(hostShellJS, shellSourceMarker)
	if at < 0 {
		return fmt.Errorf("host-shell.gen.js carries no %q stamp, so nothing can say whether it matches the sources beside it",
			strings.TrimSpace(shellSourceMarker))
	}
	line := hostShellJS[at+len(shellSourceMarker):]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	var want map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &want); err != nil {
		return fmt.Errorf("host-shell.gen.js: undecodable source stamp: %w", err)
	}
	if len(want) == 0 {
		return errors.New("host-shell.gen.js: the source stamp names no files")
	}
	paths := make([]string, 0, len(want))
	for p := range want {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var drift []string
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join("..", "WASM", filepath.FromSlash(p)))
		if err != nil {
			drift = append(drift, "  "+p+" — "+err.Error())
			continue
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want[p] {
			drift = append(drift, "  "+p)
		}
	}
	if len(drift) == 0 {
		return nil
	}
	return fmt.Errorf("host-shell.gen.js was generated from older sources — %d of %d changed since:\n%s",
		len(drift), len(want), strings.Join(drift, "\n"))
}

// TestGeneratedShellIsFresh gives the check a failure of its own, so `go test ./...` names
// the problem once rather than reporting it as every other test's boot failing.
func TestGeneratedShellIsFresh(t *testing.T) { requireFreshShell(t) }
