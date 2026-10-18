package main

import (
	"bytes"
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
// host.skb, the genesis host blob, is generated, gitignored and never pruned, and
// everything this target runs goes through it: the shared host TS, the transport bundle
// inside it, and the engine. So a checkout whose npm build has not been re-run tests a
// program that is no longer in the repository, with every suite green.
//
// bundle-host.mjs stamps the sources the host script was generated from into it
// (scripts/source-stamp.mjs); this re-hashes them. The file list comes from the artifact,
// so it never goes out of step with the build, and every listed source is checked byte for
// byte. The blob's engine must also be the checked-in qjs/qjs.wasm.

// shellSourceMarker introduces the stamp line bundle-host.mjs writes.
const shellSourceMarker = "//@sources "

var shellStamp struct {
	sync.Once
	err error
}

// requireFreshShell fails the caller when host.skb was built from sources that have since
// changed. Once per process: every realm boot asks, and the tree does not move
// under a running test binary.
func requireFreshShell(tb testing.TB) {
	tb.Helper()
	shellStamp.Do(func() { shellStamp.err = shellSourceDrift() })
	if shellStamp.err != nil {
		tb.Fatalf("%v\n\nRegenerate it:  (cd WASM && npm run build:native)", shellStamp.err)
	}
}

// genesisParts splits the genesis blob without checking its signatures, which boot does:
// this only asks what it was built from.
func genesisParts() (script string, qjsWasm []byte, err error) {
	if len(genesisHost) < offBody {
		return "", nil, errors.New("host.skb is shorter than an envelope")
	}
	body := genesisHost[offBody:]
	var parts [][]byte
	for len(body) >= 4 && len(parts) < 3 {
		n := int(body[0])<<24 | int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		if n > len(body)-4 {
			return "", nil, errors.New("host.skb: truncated body")
		}
		parts, body = append(parts, body[4:4+n]), body[4+n:]
	}
	if len(parts) < 3 {
		return "", nil, errors.New("host.skb: truncated body")
	}
	return string(parts[1]), parts[2], nil
}

// shellSourceDrift reports which stamped sources no longer hash to what they did when
// host.skb was built, or nil when the artifact is current.
func shellSourceDrift() error {
	hostJS, engine, err := genesisParts()
	if err != nil {
		return err
	}
	if disk, err := os.ReadFile(filepath.Join("qjs", "qjs.wasm")); err != nil || !bytes.Equal(disk, engine) {
		return errors.New("host.skb carries another engine than qjs/qjs.wasm")
	}
	at := strings.Index(hostJS, shellSourceMarker)
	if at < 0 {
		return fmt.Errorf("the host script carries no %q stamp, so nothing can say whether it matches the sources beside it",
			strings.TrimSpace(shellSourceMarker))
	}
	line := hostJS[at+len(shellSourceMarker):]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	var want map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &want); err != nil {
		return fmt.Errorf("host script: undecodable source stamp: %w", err)
	}
	if len(want) == 0 {
		return errors.New("host script: the source stamp names no files")
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
	return fmt.Errorf("host.skb was built from older sources — %d of %d changed since:\n%s",
		len(drift), len(want), strings.Join(drift, "\n"))
}

// TestGeneratedShellIsFresh gives the check a failure of its own, so `go test ./...` names
// the problem once instead of as every other test's boot failing.
func TestGeneratedShellIsFresh(t *testing.T) { requireFreshShell(t) }
