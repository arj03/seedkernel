package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bundle-freshness high-water mark must survive a reboot: the marks live in the JS
// realm (bundle.ts FreshnessMarks) and are persisted through Go's atomic-write seam, so
// a fresh realm must re-read them from the file (README §12.4). This drives the real
// load path — boot, load, "reboot", load again — so a regression that dropped the write
// (or left it non-atomic and unreadable) shows up as a downgrade that is wrongly allowed.
func TestBundleFreshnessPersistsAcrossReboot(t *testing.T) {
	// The mark is a SIBLING of the data dir (a fs-capable guest writes files inside the
	// dir and must not be able to reach its own mark), so give the dir a parent we can
	// list: one data directory plus exactly one mark file, and no stray temp.
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data")

	// One author across every "boot": the mark is keyed by (author, app). The author is
	// minted against the first realm's sodium, so boot once before writing bundles.
	bootRealmIn(t, dataDir)
	author, authorPub := testAuthor(t)
	policyJSON := `{"authors":["` + hex.EncodeToString(authorPub) + `"]}`

	// reboot stands up a fresh realm and node on the same data dir — the marks are
	// in-realm state, so this is what forces the next load to re-read them from the file.
	reboot := func() { bootShell(t, dataDir, policyJSON, nil) }
	load := func(version int) string {
		bundlePath, _ := writeTestBundle(t, author, authorPub, "testapp", version)
		return loadBundle(bundlePath)
	}

	// First boot: v3 clears the (empty) mark and, once loaded, advances + persists it.
	reboot()
	if status := load(3); !strings.HasPrefix(status, "testapp v3") {
		t.Fatalf("v3 on a fresh store: %s", status)
	}

	// The advance must have written the mark to disk (atomically — no temp left behind).
	// Where that file is is the shared rule's (`freshnessPathFor`, bundle.ts), asked of
	// the realm rather than recomputed here: a test that spelled the sibling-file
	// convention itself could pass while the two targets wrote to different places.
	markPath := evalString(t, "freshnessPathFor("+jsonString(dataDir)+")")
	if _, err := os.Stat(markPath); err != nil {
		t.Fatalf("freshness mark was not persisted: %v", err)
	}
	entries, _ := os.ReadDir(parent)
	files := 0
	for _, e := range entries {
		if !e.IsDir() {
			files++
		}
	}
	if files != 1 {
		t.Fatalf("%d files beside the data dir, want exactly 1 (a stray temp means the write was not atomic)", files)
	}

	// Reboot: a v2 downgrade is now refused purely from the persisted mark.
	reboot()
	if status := load(2); !strings.Contains(status, "downgrade refused") {
		t.Fatalf("v2 after reboot: expected a downgrade refusal, got: %s (mark did not survive the reboot)", status)
	}
	// An equal-version reload (v3) and a newer version (v4) both pass; v4 advances the mark.
	if status := load(3); !strings.HasPrefix(status, "testapp v3") {
		t.Fatalf("v3 after reboot: %s", status)
	}
	if status := load(4); !strings.HasPrefix(status, "testapp v4") {
		t.Fatalf("v4 after reboot: %s", status)
	}

	// The v4 advance must persist too: after another reboot, v3 is a refused downgrade.
	reboot()
	if status := load(3); !strings.Contains(status, "downgrade refused") {
		t.Fatalf("v3 after the second reboot: expected a downgrade refusal (mark is 4), got: %s", status)
	}
}
