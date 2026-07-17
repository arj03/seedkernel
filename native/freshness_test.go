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
	// Isolate the global store path and restore it afterwards, so this test neither sees
	// nor leaks marks to the other tests in the package (which run with it empty).
	saved := freshnessStorePath
	defer func() { freshnessStorePath = saved }()

	storeDir := t.TempDir()
	freshnessStorePath = filepath.Join(storeDir, "data.freshness.json")

	// One author across every "boot": the mark is keyed by (author, app).
	boot()
	author, authorPub := testAuthor(t)
	policyJSON := `{"authors":["` + hex.EncodeToString(authorPub) + `"]}`

	// reboot stands up a fresh realm — the marks are in-realm state, so this is what
	// forces the next load to re-read them from the file.
	reboot := func() {
		boot()
		if err := applyPolicy(policyJSON); err != nil {
			t.Fatalf("applyPolicy: %v", err)
		}
	}
	load := func(version int) string {
		dir, _ := writeTestBundle(t, author, authorPub, "testapp", version)
		return loadBundle(dir)
	}

	// First boot: v3 clears the (empty) mark and, once loaded, advances + persists it.
	reboot()
	if status := load(3); !strings.HasPrefix(status, "testapp v3") {
		t.Fatalf("v3 on a fresh store: %s", status)
	}

	// The advance must have written the mark to disk (atomically — no temp left behind).
	if _, err := os.Stat(freshnessStorePath); err != nil {
		t.Fatalf("freshness mark was not persisted: %v", err)
	}
	entries, _ := os.ReadDir(storeDir)
	if len(entries) != 1 {
		t.Fatalf("store dir has %d files, want exactly 1 (a stray temp means the write was not atomic)", len(entries))
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
