package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The bundle-freshness high-water mark must survive a reboot: it is persisted to a file
// and re-read into an empty in-memory map at next boot (README §12.4). This exercises the
// persist → forget → reload path directly on checkBundleFreshness/advanceBundleFreshness,
// so a regression that dropped the write (or left it non-atomic and unreadable) shows up
// as a downgrade that is wrongly allowed after the "reboot".
func TestBundleFreshnessPersistsAcrossReboot(t *testing.T) {
	// Isolate the global freshness state and restore it afterwards, so this test neither
	// sees nor leaks marks to the other tests in the package.
	savedPath, savedHW := freshnessStorePath, freshnessHW
	defer func() { freshnessStorePath, freshnessHW = savedPath, savedHW }()

	storeDir := t.TempDir()
	freshnessStorePath = filepath.Join(storeDir, "data.freshness.json")
	freshnessHW = nil

	const author, app = "0011223344556677", "myapp"

	// First boot: v3 clears the (empty) mark and, once loaded, advances + persists it.
	if err := checkBundleFreshness(author, app, 3); err != nil {
		t.Fatalf("v3 check on a fresh store: %v", err)
	}
	advanceBundleFreshness(author, app, 3)

	// The advance must have written the mark to disk (atomically — no temp left behind).
	if _, err := os.Stat(freshnessStorePath); err != nil {
		t.Fatalf("freshness mark was not persisted: %v", err)
	}
	entries, _ := os.ReadDir(storeDir)
	if len(entries) != 1 {
		t.Fatalf("store dir has %d files, want exactly 1 (a stray temp means the write was not atomic)", len(entries))
	}

	// Simulate a reboot: forget the in-memory marks so the next check must re-read the file.
	freshnessHW = nil

	// A v2 downgrade is now refused purely from the persisted mark.
	if err := checkBundleFreshness(author, app, 2); err == nil {
		t.Fatal("v2 after reboot: expected a downgrade refusal, got nil (mark did not survive the reboot)")
	}
	// An equal-version reload (v3) and a newer version (v4) both pass; v4 advances the mark.
	if err := checkBundleFreshness(author, app, 3); err != nil {
		t.Fatalf("v3 after reboot: %v", err)
	}
	if err := checkBundleFreshness(author, app, 4); err != nil {
		t.Fatalf("v4 after reboot: %v", err)
	}
	advanceBundleFreshness(author, app, 4)

	// The v4 advance must persist too: after another reboot, v3 is a refused downgrade.
	freshnessHW = nil
	if err := checkBundleFreshness(author, app, 3); err == nil {
		t.Fatal("v3 after the second reboot: expected a downgrade refusal (mark is 4)")
	}
}
