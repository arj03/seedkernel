package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bundle freshness mark must survive a reboot: the marks live in the JS realm
// (bundle.ts FreshnessMarks) and are persisted through Go's atomic write, so a fresh realm
// must re-read them from the file (§12.4). This uses the real install path (boot,
// install, reboot, install again), so a regression that dropped the write (or left it
// non-atomic and unreadable) shows up as a downgrade that is wrongly allowed.
func TestBundleFreshnessPersistsAcrossReboot(t *testing.T) {
	// The mark file sits beside the data dir (a guest with fs writes files inside the dir
	// and must not be able to reach its own mark), so give the dir a parent to list: one
	// data directory plus exactly one mark file, and no stray temp.
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data")

	// One author across every boot: the mark is keyed by (author, app). The author is
	// created with the first realm's sodium, so boot once before writing bundles.
	bootRealmIn(t, dataDir)
	author := testAuthor(t)
	policyJSON := `{"authors":["` + hex.EncodeToString(author.id()) + `"]}`

	// reboot starts a fresh realm and node on the same data dir; the marks are in-realm
	// state, so this forces the next install to re-read them from the file.
	reboot := func() { bootShell(t, dataDir, policyJSON, nil) }
	load := func(version int) string {
		bundlePath, _ := writeTestBundle(t, author, "testapp", version)
		return loadBundle(bundlePath)
	}

	// First boot: v3 passes the (empty) mark and, once installed, advances and persists it.
	reboot()
	if status := load(3); !strings.HasPrefix(status, "testapp v3") {
		t.Fatalf("v3 on a fresh store: %s", status)
	}

	// The advance must have written the mark to disk (atomically, no temp left behind).
	// The file's location comes from the shared rule (`freshnessPathFor`, bundle.ts), asked
	// of the realm instead of recomputed here, so the test cannot pass while the two
	// targets write to different places.
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
	// An equal-version reinstall (v3) and a newer version (v4) both pass; v4 advances the
	// mark. Each gets its own boot: an install without `replaces` needs a free slot, and
	// this tests the reboot path, not in-place replacement.
	if status := load(3); !strings.HasPrefix(status, "testapp v3") {
		t.Fatalf("v3 after reboot: %s", status)
	}
	reboot()
	if status := load(4); !strings.HasPrefix(status, "testapp v4") {
		t.Fatalf("v4 after reboot: %s", status)
	}

	// The v4 advance must persist too: after another reboot, v3 is a refused downgrade.
	reboot()
	if status := load(3); !strings.Contains(status, "downgrade refused") {
		t.Fatalf("v3 after the second reboot: expected a downgrade refusal (mark is 4), got: %s", status)
	}
}

// A mark the disk refuses fails the install on this target too. If the native write
// swallowed its error, the shared rollback would never run: the install would report
// success while the mark was never written, reopening the downgrade path at the next boot
// with no explanation. The write is Go's, so this is the only place to check it.
func TestFreshnessPersistFailureFailsTheLoad(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data")
	bootRealmIn(t, dataDir)
	author := testAuthor(t)
	policyJSON := `{"authors":["` + hex.EncodeToString(author.id()) + `"]}`
	bootShell(t, dataDir, policyJSON, nil)

	// A directory where the mark file goes. Every write ends in a rename onto that path,
	// which the OS refuses whatever the process's privileges, standing in for a full or
	// read-only disk.
	markPath := evalString(t, "freshnessPathFor("+jsonString(dataDir)+")")
	os.Remove(markPath) // the boot may already have written one
	if err := os.MkdirAll(markPath, 0o755); err != nil {
		t.Fatal(err)
	}

	bundlePath, _ := writeTestBundle(t, author, "testapp", 4)
	status := loadBundle(bundlePath)
	if !strings.Contains(status, "could not be persisted") {
		t.Fatalf("a load whose mark cannot be written must fail loudly, got: %s", status)
	}

	// And it kept nothing: the in-memory mark was rolled back, so the store never got
	// ahead of the disk. A lower version installing now shows it; after a swallowed error
	// the mark would be at 4 and refuse this as a downgrade.
	if err := os.Remove(markPath); err != nil {
		t.Fatal(err)
	}
	older, _ := writeTestBundle(t, author, "testapp", 2)
	if status := loadBundle(older); !strings.HasPrefix(status, "testapp v2") {
		t.Fatalf("the failed load must leave no mark behind, got: %s", status)
	}
}

func TestFreshnessReadFailuresFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		directory bool
	}{
		{name: "malformed JSON"},
		{name: "read error", directory: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			dataDir := filepath.Join(parent, "data")
			bootRealmIn(t, dataDir)
			markPath := evalString(t, "freshnessPathFor("+jsonString(dataDir)+")")
			if tc.directory {
				if err := os.Mkdir(markPath, 0o755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(markPath, []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}

			policy := `{"authors":[]}`
			cfg := nodeConfig{PolicyJSON: &policy, KeyHex: testKeyHex(t), ContactSecretHex: testContactSecretHex}
			if _, err := startNode(cfg); err == nil {
				t.Fatalf("freshness %s was silently treated as an empty store", tc.name)
			}
		})
	}
}
