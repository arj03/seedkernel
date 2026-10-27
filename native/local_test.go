package main

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The control socket is owner-only from the moment it is bound, and reachable by its owner.
func TestListenPrivateOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits: the socket takes its directory's ACL")
	}
	path := filepath.Join(t.TempDir(), "data.control")
	ln, err := listenPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want an owner-only socket", fi.Mode())
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// An --op on a serving node's directory reaches that node through its control socket, as
// on Node (WASM/tests/loader-node.test.mjs): nothing boots, a command line that would boot
// is refused, a live socket is never replaced and a stale one is.
func TestControlEndpointNative(t *testing.T) {
	bootRealm(t)
	work := t.TempDir()
	app := testAuthor(t)
	bundle, _ := writeBundle(t, app, "echo", 1, `function handle(arg) { return arg.subarray(33 + arg[32]); }`, nil)
	policy := filepath.Join(work, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"authors":["`+hex.EncodeToString(app.id())+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "data")
	serve := func(key string) *loaderRun {
		return startLoader(t, work, nil, "--policy", policy, "--dir", dir, "--key", filepath.Join(work, key),
			"--bundle", bundle, "--listen", "127.0.0.1:0")
	}
	op := func(arg byte, extra ...string) (error, string, []byte) {
		r := startLoader(t, work, []byte{arg}, append([]string{"--dir", dir, "--op", "echo"}, extra...)...)
		err, log := r.exit(t)
		return err, log, []byte(r.stdout.String())
	}

	holder := serve("holder.key")
	holder.wait(t, "control ")
	if err, log, out := op(4); err != nil || !bytes.Equal(out, []byte{4}) {
		t.Fatalf("the serving node did not answer (got %v): %v\n%s", out, err, log)
	}
	if _, err := os.Stat(filepath.Join(work, "seedkernel.key")); err == nil {
		t.Fatal("the --op stood up a node of its own")
	}
	if err, log, out := op(5, "--bundle", bundle); err == nil || len(out) != 0 || !strings.Contains(log, "reading no --bundle") {
		t.Fatalf("an --op naming a bundle was not refused while the node serves: %v\n%s", err, log)
	}
	if log := serve("second.key").until(t, "control unavailable"); !strings.Contains(log, "already listens") {
		t.Fatalf("a second node took the live socket:\n%s", log)
	}
	holder.stop()
	if err, log, _ := op(6); err == nil || !strings.Contains(log, "no node is serving") {
		t.Fatalf("a stale socket answered: %v\n%s", err, log)
	}
	again := serve("holder.key")
	again.wait(t, "control ")
	if err, log, out := op(7); err != nil || !bytes.Equal(out, []byte{7}) {
		t.Fatalf("a restarted node did not replace the stale socket (got %v): %v\n%s", out, err, log)
	}
	again.stop()
}

// On Windows a Node node's control "socket" is a file naming a pipe (host/platform-node.ts),
// which this binary cannot reach: connecting refuses it rather than reading it as nobody
// serving, a listener replaces it once its pipe is gone, and any other file is refused.
func TestCheckLocalPathNodePipe(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only Node on Windows leaves pipe files")
	}
	dir := t.TempDir()
	pipeFile := filepath.Join(dir, "data.control")
	if err := os.WriteFile(pipeFile, []byte(`\\.\pipe\seedkernel-`+strings.Repeat("0", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkLocalPath(pipeFile, false); err == nil {
		t.Fatal("connecting read a Node pipe file as nobody serving")
	}
	if err := checkLocalPath(pipeFile, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pipeFile); !os.IsNotExist(err) {
		t.Fatal("a stale pipe file was kept")
	}
	other := filepath.Join(dir, "other.control")
	if err := os.WriteFile(other, []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, listening := range []bool{false, true} {
		if err := checkLocalPath(other, listening); err == nil {
			t.Fatalf("a file that is no control socket was taken (listening %v)", listening)
		}
	}
}
