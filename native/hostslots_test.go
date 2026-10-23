package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain lets a test run this binary's own main as the loader, in a child process, the
// way an operator runs it: the child gets its arguments as JSON in the environment.
func TestMain(m *testing.M) {
	if args := os.Getenv("SEEDKERNEL_TEST_LOADER_ARGS"); args != "" {
		var argv []string
		if err := json.Unmarshal([]byte(args), &argv); err != nil {
			panic(err)
		}
		os.Args = append([]string{os.Args[0]}, argv...)
		main()
		os.Exit(0)
	}
	// Every boot reads the loader's realm (the platform ABI, the host's arguments), so the
	// tests stand one up as main does.
	_, engine, err := hostParts(genesisHost)
	if err == nil {
		ldr, err = newLoader(engine, []string{}, genesisHost)
	}
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// hostAuthor is this clone's host author, from the key the genesis blob was signed with
// (WASM/host-author.key), derived as bundle-author.ts hybridAuthorKeysFromSeed derives it.
func hostAuthor(t *testing.T) authorKeys {
	t.Helper()
	seedHex, err := os.ReadFile(filepath.Join("..", "WASM", "host-author.key"))
	if err != nil {
		t.Fatal("host-author.key:", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil {
		t.Fatal(err)
	}
	edPriv := ed25519.NewKeyFromSeed(seed)
	mlPk, mlSk := testSigner(t).keypair(t, blake2b256(append(seed, "seedkernel-author-mldsa-v1"...)))
	a := authorKeys{edPriv: edPriv, edPub: edPriv.Public().(ed25519.PublicKey), mlPk: mlPk, mlSk: mlSk}
	if !bytes.Equal(a.edPub, genesisHost[offEdPk:offMlPk]) || !bytes.Equal(a.mlPk, genesisHost[offMlPk:offEdSig]) {
		t.Fatal("host-author.key is not the genesis blob's author: rebuild (cd WASM && npm run build:native)")
	}
	return a
}

// loaderRun is one run of the loader on a test's node.
type loaderRun struct {
	cmd    *exec.Cmd
	stderr *syncBuffer
	done   chan error
}

// startLoader runs main in a child with these arguments and stdin.
func startLoader(t *testing.T, work string, stdin []byte, args ...string) *loaderRun {
	t.Helper()
	argv, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0])
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "SEEDKERNEL_TEST_LOADER_ARGS="+string(argv), "SEEDKERNEL_HOST_HEALTH_MS=300")
	cmd.Stdin = bytes.NewReader(stdin)
	r := &loaderRun{cmd: cmd, stderr: &syncBuffer{}, done: make(chan error, 1)}
	cmd.Stderr = r.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { r.done <- cmd.Wait() }()
	return r
}

// until waits for a stderr line matching want, then stops the loader.
func (r *loaderRun) until(t *testing.T, want string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(r.stderr.String(), want) {
		if time.Now().After(deadline) {
			r.cmd.Process.Kill()
			t.Fatalf("no %q in:\n%s", want, r.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.cmd.Process.Kill()
	<-r.done
	return r.stderr.String()
}

// exit waits for the loader to end by itself.
func (r *loaderRun) exit(t *testing.T) (error, string) {
	t.Helper()
	select {
	case err := <-r.done:
		return err, r.stderr.String()
	case <-time.After(20 * time.Second):
		r.cmd.Process.Kill()
		t.Fatalf("the loader did not exit:\n%s", r.stderr.String())
		return nil, ""
	}
}

// The native loader keeps the update rules end to end, as the Node loader does
// (WASM/tests/host-updates.test.mjs): an app stages a host over `host/stage`, the running
// host checks it, the next start tries it and commits it after its window, a host that
// fails before that is dropped for the committed one, and under `now` the node reboots
// into a staged host in place.
func TestHostUpdatesNative(t *testing.T) {
	bootRealm(t)
	hostKeys, script := hostAuthor(t), testScript(t)
	work := t.TempDir()
	app := testAuthor(t)
	updater, _ := writeBundle(t, app, "updater", 1, `
		async function handle(arg) {
		  const n = arg[32];
		  let op = "";
		  for (let i = 0; i < n; i++) op += String.fromCharCode(arg[33 + i]);
		  if (op === "stage") await host.call("host/stage", arg.subarray(33 + n));
		  return new Uint8Array([1]);
		}`, []string{"host"})
	policy := filepath.Join(work, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"authors":["`+hex.EncodeToString(app.id())+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--policy", policy, "--dir", filepath.Join(work, "data"), "--key", filepath.Join(work, "node.key"),
		"--bundle", updater}
	slot := func(name string) string { return filepath.Join(work, "data.host", name) }
	committed := func() int {
		env, err := os.ReadFile(slot("committed.skb"))
		if err != nil {
			return 0
		}
		var m struct{ Version int }
		if err := json.Unmarshal(hostPart(t, env, partManifest), &m); err != nil {
			t.Fatal("committed:", err)
		}
		return m.Version
	}
	stage := func(blob []byte, mode string) (error, string) {
		return startLoader(t, work, blob, append(base, "--host-updates", mode, "--op", "stage")...).exit(t)
	}
	serve := append(base, "--listen", "127.0.0.1:0")

	if err, log := stage(hostEnvelope(t, hostKeys, 2, ldr.abi, script), "off"); err == nil || !strings.Contains(log, "updates are off") {
		t.Fatalf("staging with updates off: %v\n%s", err, log)
	}
	if err, log := stage(hostEnvelope(t, hostKeys, 2, ldr.abi, script), "next"); err != nil || !strings.Contains(log, "staged v2") {
		t.Fatalf("staging v2: %v\n%s", err, log)
	}
	log := startLoader(t, work, nil, serve...).until(t, "committed after")
	if !strings.Contains(log, "trying v2 (committed is v1)") || committed() != 2 {
		t.Fatalf("v2 was not tried and committed (committed v%d):\n%s", committed(), log)
	}
	if err, log := stage(hostEnvelope(t, hostKeys, 2, ldr.abi, script), "next"); err == nil || !strings.Contains(log, "v2 is not above v2") {
		t.Fatalf("staging at the floor: %v\n%s", err, log)
	}
	if err, log := stage(hostEnvelope(t, testAuthor(t), 5, ldr.abi, script), "next"); err == nil || !strings.Contains(log, "not the running host's author") {
		t.Fatalf("staging another author's host: %v\n%s", err, log)
	}
	tampered := hostEnvelope(t, hostKeys, 5, ldr.abi, script)
	tampered[len(tampered)-1] ^= 1
	appBundle, err := os.ReadFile(updater)
	if err != nil {
		t.Fatal(err)
	}
	for what, blob := range map[string][]byte{"a tampered host": tampered, "an app bundle": appBundle} {
		if err, log := stage(blob, "next"); err == nil || !strings.Contains(log, "host: signature invalid") {
			t.Fatalf("staging %s: %v\n%s", what, err, log)
		}
	}
	if _, err := os.Stat(slot("pending.skb")); err == nil {
		t.Fatal("a refused host was kept")
	}

	if err, log := stage(hostEnvelope(t, hostKeys, 3, ldr.abi, `throw new Error("broken host");`), "next"); err != nil {
		t.Fatalf("staging v3: %v\n%s", err, log)
	}
	log = startLoader(t, work, nil, serve...).until(t, "listening on")
	if !strings.Contains(log, "trying v3") || !strings.Contains(log, "discarded the pending host") || committed() != 2 {
		t.Fatalf("a broken v3 was not dropped for v2 (committed v%d):\n%s", committed(), log)
	}
	if _, err := os.Stat(slot("pending.skb")); err == nil {
		t.Fatal("the broken host is still pending")
	}

	if err := os.WriteFile(slot("pending.skb"), hostEnvelope(t, hostKeys, 4, ldr.abi, script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(slot("tried"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	log = startLoader(t, work, nil, serve...).until(t, "listening on")
	if !strings.Contains(log, "it was tried and never committed") || strings.Contains(log, "trying v4") {
		t.Fatalf("a host marked tried was run again:\n%s", log)
	}

	log = startLoader(t, work, hostEnvelope(t, hostKeys, 6, ldr.abi, script),
		append(serve, "--host-updates", "now", "--op", "stage")...).until(t, "committed after")
	if !strings.Contains(log, "staged v6") || !strings.Contains(log, "trying v6") || committed() != 6 {
		t.Fatalf("under now, v6 did not boot in place and commit (committed v%d):\n%s", committed(), log)
	}
}

// syncBuffer collects a child's stderr while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
