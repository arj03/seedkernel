package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

	"seedloader/qjs"
)

// wireServe (README §12.8): a node answers a peer's request from its confined
// guest's synchronous `handle`, with no app-specific host code. This wires the whole
// stack together — net (real socket req/res) + cap-bridge (fs) + a confined guest
// realm — and proves it against a storage-shaped app: peer B stores a value at A and
// fetches it back, served entirely by A's guest. Two nodes share one host realm (only
// A holds / touches fs), as in transport_test.go.
func TestServe(t *testing.T) {
	dir := t.TempDir()
	wrt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd := bootSodium(wrt)
	rt, err := qjs.New()
	if err != nil {
		wrt.Close(ctx)
		t.Fatal(err)
	}
	hostQc := rt.Context()
	el := newEventLoop(hostQc)
	if err := installEngineHost(hostQc, el, sd, dir); err != nil {
		rt.Close()
		wrt.Close(ctx)
		t.Fatal("host:", err)
	}
	defer func() { rt.Close(); wrt.Close(ctx) }()

	// A (holder, listens) and B (requester) in the one host realm. A's cap-bridge is
	// built over A's identity + transport; __transport is the one wireServe serves.
	if _, err := hostQc.Eval("setup.js", qjs.Code(`
		globalThis.idA = sodium.crypto_sign_keypair();
		globalThis.idB = sodium.crypto_sign_keypair();
		globalThis.aId = toHex(idA.publicKey);
		globalThis.bId = toHex(idB.publicKey);
		globalThis.netA = makeNetwork(idA, { host: "127.0.0.1", port: 0 }, undefined);
		globalThis.netB = makeNetwork(idB, undefined, undefined);
		globalThis.tA = new Transport(aId, netA, 2000);
		globalThis.tB = new Transport(bId, netB, 2000);
		globalThis.__transport = tA;
		__buildCapBridge(["crypto", "fs"], idA, tA, []);
	`)); err != nil {
		t.Fatal("setup:", err)
	}

	// Bind A's listener (sets netA.port).
	if _, _, _, err := el.await(`(async () => { await netA.start(); return new Uint8Array(0); })()`, 5*time.Second); err != nil {
		t.Fatal("start:", err)
	}

	// The holder guest: type 1 = STORE (payload already framed for FS_PUT),
	// type 2 = FETCH (payload = key). Local fs + crypto only — fully synchronous.
	const holderSource = `
		register("handle", (arg) => {
		  const type = arg[0];
		  const payload = arg.slice(1);
		  if (type === 1) { host.call(CAP_FS_PUT, payload); return new Uint8Array([1]); }
		  if (type === 2) { return host.call(CAP_FS_GET, payload); }
		  return new Uint8Array(0);
		});
	`
	g, err := newGuestRealm(el, "", "{}", holderSource)
	if err != nil {
		t.Fatal("guest:", err)
	}
	defer g.close()
	wireServe(hostQc, g)

	// B dials A, stores a value through A's holder, then fetches it back.
	kind, value, msg, err := el.await(`(async () => {
		netB.addPeerAddr(aId, { host: "127.0.0.1", port: netA.port, transport: "tcp" });
		const key = new TextEncoder().encode("greeting");
		const val = new TextEncoder().encode("held by the cohort");
		const store = new Uint8Array(4 + key.length + val.length);
		new DataView(store.buffer).setUint32(0, key.length);
		store.set(key, 4); store.set(val, 4 + key.length);
		const ok = await tB.request(aId, new TextEncoder().encode("_test"), 1, store);
		if (ok[0] !== 1) throw new Error("store not acked");
		const got = await tB.request(aId, new TextEncoder().encode("_test"), 2, key);
		if (got[0] !== 1) throw new Error("fetch miss");
		return got.slice(1);
	})()`, 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if kind != 0 {
		t.Fatalf("holder flow failed: %s", msg)
	}
	if want := []byte("held by the cohort"); !bytes.Equal(value, want) {
		t.Fatalf("fetched %q, want %q", value, want)
	}
}
