package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"math"
	"os"
	"strings"
	"testing"
)

// End-to-end: boot the shell, exercise the signature pipeline, load the real
// seedstore bundle, and confirm its installed modules run. Set SEEDSTORE_BUNDLE
// to point at the bundle dir (defaults to the repo-relative path).
func TestShellRunsSeedstoreBundle(t *testing.T) {
	boot()

	echo := 0
	registerNative("test.echo", func(p []byte) []byte { echo++; return p })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dispatch(sign(priv, pub, name("test.echo"), []byte("hi")))
	if echo != 1 {
		t.Fatalf("signed dispatch → echo = %d, want 1", echo)
	}

	dir := os.Getenv("SEEDSTORE_BUNDLE")
	if dir == "" {
		dir = "../../seedstore/WASM/bundle"
	}
	if status := loadBundle(dir); !strings.HasPrefix(status, "seedstore v1  installed=[codec reputation]") {
		t.Fatalf("bundle load: %s", status)
	}

	if got := fnv(run(name("seedstore.codec"), codecEncodeReq())); got != 0xd9b165c5 {
		t.Fatalf("codec encode fnv=%08x, want d9b165c5", got)
	}
	if s := observeReputation(); s != 1.0 {
		t.Fatalf("reputation score=%v, want 1.0", s)
	}
}

func codecEncodeReq() []byte {
	req := make([]byte, 7+10*65536)
	req[0], req[1], req[2] = 1, 10, 6 // OP_ENCODE k=10 m=6
	binary.BigEndian.PutUint32(req[3:7], 65536)
	for i := 7; i < len(req); i++ {
		req[i] = byte((i-7)*1103515245 + 12345)
	}
	return req
}

func observeReputation() float64 {
	req := make([]byte, 1+32+8+1)
	req[0] = 1 // OP_OBSERVE; pk=zeros; now=1e6 ms BE; result=1 (pass)
	binary.BigEndian.PutUint64(req[33:41], 1_000_000)
	req[41] = 1
	resp := run(name("seedstore.reputation"), req)
	if len(resp) != 8 {
		return -1
	}
	return math.Float64frombits(binary.LittleEndian.Uint64(resp))
}

func envelope(n, payload []byte) []byte {
	return append(append([]byte{0x53, 0x44, 1, byte(len(n))}, n...), payload...)
}

func sign(priv ed25519.PrivateKey, pub, innerName, payload []byte) []byte {
	inner := envelope(innerName, payload)
	wp := append([]byte{0, 0, 0, 32}, pub...)
	wp = append(append(wp, 0, 64), ed25519.Sign(priv, inner)...)
	return envelope(name("signature"), append(wp, inner...))
}

func fnv(b []byte) uint32 {
	h := uint32(2166136261)
	for _, x := range b {
		h ^= uint32(x)
		h *= 16777619
	}
	return h
}
