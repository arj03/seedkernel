package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"seedloader/qjs"
)

// ── fuzzing the pre-trust bundle parsers (§12.4) ─────────────────────────────
//
// unpackBundle and verifyManifest are the first code any supplied bytes reach: the
// container walks three attacker-chosen lengths over one blob, and the manifest envelope
// must read the suite byte to know its own field widths BEFORE it can check a signature.
// Both run entirely before a trust decision, so the property worth stating is not "these
// bytes are good" but "no bytes at all can make this parser do something other than
// answer or refuse in its own vocabulary".
//
// The targets drive the SHARED readers in the booted realm rather than a Go restatement:
// a second implementation would be a second parser, and the one under attack is the one
// that ships. bundle_helper_test.go's writer supplies the seeds, so the corpus starts on
// blobs that already parse and the mutator works outward from there.

// bundleFuzzJS installs the probes. Each answers ONE JSON line describing what the shared
// reader did, so every assertion below is a Go statement about a shared-JS outcome rather
// than a JS assertion the fuzzer cannot minimize.
const bundleFuzzJS = `
"use strict";
const __fzEnc = new TextEncoder(), __fzDec = new TextDecoder();
const __fz = (o) => __fzEnc.encode(JSON.stringify(o));
// What was thrown, in the two terms the assertions care about: the class (a TypeError
// means the parser fell off its own vocabulary into the engine's) and the message.
const __thrown = (e) => ({
  threw: true,
  name: (e && e.name) || typeof e,
  msg: String((e && e.message) !== undefined ? e.message : e),
});

globalThis.__fuzzUnpack = (ab) => {
  const blob = new Uint8Array(ab);
  // The container's own declared count, read the way the parser reads it — so the
  // assertion can compare "entries the blob declared" with "entries handed back" and
  // catch a name that silently shadowed another.
  const declared = blob.length >= 6 ? (blob[4] << 8) | blob[5] : -1;
  let files;
  try { files = unpackBundle(blob); }
  catch (e) { return __fz(__thrown(e)); }
  const names = Object.keys(files);
  let total = 0, nonBytes = 0;
  // The whole map in ONE value, canonically: [nameLen u32][name utf8][dataLen u32][data]
  // per entry. Hashed rather than returned, so the Go oracle compares every name AND every
  // byte at a fixed cost per execution instead of carrying the blob back through JSON.
  //
  // BY NAME, not in the blob's order: what the container answers is a lookup table, and
  // this one is a JS object, whose keys come back integer-like-first rather than in
  // insertion order. Nothing downstream iterates it — the loader asks for manifest.bundle,
  // guest.js and each module by name — so an order claim here would be a claim about the
  // engine's property ordering and about nothing the format says.
  const entries = [];
  for (const n of names) {
    const v = files[n];
    if (!(v instanceof Uint8Array)) { nonBytes++; continue; }
    total += v.length;
    entries.push([__fzEnc.encode(n), v]);
  }
  entries.sort((a, b) => {
    const x = a[0], y = b[0];
    for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
  });
  const parts = [];
  for (const [nb, v] of entries) {
    const head = new Uint8Array(8);
    new DataView(head.buffer).setUint32(0, nb.length, false);
    new DataView(head.buffer).setUint32(4, v.length, false);
    parts.push(head.subarray(0, 4), nb, head.subarray(4), v);
  }
  let canonLen = 0;
  for (const p of parts) canonLen += p.length;
  const canon = new Uint8Array(canonLen);
  { let at = 0; for (const p of parts) { canon.set(p, at); at += p.length; } }
  return __fz({
    threw: false, declared, n: names.length, total, nonBytes, names,
    digest: toHex(sodium.crypto_generichash(32, canon)),
    // A file named "__proto__" is an assignment to the prototype slot of an object
    // literal, not an entry: it would leave the map short AND re-point its prototype at
    // bytes the blob chose. Either of the two prototypes a map can legitimately have is
    // fine; anything else came out of the blob.
    protoSafe: (() => {
      const p = Object.getPrototypeOf(files);
      return p === null || p === Object.prototype;
    })(),
  });
};

globalThis.__fuzzVerifyManifest = (ab) => {
  try {
    const v = verifyManifest(sodium, new Uint8Array(ab));
    return __fz({ threw: false, verified: v !== null, app: v ? v.manifest.app : null });
  } catch (e) { return __fz(__thrown(e)); }
};

globalThis.__fuzzVerifyBundle = (ab) => {
  try {
    const b = verifyBundle(sodium, new Uint8Array(ab));
    return __fz({ threw: false, verified: true, app: b.manifest.app, modules: b.modules.length });
  } catch (e) { return __fz(__thrown(e)); }
};

// The post-signature half, reached directly: a byte-level mutation of an envelope can
// never get past the signature, so the checks an author's own broken manifest meets need
// the JSON handed straight in.
globalThis.__fuzzValidateManifest = (ab) => {
  let parsed;
  try { parsed = JSON.parse(__fzDec.decode(new Uint8Array(ab))); }
  catch { return __fz({ skip: true }); }
  try { validateManifest(parsed); return __fz({ threw: false, accepted: true }); }
  catch (e) { return __fz(__thrown(e)); }
};
`

// fuzzOutcome is one probe's answer.
type fuzzOutcome struct {
	Threw    bool     `json:"threw"`
	Skip     bool     `json:"skip"`
	Name     string   `json:"name"`
	Msg      string   `json:"msg"`
	Declared int      `json:"declared"`
	N        int      `json:"n"`
	Total    int      `json:"total"`
	NonBytes int      `json:"nonBytes"`
	Names    []string `json:"names"`
	Digest   string   `json:"digest"`
	Proto    bool     `json:"protoSafe"`
	Verified bool     `json:"verified"`
	Accepted bool     `json:"accepted"`
	App      string   `json:"app"`
	Modules  int      `json:"modules"`
}

// bundleFuzzRealm boots the realm once and installs the probes. Fuzzing re-enters the
// target thousands of times in one process, so the boot must not be per-iteration.
func bundleFuzzRealm(f *testing.F) {
	f.Helper()
	bootRealm(f)
	if _, err := qc.Eval("fuzz-bundle.js", qjs.Code(bundleFuzzJS)); err != nil {
		f.Fatal("fuzz probes:", err)
	}
}

// runProbe runs one probe over data and decodes its answer.
func runProbe(t testing.TB, name string, data []byte) fuzzOutcome {
	t.Helper()
	out, err := callRealm(name, 20*time.Second, qc.NewArrayBuffer(data))
	if err != nil {
		// The probe catches everything the reader throws, so a rejection here is the
		// REALM failing — an out-of-memory, a budget kill, an engine fault — which is a
		// finding in its own right rather than a broken harness.
		t.Fatalf("%s: the realm itself failed on %d bytes: %v", name, len(data), err)
	}
	var o fuzzOutcome
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("%s: undecodable probe answer %q: %v", name, out, err)
	}
	return o
}

// refusedInOwnVocabulary is the property every one of these parsers claims: a refusal is
// an Error this code wrote, never one the engine raised on its behalf. A TypeError or a
// RangeError means the parser walked off its own checks into the runtime's, which is
// exactly where a length-arithmetic bug shows up first.
func refusedInOwnVocabulary(t *testing.T, what string, o fuzzOutcome, data []byte) {
	t.Helper()
	if !o.Threw {
		return
	}
	if o.Name != "Error" {
		t.Errorf("%s: refused with %s (not Error): %q — input %d bytes: %x",
			what, o.Name, o.Msg, len(data), head(data))
	}
	if !strings.HasPrefix(o.Msg, "bundle:") {
		t.Errorf("%s: refusal message is not the parser's own vocabulary: %q — input %d bytes: %x",
			what, o.Msg, len(data), head(data))
	}
}

// covMarkOutcome marks what one probe reached, in the terms the mutator should be steered
// by (fuzz_cov_test.go): which refusal, or which verdict — never how big the input was.
//
// All five call sites share these ids because they share a subject: the bundle reader, read
// at different depths. A refusal MESSAGE is the one open-ended thing here — the reader has
// dozens of them and which one it chose is the whole gradient between its refusal sites — so
// that goes to the hashed window, carrying the error's constructor name with it (a
// RangeError is the parser walking off its own checks, which is a finding rather than a
// refusal).
func covMarkOutcome(o fuzzOutcome) {
	if o.Skip {
		covMark(covBundleSkip)
		return
	}
	if o.Threw {
		covMark(covBundleRefused)
		covMarkShape(o.Name + ": " + o.Msg)
		return
	}
	covMark(covBundleOK)
	covMarkIf(o.Verified, covBundleVerified)
	covMarkIf(o.Accepted, covBundleAccepted)
	if o.N == 0 {
		covMark(covBundleFilesNone)
	}
	covMarkCount(o.N, covBundleFilesOne, covBundleFilesMany)
}

// head trims a failure's input to something a test log can carry.
func head(b []byte) []byte {
	if len(b) > 96 {
		return b[:96]
	}
	return b
}

// ── the container, as a second implementation ────────────────────────────────
//
// Written from §12.4's layout rather than from the reader:
//
//	"SKB1" (4) │ count u16 │ count× ( nameLen u16 │ name utf8 │ dataLen u32 │ data )
//
// and nothing after the last entry. Comparing counts and totals, which is all a
// self-assertion can do, would miss swapped contents, a slipped offset, trailing bytes and
// every other same-length corruption — so this walks the blob and hands back exactly what
// it holds, for the digest below to compare byte for byte.

// refUnpack parses one blob, or reports why the format refuses it.
func refUnpack(blob []byte) (names, data [][]byte, reason string) {
	if len(blob) < 6 || string(blob[:4]) != "SKB1" {
		return nil, nil, "not a bundle blob"
	}
	count := int(binary.BigEndian.Uint16(blob[4:6]))
	seen := make(map[string]bool, count)
	off := 6
	for i := 0; i < count; i++ {
		if off+2 > len(blob) {
			return nil, nil, "truncated: no name length"
		}
		nameLen := int(binary.BigEndian.Uint16(blob[off:]))
		off += 2
		if off+nameLen+4 > len(blob) {
			return nil, nil, "truncated: name and data length"
		}
		name := blob[off : off+nameLen]
		off += nameLen
		dataLen := int(binary.BigEndian.Uint32(blob[off:]))
		off += 4
		if off+dataLen > len(blob) {
			return nil, nil, "truncated: data"
		}
		// One name, one file — checked on the NAME BYTES, which is the stricter reading:
		// the shared reader keys a decoded string, so two byte strings that decode alike
		// are one name to it and two to this. That is the gap the UTF-8 gate below covers.
		if seen[string(name)] {
			return nil, nil, "two files named " + strconv.Quote(string(name))
		}
		seen[string(name)] = true
		names = append(names, name)
		data = append(data, blob[off:off+dataLen])
		off += dataLen
	}
	if off != len(blob) {
		return nil, nil, "trailing bytes after the last file"
	}
	return names, data, ""
}

// refDigest is the canonical serialization of a parsed map, hashed with the one system
// hash — the same value the probe computes over what the shared reader produced. Equal
// digests mean equal names and equal bytes, entry for entry.
//
// Ordered BY NAME rather than by position, for the reason the probe gives: the container
// answers a lookup table, and this one is a JS object whose key order is the engine's.
func refDigest(names, data [][]byte) string {
	order := make([]int, len(names))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return bytes.Compare(names[order[a]], names[order[b]]) < 0 })
	var buf []byte
	for _, i := range order {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(names[i])))
		buf = append(buf, names[i]...)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(data[i])))
		buf = append(buf, data[i]...)
	}
	return hex.EncodeToString(sd.genericHash(32, buf))
}

// allUTF8 reports whether every name is valid UTF-8. The shared reader keys its map by the
// DECODED name, and a lossy decode is not a function this oracle can invert: two distinct
// name byte strings can arrive as one key, which is a real ambiguity in the format but not
// one a Go rewrite of TextDecoder's replacement rules would state any better. So the exact
// comparison is claimed only here, and the weaker exact claim below covers the rest.
func allUTF8(names [][]byte) bool {
	for _, n := range names {
		if !utf8.Valid(n) {
			return false
		}
	}
	return true
}

// containerAgrees holds the shared reader against refUnpack. Both directions, because a
// reader that refused everything would satisfy every other assertion in this file.
func containerAgrees(t *testing.T, o fuzzOutcome, blob []byte) {
	t.Helper()
	names, data, reason := refUnpack(blob)
	// This direction needs no decoder: every shape the format refuses here is one the
	// shared reader refuses for the same reason, whatever the names decode to.
	if reason != "" {
		if !o.Threw {
			t.Fatalf("unpackBundle: ACCEPTED a blob the format refuses (%s) — %d files %q, input %d bytes: %x",
				reason, o.N, o.Names, len(blob), head(blob))
		}
		return
	}
	if !allUTF8(names) {
		// Still exact, just weaker: a name the reader decoded into another name's key
		// must cost the blob its whole parse, never one entry quietly.
		if !o.Threw && o.N != len(names) {
			t.Fatalf("unpackBundle: %d entries out of a blob declaring %d distinct names — an entry was lost to a decode collision; input %d bytes: %x",
				o.N, len(names), len(blob), head(blob))
		}
		return
	}
	if o.Threw {
		t.Fatalf("unpackBundle: REFUSED (%q) a blob the format accepts as %d files — input %d bytes: %x",
			o.Msg, len(names), len(blob), head(blob))
	}
	if want := refDigest(names, data); o.Digest != want {
		got := make([]string, len(names))
		for i := range names {
			got[i] = fmt.Sprintf("%q:%d", names[i], len(data[i]))
		}
		t.Fatalf("unpackBundle: the map differs from the blob — reader gave %q, the format says %v; input %d bytes: %x",
			o.Names, got, len(blob), head(blob))
	}
}

// FuzzUnpackBundle walks the container: "SKB1" count u16, then count× ( nameLen u16, name,
// dataLen u32, data ) — three supplied lengths over one blob, read before any signature is
// checked.
func FuzzUnpackBundle(f *testing.F) {
	bundleFuzzRealm(f)
	author := testAuthor(f)
	f.Add(signedBundleBytes(f, author, "fuzz", 1, "", nil))
	f.Add(packBundle([][2]any{{"a", []byte("x")}}))
	f.Add(packBundle([][2]any{{"", []byte{}}}))
	f.Add([]byte("SKB1\x00\x00"))
	f.Add([]byte("SKB1\xff\xff"))
	f.Add([]byte("SKB1"))
	f.Add([]byte{})
	// Two entries under one name: the blob declares two files and the map can hold one.
	f.Add(packBundle([][2]any{{"manifest.bundle", []byte("first")}, {"manifest.bundle", []byte("second")}}))
	// A name the object literal reads as its prototype slot rather than as a key.
	f.Add(packBundle([][2]any{{"__proto__", []byte("x")}, {"guest.js", []byte("y")}}))
	// Bytes after the last declared file: the same bundle, from more than one byte string.
	f.Add(append(packBundle([][2]any{{"a", []byte("x")}}), 0))
	// A count that under-declares what follows, which is the same thing said differently.
	f.Add(append([]byte("SKB1\x00\x00"), 'j', 'u', 'n', 'k'))
	// One integer-like name beside one that only looks like it: a JS object hands these
	// back integer-first, so the map's order is not the blob's. Found by the fuzzer.
	f.Add(packBundle([][2]any{{"000000000", []byte("0")}, {"10000000", []byte("0")}}))

	f.Fuzz(func(t *testing.T, data []byte) {
		o := runProbe(t, "__fuzzUnpack", data)
		covMarkOutcome(o)
		refusedInOwnVocabulary(t, "unpackBundle", o, data)
		containerAgrees(t, o, data)
		if o.Threw {
			return
		}
		// A blob that parsed must hand back every file it declared. Anything less means
		// one entry overwrote another under a name the reader treated as equal — the
		// shape a bundle-shadowing attack takes, since only the LAST manifest.bundle in
		// a blob is the one whose signature is checked.
		if o.N != o.Declared {
			t.Errorf("unpackBundle: blob declared %d files, map holds %d (%q) — input %d bytes: %x",
				o.Declared, o.N, o.Names, len(data), head(data))
		}
		if !o.Proto {
			t.Errorf("unpackBundle: the returned map's prototype was replaced (%q) — input %d bytes: %x",
				o.Names, len(data), head(data))
		}
		if o.NonBytes != 0 {
			t.Errorf("unpackBundle: %d entries are not Uint8Array — input %d bytes: %x",
				o.NonBytes, len(data), head(data))
		}
		// Every byte handed back came out of the blob, so the parts cannot exceed it.
		if o.Total > len(data) {
			t.Errorf("unpackBundle: returned %d bytes from a %d-byte blob: %x",
				o.Total, len(data), head(data))
		}
	})
}

// shapedNames are the names worth landing on, which a mutator working over raw bytes
// essentially never spells: the two the loader looks up by name, the object-literal
// prototype slot, and the inherited members a map keyed by a sender's string could answer
// with if it were ever built on one.
var shapedNames = []string{
	"manifest.bundle", "guest.js", "fwd.wasm", "__proto__", "constructor",
	"toString", "hasOwnProperty", "", "a",
}

// shapeBlob reads the fuzzer's bytes as a LIST OF ENTRIES and packs them with CORRECT
// framing. Mutation over a raw blob destroys the first length field almost every time and
// spends the run in "truncated blob"; this spends it inside the walk instead, on the names
// and the offsets, where a container bug would be. Names stay valid UTF-8 so the exact
// oracle always applies (see allUTF8).
func shapeBlob(raw []byte) []byte {
	files := make([][2]any, 0, 16)
	at := 0
	next := func() byte {
		if at >= len(raw) {
			return 0
		}
		b := raw[at]
		at++
		return b
	}
	take := func(n int) []byte {
		if n > len(raw)-at {
			n = len(raw) - at
		}
		if n <= 0 {
			return []byte{}
		}
		out := raw[at : at+n]
		at += n
		return out
	}
	for at < len(raw) && len(files) < 24 {
		sel := int(next())
		name := ""
		if sel < len(shapedNames) {
			name = shapedNames[sel]
		} else {
			// A short name over a small alphabet: valid UTF-8, and narrow enough that the
			// mutator produces repeats — which is the case the container has to refuse.
			raw := take(sel % 9)
			b := make([]byte, len(raw))
			for i, c := range raw {
				b[i] = "abcdefgh._-/"[int(c)%12]
			}
			name = string(b)
		}
		files = append(files, [2]any{name, take(int(next()))})
	}
	return packBundle(files)
}

// FuzzUnpackBundleShaped is FuzzUnpackBundle's twin over WELL-FORMED blobs: the fuzzer
// chooses the names, the contents and how many there are, and the framing is always right.
// Every execution therefore reaches the same exact oracle, which for a blob the format
// accepts is a full round trip — every name and every byte back out, in order.
func FuzzUnpackBundleShaped(f *testing.F) {
	bundleFuzzRealm(f)
	f.Add([]byte{0, 4, 'm', 'a', 'n', 'i', 1, 2, 'g', 'x'})
	f.Add([]byte{3, 1, 'z', 3, 1, 'y'}) // the same name twice
	f.Add([]byte{7, 0})                 // one empty name, no data
	f.Add([]byte{})
	f.Add([]byte{9, 3, 'a', 'b', 'c', 200, 4, 'd', 'e', 'f', 'g'})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<12 {
			t.Skip()
		}
		blob := shapeBlob(raw)
		o := runProbe(t, "__fuzzUnpack", blob)
		covMarkOutcome(o)
		refusedInOwnVocabulary(t, "unpackBundle", o, blob)
		containerAgrees(t, o, blob)
		if !o.Threw && !o.Proto {
			t.Fatalf("unpackBundle: the returned map's prototype was replaced (%q) — blob %d bytes: %x",
				o.Names, len(blob), head(blob))
		}
	})
}

// FuzzVerifyManifest drives the envelope reader, which by design reads the suite byte to
// choose its field widths before it can verify anything (§14.1). The property: no byte
// string verifies, and every refusal is the reader's own.
func FuzzVerifyManifest(f *testing.F) {
	bundleFuzzRealm(f)
	author := testAuthor(f)
	mjson := manifestJSON(f, "fuzz", 1, stubGuestSrc, nil)
	env := manifestEnvelope(f, author, mjson)
	layout := layoutOf(author, env, mjson)
	f.Add(env)
	// A SECOND author's envelope. What this reader answers is internal consistency — the
	// keys are in the envelope and sign it — so more than one input legitimately verifies,
	// and WHICH author it turns out to be is policy's question afterwards (§12.5). A
	// corpus with one valid shape would leave that half of the contract untried.
	f.Add(manifestEnvelope(f, testAuthor(f), manifestJSON(f, "other", 1, stubGuestSrc, nil)))
	f.Add(env[:len(env)-1])
	f.Add(env[:1])
	f.Add([]byte{})
	f.Add([]byte{0x03})
	f.Add([]byte{manifestSuite()})
	// The retired Ed25519-only suite, which must read as "a suite this host lacks".
	f.Add([]byte{0x01})
	// The anchor. Everything below is an agreement between two verifiers, and two
	// verifiers that both refuse everything agree perfectly — so one input is pinned to
	// YES on both sides before any of that is worth reading.
	if !refManifestVerifies(layout, env) {
		f.Fatal("the oracle refuses an envelope this test just signed — layoutOf has the field widths wrong")
	}
	if o := runProbe(f, "__fuzzVerifyManifest", env); !o.Verified {
		f.Fatalf("verifyManifest refuses an envelope this test just signed (threw=%v %q)", o.Threw, o.Msg)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		o := runProbe(t, "__fuzzVerifyManifest", data)
		covMarkOutcome(o)
		refusedInOwnVocabulary(t, "verifyManifest", o, data)
		if o.Threw {
			// A suite this host cannot check, or a validly signed manifest that is broken:
			// neither is a verdict about authenticity, so there is nothing to agree with.
			return
		}
		// The envelope reads its own field widths off the suite byte BEFORE it can check
		// anything (§14.1) — the design a fuzzer is here to test. So the verdict is held
		// against two independent verifiers rather than against the reader's own
		// arithmetic: a length it mis-measures surfaces as a signature these two refuse.
		if want := refManifestVerifies(layout, data); o.Verified != want {
			t.Fatalf("verifyManifest: answered verified=%v (app %q) for a %d-byte envelope Ed25519+ML-DSA-65 say is %v: %x",
				o.Verified, o.App, len(data), want, head(data))
		}
	})
}

// manifestLayout is the envelope's fixed prefix — suite, the two public keys, the two
// signatures, then JSON to the end — MEASURED off a real envelope rather than restated
// here. The widths come from the author's own keys and from a signature this test just
// made, so a suite whose fields are other widths moves them without touching this file.
type manifestLayout struct{ edPk, mlPk, edSig, mlSig int }

func layoutOf(a authorKeys, env, mjson []byte) manifestLayout {
	l := manifestLayout{edPk: len(a.edPub), mlPk: len(a.mlPk), edSig: ed25519.SignatureSize}
	l.mlSig = len(env) - len(mjson) - 1 - l.edPk - l.mlPk - l.edSig
	return l
}

// refManifestVerifies is the second implementation of the envelope's authenticity check:
// Go's own Ed25519 and the loader's ML-DSA-65 verifier, over the signing input the format
// defines. It is what makes the assertion above about the FORMAT rather than about the
// reader agreeing with itself — a bypass is a path that answers yes where these two say no.
func refManifestVerifies(l manifestLayout, env []byte) bool {
	off := 1 + l.edPk + l.mlPk + l.edSig + l.mlSig
	if len(env) < off || env[0] != manifestSuite() {
		return false
	}
	at := 1
	edPk := env[at : at+l.edPk]
	at += l.edPk
	mlPk := env[at : at+l.mlPk]
	at += l.mlPk
	edSig := env[at : at+l.edSig]
	body := env[off:]
	pre := append(domainManifest(), manifestSuite())
	pre = append(append(append(pre, edPk...), mlPk...), body...)
	// Both halves, in the order the reader checks them: a suite that signs with two
	// algorithms is only as strong as its refusal to accept one (§14.1).
	return ed25519.Verify(ed25519.PublicKey(edPk), pre, edSig) &&
		md.verifyDetached(env[at+l.edSig:off], pre, mlPk)
}

// FuzzVerifyBundle is the whole pre-trust path in one: unpack the container, find the
// manifest, verify it, then hash every file the manifest names. Seeded with a real signed
// bundle so the mutator works on a blob whose container already parses.
func FuzzVerifyBundle(f *testing.F) {
	bundleFuzzRealm(f)
	author := testAuthor(f)
	blob := signedBundleBytes(f, author, "fuzz", 1, "", nil)
	f.Add(blob)
	f.Add(blob[:len(blob)/2])
	f.Add(packBundle([][2]any{{"manifest.bundle", []byte{}}}))
	f.Add([]byte{})
	// Trailing bytes on an otherwise valid bundle: the container must refuse it, so a
	// signed bundle cannot be re-presented under a second blob hash.
	f.Add(append(append([]byte{}, blob...), 0))
	layout := layoutOf(author, manifestEnvelope(f, author, manifestJSON(f, "fuzz", 1, stubGuestSrc, nil)),
		manifestJSON(f, "fuzz", 1, stubGuestSrc, nil))
	// The anchor, for the same reason as verifyManifest's: an agreement between two
	// implementations that both refuse everything is no evidence at all.
	if o := runProbe(f, "__fuzzVerifyBundle", blob); !o.Verified {
		f.Fatalf("verifyBundle refuses a bundle this test just signed (threw=%v %q)", o.Threw, o.Msg)
	}
	if !refVerifyBundle(layout, blob) {
		f.Fatal("the oracle refuses a bundle this test just signed")
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		o := runProbe(t, "__fuzzVerifyBundle", data)
		covMarkOutcome(o)
		refusedInOwnVocabulary(t, "verifyBundle", o, data)
		// Both directions. The forward one is the security claim — nothing is admitted
		// whose container, signature and content hashes do not all hold. The reverse holds
		// because the JSON is inside the signature: a mutation either leaves the manifest
		// byte-identical to one an author signed, and so still well-formed, or it costs
		// the envelope its signature. So a disagreement either way is a finding.
		if want := refVerifyBundle(layout, data); o.Verified != want {
			t.Fatalf("verifyBundle: answered verified=%v (%q, threw=%v) for a %d-byte blob the format says is %v: %x",
				o.Verified, o.Msg, o.Threw, len(data), want, head(data))
		}
	})
}

// refVerifyBundle is the whole pre-trust install path as a second implementation: unpack
// the container, find the manifest, check both signatures, then hash every file the
// manifest names against what it declared. Everything a bundle is admitted on.
func refVerifyBundle(l manifestLayout, blob []byte) bool {
	names, data, reason := refUnpack(blob)
	if reason != "" {
		return false
	}
	files := make(map[string][]byte, len(names))
	for i := range names {
		files[string(names[i])] = data[i]
	}
	env, ok := files["manifest.bundle"]
	if !ok || !refManifestVerifies(l, env) {
		return false
	}
	var m struct {
		Modules []struct{ Name, Hash string } `json:"modules"`
		Guest   struct {
			Hash string `json:"hash"`
		} `json:"guest"`
	}
	if json.Unmarshal(env[1+l.edPk+l.mlPk+l.edSig+l.mlSig:], &m) != nil {
		return false
	}
	hashes := func(file, declared string) bool {
		b, ok := files[file]
		return ok && strings.EqualFold(hex.EncodeToString(sd.genericHash(32, b)), declared)
	}
	for _, mod := range m.Modules {
		if !hashes(mod.Name+".wasm", mod.Hash) {
			return false
		}
	}
	// The guest is hashed as TEXT: the reader decodes it and re-encodes before hashing, so
	// bytes that are not valid UTF-8 hash as their replacement characters. Not a round trip
	// this oracle inverts — and `guest.js` is the one file where it matters.
	g, ok := files["guest.js"]
	return ok && utf8.Valid(g) && hashes("guest.js", m.Guest.Hash)
}

// FuzzValidateManifest reaches the checks that run AFTER a signature verifies. A
// byte-level fuzzer can never get there through an envelope, so the JSON goes straight in
// — which is what an author signing a broken manifest, or a stolen author key, actually
// presents to a loader.
// manifestWithClaims is the fixture manifest with its two §12.10 claim lists replaced. It
// re-encodes from the parsed form, which costs nothing here: validateManifest reads a
// parsed object, so the byte order of this document is not one of its inputs.
func manifestWithClaims(t testing.TB, protocols, services []string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(manifestJSON(t, "fuzz", 1, stubGuestSrc, nil), &m); err != nil {
		t.Fatal("fixture manifest:", err)
	}
	m["protocols"], m["services"] = protocols, services
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal("re-encode fixture manifest:", err)
	}
	return out
}

func FuzzValidateManifest(f *testing.F) {
	bundleFuzzRealm(f)
	f.Add(manifestJSON(f, "fuzz", 1, stubGuestSrc, nil))
	f.Add(manifestJSON(f, "fuzz", 1, stubGuestSrc, []string{"fs", "_net"}))
	f.Add([]byte(`{"app":"a","version":0,"modules":[],"guest":{"hash":"","requires":[]}}`))
	f.Add([]byte(`{"app":"a","version":0,"modules":[],"guest":{"hash":"","requires":[],"calls":["x"]}}`))
	f.Add([]byte(`{"app":"a","version":0,"protocols":["p"],"services":["p"],"modules":[],"guest":{"hash":"","requires":[]}}`))
	f.Add([]byte(`{"app":"a","version":0,"modules":[{"name":"m","hash":"h"}],"guest":{"hash":"","requires":[],"calls":["m"]}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	// Shapes the necessary conditions below are about, each of which must be REFUSED: two
	// modules under one name, a service outside the catalog, and an app name past the one
	// length byte its signing scope encodes.
	f.Add([]byte(`{"app":"a","version":0,"modules":[{"name":"m","hash":"h"},{"name":"m","hash":"i"}],"guest":{"hash":"","requires":[]}}`))
	f.Add([]byte(`{"app":"a","version":0,"modules":[],"guest":{"hash":"","requires":["fs/get"]}}`))
	f.Add([]byte(`{"app":"` + strings.Repeat("a", 256) + `","version":0,"modules":[],"guest":{"hash":"","requires":[]}}`))
	// The overlap is ACCEPTED, and asserted rather than assumed. Uniqueness is per list, so
	// one name in both `protocols` and `services` is not a conflict but a claim to both
	// audiences: reachable by a peer over the wire and by a co-resident guest by name. Every
	// assertion in the body is about a REFUSAL, and a validator that had quietly started
	// refusing this would satisfy all of them. bundle-install.test.mjs pins the same rule
	// from the other side.
	overlap := manifestWithClaims(f, []string{"both", "wire-only"}, []string{"both", "local-only"})
	f.Add(overlap)
	if o := runProbe(f, "__fuzzValidateManifest", overlap); !o.Accepted {
		f.Fatalf("validateManifest refuses a name claimed in both protocols and services (threw=%v %q)", o.Threw, o.Msg)
	}
	// The anchor: the fixture manifest is accepted. Without it every assertion below is
	// satisfied by a validator that refuses everything.
	if o := runProbe(f, "__fuzzValidateManifest", manifestJSON(f, "fuzz", 1, stubGuestSrc, nil)); !o.Accepted {
		f.Fatalf("validateManifest refuses the fixture manifest (threw=%v %q)", o.Threw, o.Msg)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		o := runProbe(t, "__fuzzValidateManifest", data)
		covMarkOutcome(o)
		if o.Skip {
			return
		}
		refusedInOwnVocabulary(t, "validateManifest", o, data)
		if !o.Accepted {
			return
		}
		// The probe parses the DECODED text and this parses the bytes, so for input that is
		// not valid UTF-8 the two are not reading the same document — and QuickJS's
		// TextDecoder is not WHATWG's about it (it takes a non-continuation byte as a
		// continuation, where a browser emits a replacement character and reprocesses).
		// Nothing about validateManifest is under test there, so it is skipped rather than
		// asserted against a decoder this file would have to reimplement.
		if !utf8.Valid(data) {
			return
		}
		// NECESSARY conditions, not the whole vocabulary: restating every rule would be a
		// second validator to keep in step, while these are the ones something downstream
		// would be hurt by. Each names what breaks if it does not hold.
		if why := manifestMustHold(data); why != "" {
			t.Fatalf("validateManifest: ACCEPTED a manifest where %s — %s", why, string(head(data)))
		}
	})
}

// manifestMustHold reports the first necessary condition an ACCEPTED manifest fails, or ""
// when it holds. Read against the consumers, not against isValidManifest: the app name is
// length-encoded into the slot's signing scope, the module names are the table's keys, and
// `guest.requires` is the privilege vocabulary the shell grants from.
func manifestMustHold(data []byte) string {
	var m struct {
		App     *string `json:"app"`
		Version *float64
		Modules *[]struct {
			Name *string `json:"name"`
			Hash *string `json:"hash"`
		} `json:"modules"`
		Guest *struct {
			Hash     *string   `json:"hash"`
			Requires *[]string `json:"requires"`
		} `json:"guest"`
	}
	if json.Unmarshal(data, &m) != nil {
		return "it is not even an object of the manifest's shape"
	}
	// One length byte carries the app name into `appSignScope`, so a longer one verifies
	// and installs, then throws on the guest's first signature.
	if m.App == nil || *m.App == "" || len(*m.App) > 255 {
		return "the app name is missing, empty or over the 255 bytes its signing scope encodes"
	}
	if m.Version == nil || *m.Version < 0 || *m.Version != float64(int64(*m.Version)) {
		return "the version is not a non-negative integer"
	}
	if m.Guest == nil || m.Guest.Hash == nil || m.Guest.Requires == nil {
		return "the guest declares no hash or no requires — and every app is a guest"
	}
	// A name outside the catalog is a grant that would quietly reach nothing at first use,
	// which is the failure this vocabulary is closed to prevent (§12.5).
	for _, r := range *m.Guest.Requires {
		if !hostServices()[r] {
			return "guest.requires names " + strconv.Quote(r) + ", which is no service of this host"
		}
	}
	if m.Modules == nil {
		return "modules is missing"
	}
	seen := map[string]bool{}
	for _, mod := range *m.Modules {
		if mod.Name == nil || mod.Hash == nil {
			return "a module declares no name or no hash"
		}
		// Two modules under one name is one entry in the slot's table: the second would
		// silently take the first's place, and a bundle's module names are what its guest
		// reaches by.
		if seen[*mod.Name] {
			return "two modules are named " + strconv.Quote(*mod.Name)
		}
		seen[*mod.Name] = true
	}
	return ""
}

// hostServices is this host's service vocabulary, read off the catalog itself rather than
// restated: a Go copy would agree with the loader only until the table grows. Cached — it
// is a constant of the shared bundle, and this runs inside a fuzz loop.
var hostServicesCache map[string]bool

func hostServices() map[string]bool {
	if hostServicesCache == nil {
		var names []string
		if err := json.Unmarshal([]byte(realmString(`JSON.stringify(Object.keys(HOST_SERVICES))`)), &names); err != nil {
			panic("hostServices: " + err.Error())
		}
		hostServicesCache = make(map[string]bool, len(names))
		for _, n := range names {
			hostServicesCache[n] = true
		}
	}
	return hostServicesCache
}
