// The host blob (§12.9, WASM/host/host-blob.ts): what this loader runs, signed as one. It
// is checked here, with the loader's own crypto, before any of it runs: the suite 0x02
// envelope under DOMAIN_host, both signatures, then the parts. Whether to run it (its
// author, ABI and version) is the caller's decision.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// The envelope layout, as host/bundle.ts reads it: suite, both public keys, both
// signatures, then the body.
const (
	suiteHybrid = 0x02
	edPkLen     = 32
	edSigLen    = 64
	offEdPk     = 1
	offMlPk     = offEdPk + edPkLen
	offEdSig    = offMlPk + mldsaPkBytes
	offMlSig    = offEdSig + edSigLen
	offBody     = offMlSig + mldsaSigBytes
)

// The signing prefixes (services/domains.ts) the host blob and its author id are under.
var (
	domainHost   = []byte("seedkernel-host-sig-v1\x00")
	domainAuthor = []byte("seedkernel-manifest-author-v1\x00")
)

// hostBlob is a verified blob's author, manifest and parts.
type hostBlob struct {
	env     []byte // the whole blob, which the parts alias
	author  []byte
	version int
	abi     int
	script  string
	qjs     []byte
	sodium  []byte
	mldsa   []byte
}

// errHostSignature is every authentication failure, so a probe learns nothing from which.
var errHostSignature = errors.New("host: signature invalid")

// verifyHostBlob authenticates env and splits its body. The parts alias env.
func verifyHostBlob(env []byte) (*hostBlob, error) {
	if len(env) < 1 {
		return nil, errHostSignature
	}
	if env[0] != suiteHybrid {
		return nil, fmt.Errorf("host: unsupported manifest suite 0x%02x", env[0])
	}
	if len(env) < offBody {
		return nil, errHostSignature
	}
	edPk, mlPk := env[offEdPk:offMlPk], env[offMlPk:offEdSig]
	edSig, mlSig, body := env[offEdSig:offMlSig], env[offMlSig:offBody], env[offBody:]
	keys := concat([]byte{suiteHybrid}, edPk, mlPk)
	pre := concat(domainHost, keys, genericHash(32, body, nil))
	// Both, always, so a broken half refuses good blobs rather than admitting forged ones.
	if !sd.verifyDetached(edSig, pre, edPk) || !md.verifyDetached(mlSig, pre, mlPk) {
		return nil, errHostSignature
	}
	parts := make([][]byte, 5)
	for i := range parts {
		if len(body) < 4 {
			return nil, errors.New("host: truncated body")
		}
		n := binary.BigEndian.Uint32(body)
		if uint64(n) > uint64(len(body)-4) {
			return nil, errors.New("host: truncated body")
		}
		parts[i], body = body[4:4+n], body[4+n:]
	}
	if len(body) != 0 {
		return nil, errors.New("host: trailing bytes in body")
	}
	var m struct{ Version, Abi int }
	if err := json.Unmarshal(parts[0], &m); err != nil {
		return nil, errors.New("host: malformed manifest (not JSON)")
	}
	if m.Version < 1 || m.Abi < 1 {
		return nil, errors.New("host: the manifest needs a positive integer version and abi")
	}
	return &hostBlob{
		env:     env,
		author:  genericHash(32, concat(domainAuthor, keys), nil),
		version: m.Version, abi: m.Abi,
		script: string(parts[1]), qjs: parts[2], sodium: parts[3], mldsa: parts[4],
	}, nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
