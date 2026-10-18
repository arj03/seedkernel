// The host blob (§12.9, WASM/host/host-blob.ts): what this loader runs. The running host
// checks a blob's signatures, author and version before it stages one (host-blob.ts
// checkStagedHost), so the loader holds no crypto: it reads the layout of what is in its
// slots, which only a host put there, and of the genesis blob built into it.
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
	suiteHybrid   = 0x02
	edPkLen       = 32
	edSigLen      = 64
	mldsaPkBytes  = 1952
	mldsaSigBytes = 3309
	offEdPk       = 1
	offMlPk       = offEdPk + edPkLen
	offEdSig      = offMlPk + mldsaPkBytes
	offMlSig      = offEdSig + edSigLen
	offBody       = offMlSig + mldsaSigBytes
)

// hostBlob is a blob for this loader's ABI: its version and the parts the loader runs.
type hostBlob struct {
	env     []byte // the whole blob, which the parts alias
	version int
	script  string
	qjs     []byte
}

// readHostBlob splits env without authenticating it. The parts alias env.
func readHostBlob(env []byte) (*hostBlob, error) {
	if len(env) < 1 || env[0] != suiteHybrid {
		return nil, errors.New("host: not a suite 0x02 envelope")
	}
	if len(env) < offBody {
		return nil, errors.New("host: truncated envelope")
	}
	body := env[offBody:]
	// manifest, script, qjs, sodium, mldsa: the last two are the host's own.
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
	if m.Version < 1 {
		return nil, errors.New("host: the manifest needs a positive integer version")
	}
	if m.Abi != platformABI {
		return nil, fmt.Errorf("host: the blob needs platform ABI %d, this loader implements %d", m.Abi, platformABI)
	}
	return &hostBlob{env: env, version: m.Version, script: string(parts[1]), qjs: parts[2]}, nil
}
