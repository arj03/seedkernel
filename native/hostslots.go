// Host updates (§12.9): the slots a host blob is staged into and committed from, under the
// rules every loader keeps (WASM/host/loader-node.ts keeps the same ones):
//
//   - one author, the genesis blob's: a blob from anyone else runs only by --host;
//   - a floor, the committed host's version: nothing at or below it is staged or booted;
//   - a staged blob is tried once: marked tried before it boots, so a crash is not retried;
//   - it is committed only after a health window it ran through with no fatal error, and
//     anything that fails before that is discarded and the committed host booted again.
//
// The slots live beside the data directory, as the freshness store does:
// <dir>.host/committed.skb, pending.skb, and the tried mark.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	committedFile = "committed.skb"
	pendingFile   = "pending.skb"
	triedFile     = "tried"
)

// defaultHealthWindow is how long a pending host must serve before it is committed. The
// environment's SEEDKERNEL_HOST_HEALTH_MS shortens it for tests.
const defaultHealthWindow = 30 * time.Second

// Update modes (--host-updates): refuse staging, run a staged host at the next start, or
// boot into it at once.
const (
	updatesOff  = "off"
	updatesNext = "next"
	updatesNow  = "now"
)

type hostUpdates struct {
	dir     string
	mode    string
	genesis *hostBlob
	window  time.Duration

	mu sync.Mutex
	// trying is set while the running host is the pending blob, not yet committed.
	trying bool
	// gen counts boots, so a health timer from an earlier boot commits nothing.
	gen int
	// reboot is set when a host staged under "now" is waiting to boot.
	reboot bool
}

// newHostUpdates checks the mode and the genesis blob the slots are pinned to.
func newHostUpdates(dataDir, mode string, genesis *hostBlob) (*hostUpdates, error) {
	switch mode {
	case updatesOff, updatesNext, updatesNow:
	default:
		return nil, fmt.Errorf("--host-updates must be off, next or now (got %q)", mode)
	}
	window := defaultHealthWindow
	if ms := os.Getenv("SEEDKERNEL_HOST_HEALTH_MS"); ms != "" {
		d, err := time.ParseDuration(ms + "ms")
		if err != nil {
			return nil, fmt.Errorf("SEEDKERNEL_HOST_HEALTH_MS: %w", err)
		}
		window = d
	}
	return &hostUpdates{
		dir: strings.TrimRight(dataDir, `/\`) + ".host", mode: mode, genesis: genesis, window: window,
	}, nil
}

func (u *hostUpdates) path(name string) string { return filepath.Join(u.dir, name) }

func hostLog(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  host   "+format+"\n", args...)
}

// load reads and checks one slot: nil when it is absent, or not the pinned author's for
// this ABI, which it reports.
func (u *hostUpdates) load(name string) *hostBlob {
	env, err := os.ReadFile(u.path(name))
	if err != nil {
		return nil
	}
	h, err := verifyHostBlob(env)
	switch {
	case err != nil:
		hostLog("ignored %s: %v", name, err)
		return nil
	case !bytes.Equal(h.author, u.genesis.author):
		hostLog("ignored %s: signed by %x, not this binary's host author", name, h.author)
		return nil
	case h.abi != platformABI:
		hostLog("ignored %s: it needs platform ABI %d, this loader implements %d", name, h.abi, platformABI)
		return nil
	}
	return h
}

// base is the host to fall back on: the committed one when it is newer than the genesis
// blob, which a newer binary can be.
func (u *hostUpdates) base() *hostBlob {
	if c := u.load(committedFile); c != nil && c.version > u.genesis.version {
		return c
	}
	return u.genesis
}

// choose picks the blob the next boot runs. A pending blob is tried once: the mark is
// written before it boots, so finding the mark means it never got as far as committing.
func (u *hostUpdates) choose() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.gen++
	u.trying = false
	base := u.base()
	if _, err := os.Stat(u.path(pendingFile)); err != nil {
		return base.env
	}
	if _, err := os.Stat(u.path(triedFile)); err == nil {
		u.discard("it was tried and never committed")
		return base.env
	}
	p := u.load(pendingFile)
	if p == nil || p.version <= base.version {
		u.discard("it is not above the floor")
		return base.env
	}
	if err := writeFileAtomic(u.path(triedFile), nil, ".tried-", 0o600); err != nil {
		hostLog("cannot mark v%d tried, so it is not run: %v", p.version, err)
		return base.env
	}
	u.trying = true
	hostLog("trying v%d (committed is v%d)", p.version, base.version)
	return p.env
}

// discard drops the pending blob and its mark; called with mu held.
func (u *hostUpdates) discard(reason string) {
	os.Remove(u.path(pendingFile))
	os.Remove(u.path(triedFile))
	u.trying = false
	hostLog("discarded the pending host: %s", reason)
}

// failed reports whether a failure belongs to a pending host, which it then discards: the
// caller boots the committed host instead of giving up.
func (u *hostUpdates) failed(err error) bool {
	if u == nil {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.trying {
		return false
	}
	u.discard(err.Error())
	return true
}

// started is told how the booted host's operator flow ended. A pending host that serves is
// committed once it has served for the window. One that only ran an op and exited proved
// nothing either way, so it is left pending, untried, for the next start.
func (u *hostUpdates) started(serving bool) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.trying {
		return
	}
	if !serving {
		os.Remove(u.path(triedFile))
		u.trying = false
		return
	}
	gen := u.gen
	time.AfterFunc(u.window, func() { u.commit(gen) })
}

// commit makes the pending host the committed one, which raises the floor to it.
func (u *hostUpdates) commit(gen int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.trying || u.gen != gen {
		return
	}
	if err := os.Rename(u.path(pendingFile), u.path(committedFile)); err != nil {
		hostLog("cannot commit the pending host: %v", err)
		return
	}
	os.Remove(u.path(triedFile))
	u.trying = false
	hostLog("committed after %s", u.window)
}

// stage checks a host blob a running host hands over and keeps it as pending. Answers
// whether it should boot now.
func (u *hostUpdates) stage(env []byte, running *hostBlob) (bool, error) {
	if u == nil || u.mode == updatesOff {
		return false, errors.New("host: updates are off on this node (--host-updates next|now)")
	}
	h, err := verifyHostBlob(env)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(h.author, u.genesis.author) {
		return false, fmt.Errorf("host: signed by %x, not this binary's host author", h.author)
	}
	if h.abi != platformABI {
		return false, fmt.Errorf("host: the blob needs platform ABI %d, this loader implements %d", h.abi, platformABI)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	floor := u.base().version
	if running.version > floor {
		floor = running.version
	}
	if h.version <= floor {
		return false, fmt.Errorf("host: v%d is not above v%d", h.version, floor)
	}
	if err := os.MkdirAll(u.dir, 0o700); err != nil {
		return false, err
	}
	if err := writeFileAtomic(u.path(pendingFile), env, ".pending-", 0o600); err != nil {
		return false, err
	}
	os.Remove(u.path(triedFile))
	hostLog("staged v%d", h.version)
	if u.mode == updatesNow {
		u.reboot = true
	}
	return u.reboot, nil
}

// rebootWaiting reports a pending reboot without clearing it.
func (u *hostUpdates) rebootWaiting() bool {
	if u == nil {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.reboot
}

// takeReboot reports and clears a pending reboot.
func (u *hostUpdates) takeReboot() bool {
	if u == nil {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	r := u.reboot
	u.reboot = false
	return r
}
