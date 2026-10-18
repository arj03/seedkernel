package main

import (
	"testing"
	"time"
)

// A guest realm on the engine table (host/engine-realm.ts) answers an invocation, a
// synchronous host call and a parked one.
func TestEngineRealmRoundTrip(t *testing.T) {
	bootRealm(t)
	evalString(t, `globalThis.__engineProbe = (async () => {
	  const realm = await createRealm({
	    source: "async function handle(b) { const r = await host.call('echo', b); const p = await host.call('later', r); return p; }",
	    hostCall: (name, payload) => name === 'echo' ? payload : Promise.resolve(new Uint8Array([payload.length])),
	  });
	  const out = await realm.call(new Uint8Array([1, 2, 3]));
	  realm.dispose();
	  return out;
	})(); 0`)
	out := awaitOK(t, "engine realm", "__engineProbe", 10*time.Second)
	if len(out) != 1 || out[0] != 3 {
		t.Fatalf("answer %v, want [3]", out)
	}
}
