package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestExplicitReplacementAcrossAuthors(t *testing.T) {
	for _, links := range []bool{false, true} {
		t.Run(fmt.Sprintf("link=%v", links), func(t *testing.T) {
			bootRealmIn(t, t.TempDir())
			a, b := testAuthor(t), testAuthor(t)
			requires := []string{}
			if links {
				requires = []string{"link"}
			}
			first, _ := writeBundle(t, a, "service", 10, "", requires)
			second, _ := writeBundle(t, b, "service", 1, "", requires)
			readHex := func(path string) string {
				bytes, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return hex.EncodeToString(bytes)
			}
			expr := fmt.Sprintf(`(async () => {
			  const policyJson = JSON.stringify({ authors: [%q, %q] });
			  const links = %v;
			  const first = fromHex(%q), second = fromHex(%q);
			  const n = await standUp({ dir: __dir, identity: sodium.crypto_sign_keypair(),
			    policyJson, transport: links && { bundle: first } });
			  try {
			    let old;
			    if (links) {
			      const key = n.shell.resolve("service");
			      let refused = false;
			      try { await n.shell.loadBundleBlob(second); } catch { refused = true; }
			      if (!refused) throw new Error("ordinary load acquired link");
			      old = { key };
			    } else {
			      old = await n.shell.loadBundleBlob(first);
			    }
			    const next = await n.shell.replaceBundle(old.key, second);
			    if (next.key === old.key || n.shell.resolve("service") !== next.key)
			      throw new Error("replacement did not transfer the claim");
			    if (n.shell.uninstall(old.key)) throw new Error("old identity survived");
			    if (links && !n.transport.available()) throw new Error("link was not transferred");
			    if (!links) {
			      let refused = false;
			      try { await old.invoke(new Uint8Array()); } catch { refused = true; }
			      if (!refused) throw new Error("old handle survived");
			    }
			    return await next.invoke(new Uint8Array([0, 7])); // empty op, then the echoed args
			  } finally { n.shell.close(); }
			})()`, hex.EncodeToString(a.id()), hex.EncodeToString(b.id()), links, readHex(first), readHex(second))
			got := awaitOK(t, "replacement", expr, 10*time.Second)
			if len(got) != 1 || got[0] != 7 {
				t.Fatalf("replacement invocation: %v", got)
			}
		})
	}
}
