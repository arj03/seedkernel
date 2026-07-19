package main

import "sync"

// bootOnce shares a single shell boot across every benchmark in the package (boot()
// is a global singleton; re-running it would leak a runtime and reset the kernel's
// handler table out from under already-registered handlers). The fs and RS benches
// call ensureBooted so their measured path runs against one warmed-up shell.
var bootOnce sync.Once

func ensureBooted() { bootOnce.Do(boot) }
