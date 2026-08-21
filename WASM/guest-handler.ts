// The guest half of the module ABI (README §3.2, §4) — the memory-layout constants
// app WASM modules share — at the path AssemblyScript can reach.
//
// This file is ASSEMBLYSCRIPT source and only asc may compile it. asc (0.28) resolves a
// bare specifier by joining the literal subpath under node_modules and does not honor
// package.json `exports`, so `seedkernel-wasm/guest-handler` lands on THIS file and
// re-exports the real constants — which is also what keeps the two import spellings
// resolving to one definition. There is deliberately NO `./guest-handler` exports
// entry: an entry would not change what asc does, and would offer a JS consumer a
// subpath that resolves to `i32`-typed source it cannot parse. `files` ships it
// instead, which is the whole of what the reach needs.
export * from "./assembly/seedkernel/handler";
