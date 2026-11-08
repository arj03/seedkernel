;; The scratch window's size (§4.1), which quic.c's `scratch` reserves: a turn takes a whole
;; `datagrams` event. wasm-merge links this to the module (build.sh), which imports nothing.
(module
  (global (export "scratchSize") i32 (i32.const 2621440)))
