// The quickjs-emscripten "variant" for the in-repo quickjs-ng 0.16.1 build.
// This is the same shape @jitl/quickjs-ng-wasmfile-release-sync exposes; see
// build-quickjs-ng.sh for how the engine is built. The engine is the only
// piece of the old @jitl package that differed from the native loader's —
// the JS API layer (quickjs-emscripten-core) is shared with the npm variant.
export default {
  type: "sync",
  importFFI: () => import("./ffi.mjs").then((m) => m.QuickJSFFI),
  importModuleLoader: () => import("./emscripten-module.mjs").then((m) => m.default),
};
