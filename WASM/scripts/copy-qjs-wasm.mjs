// Copy qjs.wasm, the engine every guest realm runs on, from where the native build keeps
// it (../native/qjs/, rebuilt by build-qjs.sh and checked in there, since go:embed cannot
// reach outside native/) to browser/, beside the package's other wasm, where the JS
// targets load it (host/engine-web.ts).

import { copyFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
copyFileSync(resolve(root, "../native/qjs/qjs.wasm"), resolve(root, "browser/qjs.wasm"));
console.log("copied ../native/qjs/qjs.wasm -> browser/qjs.wasm");
