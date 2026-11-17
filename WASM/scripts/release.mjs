// Cuts a native release whose host blob is signed here, with the local host-author.key,
// and compiled by .github/workflows/release.yml. Tags HEAD as v<package.json version>,
// builds and signs the host blob, opens a draft release carrying host.skb.gz and loader.js,
// and starts the workflow, which attaches the binaries to that draft for review and publish.
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(root, "..");
const tag = "v" + JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")).version;
const run = (cmd, cwd = repo) => execSync(cmd, { cwd, stdio: "inherit" });
const read = (cmd) => execSync(cmd, { cwd: repo, encoding: "utf8" }).trim();

// The binaries are compiled from the tagged commit, so it must be exactly what is built here.
if (read("git status --porcelain --untracked-files=no")) throw new Error("working tree is not clean; commit first");
// A tag at HEAD is a rerun after a failed push or upload; one elsewhere is a real conflict.
const tagged = read(`git tag -l ${tag}`);
if (tagged && read(`git rev-parse ${tag}^{commit}`) !== read("git rev-parse HEAD")) throw new Error(`${tag} exists on another commit`);

run("npm run build:native", root);
if (!tagged) run(`git tag ${tag}`);
run(`git push origin ${tag}`);
run(`gh release create ${tag} --draft --verify-tag --title ${tag} --generate-notes native/host.skb.gz native/loader.js`);
run(`gh workflow run release.yml -f tag=${tag}`);
console.log(`\n${tag}: draft release created, binaries building (gh run watch)`);
