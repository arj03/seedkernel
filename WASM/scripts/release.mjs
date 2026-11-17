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
// Only a published tag is binding: a local one left by a failed run is moved to HEAD.
const published = read(`git ls-remote origin refs/tags/${tag}`).split("\t")[0];
if (published && published !== read("git rev-parse HEAD")) throw new Error(`${tag} is already published on another commit`);

run("npm run build:native", root);
run(`git tag -f ${tag}`);
run(`git push origin ${tag}`);
run(`gh release create ${tag} --draft --verify-tag --title ${tag} --generate-notes native/host.skb.gz native/loader.js`);
run(`gh workflow run release.yml -f tag=${tag}`);
console.log(`\n${tag}: draft release created, binaries building (gh run watch)`);
