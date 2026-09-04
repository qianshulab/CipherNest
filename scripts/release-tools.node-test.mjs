import assert from "node:assert/strict";
// Kept outside Vitest's *.test.* discovery; this suite uses Node's built-in test runner.
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "..");
const releaseTools = join(repositoryRoot, "scripts", "release-tools.mjs");
const projectVersion = JSON.parse(
  readFileSync(join(repositoryRoot, "package.json"), "utf8"),
).version;

function run(args, environment = {}) {
  return spawnSync(process.execPath, [releaseTools, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, ...environment },
  });
}

function writeFixture(filePath, contents) {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, contents);
}

test("validates project version and rejects a mismatched tag", () => {
  assert.equal(run(["verify-version"]).status, 0);
  const mismatch = run(["verify-version", "--tag", "v9.9.9"]);
  assert.notEqual(mismatch.status, 0);
  assert.match(mismatch.stderr, /does not match project version/);
});

test("recognizes the three expected executable architectures", (context) => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "ciphernest-architectures-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

  const machO = Buffer.alloc(64);
  machO.writeUInt32LE(0xfeedfacf, 0);
  machO.writeUInt32LE(0x0100000c, 4);
  const machOPath = join(fixtureRoot, "ciphernest-macos");
  writeFixture(machOPath, machO);

  const pe = Buffer.alloc(512);
  pe.write("MZ", 0, "ascii");
  pe.writeUInt32LE(0x80, 0x3c);
  pe.writeUInt32LE(0x00004550, 0x80);
  pe.writeUInt16LE(0x8664, 0x84);
  const pePath = join(fixtureRoot, "ciphernest.exe");
  writeFixture(pePath, pe);

  const elf = Buffer.alloc(64);
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2], 0);
  elf.writeUInt16LE(0x003e, 18);
  const elfPath = join(fixtureRoot, "ciphernest-linux");
  writeFixture(elfPath, elf);

  assert.equal(
    run(["verify-binary", "--target", "aarch64-apple-darwin", "--path", machOPath]).status,
    0,
  );
  assert.equal(
    run(["verify-binary", "--target", "x86_64-pc-windows-msvc", "--path", pePath]).status,
    0,
  );
  assert.equal(
    run(["verify-binary", "--target", "x86_64-unknown-linux-gnu", "--path", elfPath]).status,
    0,
  );
});

test("stages an exact four-package set and verifies its hashes", (context) => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "ciphernest-release-assets-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const output = join(fixtureRoot, "output");

  const fixtures = [
    ["mac", "dmg", `CipherNest_${projectVersion}_aarch64.dmg`, "macOS fixture"],
    ["windows", "nsis", `CipherNest_${projectVersion}_x64-setup.exe`, "Windows fixture"],
    ["linux", "appimage", `CipherNest_${projectVersion}_amd64.AppImage`, "AppImage fixture"],
    ["linux", "deb", `ciphernest_${projectVersion}_amd64.deb`, "Debian fixture"],
  ];
  for (const [platform, bundle, filename, contents] of fixtures) {
    writeFixture(join(fixtureRoot, platform, bundle, filename), contents);
  }

  const stages = [
    ["aarch64-apple-darwin", join(fixtureRoot, "mac")],
    ["x86_64-pc-windows-msvc", join(fixtureRoot, "windows")],
    ["x86_64-unknown-linux-gnu", join(fixtureRoot, "linux")],
  ];
  for (const [target, bundleRoot] of stages) {
    const result = run([
      "stage",
      "--target",
      target,
      "--bundle-root",
      bundleRoot,
      "--output",
      output,
    ]);
    assert.equal(result.status, 0, result.stderr);
  }

  const result = run(["manifest", "--assets", output], { GITHUB_SHA: "0123456789abcdef" });
  assert.equal(result.status, 0, result.stderr);
  const checksums = readFileSync(join(output, "SHA256SUMS.txt"), "utf8");
  assert.equal(checksums.trim().split("\n").length, 4);
  const manifest = JSON.parse(readFileSync(join(output, "release-manifest.json"), "utf8"));
  assert.equal(manifest.version, projectVersion);
  assert.equal(manifest.sourceCommit, "0123456789abcdef");
  assert.equal(manifest.assets.length, 4);

  writeFixture(join(output, "unexpected-installer.exe"), "unexpected");
  const unexpected = run(["manifest", "--assets", output]);
  assert.notEqual(unexpected.status, 0);
  assert.match(unexpected.stderr, /unexpected installer assets/);
});

test("rejects stale bundle filenames", (context) => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "ciphernest-stale-release-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  writeFixture(join(fixtureRoot, "dmg", "CipherNest_stale_aarch64.dmg"), "stale");
  const result = run([
    "stage",
    "--target",
    "aarch64-apple-darwin",
    "--bundle-root",
    fixtureRoot,
    "--output",
    join(fixtureRoot, "output"),
  ]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not contain current version/);
});
