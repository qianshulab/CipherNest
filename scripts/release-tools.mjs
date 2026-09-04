#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const targetSpecs = {
  "aarch64-apple-darwin": {
    label: "macOS-aarch64",
    artifacts: [
      {
        bundleDirectory: "dmg",
        extension: ".dmg",
        releaseName(version) {
          return `CipherNest-${version}-macOS-aarch64.dmg`;
        },
      },
    ],
  },
  "x86_64-pc-windows-msvc": {
    label: "Windows-x86_64",
    artifacts: [
      {
        bundleDirectory: "nsis",
        extension: ".exe",
        releaseName(version) {
          return `CipherNest-${version}-Windows-x86_64-setup.exe`;
        },
      },
    ],
  },
  "x86_64-unknown-linux-gnu": {
    label: "Linux-x86_64",
    artifacts: [
      {
        bundleDirectory: "appimage",
        extension: ".AppImage",
        releaseName(version) {
          return `CipherNest-${version}-Linux-x86_64.AppImage`;
        },
      },
      {
        bundleDirectory: "deb",
        extension: ".deb",
        releaseName(version) {
          return `CipherNest-${version}-Linux-x86_64.deb`;
        },
      },
    ],
  },
};

function fail(message) {
  process.stderr.write(`release-tools: ${message}\n`);
  process.exit(1);
}

function parseArguments(values) {
  const options = new Map();
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    if (!key.startsWith("--")) {
      fail(`unexpected argument: ${key}`);
    }
    const value = values[index + 1];
    if (value === undefined || value.startsWith("--")) {
      fail(`missing value for ${key}`);
    }
    options.set(key.slice(2), value);
    index += 1;
  }
  return options;
}

function requireOption(options, name) {
  const value = options.get(name);
  if (!value) {
    fail(`missing --${name}`);
  }
  return value;
}

function packageVersionFromCargo(cargoText) {
  const packageSection = cargoText.match(/^\[package\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m);
  if (!packageSection) {
    fail("could not find [package] in src-tauri/Cargo.toml");
  }
  const version = packageSection[1].match(/^version\s*=\s*"([^"]+)"\s*$/m)?.[1];
  if (!version) {
    fail("could not find package version in src-tauri/Cargo.toml");
  }
  return version;
}

function readProjectVersion() {
  const packageJson = JSON.parse(readFileSync(join(repositoryRoot, "package.json"), "utf8"));
  const tauriConfig = JSON.parse(
    readFileSync(join(repositoryRoot, "src-tauri", "tauri.conf.json"), "utf8"),
  );
  const cargoVersion = packageVersionFromCargo(
    readFileSync(join(repositoryRoot, "src-tauri", "Cargo.toml"), "utf8"),
  );
  const versions = {
    "package.json": packageJson.version,
    "src-tauri/tauri.conf.json": tauriConfig.version,
    "src-tauri/Cargo.toml": cargoVersion,
  };
  if (new Set(Object.values(versions)).size !== 1) {
    fail(`project versions disagree: ${JSON.stringify(versions)}`);
  }
  const version = packageJson.version;
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    fail(`unsupported project version: ${version}`);
  }
  return version;
}

function verifyVersion(options) {
  const version = readProjectVersion();
  const tag =
    options.get("tag") ??
    (process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : undefined);
  if (tag && tag !== `v${version}`) {
    fail(`tag ${tag} does not match project version v${version}`);
  }
  process.stdout.write(`Verified CipherNest version ${version}${tag ? ` for ${tag}` : ""}.\n`);
}

function sha256(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function verifyBinary(options) {
  const target = requireOption(options, "target");
  const binaryPath = resolve(repositoryRoot, requireOption(options, "path"));
  if (!existsSync(binaryPath)) {
    fail(`native executable does not exist: ${binaryPath}`);
  }
  const bytes = readFileSync(binaryPath);

  if (target === "aarch64-apple-darwin") {
    if (bytes.length < 12 || bytes.readUInt32LE(0) !== 0xfeedfacf) {
      fail(`${binaryPath} is not a thin 64-bit little-endian Mach-O executable`);
    }
    if (bytes.readUInt32LE(4) !== 0x0100000c) {
      fail(`${binaryPath} is not Mach-O ARM64`);
    }
  } else if (target === "x86_64-pc-windows-msvc") {
    if (bytes.length < 64 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
      fail(`${binaryPath} is not a PE executable`);
    }
    const peOffset = bytes.readUInt32LE(0x3c);
    if (peOffset + 6 > bytes.length || bytes.readUInt32LE(peOffset) !== 0x00004550) {
      fail(`${binaryPath} has an invalid PE header`);
    }
    if (bytes.readUInt16LE(peOffset + 4) !== 0x8664) {
      fail(`${binaryPath} is not PE x86_64`);
    }
  } else if (target === "x86_64-unknown-linux-gnu") {
    const isElf64 =
      bytes.length >= 20 &&
      bytes[0] === 0x7f &&
      bytes[1] === 0x45 &&
      bytes[2] === 0x4c &&
      bytes[3] === 0x46 &&
      bytes[4] === 2;
    if (!isElf64 || bytes.readUInt16LE(18) !== 0x003e) {
      fail(`${binaryPath} is not ELF x86_64`);
    }
  } else {
    fail(`unsupported target: ${target}`);
  }

  process.stdout.write(`Verified ${basename(binaryPath)} architecture for ${target}.\n`);
}

function regularFilesRecursively(root) {
  if (!existsSync(root)) {
    return [];
  }
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const entryPath = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...regularFilesRecursively(entryPath));
    } else if (entry.isFile() && !entry.isSymbolicLink()) {
      files.push(entryPath);
    }
  }
  return files;
}

function findSingleBundle(bundleRoot, artifact, version) {
  const expectedDirectory = `${sep}${artifact.bundleDirectory}${sep}`;
  const candidates = regularFilesRecursively(bundleRoot).filter(
    (filePath) =>
      filePath.includes(expectedDirectory) &&
      filePath.toLowerCase().endsWith(artifact.extension.toLowerCase()),
  );
  if (candidates.length !== 1) {
    fail(
      `expected exactly one ${artifact.extension} in ${artifact.bundleDirectory}, found ${candidates.length}`,
    );
  }
  const versionToken = new RegExp(
    `(?:^|[_-])${version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=[_.-]|$)`,
  );
  if (!versionToken.test(basename(candidates[0]))) {
    fail(`bundle filename does not contain current version ${version}: ${basename(candidates[0])}`);
  }
  if (lstatSync(candidates[0]).size === 0) {
    fail(`bundle is empty: ${candidates[0]}`);
  }
  return candidates[0];
}

function copyWithoutReplacingDifferentFile(source, destination) {
  if (existsSync(destination)) {
    if (sha256(source) !== sha256(destination)) {
      fail(`refusing to replace a different staged file: ${destination}`);
    }
    return;
  }
  copyFileSync(source, destination);
}

function stage(options) {
  const target = requireOption(options, "target");
  const spec = targetSpecs[target];
  if (!spec) {
    fail(`unsupported target: ${target}`);
  }
  const bundleRoot = resolve(repositoryRoot, requireOption(options, "bundle-root"));
  const output = resolve(repositoryRoot, requireOption(options, "output"));
  const version = readProjectVersion();
  mkdirSync(output, { recursive: true });

  const staged = spec.artifacts.map((artifact) => {
    const source = findSingleBundle(bundleRoot, artifact, version);
    const destination = join(output, artifact.releaseName(version));
    copyWithoutReplacingDifferentFile(source, destination);
    return destination;
  });
  const checksumText = staged
    .map((filePath) => `${sha256(filePath)}  ${basename(filePath)}`)
    .sort()
    .join("\n");
  writeFileSync(join(output, `SHA256SUMS-${spec.label}.txt`), `${checksumText}\n`, {
    encoding: "utf8",
    mode: 0o644,
  });
  process.stdout.write(`Staged ${staged.length} verified release asset(s) for ${spec.label}.\n`);
}

function expectedReleaseNames(version) {
  return Object.values(targetSpecs).flatMap((spec) =>
    spec.artifacts.map((artifact) => artifact.releaseName(version)),
  );
}

function manifest(options) {
  const assetsRoot = resolve(repositoryRoot, requireOption(options, "assets"));
  const version = readProjectVersion();
  const allFiles = regularFilesRecursively(assetsRoot);
  const expectedNames = expectedReleaseNames(version);
  const expectedNameSet = new Set(expectedNames);
  const installerExtensions = [".dmg", ".exe", ".appimage", ".deb"];
  const unexpectedInstallers = allFiles.filter((filePath) => {
    const name = basename(filePath);
    return (
      installerExtensions.some((extension) => name.toLowerCase().endsWith(extension)) &&
      !expectedNameSet.has(name)
    );
  });
  if (unexpectedInstallers.length > 0) {
    fail(
      `unexpected installer assets: ${unexpectedInstallers
        .map((filePath) => basename(filePath))
        .sort()
        .join(", ")}`,
    );
  }
  const releaseFiles = [];

  for (const expectedName of expectedNames) {
    const candidates = allFiles.filter((filePath) => basename(filePath) === expectedName);
    if (candidates.length !== 1) {
      fail(`expected exactly one downloaded ${expectedName}, found ${candidates.length}`);
    }
    const flattenedPath = join(assetsRoot, expectedName);
    if (resolve(candidates[0]) !== resolve(flattenedPath)) {
      copyWithoutReplacingDifferentFile(candidates[0], flattenedPath);
    }
    releaseFiles.push(flattenedPath);
  }

  const declaredChecksums = new Map();
  for (const checksumFile of allFiles.filter((filePath) =>
    basename(filePath).startsWith("SHA256SUMS-"),
  )) {
    for (const line of readFileSync(checksumFile, "utf8").split(/\r?\n/)) {
      if (!line) continue;
      const match = line.match(/^([a-f0-9]{64}) {2}(.+)$/);
      if (!match) {
        fail(`malformed checksum line in ${checksumFile}`);
      }
      if (declaredChecksums.has(match[2])) {
        fail(`duplicate staged checksum for ${match[2]}`);
      }
      declaredChecksums.set(match[2], match[1]);
    }
  }
  if (
    declaredChecksums.size !== expectedNames.length ||
    [...declaredChecksums.keys()].some((name) => !expectedNameSet.has(name))
  ) {
    fail("staged checksum files do not describe the exact expected release asset set");
  }

  const manifestAssets = releaseFiles
    .map((filePath) => {
      const digest = sha256(filePath);
      if (declaredChecksums.get(basename(filePath)) !== digest) {
        fail(`downloaded artifact checksum mismatch: ${basename(filePath)}`);
      }
      return {
        name: basename(filePath),
        sha256: digest,
        size: lstatSync(filePath).size,
      };
    })
    .sort((left, right) => left.name.localeCompare(right.name));

  const checksumText = manifestAssets
    .map((asset) => `${asset.sha256}  ${asset.name}`)
    .join("\n");
  writeFileSync(join(assetsRoot, "SHA256SUMS.txt"), `${checksumText}\n`, "utf8");
  writeFileSync(
    join(assetsRoot, "release-manifest.json"),
    `${JSON.stringify(
      {
        schemaVersion: 1,
        product: "CipherNest",
        version,
        sourceCommit: process.env.GITHUB_SHA ?? null,
        assets: manifestAssets,
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  process.stdout.write(`Verified ${manifestAssets.length} release assets and generated manifests.\n`);
}

const [command, ...argumentValues] = process.argv.slice(2);
const options = parseArguments(argumentValues);

switch (command) {
  case "verify-version":
    verifyVersion(options);
    break;
  case "verify-binary":
    verifyBinary(options);
    break;
  case "stage":
    stage(options);
    break;
  case "manifest":
    manifest(options);
    break;
  default:
    fail("expected command: verify-version, verify-binary, stage, or manifest");
}
