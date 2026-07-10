#!/usr/bin/env node
"use strict";

// Fail the build if murk's release version disagrees anywhere it is declared.
//
// The original guard (ci.yaml) only compared Cargo.toml against
// node/package.json — which is exactly how node/package-lock.json silently
// drifted to 0.6.2 across v0.7.0 and v0.8.0: nothing cross-checked it. This
// checks every release-bumped location. Rust manifest versions come from
// `cargo metadata` (so a workspace member that drops `version.workspace = true`
// is caught), and the Cargo.lock entries are parsed directly so a stale lock is
// caught here too, before the expensive release build.

const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");

const meta = JSON.parse(
  execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 1 << 24,
  }),
);
const manifestVersion = (name) => {
  const p = meta.packages.find((x) => x.name === name);
  return p && p.version;
};

const lockToml = read("Cargo.lock");
const lockVersion = (name) => {
  const m = lockToml.match(new RegExp(`name = "${name}"\\nversion = "([^"]+)"`));
  return m && m[1];
};

const pkg = JSON.parse(read("node/package.json"));
const lock = JSON.parse(read("node/package-lock.json"));

const locations = {
  "manifest: murk-cli": manifestVersion("murk-cli"),
  "manifest: murk-napi": manifestVersion("murk-napi"),
  "Cargo.lock: murk-cli": lockVersion("murk-cli"),
  "Cargo.lock: murk-napi": lockVersion("murk-napi"),
  "node/package.json": pkg.version,
  "node/package-lock.json (root)": lock.version,
  "node/package-lock.json (packages[''])": lock.packages?.[""]?.version,
};

for (const [where, version] of Object.entries(locations)) {
  console.log(`  ${String(version).padEnd(8)} ${where}`);
}

const distinct = [...new Set(Object.values(locations))];
if (distinct.length !== 1 || !distinct[0]) {
  console.error(
    `::error::murk version drift across ${Object.keys(locations).length} locations: ${distinct.join(", ")}`,
  );
  process.exit(1);
}
console.log(`OK: all versions consistent at ${distinct[0]}`);
