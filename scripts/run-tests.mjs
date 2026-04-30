#!/usr/bin/env node
/**
 * Cross-platform test runner.
 *
 * Why this exists:
 *  - `node --test "dist/test/**\/*.test.js"` relies on shell glob expansion,
 *    which behaves differently on bash/zsh/sh/PowerShell/cmd.
 *  - `node --test dist/test/` is only fully supported on newer Node versions.
 *
 * We resolve the test files in JS, then spawn `node --test ...files`.
 */
import { readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

function findTests(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      out.push(...findTests(p));
    } else if (entry.endsWith(".test.js")) {
      out.push(p);
    }
  }
  return out;
}

const root = resolve("dist", "test");
const files = findTests(root);

if (files.length === 0) {
  console.error(`No test files found under ${root}`);
  process.exit(1);
}

const result = spawnSync(
  process.execPath,
  ["--test", "--test-reporter=spec", ...files],
  { stdio: "inherit" },
);
process.exit(result.status ?? 1);
