#!/usr/bin/env node
// Mark CLI and MCP entry points executable on POSIX (no-op on Windows).
import { chmodSync } from "node:fs";

if (process.platform !== "win32") {
  for (const p of ["dist/cli.js", "dist/mcp.js"]) {
    chmodSync(p, 0o755);
  }
}
