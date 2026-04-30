import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(__dirname, "..", "cli.js");

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function run(args: string[], stdin?: string): Promise<RunResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    child.on("error", rejectPromise);
    child.on("close", (code) =>
      resolvePromise({ code: code ?? 0, stdout, stderr }),
    );
    if (stdin !== undefined) child.stdin.write(stdin);
    child.stdin.end();
  });
}

test("CLI redacts text from stdin", async () => {
  const { code, stdout } = await run([], "email a@b.com\n");
  assert.equal(code, 0);
  assert.ok(stdout.includes("[REDACTED:EMAIL]"));
  assert.ok(!stdout.includes("a@b.com"));
});

test("CLI redacts file argument and emits stats to stderr", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safe-redact-"));
  const f = join(dir, "in.txt");
  await writeFile(f, "ip 10.0.0.1 and email a@b.com\n");
  const { code, stdout, stderr } = await run([f, "--stats"]);
  assert.equal(code, 0);
  assert.ok(stdout.includes("[REDACTED:IP]"));
  assert.ok(stdout.includes("[REDACTED:EMAIL]"));
  // stats are JSON on stderr
  const stats = JSON.parse(stderr);
  assert.ok(stats.total >= 2);
});

test("CLI --json mode preserves structure and redacts values", async () => {
  const payload = JSON.stringify({ email: "a@b.com", note: "hi" });
  const { code, stdout } = await run(["--json"], payload);
  assert.equal(code, 0);
  const parsed = JSON.parse(stdout);
  assert.ok(String(parsed.email).includes("[REDACTED"));
  assert.equal(parsed.note, "hi");
});

test("CLI --mode strict applies stricter redaction", async () => {
  const { stdout } = await run(["--mode", "strict"], "abcdef0123456789abcdef0123456789abcdef01\n");
  assert.ok(stdout.includes("[REDACTED:GENERIC_SECRET]"));
});

test("CLI --allow-domain preserves matching emails", async () => {
  const { stdout } = await run(
    ["--allow-domain", "safe.example.com"],
    "ping ops@safe.example.com and a@b.com\n",
  );
  assert.ok(stdout.includes("ops@safe.example.com"));
  assert.ok(!stdout.includes("a@b.com"));
});

test("CLI rejects invalid --mode", async () => {
  const { code, stderr } = await run(["--mode", "nope"], "x\n");
  assert.notEqual(code, 0);
  assert.ok(stderr.toLowerCase().includes("invalid"));
});

test("CLI prints help on --help", async () => {
  const { code, stdout } = await run(["--help"]);
  assert.equal(code, 0);
  assert.ok(stdout.includes("safe-redact"));
  assert.ok(stdout.includes("--mode"));
});
