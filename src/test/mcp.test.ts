import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { once } from "node:events";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MCP = resolve(__dirname, "..", "mcp.js");

/**
 * Minimal stdio JSON-RPC client for the MCP server. Speaks the
 * newline-delimited JSON framing used by `StdioServerTransport`.
 */
class StdioRpc {
  private buf = "";
  private nextId = 1;
  private pending = new Map<number, (msg: Record<string, unknown>) => void>();
  constructor(private readonly child: ChildProcessWithoutNullStreams) {
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      this.buf += chunk;
      let idx: number;
      while ((idx = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, idx).trim();
        this.buf = this.buf.slice(idx + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line) as Record<string, unknown>;
          const id = msg.id;
          if (typeof id === "number" && this.pending.has(id)) {
            this.pending.get(id)!(msg);
            this.pending.delete(id);
          }
        } catch {
          // ignore malformed lines
        }
      }
    });
  }

  request(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = this.nextId++;
    const payload = { jsonrpc: "2.0", id, method, params: params ?? {} };
    return new Promise((resolvePromise) => {
      this.pending.set(id, resolvePromise);
      this.child.stdin.write(JSON.stringify(payload) + "\n");
    });
  }

  notify(method: string, params?: Record<string, unknown>): void {
    const payload = { jsonrpc: "2.0", method, params: params ?? {} };
    this.child.stdin.write(JSON.stringify(payload) + "\n");
  }
}

async function withServer<T>(fn: (rpc: StdioRpc) => Promise<T>): Promise<T> {
  const child = spawn(process.execPath, [MCP], { stdio: ["pipe", "pipe", "pipe"] });
  const rpc = new StdioRpc(child);
  try {
    const init = await rpc.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test-client", version: "0.0.0" },
    });
    assert.ok(init.result, "initialize should return a result");
    rpc.notify("notifications/initialized");
    return await fn(rpc);
  } finally {
    child.stdin.end();
    child.kill();
    await once(child, "exit").catch(() => {});
  }
}

test("MCP: lists redact_text and redact_json tools", async () => {
  await withServer(async (rpc) => {
    const res = await rpc.request("tools/list");
    const result = res.result as { tools: Array<{ name: string }> };
    const names = result.tools.map((t) => t.name).sort();
    assert.deepEqual(names, ["redact_json", "redact_text"]);
  });
});

test("MCP: redact_text redacts and returns stats via structuredContent", async () => {
  await withServer(async (rpc) => {
    const res = await rpc.request("tools/call", {
      name: "redact_text",
      arguments: { input: "ping a@b.com from 10.0.0.1" },
    });
    const result = res.result as {
      content: Array<{ type: string; text: string }>;
      structuredContent?: { output: string; stats: { total: number } };
      isError?: boolean;
    };
    assert.ok(!result.isError);
    assert.ok(result.content[0]!.text.includes("[REDACTED:EMAIL]"));
    assert.ok(result.content[0]!.text.includes("[REDACTED:IP]"));
    assert.ok(result.structuredContent);
    assert.ok(result.structuredContent.stats.total >= 2);
  });
});

test("MCP: redact_json walks nested structures and emits paths", async () => {
  await withServer(async (rpc) => {
    const res = await rpc.request("tools/call", {
      name: "redact_json",
      arguments: {
        input: { user: { email: "x@y.com" }, password: "hunter2" },
        mode: "balanced",
      },
    });
    const result = res.result as {
      structuredContent: {
        output: { user: { email: string }; password: string };
        stats: { paths: string[] };
      };
    };
    assert.ok(
      result.structuredContent.output.user.email.includes("[REDACTED:EMAIL]"),
    );
    assert.equal(
      result.structuredContent.output.password,
      "[REDACTED:GENERIC_SECRET]",
    );
    assert.ok(result.structuredContent.stats.paths.includes("user.email"));
    assert.ok(result.structuredContent.stats.paths.includes("password"));
  });
});

test("MCP: allow.domains is honored", async () => {
  await withServer(async (rpc) => {
    const res = await rpc.request("tools/call", {
      name: "redact_text",
      arguments: {
        input: "ops@safe.example.com and a@b.com",
        allow: { domains: ["safe.example.com"] },
      },
    });
    const result = res.result as { content: Array<{ text: string }> };
    assert.ok(result.content[0]!.text.includes("ops@safe.example.com"));
    assert.ok(!result.content[0]!.text.includes("a@b.com"));
  });
});
