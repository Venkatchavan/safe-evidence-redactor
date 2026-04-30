import { test } from "node:test";
import assert from "node:assert/strict";
import { redactJson, redactValue } from "../redact.js";

test("redacts strings inside nested JSON and reports paths", () => {
  const input = {
    user: {
      email: "alice@example.com",
      phone: "+91 98765 43210",
    },
    events: [
      { ip: "10.0.0.1", note: "ok" },
      { ip: "2001:db8::1", note: "ABCDE1234F" },
    ],
  };
  const { output, stats } = redactJson(input);
  const out = output as typeof input;
  assert.ok(!JSON.stringify(out).includes("alice@example.com"));
  assert.ok(!JSON.stringify(out).includes("9876543210"));
  assert.ok(!JSON.stringify(out).includes("10.0.0.1"));
  assert.ok(!JSON.stringify(out).includes("ABCDE1234F"));
  assert.ok(stats.paths.includes("user.email"));
  assert.ok(stats.paths.includes("events[0].ip"));
  assert.ok(stats.paths.includes("events[1].note"));
});

test("force-redacts sensitive field names regardless of value", () => {
  const input = {
    password: "hunter2",
    api_key: "anything-here",
    nested: { token: "x" },
    safe: "kept",
  };
  const { output, stats } = redactJson(input);
  const out = output as Record<string, unknown>;
  assert.equal(out.password, "[REDACTED:GENERIC_SECRET]");
  assert.equal(out.api_key, "[REDACTED:GENERIC_SECRET]");
  assert.equal((out.nested as Record<string, unknown>).token, "[REDACTED:GENERIC_SECRET]");
  assert.equal(out.safe, "kept");
  assert.ok(stats.paths.includes("password"));
  assert.ok(stats.paths.includes("nested.token"));
});

test("force-redact maps cookie/auth field names to their categories", () => {
  const input = { Cookie: "x=y", Authorization: "Bearer abc" };
  const { output, stats } = redactJson(input);
  const out = output as Record<string, string>;
  assert.equal(out.Cookie, "[REDACTED:COOKIE]");
  assert.equal(out.Authorization, "[REDACTED:AUTH_HEADER]");
  assert.equal(stats.byCategory.COOKIE, 1);
  assert.equal(stats.byCategory.AUTH_HEADER, 1);
});

test("allowlist fields disables forced redaction for that field name", () => {
  const input = { token: "public-pseudo-token", email: "a@b.com" };
  const { output } = redactJson(input, { allow: { fields: ["token"] } });
  const out = output as Record<string, string>;
  assert.equal(out.token, "public-pseudo-token");
  assert.ok(String(out.email).includes("[REDACTED:EMAIL]"));
});

test("redactValue dispatches to text or json correctly", () => {
  const s = redactValue("email a@b.com");
  assert.equal(typeof s.output, "string");
  assert.ok((s.output as string).includes("[REDACTED:EMAIL]"));

  const j = redactValue({ email: "a@b.com" });
  assert.equal(typeof j.output, "object");
});

test("input objects are not mutated", () => {
  const input = { email: "a@b.com" };
  redactJson(input);
  assert.equal(input.email, "a@b.com");
});

test("primitive non-string values are returned unchanged", () => {
  const { output } = redactJson({ n: 42, b: true, x: null });
  assert.deepEqual(output, { n: 42, b: true, x: null });
});
