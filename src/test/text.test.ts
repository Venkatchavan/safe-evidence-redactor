import { test } from "node:test";
import assert from "node:assert/strict";
import { redactText } from "../redact.js";

test("redacts emails in balanced mode", () => {
  const { output, stats } = redactText("contact alice@example.com today");
  assert.ok(output.includes("[REDACTED:EMAIL]"));
  assert.ok(!output.includes("alice@example.com"));
  assert.equal(stats.byCategory.EMAIL, 1);
});

test("does NOT redact emails in minimal mode", () => {
  const { output } = redactText("contact alice@example.com", { mode: "minimal" });
  assert.ok(output.includes("alice@example.com"));
});

test("redacts Indian mobile numbers with various prefixes", () => {
  const samples = [
    "Call me at +91 98765 43210",
    "Call me at +919876543210",
    "Call me at 09876543210",
    "Call me at 9876543210",
    "Call me at 0091-9876543210",
  ];
  for (const s of samples) {
    const { output, stats } = redactText(s);
    assert.ok(stats.byCategory.PHONE >= 1, `expected phone redaction in: ${s}`);
    assert.ok(!/9876543210/.test(output), `raw number leaked: ${output}`);
  }
});

test("preserves Indian-mobile-shaped numbers in minimal mode", () => {
  const { output } = redactText("call 9876543210", { mode: "minimal" });
  assert.ok(output.includes("9876543210"));
});

test("redacts Aadhaar numbers (grouped and ungrouped)", () => {
  const cases = ["2345 6789 0123", "234567890123", "9876-5432-1098"];
  for (const c of cases) {
    const { stats } = redactText(`Aadhaar: ${c}`);
    assert.equal(stats.byCategory.AADHAAR, 1, `failed for ${c}`);
  }
});

test("does not match invalid Aadhaar starting with 0 or 1", () => {
  const { stats } = redactText("ID: 1234 5678 9012");
  assert.ok(!stats.byCategory.AADHAAR);
});

test("redacts PAN ids", () => {
  const { output, stats } = redactText("PAN: ABCDE1234F");
  assert.ok(output.includes("[REDACTED:PAN]"));
  assert.equal(stats.byCategory.PAN, 1);
});

test("redacts UPI ids without consuming generic emails", () => {
  const { output, stats } = redactText("Pay rohan@okicici and email rohan@gmail.com");
  assert.ok(output.includes("[REDACTED:UPI]"));
  assert.ok(output.includes("[REDACTED:EMAIL]"));
  assert.equal(stats.byCategory.UPI, 1);
  assert.equal(stats.byCategory.EMAIL, 1);
});

test("redacts IPv4 and IPv6 addresses", () => {
  const { output, stats } = redactText("from 10.0.0.1 and 2001:db8::1");
  assert.ok(!output.includes("10.0.0.1"));
  assert.ok(!output.includes("2001:db8::1"));
  assert.ok((stats.byCategory.IP ?? 0) >= 2);
});

test("redacts Bearer tokens", () => {
  const { output, stats } = redactText("Authorization: Bearer abcdef0123456789xyz");
  // Auth header pattern wins, so the whole header is replaced.
  assert.ok(output.includes("[REDACTED:AUTH_HEADER]"));
  assert.equal(stats.byCategory.AUTH_HEADER, 1);
});

test("redacts standalone Bearer prefix outside of header context", () => {
  const { output, stats } = redactText("token=Bearer abc123def456ghi789");
  assert.ok(output.includes("Bearer [REDACTED:BEARER]"));
  assert.equal(stats.byCategory.BEARER, 1);
});

test("redacts JWTs", () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const { output, stats } = redactText(`token=${jwt}`);
  assert.ok(output.includes("[REDACTED:JWT]"));
  assert.equal(stats.byCategory.JWT, 1);
});

test("redacts vendor API keys", () => {
  const cases = [
    "ghp_" + "a".repeat(40),
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "sk-ant-" + "x".repeat(40),
    "AIza" + "a".repeat(35),
  ];
  for (const c of cases) {
    const { output, stats } = redactText(`key=${c}`);
    assert.ok(output.includes("[REDACTED:API_KEY]"), `failed for ${c}: ${output}`);
    assert.equal(stats.byCategory.API_KEY, 1);
  }
});

test("redacts Cookie and Set-Cookie headers", () => {
  const input = "Cookie: session=abcd1234; Path=/\nSet-Cookie: x=y";
  const { output, stats } = redactText(input);
  assert.ok(output.includes("Cookie: [REDACTED:COOKIE]"));
  assert.ok(output.includes("Set-Cookie: [REDACTED:COOKIE]"));
  assert.equal(stats.byCategory.COOKIE, 2);
});

test("redacts sensitive URL query params (preserving keys)", () => {
  const input =
    "GET https://api.example.com/v1?token=abc123&user=bob&secret=zzz&page=1";
  const { output, stats } = redactText(input);
  assert.ok(output.includes("token=[REDACTED:URL_SECRET]"));
  assert.ok(output.includes("secret=[REDACTED:URL_SECRET]"));
  assert.ok(output.includes("user=bob"));
  assert.ok(output.includes("page=1"));
  assert.equal(stats.byCategory.URL_SECRET, 2);
});

test("balanced mode does NOT redact a 40-char hex commit hash", () => {
  const { stats } = redactText("commit abcdef0123456789abcdef0123456789abcdef01");
  assert.ok(!stats.byCategory.GENERIC_SECRET);
});

test("strict mode redacts long hex/base64 secrets", () => {
  const { stats } = redactText(
    "secret abcdef0123456789abcdef0123456789abcdef01",
    { mode: "strict" },
  );
  assert.ok((stats.byCategory.GENERIC_SECRET ?? 0) >= 1);
});

test("allowlist domain preserves matching emails", () => {
  const { output, stats } = redactText("ping ops@safe.example.com and a@b.com", {
    allow: { domains: ["safe.example.com"] },
  });
  assert.ok(output.includes("ops@safe.example.com"));
  assert.ok(!output.includes("a@b.com"));
  assert.equal(stats.byCategory.EMAIL, 1);
});

test("allowlist categories disables a category entirely", () => {
  const { output, stats } = redactText("a@b.com 10.0.0.1", {
    allow: { categories: ["EMAIL"] },
  });
  assert.ok(output.includes("a@b.com"));
  assert.ok(!output.includes("10.0.0.1"));
  assert.ok(!stats.byCategory.EMAIL);
});

test("allowlist regex pattern preserves matches", () => {
  const { output } = redactText("ping admin@internal.test", {
    allow: { patterns: [/admin@internal\.test/] },
  });
  assert.ok(output.includes("admin@internal.test"));
});

test("stats accumulate across categories with totals", () => {
  const { stats } = redactText("a@b.com from 10.0.0.1 with PAN ABCDE1234F");
  assert.ok(stats.total >= 3);
  assert.equal(stats.byCategory.EMAIL, 1);
  assert.equal(stats.byCategory.IP, 1);
  assert.equal(stats.byCategory.PAN, 1);
});
