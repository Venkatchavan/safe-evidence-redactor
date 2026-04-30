#!/usr/bin/env node
/**
 * safe-evidence-redactor — MCP server
 *
 * Exposes the redactor as Model Context Protocol tools over stdio so any
 * MCP-aware client (Claude Desktop, MCP Inspector, agent frameworks, ...)
 * can sanitize text/JSON before logging, sharing, or feeding it back to a
 * model.
 *
 * Tools:
 *   - redact_text: redact a string
 *   - redact_json: redact a JSON value (object/array/primitive)
 *
 * The server is fully offline. It does not initiate any outbound network
 * connections; it only speaks MCP over stdio with its parent process.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  redactJson,
  redactText,
  type RedactionCategory,
  type RedactOptions,
} from "./redact.js";

const VALID_CATEGORIES: ReadonlyArray<RedactionCategory> = [
  "EMAIL", "PHONE", "IP", "BEARER", "JWT", "API_KEY", "COOKIE",
  "AUTH_HEADER", "AADHAAR", "PAN", "UPI", "URL_SECRET", "GENERIC_SECRET",
];

const ModeEnum = z.enum(["minimal", "balanced", "strict"]);
const CategoryEnum = z.enum(
  VALID_CATEGORIES as unknown as [RedactionCategory, ...RedactionCategory[]],
);

const AllowSchema = z
  .object({
    domains: z.array(z.string()).optional(),
    fields: z.array(z.string()).optional(),
    patterns: z
      .array(z.string())
      .optional()
      .describe("Regex source strings; matches preserved."),
    categories: z.array(CategoryEnum).optional(),
  })
  .optional();

/**
 * Build a `RedactOptions` from the parsed Zod-validated args. Patterns arrive
 * as strings and are compiled here; invalid regexes are silently dropped to
 * keep the tool resilient to imperfect agent inputs.
 */
function buildOptions(args: {
  mode?: "minimal" | "balanced" | "strict";
  allow?: {
    domains?: string[];
    fields?: string[];
    patterns?: string[];
    categories?: RedactionCategory[];
  };
}): RedactOptions {
  const out: RedactOptions = {};
  if (args.mode) out.mode = args.mode;
  if (args.allow) {
    const a: NonNullable<RedactOptions["allow"]> = {};
    if (args.allow.domains) a.domains = args.allow.domains;
    if (args.allow.fields) a.fields = args.allow.fields;
    if (args.allow.categories) a.categories = args.allow.categories;
    if (args.allow.patterns) {
      const compiled: RegExp[] = [];
      for (const src of args.allow.patterns) {
        try {
          compiled.push(new RegExp(src));
        } catch {
          /* skip invalid */
        }
      }
      if (compiled.length > 0) a.patterns = compiled;
    }
    out.allow = a;
  }
  return out;
}

async function main(): Promise<void> {
  const server = new McpServer({
    name: "safe-evidence-redactor",
    version: "0.1.0",
  });

  server.registerTool(
    "redact_text",
    {
      title: "Redact text",
      description:
        "Redact PII and secrets (emails, phones, IPs, JWTs, API keys, cookies, " +
        "Aadhaar, PAN, UPI, sensitive URL params, ...) from a string. Offline.",
      inputSchema: {
        input: z.string().describe("The text to redact."),
        mode: ModeEnum.optional().describe("Aggressiveness. Default: balanced."),
        allow: AllowSchema,
      },
    },
    async (args) => {
      const { output, stats } = redactText(args.input, buildOptions(args));
      return {
        content: [{ type: "text" as const, text: output }],
        structuredContent: {
          output,
          stats: stats as unknown as Record<string, unknown>,
        },
      };
    },
  );

  server.registerTool(
    "redact_json",
    {
      title: "Redact JSON",
      description:
        "Redact PII and secrets inside a nested JSON value while preserving " +
        "structure and key names. Returns the redacted value and stats with " +
        "JSON paths affected. Offline.",
      inputSchema: {
        input: z
          .unknown()
          .describe("The JSON value (object/array/primitive) to redact."),
        mode: ModeEnum.optional(),
        allow: AllowSchema,
      },
    },
    async (args) => {
      const { output, stats } = redactJson(args.input, buildOptions(args));
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(output, null, 2) },
        ],
        structuredContent: {
          output: output as unknown,
          stats: stats as unknown as Record<string, unknown>,
        },
      };
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`safe-redact-mcp: ${msg}\n`);
  process.exit(1);
});
