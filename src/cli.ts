#!/usr/bin/env node
/**
 * safe-redact CLI
 *
 * Usage:
 *   safe-redact file.txt
 *   safe-redact report.json --json
 *   cat logs.txt | safe-redact
 *   safe-redact --mode strict --stats
 *
 * The CLI is fully offline: it reads from a file or stdin, redacts, and
 * writes the result to stdout. Stats (when requested) go to stderr so they
 * never pollute the redacted payload on stdout.
 */

import { readFile } from "node:fs/promises";
import { redactJson, redactText, type RedactionMode, type RedactOptions } from "./redact.js";

interface CliArgs {
  file?: string;
  json: boolean;
  mode: RedactionMode;
  stats: boolean;
  help: boolean;
  version: boolean;
  allowDomains: string[];
  allowFields: string[];
}

const HELP = `safe-redact — privacy-first redaction for logs, reports, and AI/MCP outputs.

Usage:
  safe-redact [file] [options]
  cat input | safe-redact [options]

Options:
  --json                 Treat input as JSON (preserves structure, redacts values).
  --mode <m>             Redaction mode: minimal | balanced | strict (default: balanced).
  --stats                Print redaction statistics to stderr.
  --allow-domain <d>     Allowlist a domain substring (repeatable).
  --allow-field <f>      Allowlist a JSON field name (repeatable).
  -h, --help             Show this help.
  -v, --version          Show version.

Examples:
  safe-redact report.json --json --stats
  safe-redact --mode strict logs.txt
  cat alert.log | safe-redact --mode balanced
`;

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    json: false,
    mode: "balanced",
    stats: false,
    help: false,
    version: false,
    allowDomains: [],
    allowFields: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--json":
        args.json = true;
        break;
      case "--stats":
        args.stats = true;
        break;
      case "--mode": {
        const v = argv[++i];
        if (v !== "minimal" && v !== "balanced" && v !== "strict") {
          throw new Error(`Invalid --mode value: ${v}`);
        }
        args.mode = v;
        break;
      }
      case "--allow-domain": {
        const v = argv[++i];
        if (!v) throw new Error("--allow-domain requires a value");
        args.allowDomains.push(v);
        break;
      }
      case "--allow-field": {
        const v = argv[++i];
        if (!v) throw new Error("--allow-field requires a value");
        args.allowFields.push(v);
        break;
      }
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "-v":
      case "--version":
        args.version = true;
        break;
      default:
        if (a && a.startsWith("-")) {
          throw new Error(`Unknown option: ${a}`);
        }
        if (a && !args.file) {
          args.file = a;
        } else if (a) {
          throw new Error(`Unexpected positional argument: ${a}`);
        }
    }
  }
  return args;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readVersion(): Promise<string> {
  try {
    const url = new URL("../package.json", import.meta.url);
    const pkg = JSON.parse(await readFile(url, "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stdout.write(HELP);
    return;
  }
  if (args.version) {
    process.stdout.write((await readVersion()) + "\n");
    return;
  }

  const input = args.file
    ? await readFile(args.file, "utf8")
    : await readStdin();

  if (input.length === 0) {
    process.stdout.write(HELP);
    return;
  }

  const opts: RedactOptions = {
    mode: args.mode,
    allow: {
      domains: args.allowDomains,
      fields: args.allowFields,
    },
  };

  if (args.json) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(input);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`safe-redact: invalid JSON input: ${msg}\n`);
      process.exit(2);
    }
    const { output, stats } = redactJson(parsed, opts);
    process.stdout.write(JSON.stringify(output, null, 2) + "\n");
    if (args.stats) {
      process.stderr.write(JSON.stringify(stats, null, 2) + "\n");
    }
  } else {
    const { output, stats } = redactText(input, opts);
    process.stdout.write(output);
    if (!output.endsWith("\n")) process.stdout.write("\n");
    if (args.stats) {
      process.stderr.write(JSON.stringify(stats, null, 2) + "\n");
    }
  }
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`safe-redact: ${msg}\n`);
  process.exit(1);
});
