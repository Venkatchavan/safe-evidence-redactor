# @venkatchavan/safe-evidence-redactor

> Privacy-first redaction for security reports, logs, AI outputs, MCP tool outputs, and bug reports.
> **Offline. No telemetry. No network.**

`@venkatchavan/safe-evidence-redactor` removes sensitive evidence (PII, secrets, tokens) from text and JSON while preserving enough context to keep the output debuggable. Use it before pasting logs into a chat, attaching reports to a ticket, or returning data from an MCP tool.

- 🔒 Redacts emails, phone numbers (incl. Indian mobile), IPv4/IPv6, Bearer tokens, JWTs, vendor API keys, cookies, `Authorization` headers, Aadhaar, PAN, UPI IDs, and sensitive URL query params.
- 🌳 Walks nested JSON: preserves keys and structure, redacts values, reports JSON paths.
- 🎚️ Three modes: `minimal`, `balanced` (default), `strict`.
- ✅ Allowlists for domains, JSON field names, regex patterns, and entire categories.
- 📊 Returns structured stats: total, by-category, JSON paths affected.
- 🧰 CLI (`safe-redact`) for files and stdin, plus a small library API.

## Install

The package is published to **GitHub Packages**.

```sh
# Authenticate once — use a GitHub personal access token with read:packages scope
npm login --registry=https://npm.pkg.github.com --scope=@venkatchavan

# Install
npm install @venkatchavan/safe-evidence-redactor

# Or globally for the CLI tools
npm install -g @venkatchavan/safe-evidence-redactor
```

Alternatively, add a `.npmrc` to your project so the scope resolves automatically:

```
@venkatchavan:registry=https://npm.pkg.github.com
```

Node 18+ required.

## Library

```ts
import { redactText, redactJson, redactValue } from "@venkatchavan/safe-evidence-redactor";

const { output, stats } = redactText(
  "Login alert from 10.0.0.5 for alice@example.com (PAN ABCDE1234F)",
);
console.log(output);
// "Login alert from [REDACTED:IP] for [REDACTED:EMAIL] (PAN [REDACTED:PAN])"
console.log(stats);
// { total: 3, byCategory: { IP: 1, EMAIL: 1, PAN: 1 }, paths: [] }
```

### JSON

```ts
const { output, stats } = redactJson({
  user: { email: "a@b.com", phone: "+91 98765 43210" },
  events: [{ ip: "10.0.0.1" }],
  password: "hunter2",
});

// output:
// {
//   user: { email: "[REDACTED:EMAIL]", phone: "[REDACTED:PHONE]" },
//   events: [{ ip: "[REDACTED:IP]" }],
//   password: "[REDACTED:GENERIC_SECRET]"
// }
// stats.paths -> ["user.email", "user.phone", "events[0].ip", "password"]
```

`redactValue(input, options)` dispatches to text or JSON depending on the input type.

### Options

```ts
interface RedactOptions {
  mode?: "minimal" | "balanced" | "strict"; // default "balanced"
  allow?: {
    domains?: string[];      // substrings to allow (e.g. "example.com")
    fields?: string[];       // JSON field names to leave untouched
    patterns?: RegExp[];     // matches fully covered by these are preserved
    categories?: Array<      // disable categories entirely
      "EMAIL" | "PHONE" | "IP" | "BEARER" | "JWT" | "API_KEY"
      | "COOKIE" | "AUTH_HEADER" | "AADHAAR" | "PAN" | "UPI"
      | "URL_SECRET" | "GENERIC_SECRET"
    >;
  };
  placeholder?: (category, match) => string; // custom replacement
}
```

### Modes

| Category         | minimal | balanced | strict |
| ---------------- | :-----: | :------: | :----: |
| AUTH_HEADER      |   ✅    |    ✅    |   ✅   |
| COOKIE           |   ✅    |    ✅    |   ✅   |
| BEARER           |   ✅    |    ✅    |   ✅   |
| JWT              |   ✅    |    ✅    |   ✅   |
| API_KEY (vendor) |   ✅    |    ✅    |   ✅   |
| URL_SECRET       |   ✅    |    ✅    |   ✅   |
| EMAIL            |         |    ✅    |   ✅   |
| UPI              |         |    ✅    |   ✅   |
| AADHAAR / PAN    |         |    ✅    |   ✅   |
| PHONE (Indian)   |         |    ✅    |   ✅   |
| IPv4 / IPv6      |         |    ✅    |   ✅   |
| PHONE (intl.)    |         |          |   ✅   |
| GENERIC_SECRET   |         |          |   ✅   |

## CLI

```sh
safe-redact file.txt
safe-redact report.json --json
cat logs.txt | safe-redact
safe-redact --mode strict --stats < dump.log
safe-redact report.json --json --allow-domain example.com --allow-field requestId
```

Stats (with `--stats`) are written to **stderr** as JSON so stdout stays clean for piping.

```sh
safe-redact --help
```

## Examples

### Before

```
2026-04-30 10:00:01 user=alice@example.com ip=10.0.0.5 phone=+91 98765 43210
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
GET https://api.example.com/v1?token=abc123&page=2
PAN ABCDE1234F, Aadhaar 2345 6789 0123, UPI rohan@okicici
```

### After (`balanced`)

```
2026-04-30 10:00:01 user=[REDACTED:EMAIL] ip=[REDACTED:IP] phone=[REDACTED:PHONE]
Authorization: [REDACTED:AUTH_HEADER]
GET https://api.example.com/v1?token=[REDACTED:URL_SECRET]&page=2
PAN [REDACTED:PAN], Aadhaar [REDACTED:AADHAAR], UPI [REDACTED:UPI]
```

## Safety

See [SECURITY.md](./SECURITY.md). Short version: this library never touches the network, has no telemetry, and is best-effort — always pair with human review for high-stakes disclosures.

## MCP server

`@venkatchavan/safe-evidence-redactor` also ships a Model Context Protocol server so any MCP-aware client (Claude Desktop, MCP Inspector, agent frameworks) can call the redactor as a tool. The server is fully offline and speaks MCP over stdio.

Tools exposed:
- `redact_text` — input: `{ input: string, mode?, allow? }`
- `redact_json` — input: `{ input: any, mode?, allow? }`

Both tools return:
- `content[0].text` — the redacted output (string, or pretty-printed JSON)
- `structuredContent` — `{ output, stats }` where `stats` includes `total`, `byCategory`, and JSON `paths`

### Run it

```sh
# Once installed:
safe-redact-mcp

# Or directly from this repo after `npm run build`:
node dist/mcp.js
```

### Claude Desktop / MCP client config

```json
{
  "mcpServers": {
    "safe-evidence-redactor": {
      "command": "npx",
      "args": ["-y", "--registry=https://npm.pkg.github.com", "@venkatchavan/safe-evidence-redactor", "safe-redact-mcp"]
    }
  }
}
```

Or, if installed globally:

```json
{
  "mcpServers": {
    "safe-evidence-redactor": {
      "command": "safe-redact-mcp"
    }
  }
}
```

### Example tool call

```json
{
  "name": "redact_text",
  "arguments": {
    "input": "alice@example.com from 10.0.0.5",
    "mode": "balanced",
    "allow": { "domains": ["safe.example.com"] }
  }
}
```

Returns:

```json
{
  "content": [{ "type": "text", "text": "[REDACTED:EMAIL] from [REDACTED:IP]" }],
  "structuredContent": {
    "output": "[REDACTED:EMAIL] from [REDACTED:IP]",
    "stats": { "total": 2, "byCategory": { "EMAIL": 1, "IP": 1 }, "paths": [] }
  }
}
```

## License

MIT — see [LICENSE](./LICENSE).
