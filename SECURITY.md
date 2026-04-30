# Security Policy

## Threat model

`safe-evidence-redactor` is designed to be used on **untrusted, sensitive
input** (logs, AI outputs, MCP tool outputs, bug reports). Its goal is to
remove PII and secrets before that data is shared, stored, or sent to a model.

### Safety guarantees

- **Fully offline.** The library and CLI never make network calls.
- **No telemetry.** Nothing is logged, phoned home, or persisted by the library.
- **No data retention.** Inputs are processed in-memory and not written to
  disk by the library itself (the CLI only writes to the stream you choose).
- **Deterministic.** Given the same input, options, and version, the output is
  the same.

### Non-goals

- This is **not** a guarantee that all PII or secrets will be detected. Pattern
  detection is inherently best-effort. Always combine with human review for
  high-stakes disclosures.
- It is not a cryptographic tool. It does not encrypt or sign data.

## Reporting a vulnerability

If you believe you have found a security issue (e.g. a bypass that causes
sensitive data to slip through, or a ReDoS vector in our patterns), please
**do not** open a public issue.

Instead, email the maintainers privately and include:

1. A minimal reproducing input.
2. The mode and options used (`minimal` / `balanced` / `strict`).
3. The version of the package.
4. Expected vs. actual behavior.

We will acknowledge within a reasonable time and work on a fix in a private
branch before disclosure.

## Hardening tips for users

- Prefer `strict` mode when redacting outputs intended for external sharing.
- Use the `allow` options to whitelist known-safe domains/fields rather than
  weakening modes globally.
- Treat the redacted output as **lower-sensitivity but not public**. Always
  review before publishing.
