/**
 * Centralized regex patterns for safe-evidence-redactor.
 *
 * Each pattern is documented with:
 *  - what it matches
 *  - the placeholder category used in the redacted output
 *  - mode applicability (minimal | balanced | strict)
 *
 * IMPORTANT:
 *  - All patterns use the global flag because the engine relies on `matchAll`.
 *  - Patterns are anchored loosely so they can match inside larger strings.
 *  - We deliberately err on the side of caution in `balanced` mode and only
 *    enable broader/looser patterns in `strict` mode.
 */

export type RedactionCategory =
  | "EMAIL"
  | "PHONE"
  | "IP"
  | "BEARER"
  | "JWT"
  | "API_KEY"
  | "COOKIE"
  | "AUTH_HEADER"
  | "AADHAAR"
  | "PAN"
  | "UPI"
  | "URL_SECRET"
  | "GENERIC_SECRET";

export type RedactionMode = "minimal" | "balanced" | "strict";

export interface PatternDef {
  category: RedactionCategory;
  /** Human-readable description for docs/tests. */
  description: string;
  /** Modes in which this pattern is active. */
  modes: ReadonlyArray<RedactionMode>;
  /** The actual regex. MUST be `g`-flagged. */
  regex: RegExp;
  /**
   * Optional transform that returns the replacement string given the match.
   * If omitted, the engine uses `[REDACTED:<CATEGORY>]`.
   */
  replace?: (match: string, ...groups: string[]) => string;
}

/* -------------------------------------------------------------------------- */
/*                                Email                                       */
/* -------------------------------------------------------------------------- */

// RFC 5322 is wildly complex; this covers the practical 99%.
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

/* -------------------------------------------------------------------------- */
/*                                 Phone                                      */
/* -------------------------------------------------------------------------- */

// Indian mobile: optional +91 / 0091 / 0 prefix, then a leading 6-9, then 9 digits.
// Tolerates a single space or dash inside the 10-digit body (commonly grouped 5+5).
// NOTE: the bare `91` prefix requires a leading `+` so that a 12-digit Aadhaar
// starting with `9` is not mis-classified as `91` + 10-digit phone.
const PHONE_INDIAN =
  /(?<![A-Za-z0-9])(?:\+91[\s-]?|0091[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?![A-Za-z0-9])/g;

// Generic international: + then 7-15 digits, with optional spaces/dashes/parens.
// Used in `strict` mode only to avoid false positives on long numeric IDs.
const PHONE_INTL =
  /(?<![A-Za-z0-9])\+\d{1,3}[\s-]?(?:\(?\d{1,4}\)?[\s-]?){2,5}\d{2,4}(?![A-Za-z0-9])/g;

/* -------------------------------------------------------------------------- */
/*                                   IP                                       */
/* -------------------------------------------------------------------------- */

const IPV4 =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g;

// IPv6: covers full and compressed forms, plus IPv4-mapped.
const IPV6 =
  /(?<![:.\w])(?:(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?:[A-F0-9]{1,4}:){1,7}:|(?:[A-F0-9]{1,4}:){1,6}:[A-F0-9]{1,4}|(?:[A-F0-9]{1,4}:){1,5}(?::[A-F0-9]{1,4}){1,2}|(?:[A-F0-9]{1,4}:){1,4}(?::[A-F0-9]{1,4}){1,3}|(?:[A-F0-9]{1,4}:){1,3}(?::[A-F0-9]{1,4}){1,4}|(?:[A-F0-9]{1,4}:){1,2}(?::[A-F0-9]{1,4}){1,5}|[A-F0-9]{1,4}:(?:(?::[A-F0-9]{1,4}){1,6})|:(?:(?::[A-F0-9]{1,4}){1,7}|:)|::ffff:(?:\d{1,3}\.){3}\d{1,3})(?![:.\w])/gi;

/* -------------------------------------------------------------------------- */
/*                       Auth: Bearer / JWT / Cookie / Header                 */
/* -------------------------------------------------------------------------- */

// Bearer <token>
const BEARER = /\bBearer\s+([A-Za-z0-9._\-+/=]{8,})/g;

// JSON Web Token: three base64url segments separated by dots, signature optional.
const JWT =
  /\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b/g;

// `Authorization:` header (any scheme).
const AUTH_HEADER =
  /\b(Authorization|Proxy-Authorization)\s*:\s*([^\r\n]+)/gi;

// `Cookie:` and `Set-Cookie:` headers — value is everything to end-of-line.
const COOKIE_HEADER =
  /\b(Set-Cookie|Cookie)\s*:\s*([^\r\n]+)/gi;

/* -------------------------------------------------------------------------- */
/*                              API keys / secrets                            */
/* -------------------------------------------------------------------------- */

// High-confidence vendor prefixes. Always on (even in minimal mode).
const VENDOR_KEYS = new RegExp(
  [
    // GitHub
    "ghp_[A-Za-z0-9]{36,}",
    "gho_[A-Za-z0-9]{36,}",
    "ghs_[A-Za-z0-9]{36,}",
    "ghu_[A-Za-z0-9]{36,}",
    "github_pat_[A-Za-z0-9_]{60,}",
    // AWS
    "AKIA[0-9A-Z]{16}",
    "ASIA[0-9A-Z]{16}",
    // Slack
    "xox[baprs]-[A-Za-z0-9-]{10,}",
    // Google
    "AIza[0-9A-Za-z\\-_]{35}",
    // Stripe
    "sk_live_[0-9a-zA-Z]{24,}",
    "rk_live_[0-9a-zA-Z]{24,}",
    "pk_live_[0-9a-zA-Z]{24,}",
    // OpenAI
    "sk-(?:proj-)?[A-Za-z0-9_-]{20,}",
    // Anthropic
    "sk-ant-[A-Za-z0-9_-]{20,}",
  ].join("|"),
  "g",
);

// Generic high-entropy-ish hex/base64 strings — only in strict mode to avoid
// chewing through commit hashes and other safe identifiers in balanced mode.
const GENERIC_HEX_SECRET = /\b[a-f0-9]{40,}\b/gi;
const GENERIC_BASE64_SECRET = /\b[A-Za-z0-9+/]{40,}={0,2}\b/g;

/* -------------------------------------------------------------------------- */
/*                                 India PII                                  */
/* -------------------------------------------------------------------------- */

// Aadhaar: 12 digits, often grouped 4-4-4. First digit is 2-9 per UIDAI spec.
const AADHAAR =
  /(?<![A-Za-z0-9])[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?![A-Za-z0-9])/g;

// PAN: 5 letters, 4 digits, 1 letter (e.g. ABCDE1234F).
const PAN = /(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])/g;

// UPI ID: handle@provider, where provider is a known-ish lowercase suffix.
// Restricted to common providers to reduce email collisions.
const UPI =
  /\b[A-Za-z0-9._-]{2,}@(?:okaxis|okicici|okhdfcbank|oksbi|ybl|paytm|upi|axl|ibl|hdfcbank|icici|sbi|axis|kotak|barodampay|fbl|pnb|cnrb|allbank|jio|airtel|apl|axisbank)\b/gi;

/* -------------------------------------------------------------------------- */
/*                          URLs with sensitive params                        */
/* -------------------------------------------------------------------------- */

// Captures `(?|&)key=value` for sensitive keys in any URL-ish context.
// We then redact only the value, preserving the key for debuggability.
const URL_SECRET_PARAM =
  /([?&#](?:token|access_token|refresh_token|id_token|api_key|apikey|key|secret|client_secret|password|passwd|pwd|code|session|sessionid|sid|auth)=)([^&#\s"'<>]+)/gi;

/* -------------------------------------------------------------------------- */
/*                            Pattern registry                                */
/* -------------------------------------------------------------------------- */

export const PATTERNS: ReadonlyArray<PatternDef> = [
  // Header-shaped patterns must run before the generic ones so the whole
  // header line is redacted, not just an embedded email/JWT inside the value.
  {
    category: "AUTH_HEADER",
    description: "HTTP Authorization / Proxy-Authorization header lines.",
    modes: ["minimal", "balanced", "strict"],
    regex: AUTH_HEADER,
    replace: (_m, name) => `${name}: [REDACTED:AUTH_HEADER]`,
  },
  {
    category: "COOKIE",
    description: "HTTP Cookie / Set-Cookie header lines.",
    modes: ["minimal", "balanced", "strict"],
    regex: COOKIE_HEADER,
    replace: (_m, name) => `${name}: [REDACTED:COOKIE]`,
  },
  {
    category: "BEARER",
    description: "`Bearer <token>` strings.",
    modes: ["minimal", "balanced", "strict"],
    regex: BEARER,
    replace: () => "Bearer [REDACTED:BEARER]",
  },
  {
    category: "JWT",
    description: "JSON Web Tokens.",
    modes: ["minimal", "balanced", "strict"],
    regex: JWT,
  },
  {
    category: "API_KEY",
    description: "Vendor-prefixed API keys (GitHub, AWS, Slack, OpenAI, ...).",
    modes: ["minimal", "balanced", "strict"],
    regex: VENDOR_KEYS,
  },
  {
    category: "URL_SECRET",
    description: "Sensitive query parameters in URLs.",
    modes: ["minimal", "balanced", "strict"],
    regex: URL_SECRET_PARAM,
    replace: (_m, prefix) => `${prefix}[REDACTED:URL_SECRET]`,
  },
  {
    category: "EMAIL",
    description: "Email addresses.",
    modes: ["balanced", "strict"],
    regex: EMAIL,
  },
  {
    category: "UPI",
    description: "UPI IDs (handle@provider).",
    modes: ["balanced", "strict"],
    regex: UPI,
  },
  // PHONE runs before AADHAAR/PAN: a `+91`-prefixed mobile must be claimed as
  // a phone before AADHAAR could greedily consume the trailing 12 digits.
  {
    category: "PHONE",
    description: "Indian mobile numbers (+91 / 10-digit 6-9 leading).",
    modes: ["balanced", "strict"],
    regex: PHONE_INDIAN,
  },
  {
    category: "AADHAAR",
    description: "Aadhaar-like 12-digit IDs.",
    modes: ["balanced", "strict"],
    regex: AADHAAR,
  },
  {
    category: "PAN",
    description: "Indian PAN-like IDs.",
    modes: ["balanced", "strict"],
    regex: PAN,
  },
  {
    category: "PHONE",
    description: "Generic international phone numbers.",
    modes: ["strict"],
    regex: PHONE_INTL,
  },
  {
    category: "IP",
    description: "IPv4 addresses.",
    modes: ["balanced", "strict"],
    regex: IPV4,
  },
  {
    category: "IP",
    description: "IPv6 addresses.",
    modes: ["balanced", "strict"],
    regex: IPV6,
  },
  {
    category: "GENERIC_SECRET",
    description: "Long hex strings that look like secrets.",
    modes: ["strict"],
    regex: GENERIC_HEX_SECRET,
  },
  {
    category: "GENERIC_SECRET",
    description: "Long base64 strings that look like secrets.",
    modes: ["strict"],
    regex: GENERIC_BASE64_SECRET,
  },
];

/** Field names whose values should always be redacted in JSON regardless of value content. */
export const SENSITIVE_FIELD_NAMES: ReadonlyArray<string> = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "client_secret",
  "api_key",
  "apikey",
  "access_token",
  "refresh_token",
  "id_token",
  "token",
  "authorization",
  "auth",
  "cookie",
  "set-cookie",
  "session",
  "sessionid",
  "sid",
  "private_key",
  "privatekey",
];
