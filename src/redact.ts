import {
  PATTERNS,
  SENSITIVE_FIELD_NAMES,
  type PatternDef,
  type RedactionCategory,
  type RedactionMode,
} from "./patterns.js";

export type { RedactionCategory, RedactionMode } from "./patterns.js";

export interface RedactOptions {
  /** Redaction aggressiveness. Defaults to `balanced`. */
  mode?: RedactionMode;
  /**
   * Allowlist: items matching any of these will NOT be redacted.
   *  - `domains`: substrings to allow inside email/URL matches (e.g. `example.com`).
   *  - `fields`: JSON field names that should be left untouched (case-insensitive).
   *  - `patterns`: regex patterns to allow. If a match is fully covered by one
   *    of these, it is preserved.
   *  - `categories`: categories to disable entirely.
   */
  allow?: {
    domains?: ReadonlyArray<string>;
    fields?: ReadonlyArray<string>;
    patterns?: ReadonlyArray<RegExp>;
    categories?: ReadonlyArray<RedactionCategory>;
  };
  /**
   * Custom replacement format. Default `[REDACTED:<CATEGORY>]`.
   * Receives the matched string and category.
   */
  placeholder?: (category: RedactionCategory, match: string) => string;
}

export interface RedactionHit {
  category: RedactionCategory;
  /** The original (unredacted) matched substring. Not stored for safety unless caller asks. */
  match?: string;
  /** JSON path (dot/bracket notation) when redacting structured input. */
  path?: string;
}

export interface RedactionStats {
  total: number;
  byCategory: Record<RedactionCategory, number>;
  paths: string[];
}

export interface RedactTextResult {
  output: string;
  stats: RedactionStats;
}

export interface RedactJsonResult<T = unknown> {
  output: T;
  stats: RedactionStats;
}

const DEFAULT_MODE: RedactionMode = "balanced";

function emptyStats(): RedactionStats {
  return {
    total: 0,
    byCategory: {} as Record<RedactionCategory, number>,
    paths: [],
  };
}

function bumpStats(
  stats: RedactionStats,
  category: RedactionCategory,
  path?: string,
): void {
  stats.total += 1;
  stats.byCategory[category] = (stats.byCategory[category] ?? 0) + 1;
  if (path && !stats.paths.includes(path)) {
    stats.paths.push(path);
  }
}

function activePatterns(
  mode: RedactionMode,
  disabled: ReadonlySet<RedactionCategory>,
): PatternDef[] {
  return PATTERNS.filter(
    (p) => p.modes.includes(mode) && !disabled.has(p.category),
  );
}

function isAllowed(
  match: string,
  allowPatterns: ReadonlyArray<RegExp>,
  allowDomains: ReadonlyArray<string>,
): boolean {
  for (const re of allowPatterns) {
    // Fresh regex eval — clone to avoid lastIndex bleed.
    const cloned = new RegExp(re.source, re.flags.replace("g", ""));
    if (cloned.test(match)) return true;
  }
  if (allowDomains.length > 0) {
    const lower = match.toLowerCase();
    for (const d of allowDomains) {
      if (lower.includes(d.toLowerCase())) return true;
    }
  }
  return false;
}

function defaultPlaceholder(category: RedactionCategory): string {
  return `[REDACTED:${category}]`;
}

/**
 * Redact a single string value. Internal helper used by both `redactText`
 * and the JSON walker.
 */
function redactStringInternal(
  input: string,
  mode: RedactionMode,
  options: RedactOptions,
  stats: RedactionStats,
  path: string | undefined,
): string {
  const disabled = new Set<RedactionCategory>(options.allow?.categories ?? []);
  const allowPatterns = options.allow?.patterns ?? [];
  const allowDomains = options.allow?.domains ?? [];
  const placeholder = options.placeholder ?? defaultPlaceholder;

  let output = input;
  for (const pattern of activePatterns(mode, disabled)) {
    // Reset lastIndex so successive `replace` calls on a global regex are clean.
    pattern.regex.lastIndex = 0;
    output = output.replace(pattern.regex, (match, ...rest) => {
      if (isAllowed(match, allowPatterns, allowDomains)) {
        return match;
      }
      bumpStats(stats, pattern.category, path);
      if (pattern.replace) {
        // `rest` ends with [offset, fullString, groups?] — strip those.
        // We accept what JS passes; pattern.replace only reads named groups it expects.
        const groups = rest.filter(
          (r) => typeof r === "string",
        ) as string[];
        return pattern.replace(match, ...groups);
      }
      return placeholder(pattern.category, match);
    });
  }
  return output;
}

/**
 * Redact sensitive evidence from a plain string.
 */
export function redactText(
  input: string,
  options: RedactOptions = {},
): RedactTextResult {
  const mode = options.mode ?? DEFAULT_MODE;
  const stats = emptyStats();
  const output = redactStringInternal(input, mode, options, stats, undefined);
  return { output, stats };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function pathJoin(base: string, key: string | number): string {
  if (typeof key === "number") return `${base}[${key}]`;
  if (base === "") return key;
  // Use bracket notation if key has special chars.
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(key) ? `${base}.${key}` : `${base}["${key}"]`;
}

function isSensitiveField(
  name: string,
  allowFields: ReadonlyArray<string>,
): boolean {
  const lower = name.toLowerCase();
  if (allowFields.some((f) => f.toLowerCase() === lower)) return false;
  return SENSITIVE_FIELD_NAMES.includes(lower);
}

function walk(
  value: unknown,
  mode: RedactionMode,
  options: RedactOptions,
  stats: RedactionStats,
  path: string,
): unknown {
  const allowFields = options.allow?.fields ?? [];
  const placeholder = options.placeholder ?? defaultPlaceholder;

  if (typeof value === "string") {
    return redactStringInternal(value, mode, options, stats, path || undefined);
  }
  if (Array.isArray(value)) {
    return value.map((v, i) => walk(v, mode, options, stats, pathJoin(path, i)));
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const childPath = pathJoin(path, k);
      if (isSensitiveField(k, allowFields) && v !== null && v !== undefined) {
        // Force redact regardless of value shape.
        const cat: RedactionCategory =
          k.toLowerCase().includes("cookie")
            ? "COOKIE"
            : k.toLowerCase().includes("auth")
              ? "AUTH_HEADER"
              : "GENERIC_SECRET";
        bumpStats(stats, cat, childPath);
        out[k] = placeholder(cat, String(v));
      } else {
        out[k] = walk(v, mode, options, stats, childPath);
      }
    }
    return out;
  }
  return value;
}

/**
 * Redact a JSON-shaped value (object/array/primitive). Returns a new value;
 * the input is not mutated.
 */
export function redactJson<T = unknown>(
  input: T,
  options: RedactOptions = {},
): RedactJsonResult<T> {
  const mode = options.mode ?? DEFAULT_MODE;
  const stats = emptyStats();
  const output = walk(input, mode, options, stats, "") as T;
  return { output, stats };
}

/**
 * Redact any JS value. Strings go through text redaction; objects/arrays
 * through JSON redaction; everything else is returned unchanged.
 */
export function redactValue<T = unknown>(
  input: T,
  options: RedactOptions = {},
): RedactJsonResult<T> {
  if (typeof input === "string") {
    const { output, stats } = redactText(input, options);
    return { output: output as unknown as T, stats };
  }
  return redactJson(input, options);
}
