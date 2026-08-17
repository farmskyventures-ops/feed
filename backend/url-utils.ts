// =====================================================================
// URL sanitization helpers
// ---------------------------------------------------------------------
// Defensive normalization for URLs that arrive from environment
// variables / operator-entered config. A very common operations mistake
// is pasting a log line or doc snippet such as
//   "Score gateway client 'score' registered (origin https://credit.farmsky.africa)."
// which leaves the value as `https://credit.farmsky.africa).` — a broken
// link that 404s. sanitizeUrl() strips wrapping quotes/parens/whitespace
// and trailing punctuation so a fat-fingered env value can never produce
// a broken outbound link or fetch target.
//
// It is intentionally conservative: it only trims junk it is confident
// about and never rewrites the host/scheme/path. If the result does not
// look like an http(s) URL the ORIGINAL trimmed string is returned so we
// never silently drop a caller-provided value.
// =====================================================================

/**
 * Clean a URL that may carry stray wrapping/trailing characters.
 * Returns '' for empty/undefined input.
 */
export function sanitizeUrl(raw: unknown): string {
  let s = String(raw ?? '').trim()
  if (!s) return ''

  // Strip a single pair of wrapping quotes/backticks/angle brackets.
  s = s.replace(/^["'`<(]+/, '').replace(/["'`>]+$/, '')

  // Strip trailing junk that commonly gets pasted in from prose/log lines —
  // closing parens/brackets, periods, commas, semicolons, slashes and
  // whitespace — repeated until stable so combinations like ")./" or ").,"
  // fully reduce (a lone strip would let the '/' shield the ').').
  let prev: string
  do { prev = s; s = s.replace(/[)\].,;/\s]+$/g, '') } while (s !== prev)

  s = s.trim()

  // Validate: if it parses as an http(s) URL, return the normalized origin+path.
  try {
    const u = new URL(s)
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      // Rebuild without a trailing slash on the pathname so downstream
      // `${base}/path` concatenation stays clean.
      const path = u.pathname === '/' ? '' : u.pathname.replace(/\/+$/, '')
      return `${u.protocol}//${u.host}${path}${u.search}`
    }
  } catch {
    /* not a parseable absolute URL — fall through to the trimmed string */
  }
  return s
}

/**
 * Read an env value and sanitize it, returning a fallback when empty.
 */
export function sanitizeUrlEnv(raw: unknown, fallback = ''): string {
  const cleaned = sanitizeUrl(raw)
  return cleaned || sanitizeUrl(fallback)
}
