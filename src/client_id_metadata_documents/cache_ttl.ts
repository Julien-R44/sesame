import type { CacheTtlOptions } from './types.ts'

const DELTA_SECONDS = /^\d+$/

/**
 * Parse a `Cache-Control` header into lowercase directive names
 * mapped to their (unquoted) values.
 */
function parseCacheControl(header: string | null) {
  const directives = new Map<string, string>()
  if (!header) return directives

  for (const part of header.split(',')) {
    const [name, value = ''] = part.split('=', 2)
    directives.set(name.trim().toLowerCase(), value.trim().replace(/^"|"$/g, ''))
  }

  return directives
}

/**
 * Parse an HTTP date into milliseconds, or null when absent or invalid.
 */
function parseHttpDate(value: string | null) {
  const time = value ? Date.parse(value) : Number.NaN

  return Number.isNaN(time) ? null : time
}

/**
 * Freshness lifetime in seconds from `max-age` or `Expires - Date`
 * (RFC 9111 §4.2.1), or null when the response is not cacheable or
 * gives no hint.
 */
function freshnessLifetime(options: CacheTtlOptions & { now: number }): number | null {
  const directives = parseCacheControl(options.cacheControl)
  if (directives.has('no-store') || directives.has('no-cache')) return null

  const maxAge = directives.get('max-age')
  if (maxAge !== undefined) return DELTA_SECONDS.test(maxAge) ? Number(maxAge) : null

  const expires = parseHttpDate(options.expires)
  if (expires === null) return null

  const date = parseHttpDate(options.date) ?? options.now

  return Math.floor((expires - date) / 1000)
}

/**
 * Age of the response when received, in seconds: the larger of the
 * `Age` header and the apparent age `now - Date` (RFC 9111 §4.2.3).
 * The request delay is ignored since it is bounded by the fetch timeout.
 */
function currentAge(options: CacheTtlOptions & { now: number }) {
  const ageValue = options.age && DELTA_SECONDS.test(options.age) ? Number(options.age) : 0

  const date = parseHttpDate(options.date)
  const apparentAge = date === null ? 0 : Math.max(0, Math.floor((options.now - date) / 1000))

  return Math.max(ageValue, apparentAge)
}

/**
 * Compute how long a document stays fresh, in seconds: its remaining
 * freshness per RFC 9111 (lifetime minus current age), clamped to
 * `[minTtl, maxTtl]`. Responses without freshness information, or
 * already stale, use `minTtl`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9111#section-4.2
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5.2
 */
export function computeCacheTtl(options: CacheTtlOptions) {
  const resolved = { ...options, now: options.now ?? Date.now() }

  const lifetime = freshnessLifetime(resolved)
  if (lifetime === null) return options.minTtl

  const remaining = lifetime - currentAge(resolved)

  return Math.min(Math.max(remaining, options.minTtl), options.maxTtl)
}
