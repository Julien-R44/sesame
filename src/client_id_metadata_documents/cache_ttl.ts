import type { CacheTtlOptions } from './types.ts'

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
 * Freshness lifetime in seconds from `Cache-Control` or `Expires`,
 * or null when the response is not cacheable or gives no hint.
 */
function freshnessLifetime(options: CacheTtlOptions): number | null {
  const directives = parseCacheControl(options.cacheControl)
  if (directives.has('no-store') || directives.has('no-cache')) return null

  const maxAge = directives.get('max-age')
  if (maxAge !== undefined) return /^\d+$/.test(maxAge) ? Number(maxAge) : null

  const expires = options.expires ? Date.parse(options.expires) : Number.NaN
  if (Number.isNaN(expires)) return null

  const date = options.date ? Date.parse(options.date) : Number.NaN
  const now = Number.isNaN(date) ? Date.now() : date

  return Math.floor((expires - now) / 1000)
}

/**
 * Compute how long a document stays fresh, in seconds. Follows the
 * response cache headers (RFC 9111) clamped to `[minTtl, maxTtl]`.
 * Responses without freshness information use `minTtl`.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5.2
 */
export function computeCacheTtl(options: CacheTtlOptions) {
  const lifetime = freshnessLifetime(options) ?? options.minTtl

  return Math.min(Math.max(lifetime, options.minTtl), options.maxTtl)
}
