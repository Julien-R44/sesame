import { E_INVALID_TARGET } from './oauth_error.ts'

const SUPPORTED_PROTOCOLS = new Set(['http:', 'https:'])
const WHITESPACE_OR_BACKSLASH = /[\s\\]/

/**
 * Options for matching a requested resource against registered resources.
 */
export interface MatchResourceIndicatorOptions {
  value: string
  resources: Iterable<string>
}

/**
 * Options for narrowing a grant to the resource requested at the token endpoint.
 */
export interface ResolveGrantResourceOptions {
  requested: string | null
  granted: string | null
}

/**
 * Detect characters that the WHATWG URL parser silently strips or rewrites
 * (control characters, whitespace, backslashes), so `https://app.com/m\tcp`
 * is rejected instead of being repaired into `https://app.com/mcp`.
 */
function hasUnsafeCharacters(value: string): boolean {
  if (WHITESPACE_OR_BACKSLASH.test(value)) return true

  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code < 0x20 || code === 0x7f) return true
  }

  return false
}

/**
 * Normalize a resource indicator (RFC 8707 §2) to its canonical form.
 *
 * The value must be an absolute http(s) URI without fragment, credentials,
 * whitespace, control characters, or backslashes.
 * Scheme and host are lowercased, default ports are dropped, and a single
 * trailing slash is removed so `https://app.com/` and `https://app.com` match.
 * Returns null when the value is not a valid resource indicator.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8707#section-2
 */
export function normalizeResourceIndicator(value: string): string | null {
  if (value.includes('#')) return null
  if (hasUnsafeCharacters(value)) return null

  const url = URL.parse(value)
  if (!url) return null
  if (!SUPPORTED_PROTOCOLS.has(url.protocol)) return null
  if (url.username || url.password) return null

  const pathname = url.pathname.endsWith('/') ? url.pathname.slice(0, -1) : url.pathname

  return `${url.protocol}//${url.host}${pathname}${url.search}`
}

/**
 * Map a requested resource to the most specific registered resource.
 *
 * An exact match wins. Otherwise the registered resource whose path is a
 * segment-boundary prefix of the requested one is selected, so
 * `https://app.com/mcp/v1` maps to `https://app.com/mcp`, then to the
 * issuer root. RFC 8707 allows mapping a resource to a more general URI.
 * Returns null for invalid values or resources on another origin.
 */
export function matchResourceIndicator(options: MatchResourceIndicatorOptions): string | null {
  const requested = normalizeResourceIndicator(options.value)
  if (!requested) return null

  const resources = [...options.resources]
  if (resources.includes(requested)) return requested
  if (URL.parse(requested)?.search) return null

  const candidates = resources.filter((resource) => requested.startsWith(`${resource}/`))
  if (candidates.length === 0) return null

  return candidates.reduce((best, candidate) => (candidate.length > best.length ? candidate : best))
}

/**
 * Resolve the resource of a token issued from an existing grant
 * (authorization code or refresh token).
 *
 * Without a requested resource, the token inherits the granted one. An
 * unbound grant (issued before resource indicators or without `resource`)
 * may be narrowed to the requested resource. A bound grant can never be
 * switched to another resource.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8707#section-2.2
 */
export function resolveGrantResource(options: ResolveGrantResourceOptions): string | null {
  if (!options.requested) return options.granted
  if (!options.granted) return options.requested
  if (options.requested === options.granted) return options.requested

  throw new E_INVALID_TARGET('The requested resource was not included in the authorization grant')
}
