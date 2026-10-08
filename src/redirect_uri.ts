/**
 * Splits a loopback redirect URI into its port-less parts.
 * Matches `http://` URIs on `localhost`, `127.0.0.1` or `[::1]`.
 */
const LOOPBACK_REDIRECT_URI = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?([/?].*)?$/

/**
 * Port-less representation of a loopback redirect URI, or null when
 * the URI is not a valid loopback redirect URI.
 */
function stripLoopbackPort(uri: string): string | null {
  if (!URL.canParse(uri)) return null

  const match = LOOPBACK_REDIRECT_URI.exec(uri)
  if (!match) return null

  return `${match[1]}${match[2] ?? ''}`
}

/**
 * Check a requested redirect URI against the registered ones.
 *
 * Uses exact string matching, except for loopback redirect URIs where
 * the port is ignored so native apps can bind an ephemeral port at
 * request time. Host, path and query must still match exactly.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-4.1.1
 */
export function isRedirectUriAllowed(options: { registered: string[]; requested: string }) {
  if (options.registered.includes(options.requested)) return true

  const requested = stripLoopbackPort(options.requested)
  if (!requested) return false

  return options.registered.some((registered) => stripLoopbackPort(registered) === requested)
}
