/**
 * Options used to build an authorization response URL.
 */
export interface ClientRedirectUrlOptions {
  redirectUri: string
  issuer: string
  state?: string | null
  params: Record<string, string>
}

/**
 * Build the client redirect URL carrying OAuth params, `state`,
 * and the `iss` parameter required by RFC 9207.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9207
 */
export function buildClientRedirectUrl(options: ClientRedirectUrlOptions): string {
  const url = new URL(options.redirectUri)
  for (const [key, value] of Object.entries(options.params)) url.searchParams.set(key, value)
  if (options.state) url.searchParams.set('state', options.state)
  url.searchParams.set('iss', options.issuer)

  return url.toString()
}
