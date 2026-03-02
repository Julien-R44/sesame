import { E_INVALID_CLIENT_METADATA } from '../oauth_error.ts'

const DANGEROUS_SCHEMES = ['javascript:', 'data:', 'vbscript:']
const LOCALHOST_HOSTS = ['localhost', '127.0.0.1', '[::1]']

/**
 * Validates a redirect URI per OAuth 2.1 / RFC 8252 rules.
 *
 * - Blocks dangerous schemes (javascript:, data:, vbscript:)
 * - Requires HTTPS unless the host is localhost (RFC 8252 §8.3)
 * - Allows custom schemes for native apps (RFC 8252 §7.1)
 * - Rejects fragments per RFC 6749 §3.1.2
 */
export function validateRedirectUri(uri: string): void {
  let parsed: URL
  try {
    parsed = new URL(uri)
  } catch {
    throw new E_INVALID_CLIENT_METADATA(`Invalid redirect URI: ${uri}`)
  }

  if (parsed.hash) {
    throw new E_INVALID_CLIENT_METADATA(`Redirect URI must not contain a fragment: ${uri}`)
  }

  if (DANGEROUS_SCHEMES.includes(parsed.protocol)) {
    throw new E_INVALID_CLIENT_METADATA(`Redirect URI uses a disallowed scheme: ${uri}`)
  }

  if (parsed.protocol === 'http:' && !LOCALHOST_HOSTS.includes(parsed.hostname)) {
    throw new E_INVALID_CLIENT_METADATA(
      `Redirect URI must use HTTPS for non-localhost hosts: ${uri}`
    )
  }
}
