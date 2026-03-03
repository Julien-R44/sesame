import vine from '@vinejs/vine'
import type { FieldContext } from '@vinejs/vine/types'

const DANGEROUS_SCHEMES = ['javascript:', 'data:', 'vbscript:']
const LOCALHOST_HOSTS = ['localhost', '127.0.0.1', '[::1]']

/**
 * Validates a redirect URI per OAuth 2.1 / RFC 8252 rules.
 * Blocks fragments, dangerous schemes, and requires HTTPS for non-localhost hosts.
 */
export const redirectUriRule = vine.createRule(
  (value: unknown, _options: undefined, field: FieldContext) => {
    let parsed: URL
    try {
      parsed = new URL(value as string)
    } catch {
      field.report('Invalid redirect URI', 'redirectUri', field)
      return
    }

    if (parsed.hash) {
      field.report('Redirect URI must not contain a fragment', 'redirectUri', field)
      return
    }

    if (DANGEROUS_SCHEMES.includes(parsed.protocol)) {
      field.report('Redirect URI uses a disallowed scheme', 'redirectUri', field)
      return
    }

    if (parsed.protocol === 'http:' && !LOCALHOST_HOSTS.includes(parsed.hostname)) {
      field.report('Redirect URI must use HTTPS for non-localhost hosts', 'redirectUri', field)
    }
  }
)

/**
 * Blocks dangerous URI schemes for metadata URIs (client_uri, logo_uri, etc.).
 *
 * RFC 7591 §5 says the server MAY verify that metadata URIs match the
 * host+scheme of redirect_uris, but this is NOT required.
 *
 * We intentionally skip this check because it breaks legitimate CLI/desktop clients
 * (e.g. OpenCode, Claude Code) that use localhost redirect URIs but have a
 * different `client_uri` pointing to their website.
 *
 * Maybe we can add an option to enable this check in the future if needed.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7591#section-5
 */
export const metadataUriRule = vine.createRule(
  (value: unknown, _options: undefined, field: FieldContext) => {
    const parsed = new URL(value as string)

    if (DANGEROUS_SCHEMES.includes(parsed.protocol)) {
      field.report('{{ field }} uses a disallowed scheme', 'metadataUri', field)
    }
  }
)
