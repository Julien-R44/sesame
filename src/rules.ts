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
 * Blocks dangerous URI schemes and enforces same host+scheme
 * matching with redirect_uris (RFC 7591 §5).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7591#section-5
 */
export const metadataUriRule = vine.createRule(
  (value: unknown, _options: undefined, field: FieldContext) => {
    const parsed = new URL(value as string)

    if (DANGEROUS_SCHEMES.includes(parsed.protocol)) {
      field.report('{{ field }} uses a disallowed scheme', 'metadataUri', field)
      return
    }

    const redirectUris: string[] = field.data.redirect_uris ?? []
    const redirectOrigins = new Set(
      redirectUris
        .map((u: string) => {
          try {
            return new URL(u)
          } catch {
            return null
          }
        })
        .filter(Boolean)
        .map((u: URL | null) => `${u!.protocol}//${u!.hostname}`)
    )

    const metaOrigin = `${parsed.protocol}//${parsed.hostname}`
    if (!redirectOrigins.has(metaOrigin)) {
      field.report(
        '{{ field }} host and scheme must match at least one redirect_uri',
        'metadataUri',
        field
      )
    }
  }
)
