import vine from '@vinejs/vine'
import type { FieldContext } from '@vinejs/vine/types'

const DANGEROUS_SCHEMES = ['javascript:', 'data:', 'vbscript:']

/**
 * Blocks dangerous URI schemes and enforces same host+scheme
 * matching with redirect_uris (RFC 7591 §5).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7591#section-5
 */
export const metadataUriRule = vine.createRule((value: unknown, _options: undefined, field: FieldContext) => {
  const parsed = new URL(value as string)

  if (DANGEROUS_SCHEMES.includes(parsed.protocol)) {
    field.report('{{ field }} uses a disallowed scheme', 'metadataUri', field)
    return
  }

  const redirectUris: string[] = field.data.redirect_uris ?? []
  const redirectOrigins = new Set(
    redirectUris
      .map((u: string) => { try { return new URL(u) } catch { return null } })
      .filter(Boolean)
      .map((u: URL | null) => `${u!.protocol}//${u!.hostname}`)
  )

  const metaOrigin = `${parsed.protocol}//${parsed.hostname}`
  if (!redirectOrigins.has(metaOrigin)) {
    field.report('{{ field }} host and scheme must match at least one redirect_uri', 'metadataUri', field)
  }
})
