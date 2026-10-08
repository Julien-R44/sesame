import vine from '@vinejs/vine'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { E_INVALID_CLIENT, E_INVALID_REQUEST } from '../oauth_error.ts'
import type { OAuthClientRecord } from '../storage/types.ts'
import { findClientByExactId } from '../storage/find_client_by_exact_id.ts'
import {
  assertClientIdMetadataDocumentsEnabled,
  isClientIdMetadataDocumentUrl,
} from '../client_id_metadata_documents/client_id_url.ts'

/**
 * Client metadata properties safe to display on a consent screen.
 */
const DISPLAY_PROPERTIES = ['client_uri', 'logo_uri', 'tos_uri', 'policy_uri'] as const

/**
 * Pick the display URIs stored in the client metadata.
 */
function pickDisplayMetadata(client: OAuthClientRecord) {
  const metadata = client.metadata ?? {}
  const entries = DISPLAY_PROPERTIES.filter((key) => typeof metadata[key] === 'string').map(
    (key) => [key, metadata[key] as string]
  )

  return Object.fromEntries(entries) as Partial<Record<(typeof DISPLAY_PROPERTIES)[number], string>>
}

/**
 * Returns public information about an OAuth client.
 * Used by the consent page to display the client's name
 * from server-side data rather than query parameters
 * (RFC 6819 §4.4.1.4 — prevent client identity spoofing).
 *
 * For Client ID Metadata Document clients, `client_id_host` is the
 * host serving the document. Consent screens should display it, along
 * with the redirect URI host, to mitigate phishing.
 */
export default class ClientInfoController {
  static validator = vine.create({
    client_id: vine.string(),
  })

  async handle(ctx: HttpContext) {
    const [error, query] = await ClientInfoController.validator.tryValidate(ctx.request.qs())
    if (error) throw new E_INVALID_REQUEST('Missing client_id')

    const manager = await ctx.containerResolver.make(SesameManager)
    assertClientIdMetadataDocumentsEnabled({ clientId: query.client_id, config: manager.config })

    const client = await findClientByExactId({ store: manager.store, clientId: query.client_id })
    if (!client) throw new E_INVALID_CLIENT('Client not found')

    const isMetadataDocument = isClientIdMetadataDocumentUrl(client.clientId)

    return {
      client_id: client.clientId,
      client_name: client.name,
      ...pickDisplayMetadata(client),
      client_id_metadata_document: isMetadataDocument,
      ...(isMetadataDocument ? { client_id_host: new URL(client.clientId).host } : {}),
    }
  }
}
