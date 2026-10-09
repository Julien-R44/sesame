import { DateTime } from 'luxon'
import type { OAuthClientRecord, SesameStore } from './types.ts'

/**
 * Marker written in `metadata.registration` by the dynamic client
 * registration endpoint (RFC 7591).
 */
export const DYNAMIC_REGISTRATION = 'dynamic'

/**
 * Metadata key holding the ISO date of a client's first successful
 * token issuance. It survives token purges and user revocations.
 */
export const FIRST_AUTHORIZED_AT = 'first_authorized_at'

/**
 * Tables whose rows mean a client is currently in use.
 */
export const CLIENT_USAGE_TABLES = [
  'oauth_access_tokens',
  'oauth_refresh_tokens',
  'oauth_authorization_codes',
  'oauth_grants',
  'oauth_pending_authorization_requests',
] as const

const DELETE_CHUNK_SIZE = 500

/**
 * Whether a client was created through dynamic client registration.
 *
 * Clients registered before the explicit marker existed are recognized by
 * `token_endpoint_auth_method`, which the registration endpoint always stores
 * and `createClient()` never adds on its own. Client ID Metadata Document
 * clients are never considered dynamically registered: their identity lives
 * at a URL the client controls.
 */
export function isDynamicallyRegistered(metadata: Record<string, any> | null): boolean {
  if (!metadata) return false
  if (metadata.client_id_metadata_document) return false
  if (metadata.registration === DYNAMIC_REGISTRATION) return true

  return metadata.token_endpoint_auth_method !== undefined
}

/**
 * Whether a client may be deleted by the unused client purge: dynamically
 * registered and never authorized. Usage tables are checked by the store.
 */
export function isPurgeableClient(metadata: Record<string, any> | null): boolean {
  if (!isDynamicallyRegistered(metadata)) return false

  return metadata![FIRST_AUTHORIZED_AT] === undefined
}

/**
 * Record the first successful token issuance of a dynamically registered
 * client, once, so the unused client purge never deletes it.
 */
export async function markFirstAuthorization(options: {
  store: SesameStore
  client: OAuthClientRecord
}): Promise<void> {
  const { client } = options
  if (!isPurgeableClient(client.metadata)) return

  const metadata = { ...client.metadata, [FIRST_AUTHORIZED_AT]: DateTime.now().toISO() }
  await options.store.updateClient({ id: client.id, data: { metadata } })
}

/**
 * Split client ids into chunks small enough for every SQL dialect's
 * bound-parameter limit.
 */
export function chunkClientIds(clientIds: string[]): string[][] {
  const chunks: string[][] = []
  for (let index = 0; index < clientIds.length; index += DELETE_CHUNK_SIZE) {
    chunks.push(clientIds.slice(index, index + DELETE_CHUNK_SIZE))
  }

  return chunks
}
