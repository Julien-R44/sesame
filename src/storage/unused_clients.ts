/**
 * Marker written in `metadata.registration` by the dynamic client
 * registration endpoint (RFC 7591).
 */
export const DYNAMIC_REGISTRATION = 'dynamic'

/**
 * Tables whose rows mean a client has been used at least once.
 */
export const CLIENT_USAGE_TABLES = [
  'oauth_access_tokens',
  'oauth_refresh_tokens',
  'oauth_authorization_codes',
  'oauth_consents',
  'oauth_pending_authorization_requests',
] as const

const DELETE_CHUNK_SIZE = 500

/**
 * Whether a client was created through dynamic client registration.
 *
 * Clients registered before the explicit marker existed are recognized by
 * `token_endpoint_auth_method`, which the registration endpoint always stores
 * and `createClient()` never adds on its own.
 */
export function isDynamicallyRegistered(metadata: Record<string, any> | null): boolean {
  if (!metadata) return false
  if (metadata.registration === DYNAMIC_REGISTRATION) return true

  return metadata.token_endpoint_auth_method !== undefined
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
