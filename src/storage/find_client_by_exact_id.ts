import type { OAuthClientRecord, SesameStore } from './types.ts'

/**
 * Find a client whose `client_id` is exactly the requested one.
 *
 * Stores may compare case-insensitively or ignore trailing spaces (e.g.
 * MySQL/MariaDB default collations), so a lookup can return a different
 * client. Such a match is treated as not found. `client_id` values are
 * compared as plain strings (RFC 6749 §2.2).
 */
export async function findClientByExactId(options: {
  store: SesameStore
  clientId: string
}): Promise<OAuthClientRecord | null> {
  const client = await options.store.findClient(options.clientId)
  if (!client || client.clientId !== options.clientId) return null

  return client
}
