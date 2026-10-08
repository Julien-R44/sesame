import { DateTime } from 'luxon'
import { OAuthGrant } from '../../src/models/oauth_grant.ts'
import type { GrantContext } from '../../src/types.ts'

/**
 * Creates a grant persisted in DB with sensible defaults.
 *
 * Does NOT create the OAuthClient — call `createTestClient()` first.
 *
 * Defaults: clientId='test-client', userId='user-1', scopes=['read'],
 * context=null, expiresAt=+30d
 */
export async function createTestGrant(options?: {
  id?: string
  clientId?: string
  userId?: string
  scopes?: string[]
  context?: GrantContext | null
  expiresAt?: DateTime
}) {
  return OAuthGrant.create({
    id: options?.id ?? crypto.randomUUID(),
    clientId: options?.clientId ?? 'test-client',
    userId: options?.userId ?? 'user-1',
    scopes: options?.scopes ?? ['read'],
    context: options?.context ?? null,
    expiresAt: options?.expiresAt ?? DateTime.now().plus({ days: 30 }),
  })
}
