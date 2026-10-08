import { DateTime } from 'luxon'
import { SesameManager } from '../../src/sesame_manager.ts'
import { OAuthAccessToken } from '../../src/models/oauth_access_token.ts'
import { TokenService } from '../../src/services/token_service.ts'
import { createManager } from './app.ts'

/**
 * Creates an access token persisted in DB with sensible defaults.
 *
 * Does NOT create the OAuthClient — call `createTestClient()` first.
 *
 * Defaults: clientId='test-client', userId='user-1', scopes=['read','write'], expiresAt=+1h
 *
 * Returns `{ id, raw, hash, manager }` — raw is the bearer token, hash is what's stored.
 */
export async function createTestAccessToken(options?: {
  manager?: SesameManager
  clientId?: string
  userId?: string | null
  scopes?: string[]
  expiresAt?: DateTime
  revokedAt?: DateTime | null
}) {
  const manager = options?.manager ?? createManager()
  const tokenService = new TokenService(manager)
  const { raw, hash } = tokenService.createAccessToken()
  const id = crypto.randomUUID()

  await OAuthAccessToken.create({
    id,
    tokenHash: hash,
    clientId: options?.clientId ?? 'test-client',
    userId: options?.userId === undefined ? 'user-1' : options.userId,
    scopes: options?.scopes ?? ['read', 'write'],
    expiresAt: options?.expiresAt ?? DateTime.now().plus({ hours: 1 }),
    revokedAt: options?.revokedAt ?? null,
  })

  return { id, raw, hash, manager }
}
