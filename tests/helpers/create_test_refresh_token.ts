import { DateTime } from 'luxon'
import { SesameManager } from '../../src/sesame_manager.ts'
import { OAuthAccessToken } from '../../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../../src/models/oauth_refresh_token.ts'
import { TokenService } from '../../src/services/token_service.ts'
import { createManager } from './app.ts'

/**
 * Creates an access token + linked refresh token persisted in DB.
 *
 * Does NOT create the OAuthClient — call `createTestClient()` first.
 *
 * Defaults: clientId='test-client', userId='user-1',
 * scopes=['read','write','offline_access'], expiresAt=+30d
 *
 * Returns `{ rawRefreshToken, accessTokenId, accessTokenHash, manager }`.
 */
export async function createTestRefreshToken(options?: {
  manager?: SesameManager
  clientId?: string
  userId?: string
  scopes?: string[]
  expiresAt?: DateTime
  revokedAt?: DateTime | null
}) {
  const manager = options?.manager ?? createManager()
  const tokenService = new TokenService(manager)
  const accessTokenId = crypto.randomUUID()
  const accessTokenHash = `access-${crypto.randomUUID()}`

  await OAuthAccessToken.create({
    id: accessTokenId,
    tokenHash: accessTokenHash,
    clientId: options?.clientId ?? 'test-client',
    userId: options?.userId ?? 'user-1',
    scopes: options?.scopes ?? ['read', 'write', 'offline_access'],
    expiresAt: DateTime.now().plus({ hours: 1 }),
  })

  const rawRefreshToken = tokenService.generateOpaqueToken()
  await OAuthRefreshToken.create({
    id: crypto.randomUUID(),
    token: tokenService.hashToken(rawRefreshToken),
    accessTokenId,
    clientId: options?.clientId ?? 'test-client',
    userId: options?.userId ?? 'user-1',
    scopes: options?.scopes ?? ['read', 'write', 'offline_access'],
    expiresAt: options?.expiresAt ?? DateTime.now().plus({ days: 30 }),
    revokedAt: options?.revokedAt ?? null,
  })

  return { rawRefreshToken, accessTokenId, accessTokenHash, manager }
}
