import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { HttpContext } from '@adonisjs/core/http'
import type { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthAccessToken } from '../models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../models/oauth_refresh_token.ts'
import {
  E_INVALID_CLIENT,
  E_INVALID_GRANT,
  E_INVALID_REQUEST,
  E_INVALID_SCOPE,
} from '../oauth_error.ts'

/**
 * Handle the Refresh Token Grant (RFC 6749 §6).
 *
 * Exchanges a refresh token for a new access token and a new
 * refresh token (rotation). The old refresh token is revoked
 * immediately after use.
 *
 * Implements replay detection: if a revoked refresh token is
 * presented, all tokens for that client+user pair are nuked
 * (both access and refresh tokens) to mitigate stolen token
 * reuse attacks.
 *
 * Scope narrowing is supported: the client may request a subset
 * of the originally granted scopes, but cannot request new ones.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.14.2
 */
export async function handleRefreshTokenGrant(ctx: HttpContext, manager: SesameManager) {
  const tokenService = new TokenService(manager)
  const clientService = new ClientService()

  const body = ctx.request.body()
  const refreshTokenRaw = body.refresh_token
  if (!refreshTokenRaw) throw new E_INVALID_REQUEST('Missing required parameter: refresh_token')

  // Authenticate the client
  const client = await clientService.authenticateClient({
    authorizationHeader: ctx.request.header('authorization'),
    bodyClientId: body.client_id,
    bodyClientSecret: body.client_secret,
  })
  if (!client.grantTypes.includes('refresh_token')) {
    throw new E_INVALID_CLIENT('Client is not allowed to use the refresh_token grant')
  }

  // Lookup the refresh token by its SHA-256 hash
  const hashedToken = tokenService.hashToken(refreshTokenRaw)
  const refreshToken = await OAuthRefreshToken.query()
    .where('token', hashedToken)
    .where('clientId', client.clientId)
    .first()

  if (!refreshToken) throw new E_INVALID_GRANT('Refresh token not found')

  // Replay detection: a revoked token being reused means it was stolen.
  // Nuke all tokens for this client+user pair as a security measure.
  if (refreshToken.revokedAt) {
    await OAuthRefreshToken.query()
      .where('clientId', client.clientId)
      .where('userId', refreshToken.userId)
      .delete()
    await OAuthAccessToken.query()
      .where('clientId', client.clientId)
      .where('userId', refreshToken.userId)
      .whereNull('revokedAt')
      .update({ revokedAt: DateTime.now().toSQL() })

    throw new E_INVALID_GRANT('Refresh token has been revoked (possible replay attack)')
  }

  if (refreshToken.expiresAt < DateTime.now())
    throw new E_INVALID_GRANT('Refresh token has expired')

  // Scope narrowing: client may request a subset of the original scopes
  const requestedScope = body.scope
  let scopes = refreshToken.scopes
  if (requestedScope) {
    const requested = requestedScope.split(' ')
    const originalSet = new Set(refreshToken.scopes)
    const invalid = requested.filter((s: string) => !originalSet.has(s))
    if (invalid.length > 0)
      throw new E_INVALID_SCOPE(`Scope not in original grant: ${invalid.join(', ')}`)
    scopes = requested
  }
  clientService.validateClientScopes(scopes, client.scopes)

  // Revoke the old refresh token before issuing new ones
  const revokedAt = DateTime.now()
  const updateResult = await OAuthRefreshToken.query()
    .where('id', refreshToken.id)
    .whereNull('revokedAt')
    .update({ revokedAt: revokedAt.toSQL() })
  const updatedRows = Array.isArray(updateResult)
    ? Number(updateResult[0] ?? 0)
    : Number(updateResult)

  if (updatedRows !== 1) {
    throw new E_INVALID_GRANT('Refresh token has already been consumed')
  }

  // Revoke the old access token (OAuth Security BCP §4.14.2)
  await OAuthAccessToken.query()
    .where('tokenHash', refreshToken.accessTokenId)
    .whereNull('revokedAt')
    .update({ revokedAt: revokedAt.toSQL() })

  // Issue a new opaque access token
  const { raw: accessTokenRaw, hash: tokenHash, expiresAt } = tokenService.createAccessToken()

  await OAuthAccessToken.create({
    id: crypto.randomUUID(),
    tokenHash,
    clientId: client.clientId,
    userId: refreshToken.userId,
    scopes,
    expiresAt: DateTime.fromJSDate(expiresAt),
  })

  // Issue a new refresh token (rotation — each use produces a fresh token)
  const { raw: newRefreshTokenRaw, hash: newRefreshTokenHash } = tokenService.createRefreshToken()
  const refreshTtl = string.seconds.parse(manager.config.refreshTokenTtl)

  await OAuthRefreshToken.create({
    id: crypto.randomUUID(),
    token: newRefreshTokenHash,
    accessTokenId: tokenHash,
    clientId: client.clientId,
    userId: refreshToken.userId,
    scopes,
    expiresAt: DateTime.now().plus({ seconds: refreshTtl }),
  })

  const ttlSeconds = string.seconds.parse(manager.config.accessTokenTtl)

  return {
    access_token: accessTokenRaw,
    token_type: 'Bearer',
    expires_in: ttlSeconds,
    scope: scopes.join(' '),
    refresh_token: newRefreshTokenRaw,
  }
}
