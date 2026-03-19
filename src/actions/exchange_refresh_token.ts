import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
import type { OAuthClient } from '../models/oauth_client.ts'
import { TokenService } from '../services/token_service.ts'
import { IdTokenService } from '../services/id_token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthAccessToken } from '../models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../models/oauth_refresh_token.ts'
import {
  E_INVALID_CLIENT,
  E_INVALID_GRANT,
  E_INVALID_REQUEST,
  E_INVALID_SCOPE,
} from '../oauth_error.ts'

export interface ExchangeRefreshTokenInput {
  client: OAuthClient
  refreshToken: string
  scope?: string
}

/**
 * Handle the Refresh Token Grant (RFC 6749 §6).
 *
 * Exchanges a refresh token for a new access token and a new
 * refresh token (rotation). The old refresh token is revoked
 * immediately after use.
 *
 * Implements replay detection: if a revoked refresh token is
 * presented, all tokens for that client+user pair are nuked
 * to mitigate stolen token reuse attacks.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 */
export class ExchangeRefreshTokenAction {
  /**
   * Rotate the refresh token, issue a new access token,
   * and optionally reissue an id_token if openid scope
   * is present.
   */
  async execute(manager: SesameManager, input: ExchangeRefreshTokenInput) {
    const tokenService = new TokenService(manager)
    const clientService = new ClientService()

    if (!input.refreshToken)
      throw new E_INVALID_REQUEST('Missing required parameter: refresh_token')

    if (!input.client.grantTypes.includes('refresh_token')) {
      throw new E_INVALID_CLIENT('Client is not allowed to use the refresh_token grant')
    }

    const hashedToken = tokenService.hashToken(input.refreshToken)
    const refreshToken = await OAuthRefreshToken.query()
      .where('token', hashedToken)
      .where('clientId', input.client.clientId)
      .first()

    if (!refreshToken) throw new E_INVALID_GRANT('Refresh token not found')

    if (refreshToken.revokedAt) {
      await this.#nukeTokensForReplay(input.client.clientId, refreshToken.userId)
      throw new E_INVALID_GRANT('Refresh token has been revoked (possible replay attack)')
    }

    if (refreshToken.expiresAt < DateTime.now()) {
      throw new E_INVALID_GRANT('Refresh token has expired')
    }

    const scopes = this.#resolveScopes(manager, input, refreshToken, clientService)

    const accessToken = tokenService.createAccessToken()
    const newRefreshToken = this.#prepareRefreshToken(manager, tokenService)
    const idToken = await this.#prepareIdToken(
      manager,
      scopes,
      refreshToken,
      input.client,
      accessToken.raw
    )

    await this.#atomicRotation(input, refreshToken, accessToken, newRefreshToken, scopes)

    const ttlSeconds = string.seconds.parse(manager.config.accessTokenTtl)

    return {
      access_token: accessToken.raw,
      token_type: 'Bearer' as const,
      expires_in: ttlSeconds,
      scope: scopes.join(' '),
      refresh_token: newRefreshToken.raw,
      ...(idToken ? { id_token: idToken } : {}),
    }
  }

  /**
   * Replay detection: nuke all tokens for this client+user
   * pair when a revoked token is reused.
   */
  async #nukeTokensForReplay(clientId: string, userId: string) {
    await OAuthRefreshToken.query().where('clientId', clientId).where('userId', userId).delete()

    await OAuthAccessToken.query()
      .where('clientId', clientId)
      .where('userId', userId)
      .whereNull('revokedAt')
      .update({ revokedAt: DateTime.now().toSQL() })
  }

  /**
   * Resolve the effective scopes for the new token. Supports
   * scope narrowing but rejects scope escalation.
   */
  #resolveScopes(
    manager: SesameManager,
    input: ExchangeRefreshTokenInput,
    refreshToken: OAuthRefreshToken,
    clientService: ClientService
  ): string[] {
    if (!input.scope) {
      clientService.validateClientScopes(refreshToken.scopes, input.client.scopes)
      return refreshToken.scopes
    }

    const requested = input.scope.split(' ')
    const originalSet = new Set(refreshToken.scopes)
    const invalid = requested.filter((s: string) => !originalSet.has(s))
    if (invalid.length > 0) {
      throw new E_INVALID_SCOPE(`Scope not in original grant: ${invalid.join(', ')}`)
    }

    const invalidScopes = manager.validateScopes(requested)
    if (invalidScopes.length > 0) {
      throw new E_INVALID_SCOPE(`Invalid scopes: ${invalidScopes.join(', ')}`)
    }

    if (manager.usesOidcScopes(requested) && !manager.isOidcEnabled) {
      throw new E_INVALID_SCOPE(
        'OIDC scopes require OIDC to be configured (set jwk and oidcProvider in config)'
      )
    }

    clientService.validateClientScopes(requested, input.client.scopes)

    return requested
  }

  /**
   * Precompute the new refresh token values for rotation.
   */
  #prepareRefreshToken(manager: SesameManager, tokenService: TokenService) {
    const { raw, hash } = tokenService.createRefreshToken()
    const refreshTtl = string.seconds.parse(manager.config.refreshTokenTtl)

    return {
      raw,
      hash,
      expiresAt: DateTime.now().plus({ seconds: refreshTtl }),
    }
  }

  /**
   * Reissue an id_token if openid scope is present.
   * No nonce on refresh per OIDC Core §12.2.
   */
  async #prepareIdToken(
    manager: SesameManager,
    scopes: string[],
    refreshToken: OAuthRefreshToken,
    client: OAuthClient,
    accessTokenRaw: string
  ) {
    if (!scopes.includes('openid')) return null

    const idTokenService = new IdTokenService(manager)
    const user = await manager.findUserById(refreshToken.userId)
    if (!user) throw new E_INVALID_GRANT('OIDC user not found')

    return idTokenService.sign({
      sub: refreshToken.userId,
      clientId: client.clientId,
      scopes,
      accessToken: accessTokenRaw,
      user,
    })
  }

  /**
   * Atomically revoke the old token pair and persist the
   * new access + refresh tokens inside a single transaction.
   */
  async #atomicRotation(
    input: ExchangeRefreshTokenInput,
    oldRefreshToken: OAuthRefreshToken,
    accessToken: { raw: string; hash: string; expiresAt: Date },
    newRefreshToken: { raw: string; hash: string; expiresAt: DateTime },
    scopes: string[]
  ) {
    await OAuthRefreshToken.transaction(async (trx) => {
      const revokedAt = DateTime.now()

      const updateResult = await OAuthRefreshToken.query()
        .useTransaction(trx)
        .where('id', oldRefreshToken.id)
        .whereNull('revokedAt')
        .update({ revokedAt: revokedAt.toSQL() })
      const updatedRows = Array.isArray(updateResult)
        ? Number(updateResult[0] ?? 0)
        : Number(updateResult)

      if (updatedRows !== 1) {
        throw new E_INVALID_GRANT('Refresh token has already been consumed')
      }

      await OAuthAccessToken.query()
        .useTransaction(trx)
        .where('tokenHash', oldRefreshToken.accessTokenId)
        .whereNull('revokedAt')
        .update({ revokedAt: revokedAt.toSQL() })

      await OAuthAccessToken.create(
        {
          id: crypto.randomUUID(),
          tokenHash: accessToken.hash,
          clientId: input.client.clientId,
          userId: oldRefreshToken.userId,
          scopes,
          expiresAt: DateTime.fromJSDate(accessToken.expiresAt),
        },
        { client: trx }
      )

      await OAuthRefreshToken.create(
        {
          id: crypto.randomUUID(),
          token: newRefreshToken.hash,
          accessTokenId: accessToken.hash,
          clientId: input.client.clientId,
          userId: oldRefreshToken.userId,
          scopes,
          expiresAt: newRefreshToken.expiresAt,
        },
        { client: trx }
      )
    })
  }
}
