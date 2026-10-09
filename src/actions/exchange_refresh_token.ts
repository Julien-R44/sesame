import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
import { describeInvalidScopes } from '../invalid_scope_description.ts'
import type { OAuthClientRecord, OAuthRefreshTokenRecord } from '../storage/types.ts'
import { TokenService } from '../services/token_service.ts'
import { IdTokenService } from '../services/id_token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { GrantService, type ResolvedTokenGrant } from '../services/grant_service.ts'
import {
  E_INVALID_CLIENT,
  E_INVALID_GRANT,
  E_INVALID_REQUEST,
  E_INVALID_SCOPE,
} from '../oauth_error.ts'
import { markFirstAuthorization } from '../storage/unused_clients.ts'

export interface ExchangeRefreshTokenInput {
  client: OAuthClientRecord
  refreshToken: string
  scope?: string
}

/**
 * Refresh token issuing new tokens and the expiries of those tokens.
 */
interface GrantResolution {
  refreshToken: OAuthRefreshTokenRecord
  accessTokenExpiresAt: Date
  refreshTokenExpiresAt: DateTime
}

/**
 * Refresh token being rotated and the tokens and grant replacing it.
 */
interface RefreshRotation {
  client: OAuthClientRecord
  oldRefreshToken: OAuthRefreshTokenRecord
  accessToken: { raw: string; hash: string; expiresAt: Date }
  newRefreshToken: { raw: string; hash: string; expiresAt: DateTime }
  scopes: string[]
  grant: ResolvedTokenGrant
}

/**
 * Handle the Refresh Token Grant (RFC 6749 §6).
 *
 * Exchanges a refresh token for a new access token and a new
 * refresh token (rotation). The old refresh token is revoked
 * immediately after use.
 *
 * ## Replay detection
 *
 * If a revoked refresh token is presented **outside** the grace
 * period, its whole grant is revoked (every token issued from the
 * same authorization) to mitigate stolen-token reuse
 * (OAuth 2.1 §4.3.1, RFC 9700 §4.14.2). Other grants of the same
 * client and user (another device, another context) are untouched.
 * Refresh tokens issued before grants existed fall back to their
 * client+user family and are adopted into a grant on rotation.
 *
 * ## Grace period (rotation reuse window)
 *
 * OAuth 2.1 requires that rotated refresh tokens be single-use.
 * However, that requirement conflicts with the realities of
 * distributed systems: if the server rotates the token but the
 * client never receives (or persists) the new token — due to a
 * network failure, a concurrent refresh from another process, or
 * a retry after timeout — the client loses its grant permanently.
 *
 * To handle this, we allow a recently-rotated refresh token to be
 * reused within a short configurable window (`refreshTokenRotationGracePeriod`,
 * defaults to 120 s). During that window the old token issues fresh
 * tokens without triggering replay-attack revocation. Tokens rotated
 * before grants existed (no `grant_id`) get no grace period.
 *
 * This is the same approach used by Auth0 ("reuse interval") and
 * Cloudflare workers-oauth-provider ("previous token"). It provides
 * most of the security benefits of strict rotation while remaining
 * reliable for real-world clients (MCP SDK, multi-process CLIs, etc.).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 * @see https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.3
 * @see https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
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
    const store = manager.store
    const refreshToken = await store.findRefreshToken({
      hash: hashedToken,
      clientId: input.client.clientId,
    })

    if (!refreshToken) throw new E_INVALID_GRANT('Refresh token not found')

    if (refreshToken.revokedAt) {
      if (!this.#isInGracePeriod(manager, refreshToken)) {
        await new GrantService(manager).revokeFamily(refreshToken)
        throw new E_INVALID_GRANT('Refresh token has been revoked (possible replay attack)')
      }

      /**
       * Within grace period — the old refresh token was recently
       * rotated and a concurrent client is reusing it. Issue new
       * tokens without nuking the family. This matches Auth0 / Okta
       * behavior for handling race conditions in multi-process
       * clients (e.g. MCP SDK proactive refresh + SDK 401 retry).
       */
      return this.#issueFreshTokens(manager, input, refreshToken)
    }

    if (refreshToken.expiresAt < DateTime.now()) {
      throw new E_INVALID_GRANT('Refresh token has expired')
    }

    await new GrantService(manager).assertActive(refreshToken.grantId)

    // Clients registered before the marker existed get it on their next refresh
    await markFirstAuthorization({ store, client: input.client })

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

    const grant = this.#resolveGrant(manager, {
      refreshToken,
      accessTokenExpiresAt: accessToken.expiresAt,
      refreshTokenExpiresAt: newRefreshToken.expiresAt,
    })
    await this.#atomicRotation(manager, {
      client: input.client,
      oldRefreshToken: refreshToken,
      accessToken,
      newRefreshToken,
      scopes,
      grant,
    })

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
   * Whether a revoked refresh token can still be reused. Tokens rotated
   * before grants existed never can: their successor may already belong
   * to a new grant, and reusing them would fork the authorization into a
   * second grant that replay detection on the first one cannot revoke.
   */
  #isInGracePeriod(manager: SesameManager, refreshToken: OAuthRefreshTokenRecord): boolean {
    if (!refreshToken.grantId || !refreshToken.revokedAt) return false

    const gracePeriodSeconds = manager.config.refreshTokenRotationGracePeriod
    if (gracePeriodSeconds <= 0) return false

    const revokedSecondsAgo = DateTime.now().diff(refreshToken.revokedAt, 'seconds').seconds

    return revokedSecondsAgo <= gracePeriodSeconds
  }

  /**
   * Grace-period reuse: the old refresh token was rotated
   * recently and a concurrent client replayed it. Issue a
   * brand-new AT + RT pair directly (the old pair is already
   * revoked from the first rotation).
   */
  async #issueFreshTokens(
    manager: SesameManager,
    input: ExchangeRefreshTokenInput,
    revokedRefreshToken: OAuthRefreshTokenRecord
  ) {
    const tokenService = new TokenService(manager)
    const clientService = new ClientService()
    await new GrantService(manager).assertActive(revokedRefreshToken.grantId)
    const scopes = this.#resolveScopes(manager, input, revokedRefreshToken, clientService)

    const accessToken = tokenService.createAccessToken()
    const newRefreshToken = this.#prepareRefreshToken(manager, tokenService)
    const idToken = await this.#prepareIdToken(
      manager,
      scopes,
      revokedRefreshToken,
      input.client,
      accessToken.raw
    )

    const accessTokenId = crypto.randomUUID()
    const grant = this.#resolveGrant(manager, {
      refreshToken: revokedRefreshToken,
      accessTokenExpiresAt: accessToken.expiresAt,
      refreshTokenExpiresAt: newRefreshToken.expiresAt,
    })

    const store = manager.store
    const issued = await store.issueTokenPair({
      grant: grant.write,
      accessToken: {
        id: accessTokenId,
        tokenHash: accessToken.hash,
        clientId: input.client.clientId,
        userId: revokedRefreshToken.userId,
        grantId: grant.grantId,
        scopes,
        expiresAt: DateTime.fromJSDate(accessToken.expiresAt),
      },
      refreshToken: {
        id: crypto.randomUUID(),
        token: newRefreshToken.hash,
        accessTokenId,
        clientId: input.client.clientId,
        userId: revokedRefreshToken.userId,
        grantId: grant.grantId,
        scopes,
        expiresAt: newRefreshToken.expiresAt,
      },
    })
    if (!issued) throw new E_INVALID_GRANT('Grant has been revoked or has expired')

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
   * Keep the new tokens in the refresh token's grant until the last of
   * them expires, adopting legacy tokens (and the presented refresh
   * token with its access token) into a new grant.
   */
  #resolveGrant(manager: SesameManager, options: GrantResolution): ResolvedTokenGrant {
    const { refreshToken } = options

    return new GrantService(manager).resolveTokenGrant({
      grantId: refreshToken.grantId,
      clientId: refreshToken.clientId,
      userId: refreshToken.userId,
      scopes: refreshToken.scopes,
      expiresAt: DateTime.max(
        DateTime.fromJSDate(options.accessTokenExpiresAt),
        options.refreshTokenExpiresAt
      ),
      adopt: { refreshTokenId: refreshToken.id, accessTokenId: refreshToken.accessTokenId },
    })
  }

  /**
   * Resolve the effective scopes for the new token. Supports
   * scope narrowing but rejects scope escalation.
   */
  #resolveScopes(
    manager: SesameManager,
    input: ExchangeRefreshTokenInput,
    refreshToken: OAuthRefreshTokenRecord,
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
      throw new E_INVALID_SCOPE(describeInvalidScopes(invalidScopes))
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
    refreshToken: OAuthRefreshTokenRecord,
    client: OAuthClientRecord,
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
   * Atomically revoke the old token pair, persist the new
   * access + refresh tokens, and extend the grant inside a
   * single transaction.
   */
  async #atomicRotation(manager: SesameManager, rotation: RefreshRotation) {
    const { client, oldRefreshToken, accessToken, newRefreshToken, scopes, grant } = rotation
    const store = manager.store
    const accessTokenId = crypto.randomUUID()
    const rotated = await store.rotateRefreshToken({
      oldRefreshTokenId: oldRefreshToken.id,
      oldAccessTokenId: oldRefreshToken.accessTokenId,
      revokedAt: DateTime.now(),
      grant: grant.write,
      accessToken: {
        id: accessTokenId,
        tokenHash: accessToken.hash,
        clientId: client.clientId,
        userId: oldRefreshToken.userId,
        grantId: grant.grantId,
        scopes,
        expiresAt: DateTime.fromJSDate(accessToken.expiresAt),
      },
      refreshToken: {
        id: crypto.randomUUID(),
        token: newRefreshToken.hash,
        accessTokenId,
        clientId: client.clientId,
        userId: oldRefreshToken.userId,
        grantId: grant.grantId,
        scopes,
        expiresAt: newRefreshToken.expiresAt,
      },
    })

    if (rotated) return

    await new GrantService(manager).assertActive(oldRefreshToken.grantId)
    throw new E_INVALID_GRANT('Refresh token has already been consumed')
  }
}
