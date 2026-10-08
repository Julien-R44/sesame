import vine from '@vinejs/vine'
import { DateTime } from 'luxon'
import { createHash } from 'node:crypto'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
import type { OAuthAuthorizationCodeRecord, OAuthClientRecord } from '../storage/types.ts'
import { TokenService } from '../services/token_service.ts'
import { IdTokenService } from '../services/id_token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { markFirstAuthorization } from '../storage/unused_clients.ts'
import { GrantService, type ResolvedTokenGrant } from '../services/grant_service.ts'
import { resolveGrantResource } from '../resource_indicators.ts'
import { E_INVALID_CLIENT, E_INVALID_GRANT, E_INVALID_REQUEST } from '../oauth_error.ts'

/**
 * Validates the code_verifier format per RFC 7636 §4.1.
 * 43-128 characters from the unreserved character set [A-Za-z0-9-._~].
 */
const codeVerifierValidator = vine.create({
  code_verifier: vine
    .string()
    .minLength(43)
    .maxLength(128)
    .regex(/^[A-Za-z0-9\-._~]+$/),
})

export interface ExchangeAuthorizationCodeInput {
  client: OAuthClientRecord
  code: string
  redirectUri: string
  codeVerifier: string

  /**
   * Raw `resource` parameter (RFC 8707). A string, or an array when repeated.
   */
  resource?: unknown
}

/**
 * Validated code and the tokens and grant it is exchanged for.
 */
interface CodeExchange {
  client: OAuthClientRecord
  authCode: OAuthAuthorizationCodeRecord
  accessToken: { raw: string; hash: string; expiresAt: Date }
  refreshToken: { raw: string; hash: string; expiresAt: DateTime } | null
  grant: ResolvedTokenGrant
  resource: string | null
}

/**
 * Handle the Authorization Code Grant (RFC 6749 §4.1.3).
 *
 * Exchanges an authorization code for an access token and
 * optionally a refresh token and id_token. Verifies PKCE,
 * validates scopes, and atomically consumes the code to
 * prevent replay. Consumed codes are kept: redeeming one
 * again revokes its whole grant (OAuth 2.1 §4.1.3).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
 */
export class ExchangeAuthorizationCodeAction {
  /**
   * Exchange an authorization code for tokens. The code is
   * consumed atomically inside a transaction.
   */
  async execute(manager: SesameManager, input: ExchangeAuthorizationCodeInput) {
    const tokenService = new TokenService(manager)
    const clientService = new ClientService()

    if (!input.client.grantTypes.includes('authorization_code')) {
      throw new E_INVALID_CLIENT('Client is not allowed to use the authorization_code grant')
    }

    const authCode = await this.#validateAuthorizationCode(manager, tokenService, input)

    await this.#verifyPkce(manager, input.codeVerifier, authCode)

    clientService.validateClientScopes(authCode.scopes, input.client.scopes)

    const resource = resolveGrantResource({
      requested: manager.resolveResource(input.resource),
      granted: authCode.resource ?? null,
    })

    const grantService = new GrantService(manager)
    await grantService.assertActive(authCode.grantId)

    const accessToken = tokenService.createAccessToken()

    const refreshToken = this.#prepareRefreshToken(manager, tokenService)
    const idToken = await this.#prepareIdToken(manager, authCode, input.client, accessToken.raw)

    const accessTokenExpiresAt = DateTime.fromJSDate(accessToken.expiresAt)
    const grant = grantService.resolveTokenGrant({
      grantId: authCode.grantId,
      clientId: input.client.clientId,
      userId: authCode.userId,
      scopes: authCode.scopes,
      expiresAt: refreshToken
        ? DateTime.max(accessTokenExpiresAt, refreshToken.expiresAt)
        : accessTokenExpiresAt,
      adopt: { codeId: authCode.id },
    })

    /**
     * The code and its PKCE proof are valid: the client completed an authorization.
     * Marking it before consuming the code means a failed write cannot cost the
     * client tokens that were already issued.
     */
    await markFirstAuthorization({ store: manager.store, client: input.client })

    await this.#atomicExchange(manager, {
      client: input.client,
      authCode,
      accessToken,
      refreshToken,
      grant,
      resource,
    })

    const ttlSeconds = string.seconds.parse(manager.config.accessTokenTtl)

    return {
      access_token: accessToken.raw,
      token_type: 'Bearer' as const,
      expires_in: ttlSeconds,
      scope: authCode.scopes.join(' '),
      ...(refreshToken ? { refresh_token: refreshToken.raw } : {}),
      ...(idToken ? { id_token: idToken } : {}),
    }
  }

  /**
   * Lookup the authorization code by hash and validate
   * it has not expired and matches the redirect_uri.
   */
  async #validateAuthorizationCode(
    manager: SesameManager,
    tokenService: TokenService,
    input: ExchangeAuthorizationCodeInput
  ) {
    if (!input.code) throw new E_INVALID_REQUEST('Missing required parameter: code')
    if (!input.redirectUri) throw new E_INVALID_REQUEST('Missing required parameter: redirect_uri')

    const hashedCode = tokenService.hashToken(input.code)
    const store = manager.store
    const authCode = await store.findAuthorizationCode({
      code: hashedCode,
      clientId: input.client.clientId,
    })

    if (!authCode) throw new E_INVALID_GRANT('Authorization code not found')

    if (authCode.consumedAt) {
      await new GrantService(manager).revokeFamily(authCode)
      throw new E_INVALID_GRANT('Authorization code has already been consumed')
    }

    if (authCode.expiresAt < DateTime.now()) {
      await store.deleteAuthorizationCode(authCode.id)
      throw new E_INVALID_GRANT('Authorization code has expired')
    }

    if (authCode.redirectUri !== input.redirectUri) {
      throw new E_INVALID_GRANT('Redirect URI mismatch')
    }

    return authCode
  }

  /**
   * Verify the PKCE code_verifier against the stored
   * code_challenge using S256 (mandatory per OAuth 2.1).
   */
  async #verifyPkce(
    manager: SesameManager,
    codeVerifier: string,
    authCode: OAuthAuthorizationCodeRecord
  ) {
    const store = manager.store
    const [verifierError] = await codeVerifierValidator.tryValidate({ code_verifier: codeVerifier })
    if (verifierError) {
      await store.deleteAuthorizationCode(authCode.id)
      throw new E_INVALID_REQUEST(
        'code_verifier must be 43-128 characters using only [A-Za-z0-9-._~] (RFC 7636 §4.1)'
      )
    }

    if (!authCode.codeChallenge) {
      await store.deleteAuthorizationCode(authCode.id)
      throw new E_INVALID_GRANT('Authorization code is missing PKCE challenge')
    }

    const challenge = createHash('sha256').update(codeVerifier).digest('base64url')
    if (challenge !== authCode.codeChallenge) {
      await store.deleteAuthorizationCode(authCode.id)
      throw new E_INVALID_GRANT('PKCE verification failed')
    }
  }

  /**
   * Precompute refresh token values if the refresh_token
   * grant type is enabled on the server.
   */
  #prepareRefreshToken(manager: SesameManager, tokenService: TokenService) {
    if (!manager.isGrantTypeEnabled('refresh_token')) return null

    const { raw, hash } = tokenService.createRefreshToken()
    const refreshTtl = string.seconds.parse(manager.config.refreshTokenTtl)

    return {
      raw,
      hash,
      expiresAt: DateTime.now().plus({ seconds: refreshTtl }),
    }
  }

  /**
   * Build an id_token JWT if the authorization code was
   * granted the openid scope.
   */
  async #prepareIdToken(
    manager: SesameManager,
    authCode: OAuthAuthorizationCodeRecord,
    client: OAuthClientRecord,
    accessTokenRaw: string
  ) {
    if (!authCode.scopes.includes('openid')) return null

    const idTokenService = new IdTokenService(manager)
    const user = await manager.findUserById(authCode.userId)
    if (!user) throw new E_INVALID_GRANT('OIDC user not found')

    return idTokenService.sign({
      sub: authCode.userId,
      clientId: client.clientId,
      scopes: authCode.scopes,
      accessToken: accessTokenRaw,
      user,
      nonce: authCode.nonce ?? undefined,
    })
  }

  /**
   * Explain why the conditional exchange failed. A concurrent request
   * consumed the code first: that is a reuse, so the tokens it issued
   * are revoked (OAuth 2.1 §4.1.3). Otherwise, the grant was revoked.
   */
  async #rejectLostExchange(manager: SesameManager, exchange: CodeExchange): Promise<never> {
    const current = await manager.store.findAuthorizationCode({
      code: exchange.authCode.code,
      clientId: exchange.client.clientId,
    })
    if (!current?.consumedAt) throw new E_INVALID_GRANT('Grant has been revoked or has expired')

    await new GrantService(manager).revokeFamily(current)
    throw new E_INVALID_GRANT('Authorization code has already been consumed')
  }

  /**
   * Atomically consume the authorization code, persist the new
   * access token (and optionally refresh token), and extend the
   * grant inside a single transaction.
   */
  async #atomicExchange(manager: SesameManager, exchange: CodeExchange) {
    const { authCode, client, accessToken, refreshToken, grant, resource } = exchange
    const store = manager.store
    const accessTokenId = crypto.randomUUID()
    const exchanged = await store.exchangeAuthorizationCode({
      codeId: authCode.id,
      consumedAt: DateTime.now(),
      grant: grant.write,
      accessToken: {
        id: accessTokenId,
        tokenHash: accessToken.hash,
        clientId: client.clientId,
        userId: authCode.userId,
        grantId: grant.grantId,
        scopes: authCode.scopes,
        resource,
        expiresAt: DateTime.fromJSDate(accessToken.expiresAt),
      },
      refreshToken: refreshToken
        ? {
            id: crypto.randomUUID(),
            token: refreshToken.hash,
            accessTokenId,
            clientId: client.clientId,
            userId: authCode.userId,
            grantId: grant.grantId,
            scopes: authCode.scopes,
            resource,
            expiresAt: refreshToken.expiresAt,
          }
        : null,
    })

    if (!exchanged) await this.#rejectLostExchange(manager, exchange)
  }
}
