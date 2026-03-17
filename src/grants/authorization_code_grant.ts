import vine from '@vinejs/vine'
import { DateTime } from 'luxon'
import { createHash } from 'node:crypto'
import string from '@adonisjs/core/helpers/string'
import type { HttpContext } from '@adonisjs/core/http'
import type { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthAuthorizationCode } from '../models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../models/oauth_refresh_token.ts'
import { E_INVALID_CLIENT, E_INVALID_GRANT, E_INVALID_REQUEST } from '../oauth_error.ts'

/**
 * Validates the code_verifier format per RFC 7636 §4.1.
 * 43-128 characters from the unreserved character set [A-Za-z0-9-._~].
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
 */
const codeVerifierValidator = vine.create({
  code_verifier: vine
    .string()
    .minLength(43)
    .maxLength(128)
    .regex(/^[A-Za-z0-9\-._~]+$/),
})

/**
 * Handle the Authorization Code Grant (RFC 6749 §4.1.3).
 *
 * Exchanges an authorization code for an access token and a refresh
 * token. A refresh token is always issued when the `refresh_token`
 * grant type is enabled on the server — the client does not need
 * to request `offline_access` explicitly.
 *
 * This matches the behavior of major OAuth providers and avoids
 * forcing MCP clients like ClaudeDesktop to know about `offline_access` to get long-lived sessions.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
 */
export async function handleAuthorizationCodeGrant(ctx: HttpContext, manager: SesameManager) {
  const tokenService = new TokenService(manager)
  const clientService = new ClientService()

  const body = ctx.request.body()
  const code = body.code
  const redirectUri = body.redirect_uri
  const codeVerifier = body.code_verifier

  if (!code) throw new E_INVALID_REQUEST('Missing required parameter: code')
  if (!redirectUri) throw new E_INVALID_REQUEST('Missing required parameter: redirect_uri')

  // Authenticate the client (Basic header or POST body)
  const client = await clientService.authenticateClient({
    authorizationHeader: ctx.request.header('authorization'),
    bodyClientId: body.client_id,
    bodyClientSecret: body.client_secret,
  })
  if (!client.grantTypes.includes('authorization_code')) {
    throw new E_INVALID_CLIENT('Client is not allowed to use the authorization_code grant')
  }

  // Lookup the authorization code by its SHA-256 hash
  const hashedCode = tokenService.hashToken(code)
  const authCode = await OAuthAuthorizationCode.query()
    .where('code', hashedCode)
    .where('clientId', client.clientId)
    .first()

  if (!authCode) throw new E_INVALID_GRANT('Authorization code not found')
  if (authCode.expiresAt < DateTime.now()) {
    await OAuthAuthorizationCode.query().where('id', authCode.id).delete()
    throw new E_INVALID_GRANT('Authorization code has expired')
  }
  if (authCode.redirectUri !== redirectUri) throw new E_INVALID_GRANT('Redirect URI mismatch')

  // Consume the code before verification — authorization codes are single-use
  // even if PKCE fails, so attackers cannot retry with different verifiers
  const deleteResult = await OAuthAuthorizationCode.query().where('id', authCode.id).delete()
  const deletedRows = Array.isArray(deleteResult)
    ? Number(deleteResult[0] ?? 0)
    : Number(deleteResult)
  if (deletedRows !== 1) {
    throw new E_INVALID_GRANT('Authorization code has already been consumed')
  }

  // PKCE S256 verification (mandatory per OAuth 2.1)
  // @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
  const [verifierError] = await codeVerifierValidator.tryValidate({ code_verifier: codeVerifier })
  if (verifierError) {
    throw new E_INVALID_REQUEST(
      'code_verifier must be 43-128 characters using only [A-Za-z0-9-._~] (RFC 7636 §4.1)'
    )
  }
  if (!authCode.codeChallenge)
    throw new E_INVALID_GRANT('Authorization code is missing PKCE challenge')
  const challenge = createHash('sha256').update(codeVerifier).digest('base64url')
  if (challenge !== authCode.codeChallenge) throw new E_INVALID_GRANT('PKCE verification failed')

  clientService.validateClientScopes(authCode.scopes, client.scopes)

  // Issue an opaque access token
  const { raw: accessTokenRaw, hash: tokenHash, expiresAt } = tokenService.createAccessToken()

  await OAuthAccessToken.create({
    id: crypto.randomUUID(),
    tokenHash,
    clientId: client.clientId,
    userId: authCode.userId,
    scopes: authCode.scopes,
    expiresAt: DateTime.fromJSDate(expiresAt),
  })

  // Issue a refresh token when the server has the refresh_token grant
  // enabled. Per RFC 6749 §5.1, refresh token issuance is "at the
  // discretion of the authorization server" — we always emit one so
  // that MCP clients that don't request offline_access still get
  // long-lived sessions
  let refreshTokenRaw: string | undefined
  if (manager.isGrantTypeEnabled('refresh_token')) {
    const { raw, hash } = tokenService.createRefreshToken()
    const refreshTtl = string.seconds.parse(manager.config.refreshTokenTtl)

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: hash,
      accessTokenId: tokenHash,
      clientId: client.clientId,
      userId: authCode.userId,
      scopes: authCode.scopes,
      expiresAt: DateTime.now().plus({ seconds: refreshTtl }),
    })

    refreshTokenRaw = raw
  }

  const ttlSeconds = string.seconds.parse(manager.config.accessTokenTtl)

  return {
    access_token: accessTokenRaw,
    token_type: 'Bearer',
    expires_in: ttlSeconds,
    scope: authCode.scopes.join(' '),
    ...(refreshTokenRaw ? { refresh_token: refreshTokenRaw } : {}),
  }
}
