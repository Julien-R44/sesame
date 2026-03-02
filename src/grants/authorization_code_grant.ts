import { DateTime } from 'luxon'
import { createHash } from 'node:crypto'
import type { HttpContext } from '@adonisjs/core/http'
import type { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthAuthorizationCode } from '../models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../models/oauth_refresh_token.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import { E_INVALID_CLIENT, E_INVALID_GRANT, E_INVALID_REQUEST } from '../oauth_error.ts'

/**
 * Handle the Authorization Code Grant (RFC 6749 §4.1.3).
 *
 * Exchanges an authorization code for an access token (and optionally
 * a refresh token if the `offline_access` scope was granted).
 *
 * Performs the following validations:
 * - Client authentication (Basic header or POST body credentials)
 * - Authorization code existence, expiration, and single-use enforcement
 * - Redirect URI matching against the original authorization request
 * - PKCE code_verifier verification using S256 (RFC 7636 §4.6)
 *
 * Access tokens are signed JWTs (RFC 9068). Refresh tokens and
 * authorization codes are opaque values stored as SHA-256 hashes.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
 * @see https://datatracker.ietf.org/doc/html/rfc9068
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
  const credentials = clientService.extractCredentials({
    authorizationHeader: ctx.request.header('authorization'),
    bodyClientId: body.client_id,
    bodyClientSecret: body.client_secret,
  })
  if (!credentials) throw new E_INVALID_CLIENT('Missing client credentials')

  const client = await OAuthClient.query().where('clientId', credentials.clientId).first()
  if (!client) throw new E_INVALID_CLIENT('Client not found')
  if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')

  // Confidential clients must provide a valid secret
  if (!client.isPublic) {
    if (!credentials.clientSecret) throw new E_INVALID_CLIENT('Missing client secret')
    if (!clientService.verifySecret(credentials.clientSecret, client.clientSecret!)) {
      throw new E_INVALID_CLIENT('Invalid client secret')
    }
  }
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
  if (!codeVerifier) throw new E_INVALID_REQUEST('Missing required parameter: code_verifier')
  if (!authCode.codeChallenge) throw new E_INVALID_GRANT('Authorization code is missing PKCE challenge')
  const challenge = createHash('sha256').update(codeVerifier).digest('base64url')
  if (challenge !== authCode.codeChallenge) throw new E_INVALID_GRANT('PKCE verification failed')

  clientService.validateClientScopes(authCode.scopes, client.scopes)

  // Issue a signed JWT access token
  const {
    token: accessToken,
    jti,
    expiresAt,
  } = await tokenService.createJwtAccessToken({
    userId: authCode.userId,
    clientId: client.clientId,
    scopes: authCode.scopes,
  })

  await OAuthAccessToken.create({
    id: crypto.randomUUID(),
    jti,
    clientId: client.clientId,
    userId: authCode.userId,
    scopes: authCode.scopes,
    expiresAt: DateTime.fromJSDate(expiresAt),
  })

  // Issue a refresh token only if the offline_access scope was granted
  let refreshTokenRaw: string | undefined
  if (authCode.scopes.includes('offline_access')) {
    const { raw, hash } = tokenService.createRefreshToken()
    const refreshTtl = manager.parseTtl(manager.config.refreshTokenTtl)

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: hash,
      accessTokenId: jti,
      clientId: client.clientId,
      userId: authCode.userId,
      scopes: authCode.scopes,
      expiresAt: DateTime.now().plus({ seconds: refreshTtl }),
    })

    refreshTokenRaw = raw
  }

  const ttlSeconds = manager.parseTtl(manager.config.accessTokenTtl)

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ttlSeconds,
    scope: authCode.scopes.join(' '),
    ...(refreshTokenRaw ? { refresh_token: refreshTokenRaw } : {}),
  }
}
