import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import { OAuthAccessToken } from '../models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../models/oauth_refresh_token.ts'
import { E_INVALID_CLIENT } from '../oauth_error.ts'

const INACTIVE = { active: false }

/**
 * Handles the OAuth 2.0 Token Introspection Endpoint (RFC 7662).
 *
 * Allows an authenticated client to determine the active state and
 * metadata of a token (access token or refresh token). The response
 * always includes at least `{ active: boolean }`.
 *
 * Supports the `token_type_hint` parameter to optimize lookup order.
 * For access tokens, verifies the JWT signature and checks revocation.
 * For refresh tokens, looks up the hashed value in the database.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 */
export default class IntrospectController {
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const clientService = new ClientService()

    // Authenticate the requesting client
    const credentials = clientService.extractCredentials({
      authorizationHeader: ctx.request.header('authorization'),
      bodyClientId: ctx.request.body().client_id,
      bodyClientSecret: ctx.request.body().client_secret,
    })
    if (!credentials) throw new E_INVALID_CLIENT('Client authentication required')

    const client = await OAuthClient.query().where('clientId', credentials.clientId).first()
    if (!client) throw new E_INVALID_CLIENT('Client not found')
    if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')

    if (!client.isPublic) {
      if (!credentials.clientSecret) throw new E_INVALID_CLIENT('Missing client secret')
      if (!clientService.verifySecret(credentials.clientSecret, client.clientSecret!)) {
        throw new E_INVALID_CLIENT('Invalid client secret')
      }
    }

    const token = ctx.request.body().token
    if (!token) return INACTIVE

    const tokenTypeHint = ctx.request.body().token_type_hint
    const tokenService = new TokenService(manager)

    // Try as JWT access token: verify signature, then check revocation
    if (!tokenTypeHint || tokenTypeHint === 'access_token') {
      try {
        const payload = await tokenService.verifyJwtAccessToken(token)
        const record = await OAuthAccessToken.query().where('jti', payload.jti).first()
        if (!record) return INACTIVE
        if (record.revokedAt) return INACTIVE
        if (record.clientId !== client.clientId) return INACTIVE
        if (payload.azp !== client.clientId) return INACTIVE

        return {
          active: true,
          token_type: 'Bearer',
          client_id: payload.azp,
          sub: payload.sub || undefined,
          scope: payload.scope,
          iss: payload.iss,
          iat: payload.iat,
          exp: payload.exp,
          jti: payload.jti,
        }
      } catch {
        // JWT verification failed — if hinted as access_token, stop here
        if (tokenTypeHint === 'access_token') return INACTIVE
      }
    }

    // Try as opaque refresh token: hash and lookup in DB
    if (!tokenTypeHint || tokenTypeHint === 'refresh_token') {
      const hashed = tokenService.hashToken(token)
      const refreshToken = await OAuthRefreshToken.query()
        .where('token', hashed)
        .where('clientId', client.clientId)
        .first()

      if (!refreshToken) return INACTIVE
      if (refreshToken.revokedAt) return INACTIVE
      if (refreshToken.expiresAt.toJSDate() < new Date()) return INACTIVE

      return {
        active: true,
        token_type: 'refresh_token',
        client_id: refreshToken.clientId,
        sub: refreshToken.userId,
        scope: refreshToken.scopes.join(' '),
        iss: manager.config.issuer,
        iat: Math.floor(refreshToken.createdAt.toMillis() / 1000),
        exp: Math.floor(refreshToken.expiresAt.toMillis() / 1000),
      }
    }

    return INACTIVE
  }
}
