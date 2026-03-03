import { DateTime } from 'luxon'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthAccessToken } from '../models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../models/oauth_refresh_token.ts'

/**
 * Handles the OAuth 2.0 Token Revocation Endpoint (RFC 7009).
 *
 * Allows an authenticated client to revoke an access token or
 * refresh token. Always responds with HTTP 200, even if the token
 * was already revoked or not found (to prevent information leakage).
 *
 * When revoking a refresh token, the associated access token is
 * also revoked as recommended by RFC 7009 §2.1.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7009
 */
export default class RevokeController {
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const clientService = new ClientService()

    // Authenticate the requesting client
    const client = await clientService.authenticateClient({
      authorizationHeader: ctx.request.header('authorization'),
      bodyClientId: ctx.request.body().client_id,
      bodyClientSecret: ctx.request.body().client_secret,
    })

    // Per RFC 7009, missing token is not an error
    const token = ctx.request.body().token
    if (!token) return ctx.response.ok({})

    const tokenTypeHint = ctx.request.body().token_type_hint
    const tokenService = new TokenService(manager)
    const hashed = tokenService.hashToken(token)

    // Try revoking as access token
    if (!tokenTypeHint || tokenTypeHint === 'access_token') {
      const record = await OAuthAccessToken.query()
        .where('tokenHash', hashed)
        .where('clientId', client.clientId)
        .first()

      if (record && !record.revokedAt) {
        record.revokedAt = DateTime.now()
        await record.save()
        return ctx.response.ok({})
      }

      if (tokenTypeHint === 'access_token') return ctx.response.ok({})
    }

    // Try revoking as refresh token
    if (!tokenTypeHint || tokenTypeHint === 'refresh_token') {
      const refreshToken = await OAuthRefreshToken.query()
        .where('token', hashed)
        .where('clientId', client.clientId)
        .first()

      if (refreshToken && !refreshToken.revokedAt) {
        refreshToken.revokedAt = DateTime.now()
        await refreshToken.save()

        // Also revoke the associated access token (RFC 7009 §2.1)
        await OAuthAccessToken.query()
          .where('tokenHash', refreshToken.accessTokenId)
          .whereNull('revokedAt')
          .update({ revokedAt: DateTime.now().toSQL() })
      }
    }

    return ctx.response.ok({})
  }
}
