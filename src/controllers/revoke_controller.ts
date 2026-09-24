import { DateTime } from 'luxon'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'

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
    const clientService = new ClientService(manager)
    const store = manager.store

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
      const revoked = await store.revokeAccessToken({
        hash: hashed,
        clientId: client.clientId,
        now: DateTime.now(),
      })
      if (revoked) return ctx.response.ok({})

      if (tokenTypeHint === 'access_token') return ctx.response.ok({})
    }

    // Try revoking as refresh token
    if (!tokenTypeHint || tokenTypeHint === 'refresh_token') {
      await store.revokeRefreshToken({
        hash: hashed,
        clientId: client.clientId,
        now: DateTime.now(),
      })
    }

    return ctx.response.ok({})
  }
}
