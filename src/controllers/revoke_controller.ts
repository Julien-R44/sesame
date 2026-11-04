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
 * Revoking a refresh token revokes its whole grant: every access
 * and refresh token issued from the same authorization (RFC 7009
 * §2.1). Refresh tokens issued before grants existed only revoke
 * their paired access token. Revoking an access token only affects
 * that token.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7009
 */
export default class RevokeController {
  /**
   * Revoke the grant of a refresh token, or only the token pair
   * for refresh tokens issued before grants existed.
   */
  async #revokeRefreshToken(manager: SesameManager, options: { hash: string; clientId: string }) {
    const store = manager.store
    const now = DateTime.now()
    const refreshToken = await store.findRefreshToken(options)
    if (!refreshToken) return false

    if (refreshToken.grantId) {
      await store.revokeGrant({ id: refreshToken.grantId, now })
      return true
    }

    await store.revokeRefreshToken({ ...options, now })
    return true
  }

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

    const hashed = new TokenService(manager).hashToken(token)
    const options = { hash: hashed, clientId: client.clientId }
    const revokeAccessToken = () => store.revokeAccessToken({ ...options, now: DateTime.now() })
    const revokeRefreshToken = () => this.#revokeRefreshToken(manager, options)

    /**
     * The hint only orders the lookups. A wrong or unknown hint still
     * revokes the token (RFC 7009 §2.1).
     */
    const [first, second] =
      ctx.request.body().token_type_hint === 'refresh_token'
        ? [revokeRefreshToken, revokeAccessToken]
        : [revokeAccessToken, revokeRefreshToken]
    if (!(await first())) await second()

    return ctx.response.ok({})
  }
}
