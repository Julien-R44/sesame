import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { GrantService, hasActiveGrant } from '../services/grant_service.ts'

const INACTIVE = { active: false }

/**
 * Handles the OAuth 2.0 Token Introspection Endpoint (RFC 7662).
 *
 * Allows an authenticated client to determine the active state and
 * metadata of a token (access token or refresh token). The response
 * always includes at least `{ active: boolean }`.
 *
 * Supports the `token_type_hint` parameter to optimize lookup order.
 * Tokens bound to a resource (RFC 8707) expose it as `aud`.
 * Both access tokens and refresh tokens are opaque values looked up
 * by their SHA-256 hash in the database. Tokens whose grant was
 * revoked or has expired are inactive.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 */
export default class IntrospectController {
  /**
   * Describe an active access token, or return null.
   */
  async #introspectAccessToken(
    manager: SesameManager,
    options: { hash: string; clientId: string }
  ) {
    const record = await manager.store.findAccessToken(options)
    if (!record || record.revokedAt) return null
    if (record.expiresAt.toJSDate() < new Date() || !hasActiveGrant(record)) return null

    return {
      active: true,
      token_type: 'Bearer',
      client_id: record.clientId,
      sub: record.userId || undefined,
      scope: record.scopes.join(' '),
      ...(record.resource ? { aud: record.resource } : {}),
      iss: manager.config.issuer,
      iat: Math.floor(record.createdAt.toMillis() / 1000),
      exp: Math.floor(record.expiresAt.toMillis() / 1000),
    }
  }

  /**
   * Describe an active refresh token, or return null.
   */
  async #introspectRefreshToken(
    manager: SesameManager,
    options: { hash: string; clientId: string }
  ) {
    const refreshToken = await manager.store.findRefreshToken(options)
    if (!refreshToken || refreshToken.revokedAt) return null
    if (refreshToken.expiresAt.toJSDate() < new Date()) return null
    if (!(await new GrantService(manager).isActive(refreshToken.grantId))) return null

    return {
      active: true,
      token_type: 'refresh_token',
      client_id: refreshToken.clientId,
      sub: refreshToken.userId,
      scope: refreshToken.scopes.join(' '),
      ...(refreshToken.resource ? { aud: refreshToken.resource } : {}),
      iss: manager.config.issuer,
      iat: Math.floor(refreshToken.createdAt.toMillis() / 1000),
      exp: Math.floor(refreshToken.expiresAt.toMillis() / 1000),
    }
  }

  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const clientService = new ClientService(manager)

    // Authenticate the requesting client
    const client = await clientService.authenticateClient({
      authorizationHeader: ctx.request.header('authorization'),
      bodyClientId: ctx.request.body().client_id,
      bodyClientSecret: ctx.request.body().client_secret,
    })

    const token = ctx.request.body().token
    if (!token) return INACTIVE

    const hashed = new TokenService(manager).hashToken(token)
    const options = { hash: hashed, clientId: client.clientId }

    /**
     * The hint only orders the lookups. A wrong or unknown hint still
     * finds the token (RFC 7662 §2.1).
     */
    const accessToken = () => this.#introspectAccessToken(manager, options)
    const refreshToken = () => this.#introspectRefreshToken(manager, options)
    const [first, second] =
      ctx.request.body().token_type_hint === 'refresh_token'
        ? [refreshToken, accessToken]
        : [accessToken, refreshToken]

    return (await first()) ?? (await second()) ?? INACTIVE
  }
}
