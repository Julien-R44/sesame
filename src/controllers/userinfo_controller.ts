import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { IdTokenService } from '../services/id_token_service.ts'
import { E_INSUFFICIENT_SCOPE, E_INVALID_REQUEST, E_INVALID_TOKEN } from '../oauth_error.ts'

/**
 * OpenID Connect UserInfo endpoint (OIDC Core §5.3).
 *
 * Returns claims about the authenticated user based on the
 * access token's scopes. Supports both GET and POST.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 */
export default class UserinfoController {
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)

    const authHeader = ctx.request.header('authorization')
    const rawToken = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7)
      : ctx.request.body().access_token

    if (!rawToken) throw new E_INVALID_REQUEST('Missing Bearer token')

    const tokenService = new TokenService(manager)
    const hashed = tokenService.hashToken(rawToken)

    const store = manager.store
    const token = await store.findAccessToken({ hash: hashed })
    if (!token) throw new E_INVALID_TOKEN('Invalid access token')
    if (token.revokedAt) throw new E_INVALID_TOKEN('Access token has been revoked')
    if (token.expiresAt.toJSDate() < new Date())
      throw new E_INVALID_TOKEN('Access token has expired')
    if (!token.scopes.includes('openid')) {
      throw new E_INSUFFICIENT_SCOPE(['openid'], 'Token does not have openid scope')
    }

    const user = await manager.findUserById(token.userId!)
    if (!user) throw new E_INVALID_TOKEN('Invalid access token')

    const userClaims = await IdTokenService.resolveUserClaims(user, token.scopes)

    ctx.response.header('Content-Type', 'application/json')

    return { sub: token.userId, ...userClaims }
  }
}
