import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { handleAuthorizationCodeGrant } from '../grants/authorization_code_grant.ts'
import { handleRefreshTokenGrant } from '../grants/refresh_token_grant.ts'
import { E_UNSUPPORTED_GRANT_TYPE } from '../oauth_error.ts'

type GrantHandler = (ctx: HttpContext, manager: SesameManager) => Promise<any>

/**
 * Grant type dispatch map. Each grant type maps to its handler
 * function. New grant types can be added here.
 */
const grantHandlers: Record<string, GrantHandler> = {
  authorization_code: handleAuthorizationCodeGrant,
  refresh_token: handleRefreshTokenGrant,
}

/**
 * Handles the OAuth 2.0 Token Endpoint (RFC 6749 §3.2).
 *
 * Dispatches to the appropriate grant handler based on the
 * `grant_type` parameter. Sets `Cache-Control: no-store` and
 * `Pragma: no-cache` headers on all token responses as required
 * by the spec.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 */
export default class TokenController {
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const grantType = ctx.request.body().grant_type

    if (!grantType) throw new E_UNSUPPORTED_GRANT_TYPE('Missing required parameter: grant_type')
    if (!manager.isGrantTypeEnabled(grantType)) {
      throw new E_UNSUPPORTED_GRANT_TYPE(`Grant type "${grantType}" is not enabled`)
    }

    const handler = grantHandlers[grantType]
    if (!handler) throw new E_UNSUPPORTED_GRANT_TYPE(`Unsupported grant type: ${grantType}`)

    const result = await handler(ctx, manager)

    ctx.response.header('Cache-Control', 'no-store')
    ctx.response.header('Pragma', 'no-cache')

    return result
  }
}
