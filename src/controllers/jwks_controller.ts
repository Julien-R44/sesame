import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'

/**
 * Serves the JSON Web Key Set (JWKS) containing public keys
 * used to verify ID token signatures.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7517
 */
export default class JwksController {
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)

    if (!manager.isOidcEnabled) {
      ctx.response.status(404)
      return { error: 'OIDC is not configured' }
    }

    ctx.response.header('Cache-Control', 'public, max-age=900')
    ctx.response.header('Content-Type', 'application/jwk-set+json')

    return manager.keyService.getPublicJwks()
  }
}
