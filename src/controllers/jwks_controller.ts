import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'

/**
 * Serves the JSON Web Key Set (JWKS) endpoint (RFC 7517 §5).
 *
 * Exposes the server's public RSA key(s) used for JWT access
 * token signature verification. Clients and resource servers
 * fetch this to validate tokens without shared secrets.
 *
 * Responses are cached with a 15-minute `max-age` to reduce
 * key-fetching overhead.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7517#section-5
 */
export default class JwksController {
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const jwks = await manager.keyService.getJwks()

    ctx.response.header('Cache-Control', 'public, max-age=900, stale-while-revalidate=60')

    return jwks
  }
}
