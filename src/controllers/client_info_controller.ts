import type { HttpContext } from '@adonisjs/core/http'
import { OAuthClient } from '../models/oauth_client.ts'
import { E_INVALID_CLIENT, E_INVALID_REQUEST } from '../oauth_error.ts'

/**
 * Returns public information about an OAuth client.
 * Used by the consent page to display the client's name
 * from server-side data rather than query parameters
 * (RFC 6819 §4.4.1.4 — prevent client identity spoofing).
 */
export default class ClientInfoController {
  async handle(ctx: HttpContext) {
    const clientId = ctx.request.qs().client_id
    if (!clientId) throw new E_INVALID_REQUEST('Missing client_id')

    const client = await OAuthClient.query().where('clientId', clientId).first()
    if (!client) throw new E_INVALID_CLIENT('Client not found')

    return { client_id: client.clientId, client_name: client.name }
  }
}
