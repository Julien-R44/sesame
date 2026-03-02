import vine from '@vinejs/vine'
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
  static validator = vine.create({
    client_id: vine.string(),
  })

  async handle(ctx: HttpContext) {
    const [error, query] = await ClientInfoController.validator.tryValidate(ctx.request.qs())
    if (error) throw new E_INVALID_REQUEST('Missing client_id')

    const client = await OAuthClient.query().where('clientId', query.client_id).first()
    if (!client) throw new E_INVALID_CLIENT('Client not found')

    return { client_id: client.clientId, client_name: client.name }
  }
}
