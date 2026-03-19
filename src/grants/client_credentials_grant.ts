import type { HttpContext } from '@adonisjs/core/http'
import type { SesameManager } from '../sesame_manager.ts'
import { ClientService } from '../services/client_service.ts'
import { ExchangeClientCredentialsAction } from '../actions/exchange_client_credentials.ts'

/**
 * Thin wrapper that extracts HTTP params and delegates to
 * ExchangeClientCredentialsAction. Kept for backward
 * compatibility with existing call sites.
 */
export async function handleClientCredentialsGrant(ctx: HttpContext, manager: SesameManager) {
  const clientService = new ClientService()
  const body = ctx.request.body()

  const client = await clientService.authenticateClient({
    authorizationHeader: ctx.request.header('authorization'),
    bodyClientId: body.client_id,
    bodyClientSecret: body.client_secret,
  })

  const action = new ExchangeClientCredentialsAction()

  return action.execute(manager, {
    client,
    scope: body.scope,
  })
}
