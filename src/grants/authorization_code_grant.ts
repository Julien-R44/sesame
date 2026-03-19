import type { HttpContext } from '@adonisjs/core/http'
import type { SesameManager } from '../sesame_manager.ts'
import { ClientService } from '../services/client_service.ts'
import { ExchangeAuthorizationCodeAction } from '../actions/exchange_authorization_code.ts'

/**
 * Thin wrapper that extracts HTTP params and delegates to
 * ExchangeAuthorizationCodeAction. Kept for backward
 * compatibility with existing call sites.
 */
export async function handleAuthorizationCodeGrant(ctx: HttpContext, manager: SesameManager) {
  const clientService = new ClientService()
  const body = ctx.request.body()

  const client = await clientService.authenticateClient({
    authorizationHeader: ctx.request.header('authorization'),
    bodyClientId: body.client_id,
    bodyClientSecret: body.client_secret,
  })

  const action = new ExchangeAuthorizationCodeAction()

  return action.execute(manager, {
    client,
    code: body.code,
    redirectUri: body.redirect_uri,
    codeVerifier: body.code_verifier,
  })
}
