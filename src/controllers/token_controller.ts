import vine from '@vinejs/vine'
import type { HttpContext } from '@adonisjs/core/http'
import type { OAuthClient } from '../models/oauth_client.ts'
import { SesameManager } from '../sesame_manager.ts'
import { ClientService } from '../services/client_service.ts'
import { ExchangeAuthorizationCodeAction } from '../actions/exchange_authorization_code.ts'
import { ExchangeRefreshTokenAction } from '../actions/exchange_refresh_token.ts'
import { ExchangeClientCredentialsAction } from '../actions/exchange_client_credentials.ts'
import { E_UNSUPPORTED_GRANT_TYPE } from '../oauth_error.ts'

/**
 * Handles the OAuth 2.0 Token Endpoint (RFC 6749 §3.2).
 *
 * Authenticates the client, extracts grant-specific params,
 * and dispatches to the appropriate action. Sets required
 * cache headers on all token responses.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
 */
export default class TokenController {
  static validator = vine.create({
    grant_type: vine.string(),
  })

  /**
   * Validate the grant type, authenticate the client,
   * and dispatch to the appropriate grant action.
   */
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const body = ctx.request.body()

    const [error, validated] = await TokenController.validator.tryValidate(body)
    if (error) throw new E_UNSUPPORTED_GRANT_TYPE('Missing required parameter: grant_type')

    if (!manager.isGrantTypeEnabled(validated.grant_type)) {
      throw new E_UNSUPPORTED_GRANT_TYPE(`Grant type "${validated.grant_type}" is not enabled`)
    }

    const clientService = new ClientService()
    const client = await clientService.authenticateClient({
      authorizationHeader: ctx.request.header('authorization'),
      bodyClientId: body.client_id,
      bodyClientSecret: body.client_secret,
    })

    const result = await this.#dispatchGrant(validated.grant_type, manager, client, body)

    ctx.response.header('Cache-Control', 'no-store')
    ctx.response.header('Pragma', 'no-cache')

    return result
  }

  /**
   * Map each grant type to its action, extracting the
   * relevant params from the request body.
   */
  #dispatchGrant(
    grantType: string,
    manager: SesameManager,
    client: OAuthClient,
    body: Record<string, any>
  ) {
    const handlers: Record<string, () => Promise<any>> = {
      authorization_code: () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: body.code,
          redirectUri: body.redirect_uri,
          codeVerifier: body.code_verifier,
        }),
      refresh_token: () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: body.refresh_token,
          scope: body.scope,
        }),
      client_credentials: () =>
        new ExchangeClientCredentialsAction().execute(manager, {
          client,
          scope: body.scope,
        }),
    }

    const handler = handlers[grantType]
    if (!handler) throw new E_UNSUPPORTED_GRANT_TYPE(`Unsupported grant type: ${grantType}`)

    return handler()
  }
}
