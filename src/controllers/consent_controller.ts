/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import vine from '@vinejs/vine'
import { DateTime } from 'luxon'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import type { OAuthPendingAuthorizationRequestRecord } from '../storage/types.ts'
import { IssueAuthorizationCodeAction } from '../actions/issue_authorization_code.ts'
import { rejectDeletedClient } from '../storage/foreign_key_violation.ts'
import { E_INVALID_CLIENT, E_INVALID_GRANT, E_INVALID_REQUEST } from '../oauth_error.ts'

/**
 * Handles user consent submission for the OAuth authorization flow.
 *
 * When a user approves access, this controller stores or updates
 * the consent record and issues an authorization code via redirect.
 * When the user denies access, it redirects back to the client
 * with an `access_denied` error.
 *
 * Consent records are persisted so that returning users are not
 * prompted again for previously approved scopes.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
 */
export default class ConsentController {
  static validator = vine.create({
    auth_token: vine.string(),
  })

  /**
   * Validate the consent submission, consume the pending
   * request, and redirect back to the client with either
   * an authorization code or an access_denied error.
   */
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)

    await ctx.auth.check()
    const user = ctx.auth.user as { id: string | number } | undefined
    if (!user) throw new E_INVALID_REQUEST('User must be authenticated')

    const [error, body] = await ConsentController.validator.tryValidate(ctx.request.body())
    if (error) throw new E_INVALID_REQUEST('Missing required parameter: auth_token')

    const userId = String(user.id)
    const tokenService = new TokenService(manager)
    const hashedToken = tokenService.hashToken(body.auth_token)
    const pendingRequest = await this.#consumePendingRequest(manager, hashedToken, userId)

    if (!pendingRequest) throw new E_INVALID_GRANT('Authorization request not found or expired')

    const store = manager.store
    const client = await store.findClient(pendingRequest.clientId)
    if (!client) throw new E_INVALID_CLIENT('Client not found')
    if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')
    if (!client.redirectUris.includes(pendingRequest.redirectUri)) {
      throw new E_INVALID_REQUEST('Invalid redirect_uri')
    }

    if (!ctx.request.body().accept) {
      return this.#redirectWithDenied(ctx, manager, pendingRequest)
    }

    await this.#persistConsent(manager, client.clientId, userId, pendingRequest.scopes)

    const action = new IssueAuthorizationCodeAction()
    const code = await action.execute(manager, {
      client,
      userId,
      scopes: pendingRequest.scopes,
      redirectUri: pendingRequest.redirectUri,
      codeChallenge: pendingRequest.codeChallenge ?? undefined,
      codeChallengeMethod: pendingRequest.codeChallengeMethod ?? undefined,
      nonce: pendingRequest.nonce ?? undefined,
    })

    const url = new URL(pendingRequest.redirectUri)
    url.searchParams.set('code', code)
    if (pendingRequest.state) url.searchParams.set('state', pendingRequest.state)
    url.searchParams.set('iss', manager.config.issuer)

    return ctx.response.redirect().toPath(url.toString())
  }

  /**
   * Atomically consume a pending authorization request so concurrent
   * consent submissions cannot produce two authorization codes.
   */
  async #consumePendingRequest(manager: SesameManager, hashedToken: string, userId: string) {
    const store = manager.store
    return store.consumePendingAuthorizationRequest({
      token: hashedToken,
      userId,
      now: DateTime.now(),
    })
  }

  /**
   * Persist or merge consent so future authorization requests
   * for the same client skip the consent screen.
   */
  async #persistConsent(
    manager: SesameManager,
    clientId: string,
    userId: string,
    scopes: string[]
  ) {
    const store = manager.store
    await rejectDeletedClient(() => store.grantConsent({ clientId, userId, scopes }))
  }

  /**
   * Redirect back to the client with an access_denied error
   * when the user denies the authorization request.
   */
  #redirectWithDenied(
    ctx: HttpContext,
    manager: SesameManager,
    pendingRequest: OAuthPendingAuthorizationRequestRecord
  ) {
    const url = new URL(pendingRequest.redirectUri)
    url.searchParams.set('error', 'access_denied')
    url.searchParams.set('error_description', 'The user denied the authorization request')
    if (pendingRequest.state) url.searchParams.set('state', pendingRequest.state)
    url.searchParams.set('iss', manager.config.issuer)

    return ctx.response.redirect().toPath(url.toString())
  }
}
