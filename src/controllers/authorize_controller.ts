/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import vine from '@vinejs/vine'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { AuthorizeAction } from '../actions/authorize.ts'
import { buildClientRedirectUrl, type ClientRedirectUrlOptions } from '../client_redirect_url.ts'
import { E_INVALID_REQUEST } from '../oauth_error.ts'

/**
 * Handles the OAuth 2.0 Authorization Endpoint (RFC 6749 §3.1).
 *
 * Validates HTTP parameters, delegates business logic to
 * AuthorizeAction, and interprets the result as redirects.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
 */
export default class AuthorizeController {
  static validator = vine.create({
    client_id: vine.string(),
    response_type: vine.string(),
    redirect_uri: vine.string(),
    scope: vine.string().optional(),
    state: vine.string().optional(),
    code_challenge: vine.string().optional(),
    code_challenge_method: vine.string().optional(),
    nonce: vine.string().optional(),
    prompt: vine.string().optional(),
  })

  /**
   * Validate the authorization request query params, run the
   * authorize action, and redirect based on the result.
   */
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)

    const [error, query] = await AuthorizeController.validator.tryValidate(ctx.request.qs())
    if (error) throw new E_INVALID_REQUEST('Invalid authorization request parameters')

    await ctx.auth.check()
    const user = ctx.auth.user as { id: string | number } | undefined

    const action = new AuthorizeAction()
    const result = await action.execute(manager, {
      clientId: query.client_id,
      responseType: query.response_type,
      redirectUri: query.redirect_uri,
      scope: query.scope,
      state: query.state,
      codeChallenge: query.code_challenge,
      codeChallengeMethod: query.code_challenge_method,
      nonce: query.nonce,
      prompt: query.prompt,
      userId: user ? String(user.id) : undefined,
    })

    if (result.type === 'redirect_error') {
      return this.#redirectToClient(ctx, {
        issuer: manager.config.issuer,
        redirectUri: query.redirect_uri,
        state: query.state,
        params: { error: result.error, error_description: result.description },
      })
    }

    if (result.type === 'login_required') {
      const params = this.#buildDisplayParams(ctx)
      const url = this.#resolvePageUrl(manager.config.loginPage, ctx, params)
      return ctx.response.redirect().toPath(url)
    }

    if (result.type === 'consent_required') {
      const params = this.#buildDisplayParams(ctx)
      params.set('auth_token', result.authToken)
      params.set('scope', result.scopes.join(' '))
      const url = this.#resolvePageUrl(manager.config.consentPage, ctx, params)
      return ctx.response.redirect().toPath(url)
    }

    return this.#redirectToClient(ctx, {
      issuer: manager.config.issuer,
      redirectUri: query.redirect_uri,
      state: query.state,
      params: { code: result.code },
    })
  }

  /**
   * Build a redirect URL with OAuth params, state, and issuer,
   * then redirect the user agent to the client's redirect_uri.
   */
  #redirectToClient(ctx: HttpContext, options: ClientRedirectUrlOptions) {
    return ctx.response.redirect().toPath(buildClientRedirectUrl(options))
  }

  /**
   * Forward original authorize query params so the
   * login/consent page can display them.
   */
  #buildDisplayParams(ctx: HttpContext): URLSearchParams {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(ctx.request.qs())) {
      if (key === 'auth_token' || value == null) continue
      params.set(key, String(value))
    }

    return params
  }

  /**
   * Resolve a login/consent page URL from either a static
   * string path or a dynamic function.
   */
  #resolvePageUrl(
    page: string | ((ctx: HttpContext, params: URLSearchParams) => string),
    ctx: HttpContext,
    params: URLSearchParams
  ) {
    if (typeof page === 'function') return page(ctx, params)
    return `${page}?${params.toString()}`
  }
}
