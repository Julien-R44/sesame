/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import vine from '@vinejs/vine'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { E_INVALID_REQUEST } from '../oauth_error.ts'
import type { GrantableScope } from '../types.ts'

/**
 * Handles user consent submission for the OAuth authorization flow.
 *
 * Thin HTTP adapter over `SesameManager.approveAuthorization()` and
 * `denyAuthorization()`. An optional `scope` field (space-delimited
 * string or array) grants a subset of the requested scopes.
 *
 * Each approval creates a grant without context, so returning users
 * are not prompted again for previously approved scopes. The context
 * is never read from the request body: only `approveAuthorization()`
 * called from application code can set it.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
 */
export default class ConsentController {
  static validator = vine.create({
    auth_token: vine.string(),
  })

  /**
   * Parse the optional `scope` field. Accepts a space-delimited
   * string or an array of strings (e.g. repeated form checkboxes).
   */
  #parseScopes(value: unknown): GrantableScope[] | undefined {
    if (value === undefined || value === null) return undefined

    const values = Array.isArray(value) ? value : [value]
    if (!values.every((item) => typeof item === 'string')) {
      throw new E_INVALID_REQUEST('Invalid parameter: scope')
    }

    const scopes = values.flatMap((item: string) => item.split(' ')).filter(Boolean)

    return scopes as GrantableScope[]
  }

  /**
   * Validate the consent submission and redirect back to the
   * client with either an authorization code or an
   * access_denied error.
   */
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)

    await ctx.auth.check()
    const user = ctx.auth.user as { id: string | number } | undefined
    if (!user) throw new E_INVALID_REQUEST('User must be authenticated')

    const [error, body] = await ConsentController.validator.tryValidate(ctx.request.body())
    if (error) throw new E_INVALID_REQUEST('Missing required parameter: auth_token')

    const options = { authToken: body.auth_token, userId: String(user.id) }

    if (!ctx.request.body().accept) {
      const decision = await manager.denyAuthorization(options)
      return ctx.response.redirect().toPath(decision.redirectUrl)
    }

    const scopes = this.#parseScopes(ctx.request.body().scope)
    const decision = await manager.approveAuthorization({ ...options, scopes })

    return ctx.response.redirect().toPath(decision.redirectUrl)
  }
}
