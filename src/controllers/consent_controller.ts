/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import vine from '@vinejs/vine'
import { DateTime } from 'luxon'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../models/oauth_authorization_code.ts'
import { OAuthConsent } from '../models/oauth_consent.ts'
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
   * Retrieve the session from the HTTP context, ensuring
   * session middleware is active.
   */
  #getAuthorizationSession(ctx: HttpContext) {
    const session = (ctx as any).session
    if (!session || typeof session.pull !== 'function') {
      throw new E_INVALID_REQUEST('Session middleware is required for the browser authorization flow')
    }

    return session
  }

  /**
   * Create and store an authorization code, then redirect the user
   * back to the client's redirect_uri with the code and state.
   *
   * The authorization code is stored as a SHA-256 hash in the database.
   * Only the raw (unhashed) value is sent to the client via the redirect.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
   */
  async #issueAuthorizationCode(
    ctx: HttpContext,
    manager: SesameManager,
    options: {
      client: OAuthClient
      userId: string
      scopes: string[]
      redirectUri: string
      codeChallenge?: string
      codeChallengeMethod?: string
      state?: string
    }
  ) {
    const tokenService = new TokenService(manager)
    const raw = tokenService.generateOpaqueToken()
    const hashed = tokenService.hashToken(raw)
    const ttl = manager.parseTtl(manager.config.authorizationCodeTtl)

    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: hashed,
      clientId: options.client.clientId,
      userId: options.userId,
      scopes: options.scopes,
      redirectUri: options.redirectUri,
      codeChallenge: options.codeChallenge ?? null,
      codeChallengeMethod: options.codeChallengeMethod ?? null,
      expiresAt: DateTime.now().plus({ seconds: ttl }),
    })

    const url = new URL(options.redirectUri)
    url.searchParams.set('code', raw)
    if (options.state) url.searchParams.set('state', options.state)
    url.searchParams.set('iss', manager.config.issuer)

    return ctx.response.redirect().toPath(url.toString())
  }

  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const session = this.#getAuthorizationSession(ctx)

    await ctx.auth.check()
    const user = ctx.auth.user as { id: string | number } | undefined
    if (!user) throw new E_INVALID_REQUEST('User must be authenticated')

    const [error, body] = await ConsentController.validator.tryValidate(ctx.request.body())
    if (error) throw new E_INVALID_REQUEST('Missing required parameter: auth_token')

    const accept = ctx.request.body().accept

    const expectedAuthToken = session.pull('sesame.authToken')
    const authorizationRequest = session.pull('sesame.authRequest') as
      | {
          clientId: string
          redirectUri: string
          scopes: string[]
          state: string | null
          codeChallenge: string | null
          codeChallengeMethod: string | null
        }
      | undefined

    if (!expectedAuthToken || expectedAuthToken !== body.auth_token) {
      session.forget(['sesame.authToken', 'sesame.authRequest'])
      throw new E_INVALID_GRANT('Authorization request token mismatch')
    }
    if (!authorizationRequest) throw new E_INVALID_GRANT('Authorization request not found')

    const client = await OAuthClient.query()
      .where('clientId', authorizationRequest.clientId)
      .first()
    if (!client) throw new E_INVALID_CLIENT('Client not found')
    if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')
    if (!client.redirectUris.includes(authorizationRequest.redirectUri)) {
      throw new E_INVALID_REQUEST('Invalid redirect_uri')
    }

    // User denied — redirect back with access_denied error
    if (!accept) {
      const url = new URL(authorizationRequest.redirectUri)
      url.searchParams.set('error', 'access_denied')
      url.searchParams.set('error_description', 'The user denied the authorization request')
      if (authorizationRequest.state) url.searchParams.set('state', authorizationRequest.state)
      url.searchParams.set('iss', manager.config.issuer)

      return ctx.response.redirect().toPath(url.toString())
    }

    // Persist or merge consent so future requests skip the consent screen
    const existingConsent = await OAuthConsent.query()
      .where('clientId', client.clientId)
      .where('userId', String(user.id))
      .first()

    if (existingConsent) {
      const merged = [...new Set([...existingConsent.scopes, ...authorizationRequest.scopes])]
      existingConsent.scopes = merged
      await existingConsent.save()
    } else {
      await OAuthConsent.create({
        id: crypto.randomUUID(),
        clientId: client.clientId,
        userId: String(user.id),
        scopes: authorizationRequest.scopes,
      })
    }

    return this.#issueAuthorizationCode(ctx, manager, {
      client,
      userId: String(user.id),
      scopes: authorizationRequest.scopes,
      redirectUri: authorizationRequest.redirectUri,
      codeChallenge: authorizationRequest.codeChallenge ?? undefined,
      codeChallengeMethod: authorizationRequest.codeChallengeMethod ?? undefined,
      state: authorizationRequest.state ?? undefined,
    })
  }
}
