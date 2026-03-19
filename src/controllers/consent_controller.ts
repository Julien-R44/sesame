/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import vine from '@vinejs/vine'
import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../models/oauth_authorization_code.ts'
import { OAuthConsent } from '../models/oauth_consent.ts'
import { OAuthPendingAuthorizationRequest } from '../models/oauth_pending_authorization_request.ts'
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
   * Atomically consume a pending authorization request from the
   * database. Uses DELETE-by-PK with affected-row check to prevent
   * concurrent consent submissions from producing two authorization
   * codes.
   */
  async #consumePendingRequest(hashedToken: string, userId: string) {
    const row = await OAuthPendingAuthorizationRequest.query()
      .where('token', hashedToken)
      .where('userId', userId)
      .where('expiresAt', '>', DateTime.now().toSQL()!)
      .first()

    if (!row) return null

    // Atomic delete by PK — only the first concurrent request succeeds
    const deleted = await OAuthPendingAuthorizationRequest.query().where('id', row.id).delete()

    const count = Array.isArray(deleted) ? Number(deleted[0]) : Number(deleted)
    if (count === 0) return null

    return row
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
      nonce?: string
    }
  ) {
    const tokenService = new TokenService(manager)
    const raw = tokenService.generateOpaqueToken()
    const hashed = tokenService.hashToken(raw)
    const ttl = string.seconds.parse(manager.config.authorizationCodeTtl)

    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: hashed,
      clientId: options.client.clientId,
      userId: options.userId,
      scopes: options.scopes,
      redirectUri: options.redirectUri,
      codeChallenge: options.codeChallenge ?? null,
      codeChallengeMethod: options.codeChallengeMethod ?? null,
      nonce: options.nonce ?? null,
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

    await ctx.auth.check()
    const user = ctx.auth.user as { id: string | number } | undefined
    if (!user) throw new E_INVALID_REQUEST('User must be authenticated')

    const [error, body] = await ConsentController.validator.tryValidate(ctx.request.body())
    if (error) throw new E_INVALID_REQUEST('Missing required parameter: auth_token')

    const accept = ctx.request.body().accept

    const tokenService = new TokenService(manager)
    const hashedToken = tokenService.hashToken(body.auth_token)
    const pendingRequest = await this.#consumePendingRequest(hashedToken, String(user.id))

    if (!pendingRequest) throw new E_INVALID_GRANT('Authorization request not found or expired')

    const client = await OAuthClient.query().where('clientId', pendingRequest.clientId).first()
    if (!client) throw new E_INVALID_CLIENT('Client not found')
    if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')
    if (!client.redirectUris.includes(pendingRequest.redirectUri)) {
      throw new E_INVALID_REQUEST('Invalid redirect_uri')
    }

    // User denied — redirect back with access_denied error
    if (!accept) {
      const url = new URL(pendingRequest.redirectUri)
      url.searchParams.set('error', 'access_denied')
      url.searchParams.set('error_description', 'The user denied the authorization request')
      if (pendingRequest.state) url.searchParams.set('state', pendingRequest.state)
      url.searchParams.set('iss', manager.config.issuer)

      return ctx.response.redirect().toPath(url.toString())
    }

    // Persist or merge consent so future requests skip the consent screen
    const existingConsent = await OAuthConsent.query()
      .where('clientId', client.clientId)
      .where('userId', String(user.id))
      .first()

    if (existingConsent) {
      const merged = [...new Set([...existingConsent.scopes, ...pendingRequest.scopes])]
      existingConsent.scopes = merged
      await existingConsent.save()
    } else {
      await OAuthConsent.create({
        id: crypto.randomUUID(),
        clientId: client.clientId,
        userId: String(user.id),
        scopes: pendingRequest.scopes,
      })
    }

    return this.#issueAuthorizationCode(ctx, manager, {
      client,
      userId: String(user.id),
      scopes: pendingRequest.scopes,
      redirectUri: pendingRequest.redirectUri,
      codeChallenge: pendingRequest.codeChallenge ?? undefined,
      codeChallengeMethod: pendingRequest.codeChallengeMethod ?? undefined,
      state: pendingRequest.state ?? undefined,
      nonce: pendingRequest.nonce ?? undefined,
    })
  }
}
