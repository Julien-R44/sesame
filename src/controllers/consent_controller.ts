/// <reference types="@adonisjs/auth/initialize_auth_middleware" />
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import { OAuthConsent } from '../models/oauth_consent.ts'
import { issueAuthorizationCode } from './authorize_controller.ts'
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
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const session = getAuthorizationSession(ctx)
    const body = ctx.request.body()

    await ctx.auth.check()
    const user = ctx.auth.user as { id: string | number } | undefined
    if (!user) throw new E_INVALID_REQUEST('User must be authenticated')

    const accept = body.accept
    const authToken = body.auth_token

    if (!authToken) throw new E_INVALID_REQUEST('Missing required parameter: auth_token')

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

    if (!expectedAuthToken || expectedAuthToken !== authToken) {
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

    return issueAuthorizationCode(ctx, manager, {
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

function getAuthorizationSession(ctx: HttpContext) {
  const session = (ctx as any).session
  if (!session || typeof session.pull !== 'function') {
    throw new E_INVALID_REQUEST('Session middleware is required for the browser authorization flow')
  }

  return session
}
