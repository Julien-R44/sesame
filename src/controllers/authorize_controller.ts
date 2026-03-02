import { DateTime } from 'luxon'
/// <reference types="@adonisjs/auth/initialize_auth_middleware" />
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../models/oauth_authorization_code.ts'
import { OAuthConsent } from '../models/oauth_consent.ts'
import { E_INVALID_CLIENT, E_INVALID_REQUEST, E_UNSUPPORTED_RESPONSE_TYPE } from '../oauth_error.ts'

/**
 * Handles the OAuth 2.0 Authorization Endpoint (RFC 6749 §3.1).
 *
 * Implements the authorization code flow with PKCE support (RFC 7636).
 * Validates the client, requested scopes, and PKCE parameters, then
 * either redirects the user to the login/consent page or directly
 * issues an authorization code if consent was already granted.
 *
 * The `iss` response parameter is included per RFC 9207 to prevent
 * mix-up attacks.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 * @see https://datatracker.ietf.org/doc/html/rfc9207
 */
export default class AuthorizeController {
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)
    const clientService = new ClientService()
    const query = ctx.request.qs()

    const clientId = query.client_id
    const responseType = query.response_type
    const redirectUri = query.redirect_uri
    const scope = query.scope
    const state = query.state
    const codeChallenge = query.code_challenge
    const codeChallengeMethod = query.code_challenge_method

    // Validate required parameters
    if (!clientId) throw new E_INVALID_REQUEST('Missing required parameter: client_id')
    if (!responseType) throw new E_INVALID_REQUEST('Missing required parameter: response_type')
    if (responseType !== 'code') throw new E_UNSUPPORTED_RESPONSE_TYPE('Only "code" is supported')
    if (!redirectUri) throw new E_INVALID_REQUEST('Missing required parameter: redirect_uri')

    // Lookup and validate the client
    const client = await OAuthClient.query().where('clientId', clientId).first()
    if (!client) throw new E_INVALID_CLIENT('Client not found')
    if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')

    if (!client.redirectUris.includes(redirectUri)) {
      throw new E_INVALID_REQUEST('Invalid redirect_uri')
    }
    if (!client.grantTypes.includes('authorization_code')) {
      return redirectWithError(
        ctx,
        manager,
        redirectUri,
        'unauthorized_client',
        'Client is not allowed to use the authorization_code grant',
        state
      )
    }

    // Validate scopes (errors redirect back to client per spec)
    const requestedScopes = scope ? scope.split(' ') : manager.config.defaultScopes
    const invalidScopes = manager.validateScopes(requestedScopes)
    if (invalidScopes.length > 0) {
      return redirectWithError(
        ctx,
        manager,
        redirectUri,
        'invalid_scope',
        `Invalid scopes: ${invalidScopes.join(', ')}`,
        state
      )
    }
    try {
      clientService.validateClientScopes(requestedScopes, client.scopes)
    } catch (error: any) {
      return redirectWithError(ctx, manager, redirectUri, 'invalid_scope', error.message, state)
    }

    // PKCE is mandatory for all clients (OAuth 2.1)
    if (!codeChallenge) {
      return redirectWithError(
        ctx,
        manager,
        redirectUri,
        'invalid_request',
        'PKCE code_challenge is required',
        state
      )
    }
    if (codeChallengeMethod !== 'S256') {
      return redirectWithError(
        ctx,
        manager,
        redirectUri,
        'invalid_request',
        'Only S256 code_challenge_method is supported',
        state
      )
    }

    // Attempt session authentication before checking user
    await ctx.auth.check()
    const user = ctx.auth.user as { id: string | number } | undefined
    if (!user) {
      const params = new URLSearchParams()
      copyAuthorizeDisplayParams(params, query)
      const loginPage = resolvePageUrl(manager.config.loginPage, ctx, params)

      return ctx.response.redirect().toPath(loginPage)
    }

    // Skip consent screen if all requested scopes are already approved
    const existingConsent = await OAuthConsent.query()
      .where('clientId', client.clientId)
      .where('userId', String(user.id))
      .first()

    if (existingConsent) {
      const consentedSet = new Set(existingConsent.scopes)
      const allCovered = requestedScopes.every((s: string) => consentedSet.has(s))
      if (allCovered) {
        return issueAuthorizationCode(ctx, manager, {
          client,
          userId: String(user.id),
          scopes: requestedScopes,
          redirectUri,
          codeChallenge,
          codeChallengeMethod,
          state,
        })
      }
    }

    // New or expanded scopes — redirect to consent page
    const params = buildAuthorizationRequestParams(ctx, manager, {
      clientId: client.clientId,
      redirectUri,
      scopes: requestedScopes,
      state,
      codeChallenge,
      codeChallengeMethod,
    })
    copyAuthorizeDisplayParams(params, query)
    const consentPage = resolvePageUrl(manager.config.consentPage, ctx, params)

    return ctx.response.redirect().toPath(consentPage)
  }
}

/**
 * Create and store an authorization code, then redirect the user
 * back to the client's `redirect_uri` with the code and state.
 *
 * The authorization code is stored as a SHA-256 hash in the database.
 * Only the raw (unhashed) value is sent to the client via the redirect.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
 */
export async function issueAuthorizationCode(
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

/**
 * Redirect back to the client with an OAuth error response
 * in the query string, as specified by RFC 6749 §4.1.2.1.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
function redirectWithError(
  ctx: HttpContext,
  manager: SesameManager,
  redirectUri: string,
  error: string,
  description: string,
  state?: string
) {
  const url = new URL(redirectUri)
  url.searchParams.set('error', error)
  url.searchParams.set('error_description', description)
  if (state) url.searchParams.set('state', state)
  url.searchParams.set('iss', manager.config.issuer)

  return ctx.response.redirect().toPath(url.toString())
}

function buildAuthorizationRequestParams(
  ctx: HttpContext,
  manager: SesameManager,
  options: {
    clientId: string
    redirectUri: string
    scopes: string[]
    state?: string
    codeChallenge?: string
    codeChallengeMethod?: string
  }
) {
  const tokenService = new TokenService(manager)
  const rawRequestToken = tokenService.generateOpaqueToken()
  const session = getAuthorizationSession(ctx)

  session.put('sesame.authToken', rawRequestToken)
  session.put('sesame.authRequest', {
    clientId: options.clientId,
    redirectUri: options.redirectUri,
    scopes: options.scopes,
    state: options.state ?? null,
    codeChallenge: options.codeChallenge ?? null,
    codeChallengeMethod: options.codeChallengeMethod ?? null,
  })

  const params = new URLSearchParams()
  params.set('auth_token', rawRequestToken)

  return params
}

function copyAuthorizeDisplayParams(params: URLSearchParams, query: Record<string, string>) {
  for (const [key, value] of Object.entries(query)) {
    if (key === 'auth_token') continue
    if (value != null) params.set(key, String(value))
  }
}

function getAuthorizationSession(ctx: HttpContext) {
  const session = (ctx as any).session
  if (!session || typeof session.put !== 'function') {
    throw new E_INVALID_REQUEST('Session middleware is required for the browser authorization flow')
  }

  return session
}

/**
 * Resolve a login/consent page URL from either a static string
 * path or a dynamic function.
 */
function resolvePageUrl(
  page: string | ((ctx: HttpContext, params: URLSearchParams) => string),
  ctx: HttpContext,
  params: URLSearchParams
): string {
  if (typeof page === 'function') return page(ctx, params)
  return `${page}?${params.toString()}`
}
