import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
import { describeInvalidScopes } from '../invalid_scope_description.ts'
import { ClientService } from '../services/client_service.ts'
import { TokenService } from '../services/token_service.ts'
import type { OAuthClientRecord } from '../storage/types.ts'
import { IssueAuthorizationCodeAction } from './issue_authorization_code.ts'
import { rejectDeletedClient } from '../storage/foreign_key_violation.ts'
import { E_INVALID_CLIENT, E_INVALID_REQUEST, E_UNSUPPORTED_RESPONSE_TYPE } from '../oauth_error.ts'

export interface AuthorizeInput {
  clientId: string
  responseType: string
  redirectUri: string
  scope?: string
  state?: string
  codeChallenge?: string
  codeChallengeMethod?: string
  nonce?: string
  userId?: string
}

export type AuthorizeResult =
  | { type: 'redirect_error'; error: string; description: string }
  | { type: 'login_required' }
  | { type: 'consent_required'; authToken: string; scopes: string[] }
  | { type: 'authorized'; code: string }

type RedirectError = AuthorizeResult & { type: 'redirect_error' }

/**
 * Handles the OAuth 2.0 authorization request business logic.
 *
 * Validates the client, scopes, and PKCE parameters, checks
 * existing consent, and either issues an authorization code
 * or signals that login/consent is required.
 *
 * Errors before redirect_uri validation are thrown as exceptions.
 * Errors after are returned as `redirect_error` results so the
 * controller can redirect back to the client per spec.
 */
export class AuthorizeAction {
  /**
   * Process an authorization request. Returns a discriminated
   * union that the controller interprets as the appropriate
   * HTTP redirect.
   */
  async execute(manager: SesameManager, input: AuthorizeInput): Promise<AuthorizeResult> {
    if (input.responseType !== 'code') {
      throw new E_UNSUPPORTED_RESPONSE_TYPE('Only "code" is supported')
    }

    const store = manager.store
    const client = await store.findClient(input.clientId)
    if (!client) throw new E_INVALID_CLIENT('Client not found')
    if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')

    if (!client.redirectUris.includes(input.redirectUri)) {
      throw new E_INVALID_REQUEST('Invalid redirect_uri')
    }

    if (!client.grantTypes.includes('authorization_code')) {
      return {
        type: 'redirect_error',
        error: 'unauthorized_client',
        description: 'Client is not allowed to use the authorization_code grant',
      }
    }

    const requestedScopes = input.scope ? input.scope.split(' ') : manager.config.defaultScopes

    const scopeError = this.#validateScopes(manager, requestedScopes, client)
    if (scopeError) return scopeError

    const pkceError = this.#validatePkce(input)
    if (pkceError) return pkceError

    if (!input.userId) return { type: 'login_required' }

    return this.#resolveConsent(
      manager,
      { ...input, userId: input.userId },
      client,
      requestedScopes
    )
  }

  /**
   * Validate requested scopes against server config, client
   * permissions, and OIDC availability.
   */
  #validateScopes(
    manager: SesameManager,
    scopes: string[],
    client: OAuthClientRecord
  ): RedirectError | null {
    const invalidScopes = manager.validateScopes(scopes)
    if (invalidScopes.length > 0) {
      return {
        type: 'redirect_error',
        error: 'invalid_scope',
        description: describeInvalidScopes(invalidScopes),
      }
    }

    const clientService = new ClientService()
    try {
      clientService.validateClientScopes(scopes, client.scopes)
    } catch (err: any) {
      return { type: 'redirect_error', error: 'invalid_scope', description: err.message }
    }

    if (manager.usesOidcScopes(scopes) && !manager.isOidcEnabled) {
      return {
        type: 'redirect_error',
        error: 'invalid_scope',
        description:
          'OIDC scopes require OIDC to be configured (set jwk and oidcProvider in config)',
      }
    }

    return null
  }

  /**
   * Ensure PKCE code_challenge is present and uses S256
   * (mandatory per OAuth 2.1).
   */
  #validatePkce(input: AuthorizeInput): RedirectError | null {
    if (!input.codeChallenge) {
      return {
        type: 'redirect_error',
        error: 'invalid_request',
        description: 'PKCE code_challenge is required',
      }
    }

    if (input.codeChallengeMethod !== 'S256') {
      return {
        type: 'redirect_error',
        error: 'invalid_request',
        description: 'Only S256 code_challenge_method is supported',
      }
    }

    return null
  }

  /**
   * Check if the user has already consented to all requested
   * scopes. If so, issue the code directly. Otherwise, create
   * a pending authorization request for the consent page.
   */
  async #resolveConsent(
    manager: SesameManager,
    input: AuthorizeInput & { userId: string },
    client: OAuthClientRecord,
    scopes: string[]
  ): Promise<AuthorizeResult> {
    const store = manager.store
    const existingConsent = await store.findConsent({
      clientId: client.clientId,
      userId: input.userId,
    })

    if (existingConsent) {
      const consentedSet = new Set(existingConsent.scopes)
      if (scopes.every((s: string) => consentedSet.has(s))) {
        const action = new IssueAuthorizationCodeAction()
        const code = await action.execute(manager, {
          client,
          userId: input.userId,
          scopes,
          redirectUri: input.redirectUri,
          codeChallenge: input.codeChallenge,
          codeChallengeMethod: input.codeChallengeMethod,
          nonce: input.nonce,
        })

        return { type: 'authorized', code }
      }
    }

    const authToken = await this.#createPendingRequest(manager, input, client.clientId, scopes)

    return { type: 'consent_required', authToken, scopes }
  }

  /**
   * Store the authorization request in the database so it can
   * be consumed atomically by the consent controller.
   */
  async #createPendingRequest(
    manager: SesameManager,
    input: AuthorizeInput & { userId: string },
    clientId: string,
    scopes: string[]
  ): Promise<string> {
    const tokenService = new TokenService(manager)
    const rawToken = tokenService.generateOpaqueToken()
    const ttl = string.seconds.parse(manager.config.authorizationRequestTtl)

    const store = manager.store
    await rejectDeletedClient(() =>
      store.createPendingAuthorizationRequest({
        id: crypto.randomUUID(),
        token: tokenService.hashToken(rawToken),
        userId: input.userId,
        clientId,
        redirectUri: input.redirectUri,
        scopes,
        state: input.state ?? null,
        codeChallenge: input.codeChallenge ?? null,
        codeChallengeMethod: input.codeChallengeMethod ?? null,
        nonce: input.nonce ?? null,
        expiresAt: DateTime.now().plus({ seconds: ttl }),
      })
    )

    return rawToken
  }
}
