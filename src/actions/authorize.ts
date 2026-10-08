import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
import { describeInvalidScopes } from '../invalid_scope_description.ts'
import { parsePrompt } from '../prompt.ts'
import { ClientService } from '../services/client_service.ts'
import { TokenService } from '../services/token_service.ts'
import type { OAuthClientRecord } from '../storage/types.ts'
import { IssueAuthorizationCodeAction } from './issue_authorization_code.ts'
import { rejectDeletedClient } from '../storage/foreign_key_violation.ts'
import { isRedirectUriAllowed } from '../redirect_uri.ts'
import { ClientIdMetadataDocumentService } from '../services/client_id_metadata_document_service.ts'
import { ClientMetadataDocumentFetcher } from '../client_id_metadata_documents/fetcher.ts'
import {
  assertClientIdMetadataDocumentsEnabled,
  isClientIdMetadataDocumentUrl,
} from '../client_id_metadata_documents/client_id_url.ts'
import {
  E_INVALID_CLIENT,
  E_INVALID_REQUEST,
  E_UNSUPPORTED_RESPONSE_TYPE,
  OAuthError,
} from '../oauth_error.ts'

export interface AuthorizeInput {
  clientId: string
  responseType: string
  redirectUri: string
  scope?: string
  state?: string
  codeChallenge?: string
  codeChallengeMethod?: string
  nonce?: string
  prompt?: string
  userId?: string

  /**
   * Raw `resource` parameter (RFC 8707). A string, or an array when repeated.
   */
  resource?: unknown
}

export type AuthorizeResult =
  | { type: 'redirect_error'; error: string; description: string }
  | { type: 'login_required' }
  | { type: 'consent_required'; authToken: string; scopes: string[]; resource: string | null }
  | { type: 'authorized'; code: string }

type RedirectError = AuthorizeResult & { type: 'redirect_error' }

/**
 * Inputs needed to decide between issuing a code and asking for consent.
 */
interface ResolveConsentOptions {
  manager: SesameManager
  input: ValidatedAuthorizeInput
  client: OAuthClientRecord
  scopes: string[]
  prompts: Set<string>
}

/**
 * Authorization request validated up to the consent decision.
 */
type ValidatedAuthorizeInput = AuthorizeInput & { userId: string; resource: string | null }

/**
 * Handles the OAuth 2.0 authorization request business logic.
 *
 * Validates the client, scopes, PKCE, and `prompt` parameters,
 * checks existing consent, and either issues an authorization code
 * or signals that login/consent is required. Only `prompt=none`
 * and `prompt=consent` change the flow; other values are ignored.
 *
 * Errors before redirect_uri validation are thrown as exceptions.
 * Errors after are returned as `redirect_error` results so the
 * controller can redirect back to the client per spec.
 */
export class AuthorizeAction {
  #fetcher: ClientMetadataDocumentFetcher

  constructor(options?: { fetcher?: ClientMetadataDocumentFetcher }) {
    this.#fetcher = options?.fetcher ?? new ClientMetadataDocumentFetcher()
  }

  /**
   * Find a registered client, or resolve a `client_id` URL through its
   * Client ID Metadata Document. Resolved clients are only persisted once
   * the user is authenticated.
   */
  async #findClient(manager: SesameManager, input: AuthorizeInput) {
    assertClientIdMetadataDocumentsEnabled({ clientId: input.clientId, config: manager.config })

    if (!isClientIdMetadataDocumentUrl(input.clientId)) {
      return manager.store.findClient(input.clientId)
    }

    const service = new ClientIdMetadataDocumentService({ manager, fetcher: this.#fetcher })

    return service.resolve({ clientId: input.clientId, persist: !!input.userId })
  }

  /**
   * Process an authorization request. Returns a discriminated
   * union that the controller interprets as the appropriate
   * HTTP redirect.
   */
  async execute(manager: SesameManager, input: AuthorizeInput): Promise<AuthorizeResult> {
    if (input.responseType !== 'code') {
      throw new E_UNSUPPORTED_RESPONSE_TYPE('Only "code" is supported')
    }

    const client = await this.#findClient(manager, input)
    if (!client) throw new E_INVALID_CLIENT('Client not found')
    if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')

    if (!isRedirectUriAllowed({ registered: client.redirectUris, requested: input.redirectUri })) {
      throw new E_INVALID_REQUEST('Invalid redirect_uri')
    }

    if (!client.grantTypes.includes('authorization_code')) {
      return {
        type: 'redirect_error',
        error: 'unauthorized_client',
        description: 'Client is not allowed to use the authorization_code grant',
      }
    }

    const resolved = this.#resolveResource(manager, input.resource)
    if ('type' in resolved) return resolved

    const requestedScopes = [
      ...new Set(input.scope ? input.scope.split(' ') : manager.config.defaultScopes),
    ]

    const scopeError = this.#validateScopes(manager, requestedScopes, client)
    if (scopeError) return scopeError

    const pkceError = this.#validatePkce(input)
    if (pkceError) return pkceError

    const prompts = parsePrompt(input.prompt)
    const promptError = this.#validatePrompt(prompts)
    if (promptError) return promptError

    if (!input.userId) return this.#requireLogin(prompts)

    return this.#resolveConsent({
      manager,
      input: { ...input, userId: input.userId, resource: resolved.resource },
      client,
      scopes: requestedScopes,
      prompts,
    })
  }

  /**
   * Resolve the requested resource (RFC 8707) to a registered resource.
   * Returns an `invalid_target` redirect error for malformed, repeated,
   * or foreign resources.
   */
  #resolveResource(
    manager: SesameManager,
    value: unknown
  ): { resource: string | null } | RedirectError {
    try {
      return { resource: manager.resolveResource(value) }
    } catch (err) {
      if (!(err instanceof OAuthError)) throw err

      return { type: 'redirect_error', error: err.oauthCode, description: err.message }
    }
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
   * `prompt=none` cannot be combined with any other value.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
   */
  #validatePrompt(prompts: Set<string>): RedirectError | null {
    if (!prompts.has('none') || prompts.size === 1) return null

    return {
      type: 'redirect_error',
      error: 'invalid_request',
      description: 'prompt=none cannot be combined with other prompt values',
    }
  }

  /**
   * Send unauthenticated users to the login page, unless the
   * client asked for no user interaction with `prompt=none`.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthError
   */
  #requireLogin(prompts: Set<string>): AuthorizeResult {
    if (!prompts.has('none')) return { type: 'login_required' }

    return {
      type: 'redirect_error',
      error: 'login_required',
      description: 'The user must be authenticated',
    }
  }

  /**
   * Check whether the user's active grants without context already
   * cover every requested scope. Grants with a context never skip the
   * consent page: the application must pick the context again.
   */
  async #hasConsent(
    manager: SesameManager,
    options: { clientId: string; userId: string; scopes: string[] }
  ): Promise<boolean> {
    const grants = await manager.store.listGrants({
      userId: options.userId,
      clientId: options.clientId,
      activeAt: DateTime.now(),
    })
    const consentable = grants.filter((grant) => grant.context === null)
    if (consentable.length === 0) return false

    const consentedSet = new Set(consentable.flatMap((grant) => grant.scopes))

    return options.scopes.every((scope) => consentedSet.has(scope))
  }

  /**
   * Issue the code directly when a stored consent covers the
   * requested scopes and `prompt=consent` was not sent. Otherwise,
   * create a pending authorization request for the consent page,
   * or fail with `consent_required` under `prompt=none`.
   */
  async #resolveConsent(options: ResolveConsentOptions): Promise<AuthorizeResult> {
    const consented =
      !options.prompts.has('consent') &&
      (await this.#hasConsent(options.manager, {
        clientId: options.client.clientId,
        userId: options.input.userId,
        scopes: options.scopes,
      }))

    if (consented) {
      const action = new IssueAuthorizationCodeAction()
      const code = await action.execute(options.manager, {
        client: options.client,
        userId: options.input.userId,
        scopes: options.scopes,
        redirectUri: options.input.redirectUri,
        codeChallenge: options.input.codeChallenge,
        codeChallengeMethod: options.input.codeChallengeMethod,
        nonce: options.input.nonce,
        resource: options.input.resource,
      })

      return { type: 'authorized', code }
    }

    if (options.prompts.has('none')) {
      return {
        type: 'redirect_error',
        error: 'consent_required',
        description: 'The user must consent to the requested scopes',
      }
    }

    const authToken = await this.#createPendingRequest(
      options.manager,
      options.input,
      options.client.clientId,
      options.scopes
    )

    return {
      type: 'consent_required',
      authToken,
      scopes: options.scopes,
      resource: options.input.resource,
    }
  }

  /**
   * Store the authorization request in the database so it can
   * be consumed atomically by the consent controller.
   */
  async #createPendingRequest(
    manager: SesameManager,
    input: ValidatedAuthorizeInput,
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
        resource: input.resource,
        expiresAt: DateTime.now().plus({ seconds: ttl }),
      })
    )

    return rawToken
  }
}
