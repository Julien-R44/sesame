import { DateTime } from 'luxon'
import type { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { buildClientRedirectUrl } from '../client_redirect_url.ts'
import { describeInvalidScopes } from '../invalid_scope_description.ts'
import { IssueAuthorizationCodeAction } from './issue_authorization_code.ts'
import { assertGrantContext } from '../services/grant_service.ts'
import { isRedirectUriAllowed } from '../redirect_uri.ts'
import {
  E_INVALID_CLIENT,
  E_INVALID_GRANT,
  E_INVALID_REQUEST,
  E_INVALID_SCOPE,
} from '../oauth_error.ts'
import type {
  ApproveAuthorizationOptions,
  AuthorizationDecision,
  DenyAuthorizationOptions,
  GrantableScope,
} from '../types.ts'
import type { OAuthClientRecord, OAuthPendingAuthorizationRequestRecord } from '../storage/types.ts'

/**
 * Pending request lookup by hashed token and owner.
 */
interface PendingRequestLookup {
  token: string
  userId: string
}

/**
 * A consumed pending request and the client it belongs to.
 */
interface ConsumedAuthorization {
  pendingRequest: OAuthPendingAuthorizationRequestRecord
  client: OAuthClientRecord
}

/**
 * Completes a pending authorization request with the user's decision.
 *
 * Shared by `SesameManager.approveAuthorization()`/`denyAuthorization()`
 * and the built-in consent controller. Pending requests are consumed
 * atomically so concurrent submissions cannot issue two codes.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
 */
export class CompleteAuthorizationAction {
  /**
   * Resolve the scopes actually granted, defaulting to the requested
   * ones. They are deduplicated, must be a subset of the requested
   * scopes, and are revalidated against the current server config.
   * An explicit empty list is always rejected.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
   */
  #resolveGrantedScopes(options: {
    manager: SesameManager
    requested: string[]
    granted?: string[]
  }): GrantableScope[] {
    if (options.granted?.length === 0) {
      throw new E_INVALID_SCOPE(
        'At least one scope must be granted. Use denyAuthorization() to refuse the request'
      )
    }

    const granted = [...new Set(options.granted ?? options.requested)]

    const requested = new Set(options.requested)
    const notRequested = granted.filter((scope) => !requested.has(scope))
    if (notRequested.length > 0) {
      throw new E_INVALID_SCOPE(`Scopes were not requested: ${notRequested.join(', ')}`)
    }

    const invalidScopes = options.manager.validateScopes(granted)
    if (invalidScopes.length > 0) throw new E_INVALID_SCOPE(describeInvalidScopes(invalidScopes))

    return granted as GrantableScope[]
  }

  /**
   * Read a pending request without consuming it, so invalid
   * input does not burn the user's authorization request.
   */
  async #findPendingRequest(manager: SesameManager, lookup: PendingRequestLookup) {
    const pendingRequest = await manager.store.findPendingAuthorizationRequest({
      ...lookup,
      now: DateTime.now(),
    })
    if (!pendingRequest) throw new E_INVALID_GRANT('Authorization request not found or expired')

    return pendingRequest
  }

  /**
   * Atomically consume the pending request, then make sure its
   * client can still receive an authorization response.
   */
  async #consume(
    manager: SesameManager,
    lookup: PendingRequestLookup
  ): Promise<ConsumedAuthorization> {
    const store = manager.store
    const pendingRequest = await store.consumePendingAuthorizationRequest({
      ...lookup,
      now: DateTime.now(),
    })
    if (!pendingRequest) throw new E_INVALID_GRANT('Authorization request not found or expired')

    const client = await store.findClient(pendingRequest.clientId)
    if (!client) throw new E_INVALID_CLIENT('Client not found')
    if (client.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')

    const registered = client.redirectUris
    if (!isRedirectUriAllowed({ registered, requested: pendingRequest.redirectUri })) {
      throw new E_INVALID_REQUEST('Invalid redirect_uri')
    }

    return { pendingRequest, client }
  }

  /**
   * Hash the raw auth token for store lookups.
   */
  #lookup(manager: SesameManager, options: DenyAuthorizationOptions): PendingRequestLookup {
    const token = new TokenService(manager).hashToken(options.authToken)

    return { token, userId: options.userId }
  }

  /**
   * Approve the request: create a grant for the granted scopes and
   * context, issue its authorization code, and return the client
   * redirect URL.
   */
  async approve(
    manager: SesameManager,
    options: ApproveAuthorizationOptions
  ): Promise<AuthorizationDecision> {
    assertGrantContext(options.context)

    const lookup = this.#lookup(manager, options)
    const pending = await this.#findPendingRequest(manager, lookup)
    const scopes = this.#resolveGrantedScopes({
      manager,
      requested: pending.scopes,
      granted: options.scopes,
    })

    const { pendingRequest, client } = await this.#consume(manager, lookup)

    const code = await new IssueAuthorizationCodeAction().execute(manager, {
      client,
      userId: options.userId,
      scopes,
      redirectUri: pendingRequest.redirectUri,
      codeChallenge: pendingRequest.codeChallenge ?? undefined,
      codeChallengeMethod: pendingRequest.codeChallengeMethod ?? undefined,
      nonce: pendingRequest.nonce ?? undefined,
      context: options.context ?? null,
      resource: pendingRequest.resource ?? null,
    })

    const redirectUrl = buildClientRedirectUrl({
      redirectUri: pendingRequest.redirectUri,
      issuer: manager.config.issuer,
      state: pendingRequest.state,
      params: { code },
    })

    return { redirectUrl, clientId: client.clientId, scopes }
  }

  /**
   * Deny the request and return the client redirect URL carrying
   * `access_denied`. Existing grants are left untouched.
   */
  async deny(
    manager: SesameManager,
    options: DenyAuthorizationOptions
  ): Promise<AuthorizationDecision> {
    const { pendingRequest, client } = await this.#consume(manager, this.#lookup(manager, options))

    const redirectUrl = buildClientRedirectUrl({
      redirectUri: pendingRequest.redirectUri,
      issuer: manager.config.issuer,
      state: pendingRequest.state,
      params: {
        error: 'access_denied',
        error_description: 'The user denied the authorization request',
      },
    })

    return { redirectUrl, clientId: client.clientId, scopes: [] }
  }
}
