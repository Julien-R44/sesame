import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
import { describeInvalidScopes } from '../invalid_scope_description.ts'
import type { OAuthClientRecord } from '../storage/types.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { BUILTIN_SCOPES, OIDC_SCOPES } from '../types.ts'
import { E_INVALID_CLIENT, E_INVALID_SCOPE } from '../oauth_error.ts'

export interface ExchangeClientCredentialsInput {
  client: OAuthClientRecord
  scope?: string
}

/**
 * Handle the Client Credentials Grant (RFC 6749 §4.4).
 *
 * Issues an access token directly to a confidential client
 * for machine-to-machine communication. No refresh token
 * is issued. User-centric OIDC scopes are rejected.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
export class ExchangeClientCredentialsAction {
  /**
   * Validate the client, resolve scopes, and issue an
   * access token for M2M usage.
   */
  async execute(manager: SesameManager, input: ExchangeClientCredentialsInput) {
    const clientService = new ClientService()

    if (input.client.isPublic) {
      throw new E_INVALID_CLIENT('Public clients cannot use the client_credentials grant')
    }

    if (!input.client.grantTypes.includes('client_credentials')) {
      throw new E_INVALID_CLIENT('Client is not allowed to use the client_credentials grant')
    }

    const scopes = this.#resolveScopes(manager, input, clientService)

    if (!input.client.userId) {
      throw new E_INVALID_CLIENT(
        'Client must be associated with a user to use the client_credentials grant'
      )
    }

    const tokenService = new TokenService(manager)
    const ttlSeconds = string.seconds.parse(manager.config.clientCredentialsAccessTokenTtl)
    const { raw: accessTokenRaw, hash: tokenHash } = tokenService.createAccessToken()
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000)

    const store = manager.store
    await store.createAccessToken({
      id: crypto.randomUUID(),
      tokenHash,
      clientId: input.client.clientId,
      userId: input.client.userId,
      scopes,
      expiresAt: DateTime.fromJSDate(expiresAt),
    })

    return {
      access_token: accessTokenRaw,
      token_type: 'Bearer' as const,
      expires_in: ttlSeconds,
      scope: scopes.join(' '),
    }
  }

  /**
   * Resolve and validate scopes. Falls back to the client's
   * non-OIDC scopes when none are requested. Rejects any
   * user-centric OIDC scopes.
   */
  #resolveScopes(
    manager: SesameManager,
    input: ExchangeClientCredentialsInput,
    clientService: ClientService
  ): string[] {
    const requestedScopes: string[] = input.scope
      ? input.scope.split(' ')
      : input.client.scopes.filter(
          (scope: string) => !BUILTIN_SCOPES.has(scope) && !OIDC_SCOPES.has(scope)
        )

    const forbiddenRequested = requestedScopes.filter(
      (scope: string) => BUILTIN_SCOPES.has(scope) || OIDC_SCOPES.has(scope)
    )
    if (forbiddenRequested.length > 0) {
      throw new E_INVALID_SCOPE(
        `Scopes not allowed for client_credentials: ${forbiddenRequested.join(', ')}`
      )
    }

    const invalidScopes = manager.validateScopes(requestedScopes)
    if (invalidScopes.length > 0) {
      throw new E_INVALID_SCOPE(describeInvalidScopes(invalidScopes))
    }

    clientService.validateClientScopes(requestedScopes, input.client.scopes)

    return requestedScopes
  }
}
