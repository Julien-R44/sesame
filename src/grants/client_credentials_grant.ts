import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { HttpContext } from '@adonisjs/core/http'
import type { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthAccessToken } from '../models/oauth_access_token.ts'
import { BUILTIN_SCOPES, OIDC_SCOPES } from '../types.ts'
import { E_INVALID_CLIENT, E_INVALID_SCOPE } from '../oauth_error.ts'

/**
 * Handle the Client Credentials Grant (RFC 6749 §4.4).
 *
 * Issues an access token directly to the client for
 * machine-to-machine (M2M) communication. The client
 * authenticates with its own credentials and receives an
 * access token without an interactive user step.
 *
 * No refresh token is issued (per spec and convention).
 *
 * User-centric OAuth/OIDC scopes (e.g. `offline_access`, `openid`,
 * `profile`, `email`) are rejected since they are meaningless in an
 * M2M context.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
export async function handleClientCredentialsGrant(ctx: HttpContext, manager: SesameManager) {
  const tokenService = new TokenService(manager)
  const clientService = new ClientService()

  const body = ctx.request.body()

  const client = await clientService.authenticateClient({
    authorizationHeader: ctx.request.header('authorization'),
    bodyClientId: body.client_id,
    bodyClientSecret: body.client_secret,
  })

  if (client.isPublic)
    throw new E_INVALID_CLIENT('Public clients cannot use the client_credentials grant')
  if (!client.grantTypes.includes('client_credentials')) {
    throw new E_INVALID_CLIENT('Client is not allowed to use the client_credentials grant')
  }

  // Resolve scopes: use requested scopes or fall back to client's configured scopes
  const requestedScopes: string[] = body.scope
    ? body.scope.split(' ')
    : client.scopes.filter(
        (scope: string) => !BUILTIN_SCOPES.has(scope) && !OIDC_SCOPES.has(scope)
      )

  // Reject user-centric OAuth/OIDC scopes — they are meaningless in M2M
  const forbiddenRequested = requestedScopes.filter(
    (scope: string) => BUILTIN_SCOPES.has(scope) || OIDC_SCOPES.has(scope)
  )
  if (forbiddenRequested.length > 0) {
    throw new E_INVALID_SCOPE(
      `Scopes not allowed for client_credentials: ${forbiddenRequested.join(', ')}`
    )
  }

  // Validate against server scopes
  const invalidScopes = manager.validateScopes(requestedScopes)
  if (invalidScopes.length > 0) {
    throw new E_INVALID_SCOPE(`Invalid scopes: ${invalidScopes.join(', ')}`)
  }

  // Validate against client scopes
  clientService.validateClientScopes(requestedScopes, client.scopes)

  if (!client.userId) {
    throw new E_INVALID_CLIENT(
      'Client must be associated with a user to use the client_credentials grant'
    )
  }

  const ttlSeconds = string.seconds.parse(manager.config.clientCredentialsAccessTokenTtl)
  const { raw: accessTokenRaw, hash: tokenHash } = tokenService.createAccessToken()
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000)

  await OAuthAccessToken.create({
    id: crypto.randomUUID(),
    tokenHash,
    clientId: client.clientId,
    userId: client.userId,
    scopes: requestedScopes,
    expiresAt: DateTime.fromJSDate(expiresAt),
  })

  return {
    access_token: accessTokenRaw,
    token_type: 'Bearer',
    expires_in: ttlSeconds,
    scope: requestedScopes.join(' '),
  }
}
