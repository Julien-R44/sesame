/// <reference types="@adonisjs/auth/initialize_auth_middleware" />
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import { E_ACCESS_DENIED, E_INVALID_CLIENT_METADATA, E_INVALID_REQUEST } from '../oauth_error.ts'
import { validateRedirectUri } from '../utils/validate_redirect_uri.ts'

/**
 * Handles the OAuth 2.0 Dynamic Client Registration Endpoint (RFC 7591).
 *
 * Allows clients to register themselves with the authorization server
 * by providing metadata such as `redirect_uris`, `grant_types`, and
 * `token_endpoint_auth_method`. Returns the assigned `client_id` and
 * optionally a `client_secret` for confidential clients.
 *
 * Can be configured to require authentication or allow public
 * registration (useful for MCP where clients self-register).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7591
 */
export default class RegisterController {
  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)

    if (!manager.config.allowDynamicRegistration) {
      throw new E_ACCESS_DENIED('Dynamic client registration is disabled')
    }

    const user = ctx.auth?.user as { id: string | number } | undefined
    if (!user && !manager.config.allowPublicRegistration) {
      throw new E_INVALID_REQUEST('Authentication required for client registration')
    }

    const clientService = new ClientService()
    const body = ctx.request.body()

    // Validate redirect URIs (required per RFC 7591 §2)
    const redirectUris = body.redirect_uris
    if (!redirectUris || !Array.isArray(redirectUris) || redirectUris.length === 0) {
      throw new E_INVALID_CLIENT_METADATA('redirect_uris is required and must be a non-empty array')
    }

    for (const uri of redirectUris) validateRedirectUri(uri)

    // Apply defaults for optional client metadata fields
    const tokenEndpointAuthMethod = body.token_endpoint_auth_method ?? 'client_secret_basic'
    const isPublic = tokenEndpointAuthMethod === 'none'
    const grantTypes = body.grant_types ?? ['authorization_code']
    const responseTypes = body.response_types ?? ['code']
    const scopes = body.scope ? body.scope.split(' ') : manager.config.defaultScopes
    const clientName = body.client_name ?? 'Unnamed Client'

    // Validate requested grant types and response types
    for (const gt of grantTypes) {
      if (!manager.isGrantTypeEnabled(gt)) {
        throw new E_INVALID_CLIENT_METADATA(`Unsupported grant type: ${gt}`)
      }
    }

    if (responseTypes.some((rt: string) => rt !== 'code')) {
      throw new E_INVALID_CLIENT_METADATA('Only "code" response type is supported')
    }

    // Generate credentials (secret only for confidential clients)
    const clientId = clientService.generateClientId()
    const clientSecret = isPublic ? null : clientService.generateClientSecret()
    const hashedSecret = clientSecret ? clientService.hashSecret(clientSecret) : null

    // Persist the new client
    await OAuthClient.create({
      id: crypto.randomUUID(),
      clientId,
      clientSecret: hashedSecret,
      name: clientName,
      redirectUris,
      scopes,
      grantTypes,
      isPublic,
      isDisabled: false,
      requirePkce: true,
      type: isPublic ? 'public' : 'confidential',
      metadata: {
        token_endpoint_auth_method: tokenEndpointAuthMethod,
        response_types: responseTypes,
        ...(body.client_uri ? { client_uri: body.client_uri } : {}),
        ...(body.logo_uri ? { logo_uri: body.logo_uri } : {}),
        ...(body.contacts ? { contacts: body.contacts } : {}),
        ...(body.tos_uri ? { tos_uri: body.tos_uri } : {}),
        ...(body.policy_uri ? { policy_uri: body.policy_uri } : {}),
        ...(body.software_id ? { software_id: body.software_id } : {}),
        ...(body.software_version ? { software_version: body.software_version } : {}),
      },
      userId: user ? String(user.id) : null,
    })

    ctx.response.header('Cache-Control', 'no-store')
    ctx.response.status(201)

    return {
      client_id: clientId,
      ...(clientSecret ? { client_secret: clientSecret } : {}),
      client_secret_expires_at: 0,
      client_name: clientName,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: responseTypes,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      scope: scopes.join(' '),
    }
  }
}
