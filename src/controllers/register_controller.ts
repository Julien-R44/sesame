/// <reference types="@adonisjs/auth/initialize_auth_middleware" />
import vine from '@vinejs/vine'
import type { Infer } from '@vinejs/vine/types'
import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { ClientService } from '../services/client_service.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import {
  E_ACCESS_DENIED,
  E_INVALID_CLIENT_METADATA,
  E_INVALID_REQUEST,
  E_INVALID_SCOPE,
} from '../oauth_error.ts'
import { metadataUriRule, redirectUriRule } from '../rules.ts'

const metadataUrl = vine.string().url({ require_protocol: true }).use(metadataUriRule()).optional()

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
  static validator = vine.create({
    redirect_uris: vine.array(vine.string().use(redirectUriRule())).minLength(1),
    token_endpoint_auth_method: vine
      .string()
      .in(['client_secret_basic', 'client_secret_post', 'none'])
      .optional(),
    grant_types: vine.array(vine.string()).optional(),
    response_types: vine.array(vine.string()).optional(),
    scope: vine.string().optional(),
    client_name: vine.string().maxLength(255).trim().optional(),
    client_uri: metadataUrl,
    logo_uri: metadataUrl,
    tos_uri: metadataUrl,
    policy_uri: metadataUrl,
    contacts: vine.array(vine.string().email()).optional(),
    software_id: vine.string().optional(),
    software_version: vine.string().optional(),
  })

  async handle(ctx: HttpContext) {
    const manager = await ctx.containerResolver.make(SesameManager)

    if (!manager.config.allowDynamicRegistration) {
      throw new E_ACCESS_DENIED('Dynamic client registration is disabled')
    }

    const user = ctx.auth?.user as { id: string | number } | undefined
    if (!user && !manager.config.allowPublicRegistration) {
      throw new E_INVALID_REQUEST('Authentication required for client registration')
    }

    let body: Infer<typeof RegisterController.validator>
    try {
      body = await RegisterController.validator.validate(ctx.request.body())
    } catch {
      throw new E_INVALID_CLIENT_METADATA('Invalid request body')
    }

    const clientService = new ClientService()

    // Apply defaults for optional client metadata fields
    const tokenEndpointAuthMethod = body.token_endpoint_auth_method ?? 'client_secret_basic'
    const isPublic = tokenEndpointAuthMethod === 'none'
    const grantTypes = body.grant_types ?? ['authorization_code']
    const responseTypes = body.response_types ?? ['code']
    const scopes = body.scope ? body.scope.split(' ') : manager.config.defaultScopes

    const invalidScopes = manager.validateScopes(scopes)
    if (invalidScopes.length > 0)
      throw new E_INVALID_SCOPE(`Unknown scopes: ${invalidScopes.join(', ')}`)

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

    const metadata = {
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      response_types: responseTypes,
      ...(body.client_uri ? { client_uri: body.client_uri } : {}),
      ...(body.logo_uri ? { logo_uri: body.logo_uri } : {}),
      ...(body.contacts ? { contacts: body.contacts } : {}),
      ...(body.tos_uri ? { tos_uri: body.tos_uri } : {}),
      ...(body.policy_uri ? { policy_uri: body.policy_uri } : {}),
      ...(body.software_id ? { software_id: body.software_id } : {}),
      ...(body.software_version ? { software_version: body.software_version } : {}),
    }

    // Persist the new client
    await OAuthClient.create({
      id: crypto.randomUUID(),
      clientId,
      clientSecret: hashedSecret,
      name: clientName,
      redirectUris: body.redirect_uris,
      scopes,
      grantTypes,
      isPublic,
      isDisabled: false,
      requirePkce: true,
      type: isPublic ? 'public' : 'confidential',
      metadata,
      userId: user ? String(user.id) : null,
    })

    ctx.response.header('Cache-Control', 'no-store')
    ctx.response.status(201)

    /**
     * RFC 7591 §3.2.1 requires the response to include ALL registered
     * metadata about this client, including fields provisioned by the server.
     */
    return {
      client_id: clientId,
      ...(clientSecret ? { client_secret: clientSecret } : {}),
      client_secret_expires_at: 0,
      client_name: clientName,
      redirect_uris: body.redirect_uris,
      grant_types: grantTypes,
      scope: scopes.join(' '),
      ...metadata,
    }
  }
}
