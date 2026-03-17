import type { HttpContext } from '@adonisjs/core/http'
import { SesameManager } from '../sesame_manager.ts'
import { E_SERVER_ERROR } from '../oauth_error.ts'
import { BUILTIN_SCOPES, type AuthServerMetadata, type ResourceServerMetadata } from '../types.ts'

type RouterLike = {
  has(routeIdentifier: string): boolean
  makeUrl(name: string, params?: Record<string, any>, opts?: { prefixUrl?: string }): string
}

const DISCOVERY_ROUTE_NAMES = {
  authorization_endpoint: 'sesame.authorize',
  token_endpoint: 'sesame.token',
  registration_endpoint: 'sesame.register',
  introspection_endpoint: 'sesame.introspect',
  revocation_endpoint: 'sesame.revoke',
} as const

/**
 * Serves OAuth 2.0 discovery metadata documents.
 *
 * Exposes three well-known endpoints:
 * - `authServer()` — OAuth Authorization Server Metadata (RFC 8414)
 * - `oidc()` — OpenID Connect Discovery 1.0 (extends authServer metadata)
 * - `protectedResource()` — OAuth Protected Resource Metadata (RFC 9728)
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414
 * @see https://datatracker.ietf.org/doc/html/rfc9728
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */
export default class MetadataController {
  #assertDiscoveryRoutes(
    router: RouterLike,
    options: { includeRegistration: boolean }
  ): asserts router is RouterLike {
    const requiredRoutes: string[] = [
      DISCOVERY_ROUTE_NAMES.authorization_endpoint,
      DISCOVERY_ROUTE_NAMES.token_endpoint,
      DISCOVERY_ROUTE_NAMES.introspection_endpoint,
      DISCOVERY_ROUTE_NAMES.revocation_endpoint,
    ]

    if (options.includeRegistration) {
      requiredRoutes.push(DISCOVERY_ROUTE_NAMES.registration_endpoint)
    }

    const missingRoutes = requiredRoutes.filter((routeName) => !router.has(routeName))
    if (missingRoutes.length > 0) {
      throw new E_SERVER_ERROR(
        `OAuth discovery is misconfigured. Missing named route(s): ${missingRoutes.join(', ')}. Register OAuth routes with sesame.registerRoutes(router) before exposing well-known metadata.`
      )
    }
  }

  /**
   * OAuth 2.0 Authorization Server Metadata (RFC 8414).
   *
   * Returns a JSON document describing the server's endpoints,
   * supported grant types, response types, authentication methods,
   * and PKCE support.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc8414#section-2
   */
  async authServer(ctx: HttpContext): Promise<AuthServerMetadata> {
    const manager = await ctx.containerResolver.make(SesameManager)
    const router = (await ctx.containerResolver.make('router')) as RouterLike
    const issuer = manager.config.issuer
    const prefixUrl = issuer
    this.#assertDiscoveryRoutes(router, {
      includeRegistration: manager.config.allowDynamicRegistration,
    })

    ctx.response.header(
      'Cache-Control',
      'public, max-age=15, stale-while-revalidate=15, stale-if-error=86400'
    )

    return {
      issuer,
      authorization_endpoint: router.makeUrl('sesame.authorize', {}, { prefixUrl }),
      token_endpoint: router.makeUrl('sesame.token', {}, { prefixUrl }),
      registration_endpoint: manager.config.allowDynamicRegistration
        ? router.makeUrl('sesame.register', {}, { prefixUrl })
        : undefined,
      introspection_endpoint: router.makeUrl('sesame.introspect', {}, { prefixUrl }),
      revocation_endpoint: router.makeUrl('sesame.revoke', {}, { prefixUrl }),
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: manager.config.grantTypes,
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      introspection_endpoint_auth_methods_supported: [
        'none',
        'client_secret_basic',
        'client_secret_post',
      ],
      revocation_endpoint_auth_methods_supported: [
        'none',
        'client_secret_basic',
        'client_secret_post',
      ],
      code_challenge_methods_supported: ['S256'],
      authorization_response_iss_parameter_supported: true,
    }
  }

  /**
   * OpenID Connect Discovery 1.0 metadata.
   *
   * Extends the authorization server metadata with OIDC-specific
   * fields like `subject_types_supported` and
   * `id_token_signing_alg_values_supported`.
   *
   * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
   */
  async oidc(ctx: HttpContext) {
    const base = await this.authServer(ctx)

    const manager = await ctx.containerResolver.make(SesameManager)

    return {
      ...base,
      subject_types_supported: ['public'],
      scopes_supported: [...Object.keys(manager.config.scopes), ...BUILTIN_SCOPES],
    }
  }

  /**
   * OAuth 2.0 Protected Resource Metadata (RFC 9728).
   *
   * Returns a JSON document that tells clients which authorization
   * servers protect this resource, which scopes are available, and
   * how to present bearer tokens. Used by MCP clients to discover
   * the authorization server.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9728
   */
  async protectedResource(ctx: HttpContext): Promise<ResourceServerMetadata> {
    const manager = await ctx.containerResolver.make(SesameManager)
    const issuer = manager.config.issuer

    ctx.response.header(
      'Cache-Control',
      'public, max-age=15, stale-while-revalidate=15, stale-if-error=86400'
    )

    return {
      resource: issuer,
      authorization_servers: [issuer],
      scopes_supported: [...Object.keys(manager.config.scopes), ...BUILTIN_SCOPES],
      bearer_methods_supported: ['header'],
    }
  }
}
