import type { HttpContext } from '@adonisjs/core/http'

/**
 * Supported grant types for v1 (MCP-focused).
 *
 * - `authorization_code`: RFC 6749 §4.1 — Authorization Code Grant
 * - `refresh_token`: RFC 6749 §6 — Refreshing an Access Token
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 */
export type GrantType = 'authorization_code' | 'refresh_token'

/**
 * User-facing configuration interface for Sésame.
 *
 * Provides all options needed to set up the OAuth 2.1 authorization
 * server, including issuer identity, scopes, token lifetimes, and
 * page redirects for the authorization flow.
 */
export interface SesameConfig {
  /**
   * The issuer URL (must be HTTPS in production).
   * Used in JWT `iss` claim and discovery metadata.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc8414#section-2
   */
  issuer: string

  /**
   * Available scopes as a record of scope name to description.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
   */
  scopes?: Record<string, string>

  /**
   * Default scopes assigned when none are requested
   * in the authorization request.
   */
  defaultScopes?: string[]

  /**
   * Enabled grant types.
   * Defaults to `['authorization_code', 'refresh_token']`.
   */
  grantTypes?: GrantType[]

  /**
   * Access token TTL as a string duration (e.g. '1h', '30m').
   * Defaults to '1h'.
   */
  accessTokenTtl?: string

  /**
   * Refresh token TTL as a string duration.
   * Defaults to '30d'.
   */
  refreshTokenTtl?: string

  /**
   * Authorization code TTL as a string duration.
   * Defaults to '10m'.
   */
  authorizationCodeTtl?: string

  /**
   * Pending authorization request TTL as a string duration.
   * Controls how long a user has to approve/deny a consent screen.
   * Defaults to `authorizationCodeTtl` (typically '10m').
   */
  authorizationRequestTtl?: string

  /**
   * Route or URL where unauthenticated users are redirected
   * to log in during the authorization flow. Can be a string
   * path or a function receiving the HttpContext and authorize
   * query parameters.
   */
  loginPage: string | ((ctx: HttpContext, params: URLSearchParams) => string)

  /**
   * Route or URL where users are redirected to approve/deny
   * client access during the authorization flow. Can be a string
   * path or a function receiving the HttpContext and authorize
   * query parameters.
   */
  consentPage: string | ((ctx: HttpContext, params: URLSearchParams) => string)

  /**
   * Allow dynamic client registration.
   * Defaults to `false`.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc7591
   */
  allowDynamicRegistration?: boolean

  /**
   * Allow unauthenticated client registration (needed for MCP).
   * Defaults to `false`.
   */
  allowPublicRegistration?: boolean
}

/**
 * Fully resolved configuration with defaults applied.
 * Created by `defineConfig()` from user-supplied `SesameConfig`.
 */
export interface ResolvedSesameConfig {
  issuer: string
  scopes: Record<string, string>
  defaultScopes: string[]
  grantTypes: GrantType[]
  accessTokenTtl: string
  refreshTokenTtl: string
  authorizationCodeTtl: string
  authorizationRequestTtl: string
  loginPage: string | ((ctx: HttpContext, params: URLSearchParams) => string)
  consentPage: string | ((ctx: HttpContext, params: URLSearchParams) => string)
  allowDynamicRegistration: boolean
  allowPublicRegistration: boolean
}

/**
 * OAuth 2.0 Authorization Server Metadata as defined by RFC 8414.
 *
 * Returned by the `/.well-known/oauth-authorization-server` endpoint
 * to allow clients to discover server capabilities.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414#section-2
 */
export interface AuthServerMetadata {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  registration_endpoint?: string
  introspection_endpoint?: string
  revocation_endpoint?: string
  response_types_supported: string[]
  response_modes_supported: string[]
  grant_types_supported: string[]
  token_endpoint_auth_methods_supported: string[]
  introspection_endpoint_auth_methods_supported?: string[]
  revocation_endpoint_auth_methods_supported?: string[]
  code_challenge_methods_supported: string[]
  authorization_response_iss_parameter_supported: boolean
}

/**
 * OAuth 2.0 Protected Resource Metadata as defined by RFC 9728.
 *
 * Returned by the `/.well-known/oauth-protected-resource` endpoint.
 * Used by MCP clients to discover which authorization servers
 * protect a given resource.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9728
 */
export interface ResourceServerMetadata {
  resource: string
  authorization_servers: string[]
  scopes_supported?: string[]
  bearer_methods_supported?: string[]
  resource_documentation?: string
}
