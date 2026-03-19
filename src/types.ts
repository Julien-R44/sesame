import type { HttpContext } from '@adonisjs/core/http'
import type { JWK } from 'jose'
import type { OAuthUserProviderContract } from './guard/types.ts'

/**
 * Augment this interface via module augmentation to enable
 * type-safe scope names across the application.
 *
 * @example
 * ```ts
 * declare module '@julr/sesame/types' {
 *   interface SesameScopes extends InferScopes<typeof sesameConfig> {}
 * }
 * ```
 */
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface SesameScopes {}

/**
 * Resolved scope type. When `SesameScopes` is augmented, narrows
 * to the declared scope keys. Otherwise falls back to `string`.
 */
export type Scope = keyof SesameScopes extends never ? string : keyof SesameScopes & string

/**
 * Extract scope keys from a config object returned by `defineConfig`.
 * Use with `declare module` to propagate type-safe scopes globally.
 */
export type InferScopes<T extends { scopes: Record<string, string> }> = {
  [K in keyof T['scopes'] & string]: true
}

/**
 * Standard OAuth/OIDC scopes that are always valid regardless
 * of server or client scope configuration.
 *
 * These scopes are:
 * - Accepted during scope validation (client and server level)
 * - Advertised in `scopes_supported` of all metadata endpoints
 *   (protected resource, OIDC discovery) so MCP clients know
 *   they can request them
 *
 * - `offline_access`: signals that the client needs a refresh token
 *   (OIDC Core §11). Note: Sesame issues refresh tokens by default
 *   when the `refresh_token` grant is enabled, regardless of whether
 *   the client requests this scope (per RFC 6749 §5.1). This scope
 *   is still advertised for clients that check metadata before
 *   building their authorization request.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 */
export const BUILTIN_SCOPES = new Set(['offline_access'])

/**
 * OIDC-recognized scopes that are accepted by server-level validation
 * without needing to be declared in the config `scopes` map.
 *
 * Unlike `BUILTIN_SCOPES`, these still require explicit client authorization
 * via `ClientService.validateClientScopes()`.
 */
export const OIDC_SCOPES = new Set(['openid', 'profile', 'email'])

/**
 * Protocol-managed claims that must never be overridden by `getOidcClaims()`.
 */
export const RESERVED_OIDC_CLAIMS = new Set([
  'sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti',
  'nonce', 'at_hash', 'auth_time', 'acr', 'azp', 'sid',
])

/**
 * Interface for User models that provide OIDC claims.
 * Implement this on your User model to include custom claims
 * in id_tokens and /userinfo responses.
 *
 * If not implemented, only protocol-level claims (sub, iss, aud, exp, iat)
 * are included.
 */
export interface OidcClaimable {
  getOidcClaims(scopes: Scope[]): Record<string, unknown> | Promise<Record<string, unknown>>
}

/**
 * Supported OAuth 2.1 grant types.
 *
 * - `authorization_code`: RFC 6749 §4.1 — Authorization Code Grant
 * - `refresh_token`: RFC 6749 §6 — Refreshing an Access Token
 * - `client_credentials`: RFC 6749 §4.4 — Client Credentials Grant (M2M)
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 */
export type GrantType = 'authorization_code' | 'refresh_token' | 'client_credentials'

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
   * Access token TTL for the client_credentials grant (M2M).
   * Defaults to `accessTokenTtl`.
   */
  clientCredentialsAccessTokenTtl?: string

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

  /**
   * JWK (JSON Web Key) for signing ID tokens.
   * Must be an RSA private key in JWK format.
   * Required together with `oidcProvider` when OIDC scopes (openid) are used.
   * Passed via env var, parsed at boot, lives in memory.
   */
  jwk?: JWK

  /**
   * User provider used by OIDC flows to resolve the subject for
   * `id_token` emission and `/userinfo`.
   *
   * This is independent from `@adonisjs/auth` guards. The provider is
   * configured once for the authorization server and must be stable for
   * the issuer. Required together with `jwk` to enable OIDC.
   */
  oidcProvider?: OAuthUserProviderContract<unknown>

  /**
   * ID token TTL as a string duration (e.g. '1h', '10m').
   * Defaults to '1h'.
   */
  idTokenTtl?: string
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
  clientCredentialsAccessTokenTtl: string
  refreshTokenTtl: string
  authorizationCodeTtl: string
  authorizationRequestTtl: string
  loginPage: string | ((ctx: HttpContext, params: URLSearchParams) => string)
  consentPage: string | ((ctx: HttpContext, params: URLSearchParams) => string)
  allowDynamicRegistration: boolean
  allowPublicRegistration: boolean
  jwk?: JWK
  oidcProvider?: OAuthUserProviderContract<unknown>
  idTokenTtl: string
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
