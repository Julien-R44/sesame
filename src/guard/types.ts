import type { DateTime } from 'luxon'
import type { HttpContext } from '@adonisjs/core/http'
import type { Exception } from '@adonisjs/core/exceptions'
import { symbols } from '@adonisjs/auth'
import type { GrantContext, Scope } from '../types.ts'

/**
 * Guard user adapter between the user provider and the guard.
 */
export type OAuthGuardUser<RealUser> = {
  getId(): string | number | BigInt
  getOriginal(): RealUser
}

/**
 * Access token that authenticated the current request, exposed on
 * `guard.accessToken`. It never contains the token value or its hash.
 */
export interface OAuthGuardAccessToken {
  /**
   * Stable identifier of the access token record, useful for audit logs.
   */
  id: string
  clientId: string
  userId: string
  scopes: Scope[]
  expiresAt: DateTime
  createdAt: DateTime

  /**
   * Grant the token was issued from. Null for client_credentials tokens
   * and tokens issued before grants existed.
   */
  grantId: string | null

  /**
   * Application context stored on the grant, read on every request.
   */
  context: GrantContext | null

  /**
   * Resource indicator (RFC 8707) the token is bound to, or null when unbound.
   */
  resource: string | null
}

/**
 * Options for `OAuthGuard.authenticate()`.
 */
export interface OAuthAuthenticateOptions {
  /**
   * Scopes required by the current route. They are advertised in the
   * `scope` parameter of the 401 challenge, merged with the resource scopes.
   */
  scopes?: Scope[]

  /**
   * Whether the route requires `all` the scopes (default) or `any` of them.
   */
  match?: 'all' | 'any'
}

/**
 * Contract for user providers used by the OAuth guard.
 */
export interface OAuthUserProviderContract<RealUser> {
  [symbols.PROVIDER_REAL_USER]: RealUser
  createUserForGuard(user: RealUser): Promise<OAuthGuardUser<RealUser>>
  findById(identifier: string | number | BigInt): Promise<OAuthGuardUser<RealUser> | null>
}

/**
 * Options of `withGuard('oauth').loginAs(user, options)` in tests, forwarded to
 * `authenticateAsClient`. Defaults to the configured default scopes
 * and no context.
 */
export interface OAuthAuthenticateAsClientOptions {
  scopes?: Scope[]
  context?: GrantContext | null
}

/**
 * Protected-resource options of an OAuth guard.
 */
export interface OAuthGuardOptions {
  /**
   * Path of the protected resource served behind this guard, relative to
   * the issuer (e.g. `/mcp`). It must match a resource registered with
   * `registerProtectedResource()`.
   *
   * When set, tokens bound to another resource (RFC 8707) are rejected.
   * Without it, the guard performs no audience check.
   */
  resource?: string

  /**
   * Also reject tokens that are not bound to any resource, such as tokens
   * issued to clients that do not send the `resource` parameter.
   * Only applies when `resource` is set. Defaults to `false`.
   */
  requireAudience?: boolean
}

/**
 * Events emitted by the OAuth guard during authentication.
 */
export type OAuthGuardEvents<RealUser> = {
  'oauth_auth:authentication_attempted': {
    ctx: HttpContext
    guardName: string
  }
  'oauth_auth:authentication_succeeded': {
    ctx: HttpContext
    guardName: string
    user: RealUser
    accessToken: OAuthGuardAccessToken
  }
  'oauth_auth:authentication_failed': {
    ctx: HttpContext
    guardName: string
    error: Exception
  }
}
