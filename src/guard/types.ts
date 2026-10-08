import type { HttpContext } from '@adonisjs/core/http'
import type { Exception } from '@adonisjs/core/exceptions'
import { symbols } from '@adonisjs/auth'
import type { Scope } from '../types.ts'

/**
 * Guard user adapter between the user provider and the guard.
 */
export type OAuthGuardUser<RealUser> = {
  getId(): string | number | BigInt
  getOriginal(): RealUser
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
  }
  'oauth_auth:authentication_failed': {
    ctx: HttpContext
    guardName: string
    error: Exception
  }
}
