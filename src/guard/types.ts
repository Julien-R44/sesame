import type { HttpContext } from '@adonisjs/core/http'
import type { Exception } from '@adonisjs/core/exceptions'
import type { LucidModel } from '@adonisjs/lucid/types/model'
import { symbols } from '@adonisjs/auth'

/**
 * Guard user adapter between the user provider and the guard.
 */
export type OAuthGuardUser<RealUser> = {
  getId(): string | number | BigInt
  getOriginal(): RealUser
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
 * Options for the Lucid-based OAuth user provider.
 */
export type OAuthLucidUserProviderOptions<Model extends LucidModel> = {
  model: () => Promise<{ default: Model }>
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
