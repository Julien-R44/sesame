import { DateTime } from 'luxon'
import type { HttpContext } from '@adonisjs/core/http'
import type { EmitterLike } from '@adonisjs/core/types/events'
import { symbols } from '@adonisjs/auth'
import { errors } from '@adonisjs/auth'
import type { AuthClientResponse, GuardContract } from '@adonisjs/auth/types'
import type { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { OAuthAccessToken } from '../models/oauth_access_token.ts'
import { OAuthClient } from '../models/oauth_client.ts'
import type { OAuthGuardEvents, OAuthUserProviderContract } from './types.ts'

/**
 * OAuth 2.0 guard for `@adonisjs/auth`.
 *
 * Verifies opaque Bearer tokens against the database,
 * checks revocation and expiry, loads the real User model
 * via the provider, and exposes OAuth-specific data (scopes, clientId).
 */
export class OAuthGuard<
  UserProvider extends OAuthUserProviderContract<unknown>,
> implements GuardContract<UserProvider[typeof symbols.PROVIDER_REAL_USER]> {
  declare [symbols.GUARD_KNOWN_EVENTS]: OAuthGuardEvents<
    UserProvider[typeof symbols.PROVIDER_REAL_USER]
  >

  driverName = 'oauth' as const
  authenticationAttempted = false
  isAuthenticated = false
  user?: UserProvider[typeof symbols.PROVIDER_REAL_USER]

  scopes: string[] = []
  clientId?: string

  #name: string
  #ctx: HttpContext
  #emitter: EmitterLike<OAuthGuardEvents<UserProvider[typeof symbols.PROVIDER_REAL_USER]>>
  #userProvider: UserProvider
  #manager: SesameManager
  #resource?: string

  constructor(
    name: string,
    ctx: HttpContext,
    emitter: EmitterLike<OAuthGuardEvents<UserProvider[typeof symbols.PROVIDER_REAL_USER]>>,
    userProvider: UserProvider,
    manager: SesameManager,
    resource?: string
  ) {
    this.#name = name
    this.#ctx = ctx
    this.#emitter = emitter
    this.#userProvider = userProvider
    this.#manager = manager
    this.#resource = resource
  }

  #extractBearerToken(): string {
    const [type, token] = (this.#ctx.request.header('authorization') ?? '').split(' ')
    if (!type || type.toLowerCase() !== 'bearer' || !token)
      throw this.#authenticationFailed('Missing Bearer token')

    return token
  }

  #authenticationFailed(description: string, options?: { includeError?: boolean }) {
    const suffix = this.#resource ?? ''
    const resourceMetadataUrl = `${this.#manager.config.issuer}/.well-known/oauth-protected-resource${suffix}`

    let header = `Bearer resource_metadata="${resourceMetadataUrl}"`
    if (options?.includeError) {
      header += `, error="invalid_token", error_description="${description}"`
    }

    this.#ctx.response.header('WWW-Authenticate', header)

    const error = new errors.E_UNAUTHORIZED_ACCESS(description, {
      guardDriverName: this.driverName,
    })

    this.#emitter.emit('oauth_auth:authentication_failed', {
      ctx: this.#ctx,
      guardName: this.#name,
      error,
    })

    return error
  }

  getUserOrFail(): UserProvider[typeof symbols.PROVIDER_REAL_USER] {
    if (!this.user) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    return this.user
  }

  async authenticate(): Promise<UserProvider[typeof symbols.PROVIDER_REAL_USER]> {
    if (this.authenticationAttempted) return this.getUserOrFail()

    this.authenticationAttempted = true
    this.#emitter.emit('oauth_auth:authentication_attempted', {
      ctx: this.#ctx,
      guardName: this.#name,
    })

    const rawToken = this.#extractBearerToken()
    const tokenService = new TokenService(this.#manager)

    const includeError = { includeError: true } as const
    const hashed = tokenService.hashToken(rawToken)
    const record = await OAuthAccessToken.query().where('tokenHash', hashed).first()
    if (!record) throw this.#authenticationFailed('Invalid or expired token', includeError)
    if (record.revokedAt) throw this.#authenticationFailed('Token has been revoked', includeError)
    if (record.expiresAt.toJSDate() < new Date())
      throw this.#authenticationFailed('Invalid or expired token', includeError)

    if (!record.userId)
      throw this.#authenticationFailed('M2M tokens are not supported', includeError)

    const providerUser = await this.#userProvider.findById(record.userId)
    if (!providerUser) throw this.#authenticationFailed('User not found', includeError)

    this.isAuthenticated = true
    this.user = providerUser.getOriginal() as UserProvider[typeof symbols.PROVIDER_REAL_USER]
    this.scopes = record.scopes
    this.clientId = record.clientId

    this.#emitter.emit('oauth_auth:authentication_succeeded', {
      ctx: this.#ctx,
      guardName: this.#name,
      user: this.user,
    })

    return this.user
  }

  async check(): Promise<boolean> {
    try {
      await this.authenticate()
      return true
    } catch (error) {
      if (error instanceof errors.E_UNAUTHORIZED_ACCESS) return false
      throw error
    }
  }

  hasScope(...scopes: string[]): boolean {
    return scopes.every((s) => this.scopes.includes(s))
  }

  hasAnyScope(...scopes: string[]): boolean {
    return scopes.some((s) => this.scopes.includes(s))
  }

  async authenticateAsClient(
    user: UserProvider[typeof symbols.PROVIDER_REAL_USER]
  ): Promise<AuthClientResponse> {
    const tokenService = new TokenService(this.#manager)
    const defaultScopes = this.#manager.config.defaultScopes

    const testClient = await OAuthClient.firstOrCreate(
      { clientId: '__test_client__' },
      {
        id: crypto.randomUUID(),
        clientId: '__test_client__',
        name: 'Test Client',
        redirectUris: ['http://localhost/callback'],
        grantTypes: ['authorization_code'],
        scopes: defaultScopes,
        isPublic: true,
        requirePkce: false,
      }
    )

    const userId = String((user as any).id ?? (user as any).getId?.() ?? 'test-user')
    const { raw, hash, expiresAt } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: testClient.clientId,
      userId,
      scopes: defaultScopes,
      expiresAt: DateTime.fromJSDate(expiresAt),
    })

    return { headers: { authorization: `Bearer ${raw}` } }
  }
}
