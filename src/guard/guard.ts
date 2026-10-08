import { DateTime } from 'luxon'
import type { HttpContext } from '@adonisjs/core/http'
import type { EmitterLike } from '@adonisjs/core/types/events'
import { symbols } from '@adonisjs/auth'
import { errors } from '@adonisjs/auth'
import type { AuthClientResponse, GuardContract } from '@adonisjs/auth/types'
import type { Scope } from '../types.ts'
import type { SesameManager } from '../sesame_manager.ts'
import { TokenService } from '../services/token_service.ts'
import { buildBearerChallenge, mergeScopes } from '../bearer_challenge.ts'
import { E_INSUFFICIENT_SCOPE } from '../oauth_error.ts'
import type {
  OAuthAuthenticateOptions,
  OAuthGuardEvents,
  OAuthUserProviderContract,
} from './types.ts'

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

  scopes: Scope[] = []
  clientId?: string

  #name: string
  #ctx: HttpContext
  #emitter: EmitterLike<OAuthGuardEvents<UserProvider[typeof symbols.PROVIDER_REAL_USER]>>
  #userProvider: UserProvider
  #manager: SesameManager
  #resource?: string
  #challengeScopes: Scope[] = []

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

  /**
   * Scopes advertised in the 401 challenge: the resource scopes merged with
   * the route scopes. A route accepting any scope adds nothing when the
   * resource scopes already satisfy it.
   */
  #resolveChallengeScopes(options?: OAuthAuthenticateOptions): Scope[] {
    const resourceScopes = this.#manager.getProtectedResourceScopes(this.#resource)
    const routeScopes = options?.scopes ?? []

    const satisfiedByResource = routeScopes.some((scope) => resourceScopes.includes(scope))
    if (options?.match === 'any' && satisfiedByResource) return resourceScopes

    return mergeScopes(resourceScopes, routeScopes) as Scope[]
  }

  #authenticationFailed(description: string, options?: { includeError?: boolean }) {
    const header = buildBearerChallenge({
      resourceMetadata: this.resourceMetadataUrl,
      scopes: this.#challengeScopes,
      error: options?.includeError ? 'invalid_token' : undefined,
      errorDescription: options?.includeError ? description : undefined,
    })

    this.#ctx.response.header('WWW-Authenticate', header)

    const error = new errors.E_UNAUTHORIZED_ACCESS(description, {
      guardDriverName: this.driverName,
    })

    void this.#emitter.emit('oauth_auth:authentication_failed', {
      ctx: this.#ctx,
      guardName: this.#name,
      error,
    })

    return error
  }

  /**
   * Protected resource metadata URL (RFC 9728) of the resource
   * protected by this guard.
   */
  get resourceMetadataUrl(): string {
    return `${this.#manager.config.issuer}/.well-known/oauth-protected-resource${this.#resource ?? ''}`
  }

  getUserOrFail(): UserProvider[typeof symbols.PROVIDER_REAL_USER] {
    if (!this.user) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    return this.user
  }

  /**
   * Authenticate the request with its Bearer token. Scopes passed in
   * `options` are advertised in the 401 challenge on failure.
   */
  async authenticate(
    options?: OAuthAuthenticateOptions
  ): Promise<UserProvider[typeof symbols.PROVIDER_REAL_USER]> {
    if (this.authenticationAttempted) return this.getUserOrFail()

    this.authenticationAttempted = true
    this.#challengeScopes = this.#resolveChallengeScopes(options)
    void this.#emitter.emit('oauth_auth:authentication_attempted', {
      ctx: this.#ctx,
      guardName: this.#name,
    })

    const rawToken = this.#extractBearerToken()
    const tokenService = new TokenService(this.#manager)

    const includeError = { includeError: true } as const
    const hashed = tokenService.hashToken(rawToken)
    const store = this.#manager.store
    const record = await store.findAccessToken({ hash: hashed })
    if (!record) throw this.#authenticationFailed('Invalid or expired token', includeError)
    if (record.revokedAt) throw this.#authenticationFailed('Invalid or expired token', includeError)
    if (record.expiresAt.toJSDate() < new Date())
      throw this.#authenticationFailed('Invalid or expired token', includeError)

    if (!record.userId) throw this.#authenticationFailed('Invalid or expired token', includeError)

    const providerUser = await this.#userProvider.findById(record.userId)
    if (!providerUser) throw this.#authenticationFailed('Invalid or expired token', includeError)

    this.isAuthenticated = true
    this.user = providerUser.getOriginal() as UserProvider[typeof symbols.PROVIDER_REAL_USER]
    this.scopes = record.scopes as Scope[]
    this.clientId = record.clientId

    void this.#emitter.emit('oauth_auth:authentication_succeeded', {
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

  hasScope(...scopes: Scope[]): boolean {
    return scopes.every((s) => this.scopes.includes(s))
  }

  hasAnyScope(...scopes: Scope[]): boolean {
    return scopes.some((s) => this.scopes.includes(s))
  }

  /**
   * Build the 403 error for a token missing required scopes. The challenge
   * lists the granted scopes plus the required ones, so a client stepping
   * up its authorization does not lose what it already has.
   */
  insufficientScopeError(requiredScopes: Scope[]) {
    const error = new E_INSUFFICIENT_SCOPE(requiredScopes)
    error.challengeScopes = mergeScopes(this.scopes, requiredScopes)
    error.resourceMetadata = this.resourceMetadataUrl

    return error
  }

  /**
   * Used internally by Japa's `loginAs` helper during testing.
   * Creates a test client and access token in DB, then returns
   * the authorization headers for the test HTTP client to use.
   *
   * @see https://docs.adonisjs.com/guides/auth/custom-auth-guard#implementing-the-guard
   */
  async authenticateAsClient(
    user: UserProvider[typeof symbols.PROVIDER_REAL_USER]
  ): Promise<AuthClientResponse> {
    const tokenService = new TokenService(this.#manager)
    const defaultScopes = this.#manager.config.defaultScopes

    const store = this.#manager.store
    let testClient = await store.findClient('__test_client__')
    if (!testClient) {
      testClient = await store.createClient({
        id: crypto.randomUUID(),
        clientId: '__test_client__',
        clientSecret: null,
        name: 'Test Client',
        redirectUris: ['http://localhost/callback'],
        grantTypes: ['authorization_code'],
        scopes: defaultScopes,
        isPublic: true,
        isDisabled: false,
        requirePkce: false,
        type: 'public',
        metadata: null,
        userId: null,
      })
    }

    const userId = String((user as any).id ?? (user as any).getId?.() ?? 'test-user')
    const { raw, hash, expiresAt } = tokenService.createAccessToken()

    await store.createAccessToken({
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
