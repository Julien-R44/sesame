import { DateTime } from 'luxon'
import type { HttpContext, Router } from '@adonisjs/core/http'
import {
  BUILTIN_SCOPES,
  OIDC_SCOPES,
  type ResolvedSesameConfig,
  type ResourceServerMetadata,
  type Scope,
} from './types.ts'
import { KeyService } from './services/key_service.ts'
import { registerOAuthRoutes, registerWellKnownRoutes as registerWellKnown } from './routes.ts'
import { OAuthAccessToken } from './models/oauth_access_token.ts'
import { OAuthRefreshToken } from './models/oauth_refresh_token.ts'
import { OAuthAuthorizationCode } from './models/oauth_authorization_code.ts'
import { OAuthConsent } from './models/oauth_consent.ts'
import { OAuthPendingAuthorizationRequest } from './models/oauth_pending_authorization_request.ts'

export interface PurgeResult {
  accessTokens: number
  refreshTokens: number
  authorizationCodes: number
  pendingRequests: number
}

/**
 * Central manager for the Sésame OAuth 2.1 server.
 *
 * Holds the resolved configuration. Registered as a singleton
 * in the AdonisJS IoC container by `SesameProvider`.
 */
export class SesameManager {
  #config: ResolvedSesameConfig
  #router: Router
  #keyService: KeyService | null

  constructor(config: ResolvedSesameConfig, router: Router) {
    this.#config = config
    this.#router = router
    this.#keyService = config.jwk ? new KeyService(config.jwk) : null
  }

  get config() {
    return this.#config
  }

  get keyService(): KeyService {
    if (!this.#keyService) {
      throw new Error('OIDC requires a JWK. Set the `jwk` option in defineConfig().')
    }

    return this.#keyService
  }

  get isOidcEnabled(): boolean {
    return this.#keyService !== null && this.#config.oidcProvider !== undefined
  }

  /**
   * Load a user by ID using the configured user provider.
   * Returns the original user model instance, or null if not found.
   */
  async findUserById(userId: string): Promise<unknown | null> {
    if (!this.#config.oidcProvider) return null
    const guardUser = await this.#config.oidcProvider.findById(userId)

    return guardUser?.getOriginal() ?? null
  }

  /**
   * Check if a scope is registered in the server configuration.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
   */
  hasScope(scope: Scope): boolean {
    return scope in this.#config.scopes
  }

  /**
   * Check if the requested scope list uses any OIDC-specific scopes.
   */
  usesOidcScopes(scopes: Scope[]): boolean {
    return scopes.some((scope) => OIDC_SCOPES.has(scope))
  }

  /**
   * Return the list of scopes that are not registered in the
   * server configuration. When no scopes are configured, all
   * requested scopes are considered unknown per RFC 6749 §3.3
   * (`invalid_scope` — "The requested scope is invalid, unknown,
   * or malformed").
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
   */
  validateScopes(scopes: Scope[]): string[] {
    const invalidScopes = new Set<string>()
    const hasOpenid = scopes.includes('openid')

    if (!hasOpenid) {
      scopes
        .filter((scope) => scope !== 'openid' && OIDC_SCOPES.has(scope))
        .forEach((scope) => invalidScopes.add(scope))
    }

    if (Object.keys(this.#config.scopes).length === 0) {
      scopes
        .filter((scope) => !BUILTIN_SCOPES.has(scope) && !OIDC_SCOPES.has(scope))
        .forEach((scope) => invalidScopes.add(scope))

      return [...invalidScopes]
    }

    scopes
      .filter((scope) => !BUILTIN_SCOPES.has(scope) && !OIDC_SCOPES.has(scope) && !this.hasScope(scope))
      .forEach((scope) => invalidScopes.add(scope))

    return [...invalidScopes]
  }

  /**
   * Check if a grant type is enabled in the server configuration.
   */
  isGrantTypeEnabled(grantType: string): boolean {
    return this.#config.grantTypes.includes(grantType as any)
  }

  /**
   * Revoke all OAuth artifacts for a given user.
   *
   * Call this when a user is deleted or deactivated to ensure
   * none of their tokens remain usable. Revokes access tokens
   * and refresh tokens, and deletes authorization codes and
   * consent records.
   */
  async revokeAllForUser(userId: string): Promise<void> {
    const now = DateTime.now()

    await OAuthAccessToken.query()
      .where('userId', userId)
      .whereNull('revokedAt')
      .update({ revokedAt: now.toSQL() })

    await OAuthRefreshToken.query()
      .where('userId', userId)
      .whereNull('revokedAt')
      .update({ revokedAt: now.toSQL() })

    await OAuthAuthorizationCode.query().where('userId', userId).delete()
    await OAuthPendingAuthorizationRequest.query().where('userId', userId).delete()
    await OAuthConsent.query().where('userId', userId).delete()
  }

  /**
   * Purge revoked and/or expired tokens and authorization codes.
   *
   * Returns the total number of deleted records. Expired tokens are
   * retained for `retentionHours` (default 168 = 7 days) to allow
   * for debugging and audit trails.
   */
  async purgeTokens(options?: {
    revokedOnly?: boolean
    expiredOnly?: boolean
    retentionHours?: number
  }): Promise<PurgeResult> {
    const revokedOnly = options?.revokedOnly ?? false
    const expiredOnly = options?.expiredOnly ?? false
    const retentionHours = options?.retentionHours ?? 168
    const purgeRevoked = revokedOnly || !expiredOnly
    const purgeExpired = expiredOnly || !revokedOnly
    const cutoff = DateTime.now().minus({ hours: retentionHours })

    let accessTokens = 0
    let refreshTokens = 0
    let authorizationCodes = 0
    let pendingRequests = 0

    if (purgeRevoked) {
      accessTokens += await this.#deleteCount(
        OAuthAccessToken.query().whereNotNull('revokedAt').delete()
      )
      refreshTokens += await this.#deleteCount(
        OAuthRefreshToken.query().whereNotNull('revokedAt').delete()
      )
    }

    if (purgeExpired) {
      accessTokens += await this.#deleteCount(
        OAuthAccessToken.query()
          .where('expiresAt', '<', cutoff.toSQL()!)
          .whereNull('revokedAt')
          .delete()
      )
      refreshTokens += await this.#deleteCount(
        OAuthRefreshToken.query()
          .where('expiresAt', '<', cutoff.toSQL()!)
          .whereNull('revokedAt')
          .delete()
      )
      authorizationCodes += await this.#deleteCount(
        OAuthAuthorizationCode.query().where('expiresAt', '<', cutoff.toSQL()!).delete()
      )
    }

    // Pending requests have no audit value — purge immediately on expiration
    pendingRequests += await this.#deleteCount(
      OAuthPendingAuthorizationRequest.query()
        .where('expiresAt', '<', DateTime.now().toSQL()!)
        .delete()
    )

    return { accessTokens, refreshTokens, authorizationCodes, pendingRequests }
  }

  /**
   * Register OAuth 2.1 endpoint routes (token, authorize, consent, etc.).
   *
   * Paths are relative — wrap the call in a `router.group().prefix()`
   * to control the mount point.
   *
   * Do not apply session-auth middleware to the entire OAuth group.
   * Endpoints like `/token`, `/introspect`, `/revoke`, and `/register`
   * must stay callable without a browser session.
   *
   * @example
   * ```ts
   * router.group(() => {
   *   sesame.registerRoutes()
   * }).prefix('/oauth')
   * ```
   */
  registerRoutes() {
    registerOAuthRoutes(this.#router)
  }

  /**
   * Register discovery routes at the root level.
   *
   * Must be called outside any prefix group so endpoints
   * remain at `/.well-known/...`.
   */
  registerDiscoveryRoutes(options?: { jwksPath?: string }) {
    registerWellKnown(this.#router, options)
  }

  /**
   * @deprecated Use `registerDiscoveryRoutes()` instead.
   */
  registerWellKnownRoutes(options?: { jwksPath?: string }) {
    this.registerDiscoveryRoutes(options)
  }

  /**
   * Register a `/.well-known/oauth-protected-resource` endpoint
   * for a specific resource path (RFC 9728). Useful for MCP
   * servers that need per-resource discovery.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9728
   */
  registerProtectedResource(options: { resource: string; scopes?: Scope[] }) {
    const wellKnownPath = `/.well-known/oauth-protected-resource${options.resource}`

    this.#router.get(wellKnownPath, async (ctx: HttpContext): Promise<ResourceServerMetadata> => {
      ctx.response.header(
        'Cache-Control',
        'public, max-age=15, stale-while-revalidate=15, stale-if-error=86400'
      )

      return {
        resource: `${this.#config.issuer}${options.resource}`,
        authorization_servers: [this.#config.issuer],
        scopes_supported: [
          ...(options.scopes ?? Object.keys(this.#config.scopes)),
          ...BUILTIN_SCOPES,
        ],
        bearer_methods_supported: ['header'],
      }
    })
  }

  #deleteCount(result: Promise<unknown>): Promise<number> {
    return result.then((r) => (Array.isArray(r) ? Number(r[0] ?? 0) : Number(r)))
  }
}
