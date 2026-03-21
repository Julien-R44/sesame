import { DateTime } from 'luxon'
import type { HttpContext, Router } from '@adonisjs/core/http'
import {
  BUILTIN_SCOPES,
  OIDC_SCOPES,
  type CreateClientOptions,
  type CreateClientResult,
  type ResolvedSesameConfig,
  type ResourceServerMetadata,
  type Scope,
  type UpdateClientOptions,
} from './types.ts'
import { ClientService } from './services/client_service.ts'
import { KeyService } from './services/key_service.ts'
import { OAuthClient } from './models/oauth_client.ts'
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
      .filter(
        (scope) => !BUILTIN_SCOPES.has(scope) && !OIDC_SCOPES.has(scope) && !this.hasScope(scope)
      )
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
   * Create a new OAuth client programmatically.
   * Returns the client and the raw secret (only available at creation time).
   */
  async createClient(options: CreateClientOptions): Promise<CreateClientResult> {
    const clientService = new ClientService()
    const isPublic = options.isPublic ?? false
    const grantTypes = options.grantTypes ?? ['authorization_code']
    const scopes = options.scopes ?? this.#config.defaultScopes

    const clientId = clientService.generateClientId()
    const clientSecret = isPublic ? null : clientService.generateClientSecret()
    const hashedSecret = clientSecret ? clientService.hashSecret(clientSecret) : null

    const client = await OAuthClient.create({
      id: crypto.randomUUID(),
      clientId,
      clientSecret: hashedSecret,
      name: options.name,
      redirectUris: options.redirectUris,
      scopes,
      grantTypes,
      isPublic,
      isDisabled: false,
      requirePkce: options.requirePkce ?? true,
      type: isPublic ? 'public' : 'confidential',
      metadata: options.metadata ?? null,
      userId: options.userId ?? null,
    })

    return { client, clientSecret }
  }

  /**
   * Find a client by its public client_id.
   */
  async findClient(clientId: string): Promise<OAuthClient | null> {
    return OAuthClient.query().where('clientId', clientId).first()
  }

  /**
   * List all clients, optionally filtered by userId.
   */
  async listClients(options?: { userId?: string }): Promise<OAuthClient[]> {
    const query = OAuthClient.query().orderBy('createdAt', 'desc')
    if (options?.userId) query.where('userId', options.userId)

    return query
  }

  /**
   * Update an existing client by its public client_id.
   * Returns the updated client, or null if not found.
   */
  async updateClient(clientId: string, options: UpdateClientOptions): Promise<OAuthClient | null> {
    const client = await OAuthClient.query().where('clientId', clientId).first()
    if (!client) return null

    if (options.name !== undefined) client.name = options.name
    if (options.redirectUris !== undefined) client.redirectUris = options.redirectUris
    if (options.scopes !== undefined) client.scopes = options.scopes
    if (options.grantTypes !== undefined) client.grantTypes = options.grantTypes
    if (options.isDisabled !== undefined) client.isDisabled = options.isDisabled
    if (options.requirePkce !== undefined) client.requirePkce = options.requirePkce
    if (options.metadata !== undefined) client.metadata = options.metadata

    await client.save()

    return client
  }

  /**
   * Delete a client and all its associated tokens, codes, and consents.
   * Returns true if the client was found and deleted.
   */
  async deleteClient(clientId: string): Promise<boolean> {
    const client = await OAuthClient.query().where('clientId', clientId).first()
    if (!client) return false

    await OAuthClient.transaction(async (trx) => {
      await Promise.all([
        OAuthRefreshToken.query({ client: trx }).where('clientId', clientId).delete(),
        OAuthAccessToken.query({ client: trx }).where('clientId', clientId).delete(),
        OAuthAuthorizationCode.query({ client: trx }).where('clientId', clientId).delete(),
        OAuthPendingAuthorizationRequest.query({ client: trx })
          .where('clientId', clientId)
          .delete(),
        OAuthConsent.query({ client: trx }).where('clientId', clientId).delete(),
      ])

      await client.useTransaction(trx).delete()
    })

    return true
  }

  /**
   * Rotate the secret of a confidential client.
   * Returns the new raw secret, or null if the client is public or not found.
   */
  async rotateClientSecret(clientId: string): Promise<string | null> {
    const client = await OAuthClient.query().where('clientId', clientId).first()
    if (!client || client.isPublic) return null

    const clientService = new ClientService()
    const newSecret = clientService.generateClientSecret()
    client.clientSecret = clientService.hashSecret(newSecret)
    await client.save()

    return newSecret
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
