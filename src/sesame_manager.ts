import { DateTime } from 'luxon'
import type { HttpContext, Router } from '@adonisjs/core/http'
import {
  BUILTIN_SCOPES,
  OIDC_SCOPES,
  type ApproveAuthorizationOptions,
  type AuthorizationDecision,
  type CreateClientOptions,
  type DenyAuthorizationOptions,
  type CreateClientResult,
  type FindPendingAuthorizationRequestOptions,
  type ListGrantsOptions,
  type RevokeGrantOptions,
  type RevokeGrantsOptions,
  type SesameGrant,
  type UpdateGrantOptions,
  type ResolvedSesameConfig,
  type ResourceServerMetadata,
  type Scope,
  type UpdateClientOptions,
} from './types.ts'
import { ClientService } from './services/client_service.ts'
import { CompleteAuthorizationAction } from './actions/complete_authorization.ts'
import { assertGrantContext, isGrantId } from './services/grant_service.ts'
import { KeyService } from './services/key_service.ts'
import { TokenService } from './services/token_service.ts'
import { registerOAuthRoutes, registerWellKnownRoutes as registerWellKnown } from './routes.ts'
import { matchResourceIndicator, normalizeResourceIndicator } from './resource_indicators.ts'
import { E_INVALID_TARGET } from './oauth_error.ts'
import type {
  OAuthClientRecord,
  OAuthGrantRecord,
  OAuthPendingAuthorizationRequestRecord,
  SesameStore,
} from './storage/types.ts'

export interface PurgeResult {
  accessTokens: number
  refreshTokens: number
  authorizationCodes: number
  pendingRequests: number
  grants: number
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
  #store: SesameStore
  /**
   * Protected resources served by this application (RFC 8707 / RFC 9728),
   * keyed by canonical resource identifier, with the scopes they advertise.
   * The issuer root is always registered.
   */
  #resources = new Map<string, Scope[]>()

  constructor(config: ResolvedSesameConfig, router: Router, store: SesameStore) {
    this.#config = config
    this.#router = router
    this.#store = store
    this.#keyService = config.jwk ? new KeyService(config.jwk) : null
    this.#resources.set(this.resourceIdentifier(), [])
  }

  /**
   * Extract the single resource value from a raw request parameter.
   * Repeated parameters are parsed as arrays by AdonisJS.
   */
  #singleResourceValue(value: unknown): string | null {
    if (Array.isArray(value) && value.length > 1) {
      throw new E_INVALID_TARGET('Only one resource parameter is supported')
    }

    const resource = Array.isArray(value) ? value[0] : value
    if (resource === undefined || resource === null || resource === '') return null
    if (typeof resource !== 'string') throw new E_INVALID_TARGET('Invalid resource parameter')

    return resource
  }

  #publicClient(client: OAuthClientRecord): OAuthClientRecord {
    const publicClient = { ...client }
    Object.defineProperty(publicClient, 'clientSecret', {
      value: client.clientSecret,
      enumerable: false,
      writable: false,
    })

    return publicClient
  }

  /**
   * Load a grant, optionally only when it belongs to the given user.
   */
  async #findOwnedGrant(options: { grantId: string; userId?: string }) {
    const grant = await this.findGrant(options.grantId)
    if (!grant) return null
    if (options.userId !== undefined && grant.userId !== options.userId) return null

    return grant
  }

  get config() {
    return this.#config
  }

  get store(): SesameStore {
    return this.#store
  }

  get keyService(): KeyService {
    if (!this.#keyService) {
      throw new Error('OIDC requires a JWK. Set the `jwk` option in defineConfig().')
    }

    return this.#keyService
  }

  /**
   * Scopes declared for a resource with `registerProtectedResource()`.
   * The OAuth guard advertises them in its `WWW-Authenticate` challenge.
   */
  getProtectedResourceScopes(resource?: string): Scope[] {
    if (!resource) return []

    return this.#resources.get(this.resourceIdentifier(resource)) ?? []
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
   * Read a pending authorization request without consuming its raw consent token.
   * Returns null for unknown, expired, consumed, or other users' requests.
   */
  async findPendingAuthorizationRequest(
    options: FindPendingAuthorizationRequestOptions
  ): Promise<OAuthPendingAuthorizationRequestRecord | null> {
    const token = new TokenService(this).hashToken(options.token)

    return this.#store.findPendingAuthorizationRequest({
      token,
      userId: options.userId,
      now: DateTime.now(),
    })
  }

  /**
   * Approve a pending authorization request from your own consent
   * controller. Pass `scopes` to grant fewer scopes than requested.
   * Returns the client redirect URL carrying the authorization code.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
   */
  async approveAuthorization(options: ApproveAuthorizationOptions): Promise<AuthorizationDecision> {
    return new CompleteAuthorizationAction().approve(this, options)
  }

  /**
   * Deny a pending authorization request from your own consent
   * controller. Returns the client redirect URL carrying `access_denied`.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
   */
  async denyAuthorization(options: DenyAuthorizationOptions): Promise<AuthorizationDecision> {
    return new CompleteAuthorizationAction().deny(this, options)
  }

  /**
   * Canonical resource identifier of a path served by this application.
   * Without a path, returns the issuer itself (the root protected resource).
   *
   * @see https://datatracker.ietf.org/doc/html/rfc8707#section-2
   */
  resourceIdentifier(path?: string): string {
    const resource = `${this.#config.issuer}${path ?? ''}`

    return normalizeResourceIndicator(resource) ?? resource
  }

  /**
   * Resolve a raw `resource` request parameter (RFC 8707) to a registered
   * resource identifier. Returns null when the parameter is absent, and
   * throws `invalid_target` when it is repeated, malformed, or not served
   * by this authorization server.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc8707#section-2
   */
  resolveResource(value: unknown): string | null {
    const resource = this.#singleResourceValue(value)
    if (!resource) return null

    if (!normalizeResourceIndicator(resource)) {
      throw new E_INVALID_TARGET(
        'The resource parameter must be an absolute http(s) URI without a fragment'
      )
    }

    const matched = matchResourceIndicator({ value: resource, resources: this.#resources.keys() })
    if (!matched) {
      throw new E_INVALID_TARGET(
        'The requested resource is not served by this authorization server'
      )
    }

    return matched
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
   * grants.
   */
  async revokeAllForUser(userId: string): Promise<void> {
    const now = DateTime.now()
    const store = this.#store

    await store.revokeAllForUser({ userId, now })
  }

  /**
   * List the active grants of a user, newest first, each with its
   * public client. A user may hold several grants for one client
   * (each authorization creates one), so group by `clientId` to
   * build a "connected applications" page.
   *
   * @example
   * ```ts
   * const grants = await sesame.listGrants({ userId: String(user.id) })
   * const apps = Object.groupBy(grants, (grant) => grant.clientId)
   * ```
   */
  async listGrants(options: ListGrantsOptions): Promise<SesameGrant[]> {
    const grants = await this.#store.listGrants({ ...options, activeAt: DateTime.now() })
    const clientIds = [...new Set(grants.map((grant) => grant.clientId))]
    const clients = await Promise.all(clientIds.map((clientId) => this.#store.findClient(clientId)))
    const clientsById = new Map(
      clients.flatMap((client) => (client ? [[client.clientId, this.#publicClient(client)]] : []))
    )

    return grants.flatMap((grant) => {
      const client = clientsById.get(grant.clientId)

      return client ? [{ ...grant, client }] : []
    })
  }

  /**
   * Find a grant by its identifier, including expired ones.
   * Returns null for identifiers that are not UUIDs (e.g. a bad route param).
   */
  async findGrant(grantId: string): Promise<OAuthGrantRecord | null> {
    if (!isGrantId(grantId)) return null

    return this.#store.findGrant(grantId)
  }

  /**
   * Revoke a grant: every code, access token, and refresh token
   * issued from it stops working. Pass `userId` to only revoke a
   * grant owned by that user. Returns false when nothing was revoked.
   */
  async revokeGrant(options: RevokeGrantOptions): Promise<boolean> {
    const grant = await this.#findOwnedGrant(options)
    if (!grant) return false

    return this.#store.revokeGrant({ id: grant.id, now: DateTime.now() })
  }

  /**
   * Revoke every grant of a user, or only those of one client
   * ("disconnect this application"). Returns the number of revoked grants.
   */
  async revokeGrants(options: RevokeGrantsOptions): Promise<number> {
    return this.#store.revokeGrants({ ...options, now: DateTime.now() })
  }

  /**
   * Replace the application context of a grant. The OAuth guard reads
   * it on every request, so the change applies immediately. Pass
   * `userId` to only update a grant owned by that user. Returns the
   * updated grant, or null when not found.
   */
  async updateGrant(options: UpdateGrantOptions): Promise<OAuthGrantRecord | null> {
    assertGrantContext(options.context)

    const grant = await this.#findOwnedGrant(options)
    if (!grant) return null

    await this.#store.updateGrant({ id: grant.id, data: { context: options.context } })

    return this.#store.findGrant(grant.id)
  }

  /**
   * Purge revoked and/or expired tokens, authorization codes, and grants.
   *
   * Returns the number of deleted records per table. Expired records and
   * revoked refresh tokens are retained for `retentionHours` (default
   * 168 = 7 days): rotated refresh tokens must outlive their rotation for
   * replay detection to keep working. Revoked access tokens are purged
   * immediately.
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
    const store = this.#store

    return store.purgeTokens({ purgeRevoked, purgeExpired, cutoff, now: DateTime.now() })
  }

  /**
   * Delete dynamically registered clients that were never used: created more
   * than `olderThanDays` days ago (default 30) and without any token,
   * authorization code, consent, or pending authorization request.
   *
   * Clients created with `createClient()` are never deleted. Returns the
   * number of deleted clients. Throws when `olderThanDays` is not an
   * integer of at least 1.
   */
  async purgeUnusedClients(options?: { olderThanDays?: number }): Promise<number> {
    const olderThanDays = options?.olderThanDays ?? 30
    if (!Number.isInteger(olderThanDays) || olderThanDays < 1) {
      throw new Error('olderThanDays must be a positive integer')
    }

    const createdBefore = DateTime.now().minus({ days: olderThanDays })

    return this.#store.purgeUnusedClients({ createdBefore })
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

    const store = this.#store
    const client = await store.createClient({
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

    return { client: this.#publicClient(client), clientSecret }
  }

  /**
   * Find a client by its public client_id.
   */
  async findClient(clientId: string) {
    const store = this.#store
    const client = await store.findClient(clientId)

    return client ? this.#publicClient(client) : null
  }

  /**
   * List all clients, optionally filtered by userId.
   */
  async listClients(options?: { userId?: string }) {
    const store = this.#store
    const clients = await store.listClients(options)

    return clients.map((client) => this.#publicClient(client))
  }

  /**
   * Update an existing client by its public client_id.
   * Returns the updated client, or null if not found.
   */
  async updateClient(clientId: string, options: UpdateClientOptions) {
    const store = this.#store
    const client = await store.findClient(clientId)
    if (!client) return null

    if (options.name !== undefined) client.name = options.name
    if (options.redirectUris !== undefined) client.redirectUris = options.redirectUris
    if (options.scopes !== undefined) client.scopes = options.scopes
    if (options.grantTypes !== undefined) client.grantTypes = options.grantTypes
    if (options.isDisabled !== undefined) client.isDisabled = options.isDisabled
    if (options.requirePkce !== undefined) client.requirePkce = options.requirePkce
    if (options.metadata !== undefined) client.metadata = options.metadata

    await store.updateClient({ id: client.id, data: options })

    const updated = await store.findClient(clientId)

    return updated ? this.#publicClient(updated) : null
  }

  /**
   * Delete a client and all its associated tokens, codes, and grants.
   * Returns true if the client was found and deleted.
   */
  async deleteClient(clientId: string): Promise<boolean> {
    return this.#store.deleteClient(clientId)
  }

  /**
   * Rotate the secret of a confidential client.
   * Returns the new raw secret, or null if the client is public or not found.
   */
  async rotateClientSecret(clientId: string): Promise<string | null> {
    const store = this.#store
    const client = await store.findClient(clientId)
    if (!client || client.isPublic) return null

    const clientService = new ClientService()
    const newSecret = clientService.generateClientSecret()
    client.clientSecret = clientService.hashSecret(newSecret)
    await store.updateClientSecret({ id: client.id, secret: client.clientSecret })

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
   * The resource also becomes a valid `resource` parameter (RFC 8707).
   * Tokens requested for it are bound to it, and only guards declaring
   * the same `resource` accept them.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9728
   * @see https://datatracker.ietf.org/doc/html/rfc8707
   */
  registerProtectedResource(options: { resource: string; scopes?: Scope[] }) {
    this.#resources.set(this.resourceIdentifier(options.resource), options.scopes ?? [])

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
}
