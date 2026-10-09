import { DateTime } from 'luxon'
import { BaseModel } from '@adonisjs/lucid/orm'
import { CLIENT_USAGE_TABLES, chunkClientIds, isPurgeableClient } from '../unused_clients.js'
import { falseOnInactiveGrant, InactiveGrantError } from '../inactive_grant.js'
import { OAuthAccessToken } from '../../models/oauth_access_token.js'
import { OAuthAuthorizationCode } from '../../models/oauth_authorization_code.js'
import { OAuthClient } from '../../models/oauth_client.js'
import { OAuthGrant } from '../../models/oauth_grant.js'
import { OAuthPendingAuthorizationRequest } from '../../models/oauth_pending_authorization_request.js'
import { OAuthRefreshToken } from '../../models/oauth_refresh_token.js'
import type {
  CreateAccessTokenRecord,
  CreateAuthorizationCodeRecord,
  CreateClientRecord,
  CreateGrantRecord,
  CreatePendingAuthorizationRequestRecord,
  ExchangeAuthorizationCodeOptions,
  GrantAdoption,
  IssueTokenPairOptions,
  ListStoredGrantsOptions,
  OAuthAccessTokenRecord,
  OAuthAccessTokenWithGrantRecord,
  OAuthAuthorizationCodeRecord,
  OAuthClientRecord,
  OAuthGrantRecord,
  OAuthPendingAuthorizationRequestRecord,
  OAuthRefreshTokenRecord,
  PendingAuthorizationRequestLookupOptions,
  PurgeTokensOptions,
  PurgeUnusedClientsOptions,
  RotateRefreshTokenOptions,
  SesamePurgeResult,
  SesameStore,
  TokenGrantWrite,
  UpdateClientRecord,
  UpdateGrantRecord,
} from '../types.js'

/**
 * Grant columns selected alongside an access token, prefixed to avoid clashes.
 */
const GRANT_COLUMNS = [
  'id',
  'client_id',
  'user_id',
  'scopes',
  'context',
  'expires_at',
  'created_at',
  'updated_at',
]
const GRANT_PREFIX = 'grant__'

/**
 * Persist OAuth records through the application's Lucid connection.
 */
export class LucidStore implements SesameStore {
  #client?: any

  /**
   * Bind this store to a Lucid transaction when one is supplied.
   */
  constructor(client?: any) {
    this.#client = client
  }

  /**
   * Normalize affected-row results across Lucid's SQL drivers.
   */
  #affectedRows(result: unknown): number {
    if (Array.isArray(result)) return Number(result[0] ?? 0)

    return Number(result)
  }

  /**
   * Bind a model query to this store's transaction when present.
   */
  #query(model: typeof BaseModel) {
    return model.query(this.#client ? { client: this.#client } : undefined)
  }

  /**
   * Return a plain record with omitted nullable columns normalized.
   */
  #record<T>(model: InstanceType<typeof BaseModel>, nullableFields: string[] = []): T {
    const attributes = { ...model.$attributes }

    for (const field of nullableFields) {
      if (attributes[field] === undefined) attributes[field] = null
    }

    return attributes as T
  }

  /**
   * Normalize Lucid client values to the store's plain-record contract.
   */
  #clientRecord(client: InstanceType<typeof BaseModel>): OAuthClientRecord {
    const record = this.#record<OAuthClientRecord>(client, [
      'clientSecret',
      'metadata',
      'type',
      'userId',
    ])

    return {
      ...record,
      isPublic: Boolean(record.isPublic),
      isDisabled: Boolean(record.isDisabled),
      requirePkce: Boolean(record.requirePkce),
    }
  }

  /**
   * Query clients referenced by no token, code, grant, or pending request.
   */
  #unusedClientsQuery() {
    const query = this.#query(OAuthClient)
    for (const table of CLIENT_USAGE_TABLES) {
      query.whereNotExists((usage) => {
        usage
          .from(table)
          .select(1)
          .whereColumn(`${table}.client_id`, `${OAuthClient.table}.client_id`)
      })
    }

    return query
  }

  /**
   * Normalize a Lucid grant to the store's plain-record contract.
   */
  #grantRecord(grant: InstanceType<typeof BaseModel>): OAuthGrantRecord {
    return this.#record<OAuthGrantRecord>(grant, ['context'])
  }

  /**
   * Rebuild the grant selected alongside an access token, if any.
   */
  #joinedGrant(extras: Record<string, unknown>): OAuthGrantRecord | null {
    if (extras[`${GRANT_PREFIX}id`] === null || extras[`${GRANT_PREFIX}id`] === undefined) {
      return null
    }

    const row = Object.fromEntries(
      GRANT_COLUMNS.map((column) => [column, extras[`${GRANT_PREFIX}${column}`]])
    )
    const grant = OAuthGrant.$createFromAdapterResult(row)

    return grant ? this.#grantRecord(grant) : null
  }

  /**
   * Extend or create the grant written alongside a token issuance.
   * Must run inside a transaction.
   */
  async #applyGrantWrite(write?: TokenGrantWrite): Promise<void> {
    if (!write) return
    if (write.type === 'create') {
      await OAuthGrant.create(write.grant, { client: this.#client })
      await this.#adoptIntoGrant(write.grant.id, write.adopt)
      return
    }

    await this.#extendGrant(write)
  }

  /**
   * Lock an active grant and move its expiry forward, or throw so the
   * issuance rolls back when the grant was revoked or expired meanwhile.
   */
  async #extendGrant(write: { id: string; expiresAt: DateTime }): Promise<void> {
    const now = DateTime.now()
    const query = this.#query(OAuthGrant)
      .where('id', write.id)
      .where('expiresAt', '>', now.toSQL()!)
    const isSqlite = String(this.#client?.dialect?.name ?? '').includes('sqlite')
    const grant = await (isSqlite ? query : query.forUpdate()).first()
    if (!grant) throw new InactiveGrantError()
    if (this.#grantRecord(grant).expiresAt >= write.expiresAt) return

    await this.#query(OAuthGrant)
      .where('id', write.id)
      .update({ expiresAt: write.expiresAt.toSQL(), updatedAt: now.toSQL() })
  }

  /**
   * Attach pre-grant credentials to a newly created grant.
   */
  async #adoptIntoGrant(grantId: string, adopt: GrantAdoption): Promise<void> {
    const targets = [
      { model: OAuthAuthorizationCode, id: adopt.codeId },
      { model: OAuthRefreshToken, id: adopt.refreshTokenId },
      { model: OAuthAccessToken, id: adopt.accessTokenId },
    ]

    for (const target of targets) {
      if (!target.id) continue

      await this.#query(target.model)
        .where('id', target.id)
        .whereNull('grantId')
        .update({ grantId })
    }
  }

  /**
   * Delete grants with their codes and refresh tokens and revoke their
   * access tokens. Must run inside a transaction. The grants are deleted
   * first so a concurrent issuance holding their lock cannot outlive them.
   */
  async #revokeGrantIds(ids: string[], now: DateTime): Promise<number> {
    if (ids.length === 0) return 0

    const count = this.#affectedRows(await this.#query(OAuthGrant).whereIn('id', ids).delete())
    await this.#query(OAuthRefreshToken).whereIn('grantId', ids).delete()
    await this.#query(OAuthAuthorizationCode).whereIn('grantId', ids).delete()
    await this.#query(OAuthAccessToken)
      .whereIn('grantId', ids)
      .whereNull('revokedAt')
      .update({ revokedAt: now.toSQL(), updatedAt: now.toSQL() })

    return count
  }

  /**
   * Execute related writes in one real database transaction.
   */
  async #transaction<T>(callback: (store: LucidStore) => Promise<T>): Promise<T> {
    return OAuthClient.transaction(async (client) => callback(new LucidStore(client)))
  }

  /**
   * Find a registered client by its public identifier.
   */
  async findClient(clientId: string): Promise<OAuthClientRecord | null> {
    const client = await this.#query(OAuthClient).where('clientId', clientId).first()

    return client ? this.#clientRecord(client) : null
  }

  /**
   * List clients newest first, optionally for a single owner.
   */
  async listClients(options?: { userId?: string }): Promise<OAuthClientRecord[]> {
    const query = this.#query(OAuthClient).orderBy('createdAt', 'desc')
    if (options?.userId) query.where('userId', options.userId)

    const clients = await query

    return clients.map((client) => this.#clientRecord(client))
  }

  /**
   * Insert a client and return its stored record.
   */
  async createClient(data: CreateClientRecord): Promise<OAuthClientRecord> {
    await OAuthClient.create(data, this.#client ? { client: this.#client } : undefined)
    const client = await this.findClient(data.clientId)
    if (!client) throw new Error('Failed to reload inserted OAuth client')

    return client
  }

  /**
   * Update only the supplied public client fields.
   */
  async updateClient(options: { id: string; data: UpdateClientRecord }): Promise<void> {
    const values: Record<string, unknown> = {}
    const { data } = options

    if (data.name !== undefined) values.name = data.name
    if (data.redirectUris !== undefined) values.redirectUris = JSON.stringify(data.redirectUris)
    if (data.scopes !== undefined) values.scopes = JSON.stringify(data.scopes)
    if (data.grantTypes !== undefined) values.grantTypes = JSON.stringify(data.grantTypes)
    if (data.isDisabled !== undefined) values.isDisabled = data.isDisabled
    if (data.requirePkce !== undefined) values.requirePkce = data.requirePkce
    if (data.metadata !== undefined)
      values.metadata = data.metadata === null ? null : JSON.stringify(data.metadata)
    if (Object.keys(values).length === 0) return

    values.updatedAt = DateTime.now().toSQL()
    await this.#query(OAuthClient).where('id', options.id).update(values)
  }

  /**
   * Replace a confidential client's stored secret hash.
   */
  async updateClientSecret(options: { id: string; secret: string }): Promise<void> {
    await this.#query(OAuthClient).where('id', options.id).update({
      clientSecret: options.secret,
      updatedAt: DateTime.now().toSQL(),
    })
  }

  /**
   * Delete a client and all its associated OAuth records atomically.
   */
  async deleteClient(clientId: string): Promise<boolean> {
    return this.#transaction(async (store) => {
      const client = await store.findClient(clientId)
      if (!client) return false

      await store.#query(OAuthRefreshToken).where('clientId', clientId).delete()
      await store.#query(OAuthAccessToken).where('clientId', clientId).delete()
      await store.#query(OAuthAuthorizationCode).where('clientId', clientId).delete()
      await store.#query(OAuthPendingAuthorizationRequest).where('clientId', clientId).delete()
      await store.#query(OAuthGrant).where('clientId', clientId).delete()

      const count = this.#affectedRows(
        await store.#query(OAuthClient).where('id', client.id).delete()
      )

      return count === 1
    })
  }

  /**
   * Look up an access-token hash with its grant in one query,
   * optionally limited to one client.
   */
  async findAccessToken(options: {
    hash: string
    clientId?: string
  }): Promise<OAuthAccessTokenWithGrantRecord | null> {
    const table = OAuthAccessToken.table
    const query = this.#query(OAuthAccessToken)
      .leftJoin(`${OAuthGrant.table} as g`, 'g.id', `${table}.grant_id`)
      .select(
        `${table}.*`,
        ...GRANT_COLUMNS.map((column) => `g.${column} as ${GRANT_PREFIX}${column}`)
      )
      .where(`${table}.token_hash`, options.hash)
    if (options.clientId) query.where(`${table}.client_id`, options.clientId)

    const token = await query.first()
    if (!token) return null

    const record = this.#record<OAuthAccessTokenRecord>(token, [
      'userId',
      'grantId',
      'revokedAt',
      'resource',
    ])

    return { ...record, grant: this.#joinedGrant(token.$extras) }
  }

  /**
   * Insert a hashed access token.
   */
  async createAccessToken(data: CreateAccessTokenRecord): Promise<void> {
    await OAuthAccessToken.create(data, this.#client ? { client: this.#client } : undefined)
  }

  /**
   * Revoke an active access token owned by the requesting client.
   */
  async revokeAccessToken(options: {
    hash: string
    clientId: string
    now: DateTime
  }): Promise<boolean> {
    const result = await this.#query(OAuthAccessToken)
      .where('tokenHash', options.hash)
      .where('clientId', options.clientId)
      .whereNull('revokedAt')
      .update({ revokedAt: options.now.toSQL(), updatedAt: options.now.toSQL() })

    return this.#affectedRows(result) === 1
  }

  /**
   * Look up a refresh-token hash owned by a client.
   */
  async findRefreshToken(options: {
    hash: string
    clientId: string
  }): Promise<OAuthRefreshTokenRecord | null> {
    const token = await this.#query(OAuthRefreshToken)
      .where('token', options.hash)
      .where('clientId', options.clientId)
      .first()

    return token
      ? this.#record<OAuthRefreshTokenRecord>(token, ['grantId', 'revokedAt', 'resource'])
      : null
  }

  /**
   * Delete a refresh token and revoke its associated access token together.
   * The refresh token is deleted rather than marked revoked so the rotation
   * grace period cannot bring it back.
   */
  async revokeRefreshToken(options: {
    hash: string
    clientId: string
    now: DateTime
  }): Promise<void> {
    await this.#transaction(async (store) => {
      const token = await store.findRefreshToken(options)
      if (!token) return

      await store.#query(OAuthRefreshToken).where('id', token.id).delete()
      await store.#query(OAuthAccessToken)
        .where('id', token.accessTokenId)
        .whereNull('revokedAt')
        .update({ revokedAt: options.now.toSQL(), updatedAt: options.now.toSQL() })
    })
  }

  /**
   * Invalidate a client's grant-less token family after refresh-token replay.
   */
  async revokeLegacyTokenFamily(options: {
    clientId: string
    userId: string
    now: DateTime
  }): Promise<void> {
    await this.#transaction(async (store) => {
      await store.#query(OAuthRefreshToken)
        .where('clientId', options.clientId)
        .where('userId', options.userId)
        .whereNull('grantId')
        .delete()
      await store.#query(OAuthAccessToken)
        .where('clientId', options.clientId)
        .where('userId', options.userId)
        .whereNull('grantId')
        .whereNull('revokedAt')
        .update({ revokedAt: options.now.toSQL(), updatedAt: options.now.toSQL() })
    })
  }

  /**
   * Find an authorization-code hash issued to a client.
   */
  async findAuthorizationCode(options: {
    code: string
    clientId: string
  }): Promise<OAuthAuthorizationCodeRecord | null> {
    const code = await this.#query(OAuthAuthorizationCode)
      .where('code', options.code)
      .where('clientId', options.clientId)
      .first()

    return code
      ? this.#record<OAuthAuthorizationCodeRecord>(code, [
          'grantId',
          'codeChallenge',
          'codeChallengeMethod',
          'nonce',
          'consumedAt',
          'resource',
        ])
      : null
  }

  /**
   * Store a short-lived authorization-code hash.
   */
  async createAuthorizationCode(data: CreateAuthorizationCodeRecord): Promise<void> {
    await OAuthAuthorizationCode.create(data, this.#client ? { client: this.#client } : undefined)
  }

  /**
   * Discard an expired or invalid authorization code.
   */
  async deleteAuthorizationCode(id: string): Promise<void> {
    await this.#query(OAuthAuthorizationCode).where('id', id).delete()
  }

  /**
   * Consume a code exactly once and issue its tokens in one transaction.
   */
  async exchangeAuthorizationCode(options: ExchangeAuthorizationCodeOptions): Promise<boolean> {
    return falseOnInactiveGrant(() =>
      this.#transaction(async (store) => {
        const consumed = this.#affectedRows(
          await store.#query(OAuthAuthorizationCode)
            .where('id', options.codeId)
            .whereNull('consumedAt')
            .update({
              consumedAt: options.consumedAt.toSQL(),
              updatedAt: options.consumedAt.toSQL(),
            })
        )
        if (consumed !== 1) return false

        await store.#applyGrantWrite(options.grant)
        await store.createAccessToken(options.accessToken)
        if (options.refreshToken) {
          await OAuthRefreshToken.create(options.refreshToken, { client: store.#client })
        }

        return true
      })
    )
  }

  /**
   * Insert a new grant.
   */
  async createGrant(data: CreateGrantRecord): Promise<void> {
    await OAuthGrant.create(data, this.#client ? { client: this.#client } : undefined)
  }

  /**
   * Find a grant by its identifier.
   */
  async findGrant(id: string): Promise<OAuthGrantRecord | null> {
    const grant = await this.#query(OAuthGrant).where('id', id).first()

    return grant ? this.#grantRecord(grant) : null
  }

  /**
   * List a user's grants newest first, optionally for one client or only active ones.
   */
  async listGrants(options: ListStoredGrantsOptions): Promise<OAuthGrantRecord[]> {
    const query = this.#query(OAuthGrant)
      .where('userId', options.userId)
      .orderBy('createdAt', 'desc')
    if (options.clientId) query.where('clientId', options.clientId)
    if (options.activeAt) query.where('expiresAt', '>', options.activeAt.toSQL()!)

    const grants = await query

    return grants.map((grant) => this.#grantRecord(grant))
  }

  /**
   * Update the mutable fields of a grant.
   */
  async updateGrant(options: { id: string; data: UpdateGrantRecord }): Promise<void> {
    if (options.data.context === undefined) return

    const context = options.data.context === null ? null : JSON.stringify(options.data.context)
    await this.#query(OAuthGrant)
      .where('id', options.id)
      .update({ context, updatedAt: DateTime.now().toSQL() })
  }

  /**
   * Revoke a grant and its whole token family atomically.
   */
  async revokeGrant(options: { id: string; now: DateTime }): Promise<boolean> {
    const count = await this.#transaction((store) =>
      store.#revokeGrantIds([options.id], options.now)
    )

    return count > 0
  }

  /**
   * Revoke every grant of a user, optionally for one client.
   */
  async revokeGrants(options: {
    userId: string
    clientId?: string
    now: DateTime
  }): Promise<number> {
    return this.#transaction(async (store) => {
      const query = store.#query(OAuthGrant).select('id').where('userId', options.userId)
      if (options.clientId) query.where('clientId', options.clientId)

      const grants = await query

      return store.#revokeGrantIds(
        grants.map((grant) => String(grant.$attributes.id)),
        options.now
      )
    })
  }

  /**
   * Persist an authorization request awaiting user consent.
   */
  async createPendingAuthorizationRequest(
    data: CreatePendingAuthorizationRequestRecord
  ): Promise<void> {
    await OAuthPendingAuthorizationRequest.create(
      data,
      this.#client ? { client: this.#client } : undefined
    )
  }

  /**
   * Read an unexpired pending request for its owner without consuming it.
   */
  async findPendingAuthorizationRequest(
    options: PendingAuthorizationRequestLookupOptions
  ): Promise<OAuthPendingAuthorizationRequestRecord | null> {
    const row = await this.#query(OAuthPendingAuthorizationRequest)
      .where('token', options.token)
      .where('userId', options.userId)
      .where('expiresAt', '>', options.now.toSQL()!)
      .first()
    if (!row) return null

    return this.#record<OAuthPendingAuthorizationRequestRecord>(row, [
      'state',
      'codeChallenge',
      'codeChallengeMethod',
      'nonce',
      'resource',
    ])
  }

  /**
   * Return a valid pending request only to the process that deletes it.
   */
  async consumePendingAuthorizationRequest(
    options: PendingAuthorizationRequestLookupOptions
  ): Promise<OAuthPendingAuthorizationRequestRecord | null> {
    const request = await this.findPendingAuthorizationRequest(options)
    if (!request) return null

    const deleted = this.#affectedRows(
      await this.#query(OAuthPendingAuthorizationRequest).where('id', request.id).delete()
    )
    if (deleted !== 1) return null

    return request
  }

  /**
   * Persist a new access/refresh pair atomically during the grace period.
   */
  async issueTokenPair(options: IssueTokenPairOptions): Promise<boolean> {
    return falseOnInactiveGrant(() =>
      this.#transaction(async (store) => {
        await store.#applyGrantWrite(options.grant)
        await store.createAccessToken(options.accessToken)
        await OAuthRefreshToken.create(options.refreshToken, { client: store.#client })

        return true
      })
    )
  }

  /**
   * Conditionally consume a refresh token and persist its replacement pair.
   */
  async rotateRefreshToken(options: RotateRefreshTokenOptions): Promise<boolean> {
    return falseOnInactiveGrant(() =>
      this.#transaction(async (store) => {
        const updated = this.#affectedRows(
          await store.#query(OAuthRefreshToken)
            .where('id', options.oldRefreshTokenId)
            .whereNull('revokedAt')
            .update({ revokedAt: options.revokedAt.toSQL(), updatedAt: options.revokedAt.toSQL() })
        )
        if (updated !== 1) return false

        await store.#query(OAuthAccessToken)
          .where('id', options.oldAccessTokenId)
          .whereNull('revokedAt')
          .update({ revokedAt: options.revokedAt.toSQL(), updatedAt: options.revokedAt.toSQL() })
        await store.#applyGrantWrite(options.grant)
        await store.createAccessToken(options.accessToken)
        await OAuthRefreshToken.create(options.refreshToken, { client: store.#client })

        return true
      })
    )
  }

  /**
   * Revoke a user's tokens and remove their grants and short-lived OAuth records.
   */
  async revokeAllForUser(options: { userId: string; now: DateTime }): Promise<void> {
    await this.#transaction(async (store) => {
      await store.#query(OAuthAccessToken)
        .where('userId', options.userId)
        .whereNull('revokedAt')
        .update({ revokedAt: options.now.toSQL(), updatedAt: options.now.toSQL() })
      await store.#query(OAuthRefreshToken).where('userId', options.userId).delete()
      await store.#query(OAuthAuthorizationCode).where('userId', options.userId).delete()
      await store.#query(OAuthPendingAuthorizationRequest).where('userId', options.userId).delete()
      await store.#query(OAuthGrant).where('userId', options.userId).delete()
    })
  }

  /**
   * Remove revoked and aged OAuth records and return per-table counts.
   */
  async purgeTokens(options: PurgeTokensOptions): Promise<SesamePurgeResult> {
    return this.#transaction(async (store) => {
      const counts = {
        accessTokens: 0,
        refreshTokens: 0,
        authorizationCodes: 0,
        pendingRequests: 0,
        grants: 0,
      }

      if (options.purgeRevoked) {
        counts.accessTokens += this.#affectedRows(
          await store.#query(OAuthAccessToken).whereNotNull('revokedAt').delete()
        )
        counts.refreshTokens += this.#affectedRows(
          await store.#query(OAuthRefreshToken)
            .where('revokedAt', '<', options.cutoff.toSQL()!)
            .delete()
        )
      }

      if (options.purgeExpired) {
        counts.accessTokens += this.#affectedRows(
          await store.#query(OAuthAccessToken)
            .where('expiresAt', '<', options.cutoff.toSQL()!)
            .whereNull('revokedAt')
            .delete()
        )
        counts.refreshTokens += this.#affectedRows(
          await store.#query(OAuthRefreshToken)
            .where('expiresAt', '<', options.cutoff.toSQL()!)
            .whereNull('revokedAt')
            .delete()
        )
        counts.authorizationCodes += this.#affectedRows(
          await store.#query(OAuthAuthorizationCode)
            .where('expiresAt', '<', options.cutoff.toSQL()!)
            .delete()
        )
        counts.grants += this.#affectedRows(
          await store.#query(OAuthGrant).where('expiresAt', '<', options.cutoff.toSQL()!).delete()
        )
      }

      counts.pendingRequests += this.#affectedRows(
        await store.#query(OAuthPendingAuthorizationRequest)
          .where('expiresAt', '<', options.now.toSQL()!)
          .delete()
      )

      return counts
    })
  }

  /**
   * Delete dynamically registered clients that were never authorized and are unused.
   */
  async purgeUnusedClients(options: PurgeUnusedClientsOptions): Promise<number> {
    return this.#transaction(async (store) => {
      const candidates = await store.#unusedClientsQuery().where(
        'createdAt',
        '<',
        options.createdBefore.toSQL()!
      )

      const clientIds = candidates
        .map((client) => this.#clientRecord(client))
        .filter((client) => isPurgeableClient(client.metadata))
        .map((client) => client.clientId)

      let deleted = 0
      for (const chunk of chunkClientIds(clientIds)) {
        deleted += this.#affectedRows(
          await store.#unusedClientsQuery().whereIn('clientId', chunk).delete()
        )
      }

      return deleted
    })
  }
}

/**
 * Create a Sesame store backed by the application's Lucid connection.
 */
export function lucidStore(): SesameStore {
  return new LucidStore()
}

export {
  OAuthAccessToken,
  OAuthAuthorizationCode,
  OAuthClient,
  OAuthGrant,
  OAuthPendingAuthorizationRequest,
  OAuthRefreshToken,
}
