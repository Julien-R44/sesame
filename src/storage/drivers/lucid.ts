import { DateTime } from 'luxon'
import { BaseModel } from '@adonisjs/lucid/orm'
import { retryConsentConflict } from '../consent_retry.js'
import { OAuthAccessToken } from '../../models/oauth_access_token.js'
import { OAuthAuthorizationCode } from '../../models/oauth_authorization_code.js'
import { OAuthClient } from '../../models/oauth_client.js'
import { OAuthConsent } from '../../models/oauth_consent.js'
import { OAuthPendingAuthorizationRequest } from '../../models/oauth_pending_authorization_request.js'
import { OAuthRefreshToken } from '../../models/oauth_refresh_token.js'
import type {
  CreateAccessTokenRecord,
  CreateAuthorizationCodeRecord,
  CreateClientRecord,
  CreatePendingAuthorizationRequestRecord,
  ExchangeAuthorizationCodeOptions,
  IssueTokenPairOptions,
  OAuthAccessTokenRecord,
  OAuthAuthorizationCodeRecord,
  OAuthClientRecord,
  OAuthConsentRecord,
  OAuthPendingAuthorizationRequestRecord,
  OAuthRefreshTokenRecord,
  PendingAuthorizationRequestLookupOptions,
  PurgeTokensOptions,
  RotateRefreshTokenOptions,
  SesamePurgeResult,
  SesameStore,
  UpdateClientRecord,
} from '../types.js'

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
      await store.#query(OAuthConsent).where('clientId', clientId).delete()

      const count = this.#affectedRows(
        await store.#query(OAuthClient).where('id', client.id).delete()
      )

      return count === 1
    })
  }

  /**
   * Look up an access-token hash, optionally limited to one client.
   */
  async findAccessToken(options: {
    hash: string
    clientId?: string
  }): Promise<OAuthAccessTokenRecord | null> {
    const query = this.#query(OAuthAccessToken).where('tokenHash', options.hash)
    if (options.clientId) query.where('clientId', options.clientId)

    const token = await query.first()

    return token ? this.#record<OAuthAccessTokenRecord>(token, ['userId', 'revokedAt']) : null
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

    return token ? this.#record<OAuthRefreshTokenRecord>(token, ['revokedAt']) : null
  }

  /**
   * Revoke a refresh token and its associated active access token together.
   */
  async revokeRefreshToken(options: {
    hash: string
    clientId: string
    now: DateTime
  }): Promise<void> {
    await this.#transaction(async (store) => {
      const token = await store.findRefreshToken(options)
      if (!token) return

      const result = await store.#query(OAuthRefreshToken)
        .where('id', token.id)
        .whereNull('revokedAt')
        .update({ revokedAt: options.now.toSQL(), updatedAt: options.now.toSQL() })
      if (this.#affectedRows(result) !== 1) return

      await store.#query(OAuthAccessToken)
        .where('id', token.accessTokenId)
        .whereNull('revokedAt')
        .update({ revokedAt: options.now.toSQL(), updatedAt: options.now.toSQL() })
    })
  }

  /**
   * Invalidate a client's token family after refresh-token replay.
   */
  async revokeTokenFamily(options: {
    clientId: string
    userId: string
    now: DateTime
  }): Promise<void> {
    await this.#transaction(async (store) => {
      await store.#query(OAuthRefreshToken)
        .where('clientId', options.clientId)
        .where('userId', options.userId)
        .delete()
      await store.#query(OAuthAccessToken)
        .where('clientId', options.clientId)
        .where('userId', options.userId)
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
          'codeChallenge',
          'codeChallengeMethod',
          'nonce',
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
    return this.#transaction(async (store) => {
      const deleted = this.#affectedRows(
        await store.#query(OAuthAuthorizationCode).where('id', options.codeId).delete()
      )
      if (deleted !== 1) return false

      await store.createAccessToken(options.accessToken)
      if (options.refreshToken) {
        await OAuthRefreshToken.create(options.refreshToken, { client: store.#client })
      }

      return true
    })
  }

  /**
   * Find a user's current consent for a client.
   */
  async findConsent(options: {
    clientId: string
    userId: string
  }): Promise<OAuthConsentRecord | null> {
    const consent = await this.#query(OAuthConsent)
      .where('clientId', options.clientId)
      .where('userId', options.userId)
      .first()

    return consent ? this.#record<OAuthConsentRecord>(consent) : null
  }

  /**
   * Merge newly approved scopes into the user's consent.
   */
  async grantConsent(options: {
    clientId: string
    userId: string
    scopes: string[]
  }): Promise<void> {
    await retryConsentConflict(() =>
      this.#transaction(async (store) => {
        const row = await store.#query(OAuthConsent)
          .where('clientId', options.clientId)
          .where('userId', options.userId)
          .forUpdate()
          .first()

        if (row) {
          const existing = this.#record<OAuthConsentRecord>(row)
          const scopes = [...new Set([...existing.scopes, ...options.scopes])]
          await store.#query(OAuthConsent)
            .where('id', existing.id)
            .update({
              scopes: JSON.stringify(scopes),
              updatedAt: DateTime.now().toSQL(),
            })
          return
        }

        await OAuthConsent.create(
          {
            id: crypto.randomUUID(),
            clientId: options.clientId,
            userId: options.userId,
            scopes: options.scopes,
          },
          { client: store.#client }
        )
      })
    )
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
  async issueTokenPair(options: IssueTokenPairOptions): Promise<void> {
    await this.#transaction(async (store) => {
      await store.createAccessToken(options.accessToken)
      await OAuthRefreshToken.create(options.refreshToken, { client: store.#client })
    })
  }

  /**
   * Conditionally consume a refresh token and persist its replacement pair.
   */
  async rotateRefreshToken(options: RotateRefreshTokenOptions): Promise<boolean> {
    return this.#transaction(async (store) => {
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
      await store.createAccessToken(options.accessToken)
      await OAuthRefreshToken.create(options.refreshToken, { client: store.#client })

      return true
    })
  }

  /**
   * Revoke a user's tokens and remove their short-lived OAuth records.
   */
  async revokeAllForUser(options: { userId: string; now: DateTime }): Promise<void> {
    await this.#transaction(async (store) => {
      await store.#query(OAuthAccessToken)
        .where('userId', options.userId)
        .whereNull('revokedAt')
        .update({ revokedAt: options.now.toSQL(), updatedAt: options.now.toSQL() })
      await store.#query(OAuthRefreshToken)
        .where('userId', options.userId)
        .whereNull('revokedAt')
        .update({ revokedAt: options.now.toSQL(), updatedAt: options.now.toSQL() })
      await store.#query(OAuthAuthorizationCode).where('userId', options.userId).delete()
      await store.#query(OAuthPendingAuthorizationRequest).where('userId', options.userId).delete()
      await store.#query(OAuthConsent).where('userId', options.userId).delete()
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
      }

      if (options.purgeRevoked) {
        counts.accessTokens += this.#affectedRows(
          await store.#query(OAuthAccessToken).whereNotNull('revokedAt').delete()
        )
        counts.refreshTokens += this.#affectedRows(
          await store.#query(OAuthRefreshToken).whereNotNull('revokedAt').delete()
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
      }

      counts.pendingRequests += this.#affectedRows(
        await store.#query(OAuthPendingAuthorizationRequest)
          .where('expiresAt', '<', options.now.toSQL()!)
          .delete()
      )

      return counts
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
  OAuthConsent,
  OAuthPendingAuthorizationRequest,
  OAuthRefreshToken,
}
