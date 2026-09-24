import { MysqlAdapter, PostgresAdapter, SqliteAdapter, type Kysely, type Transaction } from 'kysely'
import { DateTime } from 'luxon'
import { retryConsentConflict } from '../consent_retry.js'
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
  PurgeTokensOptions,
  RotateRefreshTokenOptions,
  SesamePurgeResult,
  SesameStore,
  UpdateClientRecord,
} from '../types.js'

export type KyselyDialect = 'sqlite' | 'postgres' | 'mysql'

export interface KyselyStoreOptions<DB> {
  db: Kysely<DB>
  /**
   * Required only when a custom Kysely adapter cannot be identified.
   */
  dialect?: KyselyDialect
}

interface TableShape {
  name: string
  json: readonly string[]
  dates: readonly string[]
  booleans?: readonly string[]
  nullable?: readonly string[]
  updatedAt?: boolean
}

type DatabaseConnection = Kysely<any> | Transaction<any>
type Row = Record<string, unknown>

const tables = {
  clients: {
    name: 'oauth_clients',
    json: ['redirectUris', 'scopes', 'grantTypes', 'metadata'],
    dates: ['createdAt', 'updatedAt'],
    booleans: ['isPublic', 'isDisabled', 'requirePkce'],
    nullable: ['clientSecret', 'type', 'metadata', 'userId'],
    updatedAt: true,
  },
  accessTokens: {
    name: 'oauth_access_tokens',
    json: ['scopes'],
    dates: ['expiresAt', 'revokedAt', 'createdAt', 'updatedAt'],
    nullable: ['userId', 'revokedAt'],
    updatedAt: true,
  },
  refreshTokens: {
    name: 'oauth_refresh_tokens',
    json: ['scopes'],
    dates: ['expiresAt', 'revokedAt', 'createdAt', 'updatedAt'],
    nullable: ['revokedAt'],
    updatedAt: true,
  },
  authorizationCodes: {
    name: 'oauth_authorization_codes',
    json: ['scopes'],
    dates: ['expiresAt', 'createdAt', 'updatedAt'],
    nullable: ['codeChallenge', 'codeChallengeMethod', 'nonce'],
    updatedAt: true,
  },
  consents: {
    name: 'oauth_consents',
    json: ['scopes'],
    dates: ['createdAt', 'updatedAt'],
    updatedAt: true,
  },
  pendingAuthorizationRequests: {
    name: 'oauth_pending_authorization_requests',
    json: ['scopes'],
    dates: ['expiresAt', 'createdAt'],
    nullable: ['state', 'codeChallenge', 'codeChallengeMethod', 'nonce'],
  },
} satisfies Record<string, TableShape>

/**
 * Translate record fields to database column names.
 */
function snakeCase(value: string): string {
  return value.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)
}

/**
 * Translate database column names to record fields.
 */
function camelCase(value: string): string {
  return value.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase())
}

/**
 * Normalize driver timestamps to Luxon values.
 */
function toDateTime(value: unknown): DateTime {
  if (DateTime.isDateTime(value)) return value
  if (value instanceof Date) return DateTime.fromJSDate(value)
  if (typeof value === 'number') return DateTime.fromMillis(value)
  if (typeof value === 'string') {
    const iso = DateTime.fromISO(value, { setZone: true })
    if (iso.isValid) return iso

    const sql = DateTime.fromSQL(value, { setZone: true })
    if (sql.isValid) return sql
  }

  throw new TypeError(`Invalid database timestamp: ${String(value)}`)
}

/**
 * Encode a field according to its table and SQL dialect.
 */
function encodeValue(value: unknown, field: string, shape: TableShape, dialect: KyselyDialect) {
  if (value === null || value === undefined) return value
  if (shape.json.includes(field)) return JSON.stringify(value)
  if (shape.dates.includes(field)) {
    const date = toDateTime(value)
    return dialect === 'sqlite' ? date.toUTC().toISO() : date.toJSDate()
  }
  if (shape.booleans?.includes(field))
    return dialect === 'postgres' ? Boolean(value) : Number(value)

  return value
}

/**
 * Decode a field returned by a SQL driver.
 */
function decodeValue(value: unknown, field: string, shape: TableShape) {
  if (value === null || value === undefined) return value
  if (shape.json.includes(field)) return typeof value === 'string' ? JSON.parse(value) : value
  if (shape.dates.includes(field)) return toDateTime(value)
  if (shape.booleans?.includes(field)) return value === true || value === 1 || value === '1'

  return value
}

/**
 * Encode a record for a concrete SQL insert or update.
 */
function encodeRow(row: Row, shape: TableShape, dialect: KyselyDialect): Row {
  return Object.fromEntries(
    Object.entries(row).map(([field, value]) => [
      snakeCase(field),
      encodeValue(value, field, shape, dialect),
    ])
  )
}

/**
 * Decode a SQL row into an OAuth persistence record.
 */
function decodeRow<T>(row: Row, shape: TableShape): T {
  return Object.fromEntries(
    Object.entries(row).map(([column, value]) => {
      const field = camelCase(column)
      return [field, decodeValue(value, field, shape)]
    })
  ) as T
}

/**
 * Identify the connection's SQL dialect for value encoding.
 */
function inferDialect<DB>(db: Kysely<DB>): KyselyDialect {
  const adapter = db.getExecutor().adapter
  if (adapter instanceof SqliteAdapter) return 'sqlite'
  if (adapter instanceof PostgresAdapter) return 'postgres'
  if (adapter instanceof MysqlAdapter) return 'mysql'

  throw new Error('Unknown Kysely dialect. Pass the dialect option to kyselyStore().')
}

/**
 * OAuth persistence backed by a Kysely connection.
 */
export class KyselyStore implements SesameStore {
  #db: DatabaseConnection
  #dialect: KyselyDialect
  #inTransaction: boolean

  /**
   * Bind the store to a Kysely connection or an active transaction.
   */
  constructor(db: DatabaseConnection, dialect: KyselyDialect, inTransaction = false) {
    this.#db = db
    this.#dialect = dialect
    this.#inTransaction = inTransaction
  }

  /**
   * Add nullable fields and timestamps before encoding a new record.
   */
  #newRow(data: Row, shape: TableShape): Row {
    const row = { ...data }
    const now = DateTime.now()
    for (const field of shape.nullable ?? []) {
      if (row[field] === undefined) row[field] = null
    }
    if (!row.createdAt) row.createdAt = now
    if (shape.updatedAt && !row.updatedAt) row.updatedAt = now

    return encodeRow(row, shape, this.#dialect)
  }

  /**
   * Execute one OAuth operation in a transaction.
   */
  #transaction<T>(operation: (store: KyselyStore) => Promise<T>): Promise<T> {
    if (this.#inTransaction) throw new Error('Nested Sesame transactions are not supported')

    return (this.#db as Kysely<any>).transaction().execute(async (trx) => {
      return operation(new KyselyStore(trx, this.#dialect, true))
    })
  }

  /**
   * Return the client registered under a public client ID.
   */
  async findClient(clientId: string): Promise<OAuthClientRecord | null> {
    const row = await this.#db
      .selectFrom(tables.clients.name)
      .selectAll()
      .where('client_id', '=', clientId)
      .executeTakeFirst()

    return row ? decodeRow<OAuthClientRecord>(row, tables.clients) : null
  }

  /**
   * List clients in descending creation order, optionally for one user.
   */
  async listClients(options?: { userId?: string }): Promise<OAuthClientRecord[]> {
    let query = this.#db.selectFrom(tables.clients.name).selectAll()
    if (options?.userId) query = query.where('user_id', '=', options.userId)

    const rows = await query.orderBy('created_at', 'desc').execute()
    return rows.map((row: Row) => decodeRow<OAuthClientRecord>(row, tables.clients))
  }

  /**
   * Insert a new OAuth client and return its persisted representation.
   */
  async createClient(data: CreateClientRecord): Promise<OAuthClientRecord> {
    await this.#db
      .insertInto(tables.clients.name)
      .values(this.#newRow(data, tables.clients))
      .execute()

    const client = await this.findClient(data.clientId)
    if (!client) throw new Error('Failed to reload inserted OAuth client')

    return client
  }

  /**
   * Update the mutable metadata of one OAuth client.
   */
  async updateClient(options: { id: string; data: UpdateClientRecord }): Promise<void> {
    if (!Object.keys(options.data).length) return

    await this.#db
      .updateTable(tables.clients.name)
      .set(encodeRow({ ...options.data, updatedAt: DateTime.now() }, tables.clients, this.#dialect))
      .where('id', '=', options.id)
      .execute()
  }

  /**
   * Replace a confidential client's hashed secret.
   */
  async updateClientSecret(options: { id: string; secret: string }): Promise<void> {
    await this.#db
      .updateTable(tables.clients.name)
      .set(
        encodeRow(
          { clientSecret: options.secret, updatedAt: DateTime.now() },
          tables.clients,
          this.#dialect
        )
      )
      .where('id', '=', options.id)
      .execute()
  }

  /**
   * Delete a client and all OAuth records that refer to it.
   */
  async deleteClient(clientId: string): Promise<boolean> {
    return this.#transaction(async (store) => {
      const db = store.#db
      await db.deleteFrom(tables.refreshTokens.name).where('client_id', '=', clientId).execute()
      await db.deleteFrom(tables.accessTokens.name).where('client_id', '=', clientId).execute()
      await db
        .deleteFrom(tables.authorizationCodes.name)
        .where('client_id', '=', clientId)
        .execute()
      await db
        .deleteFrom(tables.pendingAuthorizationRequests.name)
        .where('client_id', '=', clientId)
        .execute()
      await db.deleteFrom(tables.consents.name).where('client_id', '=', clientId).execute()
      const result = await db
        .deleteFrom(tables.clients.name)
        .where('client_id', '=', clientId)
        .executeTakeFirst()

      return Number(result.numDeletedRows ?? 0) > 0
    })
  }

  /**
   * Find an access token by its hash, optionally restricted to a client.
   */
  async findAccessToken(options: {
    hash: string
    clientId?: string
  }): Promise<OAuthAccessTokenRecord | null> {
    let query = this.#db
      .selectFrom(tables.accessTokens.name)
      .selectAll()
      .where('token_hash', '=', options.hash)
    if (options.clientId) query = query.where('client_id', '=', options.clientId)

    const row = await query.executeTakeFirst()
    return row ? decodeRow<OAuthAccessTokenRecord>(row, tables.accessTokens) : null
  }

  /**
   * Persist a hashed access token.
   */
  async createAccessToken(data: CreateAccessTokenRecord): Promise<void> {
    await this.#db
      .insertInto(tables.accessTokens.name)
      .values(this.#newRow(data, tables.accessTokens))
      .execute()
  }

  /**
   * Conditionally revoke an active access token owned by a client.
   */
  async revokeAccessToken(options: {
    hash: string
    clientId: string
    now: DateTime
  }): Promise<boolean> {
    const result = await this.#db
      .updateTable(tables.accessTokens.name)
      .set(
        encodeRow(
          { revokedAt: options.now, updatedAt: options.now },
          tables.accessTokens,
          this.#dialect
        )
      )
      .where('token_hash', '=', options.hash)
      .where('client_id', '=', options.clientId)
      .where('revoked_at', 'is', null)
      .executeTakeFirst()

    return Number(result.numUpdatedRows ?? 0) > 0
  }

  /**
   * Find a refresh token by its hash and owning client.
   */
  async findRefreshToken(options: {
    hash: string
    clientId: string
  }): Promise<OAuthRefreshTokenRecord | null> {
    const row = await this.#db
      .selectFrom(tables.refreshTokens.name)
      .selectAll()
      .where('token', '=', options.hash)
      .where('client_id', '=', options.clientId)
      .executeTakeFirst()

    return row ? decodeRow<OAuthRefreshTokenRecord>(row, tables.refreshTokens) : null
  }

  /**
   * Revoke a refresh token and the access token paired with it atomically.
   */
  async revokeRefreshToken(options: {
    hash: string
    clientId: string
    now: DateTime
  }): Promise<void> {
    await this.#transaction(async (store) => {
      const token = await store.findRefreshToken(options)
      if (!token || token.revokedAt) return

      const values = encodeRow(
        { revokedAt: options.now, updatedAt: options.now },
        tables.refreshTokens,
        this.#dialect
      )
      const result = await store.#db
        .updateTable(tables.refreshTokens.name)
        .set(values)
        .where('id', '=', token.id)
        .where('revoked_at', 'is', null)
        .executeTakeFirst()
      if (Number(result.numUpdatedRows ?? 0) === 0) return

      await store.#db
        .updateTable(tables.accessTokens.name)
        .set(
          encodeRow(
            { revokedAt: options.now, updatedAt: options.now },
            tables.accessTokens,
            this.#dialect
          )
        )
        .where('id', '=', token.accessTokenId)
        .where('revoked_at', 'is', null)
        .execute()
    })
  }

  /**
   * Delete refresh tokens and revoke access tokens after replay detection.
   */
  async revokeTokenFamily(options: {
    clientId: string
    userId: string
    now: DateTime
  }): Promise<void> {
    await this.#transaction(async (store) => {
      await store.#db
        .deleteFrom(tables.refreshTokens.name)
        .where('client_id', '=', options.clientId)
        .where('user_id', '=', options.userId)
        .execute()
      await store.#db
        .updateTable(tables.accessTokens.name)
        .set(
          encodeRow(
            { revokedAt: options.now, updatedAt: options.now },
            tables.accessTokens,
            this.#dialect
          )
        )
        .where('client_id', '=', options.clientId)
        .where('user_id', '=', options.userId)
        .where('revoked_at', 'is', null)
        .execute()
    })
  }

  /**
   * Find an authorization code by its hash and owning client.
   */
  async findAuthorizationCode(options: {
    code: string
    clientId: string
  }): Promise<OAuthAuthorizationCodeRecord | null> {
    const row = await this.#db
      .selectFrom(tables.authorizationCodes.name)
      .selectAll()
      .where('code', '=', options.code)
      .where('client_id', '=', options.clientId)
      .executeTakeFirst()

    return row ? decodeRow<OAuthAuthorizationCodeRecord>(row, tables.authorizationCodes) : null
  }

  /**
   * Persist a hashed, short-lived authorization code.
   */
  async createAuthorizationCode(data: CreateAuthorizationCodeRecord): Promise<void> {
    await this.#db
      .insertInto(tables.authorizationCodes.name)
      .values(this.#newRow(data, tables.authorizationCodes))
      .execute()
  }

  /**
   * Remove an invalid or expired authorization code.
   */
  async deleteAuthorizationCode(id: string): Promise<void> {
    await this.#db.deleteFrom(tables.authorizationCodes.name).where('id', '=', id).execute()
  }

  /**
   * Consume a code once and issue its token pair in one transaction.
   */
  async exchangeAuthorizationCode(options: ExchangeAuthorizationCodeOptions): Promise<boolean> {
    return this.#transaction(async (store) => {
      const deleted = await store.#db
        .deleteFrom(tables.authorizationCodes.name)
        .where('id', '=', options.codeId)
        .executeTakeFirst()
      if (Number(deleted.numDeletedRows ?? 0) !== 1) return false

      await store.createAccessToken(options.accessToken)
      if (options.refreshToken) {
        await store.#db
          .insertInto(tables.refreshTokens.name)
          .values(store.#newRow(options.refreshToken, tables.refreshTokens))
          .execute()
      }

      return true
    })
  }

  /**
   * Find scopes consented to by a user for a client.
   */
  async findConsent(options: {
    clientId: string
    userId: string
  }): Promise<OAuthConsentRecord | null> {
    const row = await this.#db
      .selectFrom(tables.consents.name)
      .selectAll()
      .where('client_id', '=', options.clientId)
      .where('user_id', '=', options.userId)
      .executeTakeFirst()

    return row ? decodeRow<OAuthConsentRecord>(row, tables.consents) : null
  }

  /**
   * Merge newly granted scopes into the user's existing consent.
   */
  async grantConsent(options: {
    clientId: string
    userId: string
    scopes: string[]
  }): Promise<void> {
    await retryConsentConflict(() =>
      this.#transaction(async (store) => {
        const query = store.#db
          .selectFrom(tables.consents.name)
          .selectAll()
          .where('client_id', '=', options.clientId)
          .where('user_id', '=', options.userId)
        const row = await (
          this.#dialect === 'sqlite' ? query : query.forUpdate()
        ).executeTakeFirst()

        if (row) {
          const existing = decodeRow<OAuthConsentRecord>(row, tables.consents)
          const scopes = [...new Set([...existing.scopes, ...options.scopes])]
          await store.#db
            .updateTable(tables.consents.name)
            .set(encodeRow({ scopes, updatedAt: DateTime.now() }, tables.consents, this.#dialect))
            .where('id', '=', existing.id)
            .execute()
          return
        }

        await store.#db
          .insertInto(tables.consents.name)
          .values(store.#newRow({ id: crypto.randomUUID(), ...options }, tables.consents))
          .execute()
      })
    )
  }

  /**
   * Persist the authorization context for the consent redirect.
   */
  async createPendingAuthorizationRequest(
    data: CreatePendingAuthorizationRequestRecord
  ): Promise<void> {
    await this.#db
      .insertInto(tables.pendingAuthorizationRequests.name)
      .values(this.#newRow(data, tables.pendingAuthorizationRequests))
      .execute()
  }

  /**
   * Delete and return an unexpired pending request exactly once.
   */
  async consumePendingAuthorizationRequest(options: {
    token: string
    userId: string
    now: DateTime
  }): Promise<OAuthPendingAuthorizationRequestRecord | null> {
    return this.#transaction(async (store) => {
      const row = await store.#db
        .selectFrom(tables.pendingAuthorizationRequests.name)
        .selectAll()
        .where('token', '=', options.token)
        .where('user_id', '=', options.userId)
        .where(
          'expires_at',
          '>',
          encodeValue(options.now, 'expiresAt', tables.pendingAuthorizationRequests, this.#dialect)
        )
        .executeTakeFirst()
      if (!row) return null

      const deleted = await store.#db
        .deleteFrom(tables.pendingAuthorizationRequests.name)
        .where('id', '=', row.id as string)
        .where(
          'expires_at',
          '>',
          encodeValue(options.now, 'expiresAt', tables.pendingAuthorizationRequests, this.#dialect)
        )
        .executeTakeFirst()
      if (Number(deleted.numDeletedRows ?? 0) !== 1) return null

      return decodeRow<OAuthPendingAuthorizationRequestRecord>(
        row,
        tables.pendingAuthorizationRequests
      )
    })
  }

  /**
   * Issue an access and refresh token together for grace-period reuse.
   */
  async issueTokenPair(options: IssueTokenPairOptions): Promise<void> {
    await this.#transaction(async (store) => {
      await store.createAccessToken(options.accessToken)
      await store.#db
        .insertInto(tables.refreshTokens.name)
        .values(store.#newRow(options.refreshToken, tables.refreshTokens))
        .execute()
    })
  }

  /**
   * Conditionally rotate a refresh token and replace its access token.
   */
  async rotateRefreshToken(options: RotateRefreshTokenOptions): Promise<boolean> {
    return this.#transaction(async (store) => {
      const result = await store.#db
        .updateTable(tables.refreshTokens.name)
        .set(
          encodeRow(
            { revokedAt: options.revokedAt, updatedAt: options.revokedAt },
            tables.refreshTokens,
            this.#dialect
          )
        )
        .where('id', '=', options.oldRefreshTokenId)
        .where('revoked_at', 'is', null)
        .executeTakeFirst()
      if (Number(result.numUpdatedRows ?? 0) !== 1) return false

      await store.#db
        .updateTable(tables.accessTokens.name)
        .set(
          encodeRow(
            { revokedAt: options.revokedAt, updatedAt: options.revokedAt },
            tables.accessTokens,
            this.#dialect
          )
        )
        .where('id', '=', options.oldAccessTokenId)
        .where('revoked_at', 'is', null)
        .execute()
      await store.createAccessToken(options.accessToken)
      await store.#db
        .insertInto(tables.refreshTokens.name)
        .values(store.#newRow(options.refreshToken, tables.refreshTokens))
        .execute()

      return true
    })
  }

  /**
   * Revoke tokens and discard codes and consents for a deleted user.
   */
  async revokeAllForUser(options: { userId: string; now: DateTime }): Promise<void> {
    await this.#transaction(async (store) => {
      await store.#db
        .updateTable(tables.accessTokens.name)
        .set(
          encodeRow(
            { revokedAt: options.now, updatedAt: options.now },
            tables.accessTokens,
            this.#dialect
          )
        )
        .where('user_id', '=', options.userId)
        .where('revoked_at', 'is', null)
        .execute()
      await store.#db
        .updateTable(tables.refreshTokens.name)
        .set(
          encodeRow(
            { revokedAt: options.now, updatedAt: options.now },
            tables.refreshTokens,
            this.#dialect
          )
        )
        .where('user_id', '=', options.userId)
        .where('revoked_at', 'is', null)
        .execute()
      await store.#db
        .deleteFrom(tables.authorizationCodes.name)
        .where('user_id', '=', options.userId)
        .execute()
      await store.#db
        .deleteFrom(tables.pendingAuthorizationRequests.name)
        .where('user_id', '=', options.userId)
        .execute()
      await store.#db
        .deleteFrom(tables.consents.name)
        .where('user_id', '=', options.userId)
        .execute()
    })
  }

  /**
   * Purge revoked and expired records, returning deleted row counts.
   */
  async purgeTokens(options: PurgeTokensOptions): Promise<SesamePurgeResult> {
    return this.#transaction(async (store) => {
      const result: SesamePurgeResult = {
        accessTokens: 0,
        refreshTokens: 0,
        authorizationCodes: 0,
        pendingRequests: 0,
      }
      const db = store.#db

      if (options.purgeRevoked) {
        const access = await db
          .deleteFrom(tables.accessTokens.name)
          .where('revoked_at', 'is not', null)
          .executeTakeFirst()
        const refresh = await db
          .deleteFrom(tables.refreshTokens.name)
          .where('revoked_at', 'is not', null)
          .executeTakeFirst()
        result.accessTokens += Number(access.numDeletedRows ?? 0)
        result.refreshTokens += Number(refresh.numDeletedRows ?? 0)
      }

      if (options.purgeExpired) {
        const access = await db
          .deleteFrom(tables.accessTokens.name)
          .where(
            'expires_at',
            '<',
            encodeValue(options.cutoff, 'expiresAt', tables.accessTokens, this.#dialect)
          )
          .where('revoked_at', 'is', null)
          .executeTakeFirst()
        const refresh = await db
          .deleteFrom(tables.refreshTokens.name)
          .where(
            'expires_at',
            '<',
            encodeValue(options.cutoff, 'expiresAt', tables.refreshTokens, this.#dialect)
          )
          .where('revoked_at', 'is', null)
          .executeTakeFirst()
        const codes = await db
          .deleteFrom(tables.authorizationCodes.name)
          .where(
            'expires_at',
            '<',
            encodeValue(options.cutoff, 'expiresAt', tables.authorizationCodes, this.#dialect)
          )
          .executeTakeFirst()
        result.accessTokens += Number(access.numDeletedRows ?? 0)
        result.refreshTokens += Number(refresh.numDeletedRows ?? 0)
        result.authorizationCodes += Number(codes.numDeletedRows ?? 0)
      }

      const pending = await db
        .deleteFrom(tables.pendingAuthorizationRequests.name)
        .where(
          'expires_at',
          '<',
          encodeValue(options.now, 'expiresAt', tables.pendingAuthorizationRequests, this.#dialect)
        )
        .executeTakeFirst()
      result.pendingRequests = Number(pending.numDeletedRows ?? 0)

      return result
    })
  }
}

/**
 * Create a Sesame persistence store backed by an existing Kysely connection.
 */
export function kyselyStore<DB>(options: KyselyStoreOptions<DB>): SesameStore {
  const dialect = options.dialect ?? inferDialect(options.db)
  return new KyselyStore(options.db, dialect)
}
