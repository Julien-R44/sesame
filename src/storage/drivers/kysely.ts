import {
  MysqlAdapter,
  PostgresAdapter,
  SqliteAdapter,
  type ExpressionBuilder,
  type Kysely,
  type Transaction,
} from 'kysely'
import { DateTime } from 'luxon'
import { CLIENT_USAGE_TABLES, chunkClientIds, isPurgeableClient } from '../unused_clients.js'
import { falseOnInactiveGrant, InactiveGrantError } from '../inactive_grant.js'
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
    nullable: ['userId', 'grantId', 'revokedAt'],
    updatedAt: true,
  },
  refreshTokens: {
    name: 'oauth_refresh_tokens',
    json: ['scopes'],
    dates: ['expiresAt', 'revokedAt', 'createdAt', 'updatedAt'],
    nullable: ['grantId', 'revokedAt'],
    updatedAt: true,
  },
  authorizationCodes: {
    name: 'oauth_authorization_codes',
    json: ['scopes'],
    dates: ['expiresAt', 'consumedAt', 'createdAt', 'updatedAt'],
    nullable: ['grantId', 'codeChallenge', 'codeChallengeMethod', 'nonce', 'consumedAt'],
    updatedAt: true,
  },
  grants: {
    name: 'oauth_grants',
    json: ['scopes', 'context'],
    dates: ['expiresAt', 'createdAt', 'updatedAt'],
    nullable: ['context'],
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
 * Match clients referenced by no token, code, grant, or pending request.
 */
function isUnusedClient(eb: ExpressionBuilder<any, any>) {
  return eb.and(
    CLIENT_USAGE_TABLES.map((table) =>
      eb.not(
        eb.exists(
          eb
            .selectFrom(table)
            .select(eb.lit(1).as('used'))
            .whereRef(`${table}.client_id`, '=', `${tables.clients.name}.client_id`)
        )
      )
    )
  )
}

/**
 * Split an access token row joined with its grant into both records.
 */
function decodeTokenWithGrant(row: Row): OAuthAccessTokenWithGrantRecord {
  const tokenRow: Row = {}
  const grantRow: Row = {}
  for (const [column, value] of Object.entries(row)) {
    if (column.startsWith(GRANT_PREFIX)) grantRow[column.slice(GRANT_PREFIX.length)] = value
    else tokenRow[column] = value
  }

  const token = decodeRow<OAuthAccessTokenRecord>(tokenRow, tables.accessTokens)
  if (grantRow.id === null || grantRow.id === undefined) return { ...token, grant: null }

  return { ...token, grant: decodeRow<OAuthGrantRecord>(grantRow, tables.grants) }
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
   * Extend or create the grant written alongside a token issuance.
   * Must run inside a transaction.
   */
  async #applyGrantWrite(write?: TokenGrantWrite): Promise<void> {
    if (!write) return
    if (write.type === 'create') {
      await this.#db
        .insertInto(tables.grants.name)
        .values(this.#newRow(write.grant, tables.grants))
        .execute()
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
    const query = this.#db
      .selectFrom(tables.grants.name)
      .select('expires_at')
      .where('id', '=', write.id)
      .where('expires_at', '>', encodeValue(now, 'expiresAt', tables.grants, this.#dialect))
    const row = await (this.#dialect === 'sqlite' ? query : query.forUpdate()).executeTakeFirst()
    if (!row) throw new InactiveGrantError()
    if (toDateTime(row.expires_at) >= write.expiresAt) return

    await this.#db
      .updateTable(tables.grants.name)
      .set(encodeRow({ expiresAt: write.expiresAt, updatedAt: now }, tables.grants, this.#dialect))
      .where('id', '=', write.id)
      .execute()
  }

  /**
   * Attach pre-grant credentials to a newly created grant.
   */
  async #adoptIntoGrant(grantId: string, adopt: GrantAdoption): Promise<void> {
    const targets = [
      { table: tables.authorizationCodes.name, id: adopt.codeId },
      { table: tables.refreshTokens.name, id: adopt.refreshTokenId },
      { table: tables.accessTokens.name, id: adopt.accessTokenId },
    ]

    for (const target of targets) {
      if (!target.id) continue

      await this.#db
        .updateTable(target.table)
        .set({ grant_id: grantId })
        .where('id', '=', target.id)
        .where('grant_id', 'is', null)
        .execute()
    }
  }

  /**
   * Delete grants with their codes and refresh tokens and revoke their
   * access tokens. Must run inside a transaction. The grants are deleted
   * first so a concurrent issuance holding their lock cannot outlive them.
   */
  async #revokeGrantIds(ids: string[], now: DateTime): Promise<number> {
    if (ids.length === 0) return 0

    const result = await this.#db
      .deleteFrom(tables.grants.name)
      .where('id', 'in', ids)
      .executeTakeFirst()
    await this.#db.deleteFrom(tables.refreshTokens.name).where('grant_id', 'in', ids).execute()
    await this.#db.deleteFrom(tables.authorizationCodes.name).where('grant_id', 'in', ids).execute()
    await this.#db
      .updateTable(tables.accessTokens.name)
      .set(encodeRow({ revokedAt: now, updatedAt: now }, tables.accessTokens, this.#dialect))
      .where('grant_id', 'in', ids)
      .where('revoked_at', 'is', null)
      .execute()

    return Number(result.numDeletedRows ?? 0)
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
      await db.deleteFrom(tables.grants.name).where('client_id', '=', clientId).execute()
      const result = await db
        .deleteFrom(tables.clients.name)
        .where('client_id', '=', clientId)
        .executeTakeFirst()

      return Number(result.numDeletedRows ?? 0) > 0
    })
  }

  /**
   * Find an access token and its grant by the token hash in one query,
   * optionally restricted to a client.
   */
  async findAccessToken(options: {
    hash: string
    clientId?: string
  }): Promise<OAuthAccessTokenWithGrantRecord | null> {
    let query = this.#db
      .selectFrom(`${tables.accessTokens.name} as t`)
      .leftJoin(`${tables.grants.name} as g`, 'g.id', 't.grant_id')
      .selectAll('t')
      .select(GRANT_COLUMNS.map((column) => `g.${column} as ${GRANT_PREFIX}${column}`) as any)
      .where('t.token_hash', '=', options.hash)
    if (options.clientId) query = query.where('t.client_id', '=', options.clientId)

    const row = await query.executeTakeFirst()
    return row ? decodeTokenWithGrant(row as Row) : null
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
   * Delete refresh tokens and revoke access tokens without a grant after replay detection.
   */
  async revokeLegacyTokenFamily(options: {
    clientId: string
    userId: string
    now: DateTime
  }): Promise<void> {
    await this.#transaction(async (store) => {
      await store.#db
        .deleteFrom(tables.refreshTokens.name)
        .where('client_id', '=', options.clientId)
        .where('user_id', '=', options.userId)
        .where('grant_id', 'is', null)
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
        .where('grant_id', 'is', null)
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
    return falseOnInactiveGrant(() =>
      this.#transaction(async (store) => {
        const consumed = await store.#db
          .updateTable(tables.authorizationCodes.name)
          .set(
            encodeRow(
              { consumedAt: options.consumedAt, updatedAt: options.consumedAt },
              tables.authorizationCodes,
              this.#dialect
            )
          )
          .where('id', '=', options.codeId)
          .where('consumed_at', 'is', null)
          .executeTakeFirst()
        if (Number(consumed.numUpdatedRows ?? 0) !== 1) return false

        await store.#applyGrantWrite(options.grant)
        await store.createAccessToken(options.accessToken)
        if (options.refreshToken) {
          await store.#db
            .insertInto(tables.refreshTokens.name)
            .values(store.#newRow(options.refreshToken, tables.refreshTokens))
            .execute()
        }

        return true
      })
    )
  }

  /**
   * Persist a new grant.
   */
  async createGrant(data: CreateGrantRecord): Promise<void> {
    await this.#db
      .insertInto(tables.grants.name)
      .values(this.#newRow(data, tables.grants))
      .execute()
  }

  /**
   * Find a grant by its identifier.
   */
  async findGrant(id: string): Promise<OAuthGrantRecord | null> {
    const row = await this.#db
      .selectFrom(tables.grants.name)
      .selectAll()
      .where('id', '=', id)
      .executeTakeFirst()

    return row ? decodeRow<OAuthGrantRecord>(row, tables.grants) : null
  }

  /**
   * List a user's grants newest first, optionally for one client or only active ones.
   */
  async listGrants(options: ListStoredGrantsOptions): Promise<OAuthGrantRecord[]> {
    let query = this.#db
      .selectFrom(tables.grants.name)
      .selectAll()
      .where('user_id', '=', options.userId)
    if (options.clientId) query = query.where('client_id', '=', options.clientId)
    if (options.activeAt) {
      query = query.where(
        'expires_at',
        '>',
        encodeValue(options.activeAt, 'expiresAt', tables.grants, this.#dialect)
      )
    }

    const rows = await query.orderBy('created_at', 'desc').execute()
    return rows.map((row: Row) => decodeRow<OAuthGrantRecord>(row, tables.grants))
  }

  /**
   * Update the mutable fields of a grant.
   */
  async updateGrant(options: { id: string; data: UpdateGrantRecord }): Promise<void> {
    if (!Object.keys(options.data).length) return

    await this.#db
      .updateTable(tables.grants.name)
      .set(encodeRow({ ...options.data, updatedAt: DateTime.now() }, tables.grants, this.#dialect))
      .where('id', '=', options.id)
      .execute()
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
      let query = store.#db
        .selectFrom(tables.grants.name)
        .select('id')
        .where('user_id', '=', options.userId)
      if (options.clientId) query = query.where('client_id', '=', options.clientId)

      const rows = await query.execute()

      return store.#revokeGrantIds(
        rows.map((row: Row) => String(row.id)),
        options.now
      )
    })
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
   * Read an unexpired pending request for its owner without consuming it.
   */
  async findPendingAuthorizationRequest(
    options: PendingAuthorizationRequestLookupOptions
  ): Promise<OAuthPendingAuthorizationRequestRecord | null> {
    const row = await this.#db
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

    return decodeRow<OAuthPendingAuthorizationRequestRecord>(
      row,
      tables.pendingAuthorizationRequests
    )
  }

  /**
   * Delete and return an unexpired pending request exactly once.
   */
  async consumePendingAuthorizationRequest(
    options: PendingAuthorizationRequestLookupOptions
  ): Promise<OAuthPendingAuthorizationRequestRecord | null> {
    return this.#transaction(async (store) => {
      const request = await store.findPendingAuthorizationRequest(options)
      if (!request) return null

      const deleted = await store.#db
        .deleteFrom(tables.pendingAuthorizationRequests.name)
        .where('id', '=', request.id)
        .where(
          'expires_at',
          '>',
          encodeValue(options.now, 'expiresAt', tables.pendingAuthorizationRequests, this.#dialect)
        )
        .executeTakeFirst()
      if (Number(deleted.numDeletedRows ?? 0) !== 1) return null

      return request
    })
  }

  /**
   * Issue an access and refresh token together for grace-period reuse.
   */
  async issueTokenPair(options: IssueTokenPairOptions): Promise<boolean> {
    return falseOnInactiveGrant(() =>
      this.#transaction(async (store) => {
        await store.#applyGrantWrite(options.grant)
        await store.createAccessToken(options.accessToken)
        await store.#db
          .insertInto(tables.refreshTokens.name)
          .values(store.#newRow(options.refreshToken, tables.refreshTokens))
          .execute()

        return true
      })
    )
  }

  /**
   * Conditionally rotate a refresh token and replace its access token.
   */
  async rotateRefreshToken(options: RotateRefreshTokenOptions): Promise<boolean> {
    return falseOnInactiveGrant(() =>
      this.#transaction(async (store) => {
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
        await store.#applyGrantWrite(options.grant)
        await store.createAccessToken(options.accessToken)
        await store.#db
          .insertInto(tables.refreshTokens.name)
          .values(store.#newRow(options.refreshToken, tables.refreshTokens))
          .execute()

        return true
      })
    )
  }

  /**
   * Revoke tokens and discard codes and grants for a deleted user.
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
      await store.#db.deleteFrom(tables.grants.name).where('user_id', '=', options.userId).execute()
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
        grants: 0,
      }
      const db = store.#db

      if (options.purgeRevoked) {
        const access = await db
          .deleteFrom(tables.accessTokens.name)
          .where('revoked_at', 'is not', null)
          .executeTakeFirst()
        const refresh = await db
          .deleteFrom(tables.refreshTokens.name)
          .where(
            'revoked_at',
            '<',
            encodeValue(options.cutoff, 'revokedAt', tables.refreshTokens, this.#dialect)
          )
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
        const grants = await db
          .deleteFrom(tables.grants.name)
          .where(
            'expires_at',
            '<',
            encodeValue(options.cutoff, 'expiresAt', tables.grants, this.#dialect)
          )
          .executeTakeFirst()
        result.authorizationCodes += Number(codes.numDeletedRows ?? 0)
        result.grants += Number(grants.numDeletedRows ?? 0)
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

  /**
   * Delete dynamically registered clients that were never authorized and are unused.
   */
  async purgeUnusedClients(options: PurgeUnusedClientsOptions): Promise<number> {
    return this.#transaction(async (store) => {
      const db = store.#db
      const createdBefore = encodeValue(
        options.createdBefore,
        'createdAt',
        tables.clients,
        this.#dialect
      )

      const candidates = await db
        .selectFrom(tables.clients.name)
        .select(['client_id', 'metadata'])
        .where('created_at', '<', createdBefore)
        .where(isUnusedClient)
        .execute()

      const clientIds = candidates
        .map((row: Row) =>
          decodeRow<Pick<OAuthClientRecord, 'clientId' | 'metadata'>>(row, tables.clients)
        )
        .filter((client) => isPurgeableClient(client.metadata))
        .map((client) => client.clientId)

      let deleted = 0
      for (const chunk of chunkClientIds(clientIds)) {
        const result = await db
          .deleteFrom(tables.clients.name)
          .where('client_id', 'in', chunk)
          .where(isUnusedClient)
          .executeTakeFirst()
        deleted += Number(result.numDeletedRows ?? 0)
      }

      return deleted
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
