import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { test } from '@japa/runner'
import type { Assert } from '@japa/assert'
import { AceFactory } from '@adonisjs/core/factories'
import { HttpContextFactory, RequestFactory } from '@adonisjs/core/factories/http'
import type { ApplicationService } from '@adonisjs/core/types'
import { MigrationRunner } from '@adonisjs/lucid/migration'
import Database from 'better-sqlite3'
import { Kysely, SqliteDialect } from 'kysely'
import { DateTime } from 'luxon'
import SesameUpgrade from '../commands/sesame_upgrade.ts'
import { createApp, createTestConfig } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createFakeEmitter, FakeUserProvider } from './helpers/fakes.ts'
import { SesameManager } from '../src/sesame_manager.ts'
import { OAuthGuard } from '../src/guard/guard.ts'
import { TokenService } from '../src/services/token_service.ts'
import { ExchangeRefreshTokenAction } from '../src/actions/exchange_refresh_token.ts'
import { lucidStore } from '../src/storage/drivers/lucid.ts'
import { kyselyStore } from '../src/storage/drivers/kysely.ts'
import type { SesameStore } from '../src/storage/types.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import * as kyselyUpgrade from '../src/storage/migrations/sesame_v000800_add_oauth_grants.ts'
import * as kyselyResourceUpgrade from '../src/storage/migrations/sesame_v000800_add_oauth_resource_columns.ts'
import * as kyselyV07 from './fixtures/migrations_0_7/kysely.ts'

const STUBS_ROOT = fileURLToPath(new URL('../stubs/', import.meta.url))
const RESOURCE_TABLES = [
  'oauth_pending_authorization_requests',
  'oauth_authorization_codes',
  'oauth_access_tokens',
  'oauth_refresh_tokens',
]

/**
 * List the tables of a Kysely database that have a `resource` column.
 */
async function kyselyResourceTables(db: Kysely<any>) {
  const tables = await db.introspection.getTables()

  return tables
    .filter((table) => table.columns.some((column) => column.name === 'resource'))
    .map((table) => table.name)
    .sort()
}

/**
 * Run the given Ace command inside a throwaway application root.
 */
async function runUpgradeCommand(argv: string[], cleanup: (fn: () => Promise<void>) => void) {
  const root = join(tmpdir(), `sesame-upgrade-${crypto.randomUUID()}`)
  await mkdir(root, { recursive: true })
  cleanup(() => rm(root, { recursive: true, force: true }))

  const ace = await new AceFactory().make(new URL(`file://${root}/`))
  await ace.boot()
  const command = await ace.create(SesameUpgrade, argv)
  await command.exec()

  return { command, root }
}

/**
 * Exercise legacy tokens on an upgraded database: the legacy access
 * token still authenticates, and the legacy refresh token is adopted
 * into a grant on rotation.
 */
async function assertLegacyTokensWork(options: {
  manager: SesameManager
  accessToken: string
  refreshToken: string
  assert: Assert
}) {
  const { manager, assert } = options
  const client = (await manager.store.findClient('test-client'))!
  const provider = new FakeUserProvider([{ id: 'user-1', name: 'Legacy User' }])

  /**
   * Authenticate a bearer token through the OAuth guard.
   */
  const authenticate = async (token: string) => {
    const request = new RequestFactory().merge({ url: '/' }).create()
    request.request.headers.authorization = `Bearer ${token}`
    const ctx = new HttpContextFactory().merge({ request }).create()
    const guard = new OAuthGuard('oauth', ctx, createFakeEmitter(), provider, manager)
    await guard.authenticate()

    return guard
  }

  const legacyGuard = await authenticate(options.accessToken)
  assert.isUndefined(legacyGuard.grantId)

  const refreshed = await new ExchangeRefreshTokenAction().execute(manager, {
    client,
    refreshToken: options.refreshToken,
  })
  const guard = await authenticate(refreshed.access_token)
  assert.isString(guard.grantId)
  assert.isNull(guard.context)
  assert.lengthOf(await manager.listGrants({ userId: 'user-1' }), 1)
}

/**
 * Seed a pre-grant token pair through a store that predates grant columns.
 */
async function seedLegacyTokens(options: { manager: SesameManager; insert: LegacyInsert }) {
  const tokenService = new TokenService(options.manager)
  const accessToken = tokenService.generateOpaqueToken()
  const refreshToken = tokenService.generateOpaqueToken()
  const accessTokenId = crypto.randomUUID()
  const now = DateTime.now()

  await options.insert('oauth_access_tokens', {
    id: accessTokenId,
    tokenHash: tokenService.hashToken(accessToken),
    clientId: 'test-client',
    userId: 'user-1',
    scopes: ['read'],
    expiresAt: now.plus({ hours: 1 }),
  })
  await options.insert('oauth_refresh_tokens', {
    id: crypto.randomUUID(),
    token: tokenService.hashToken(refreshToken),
    accessTokenId,
    clientId: 'test-client',
    userId: 'user-1',
    scopes: ['read'],
    expiresAt: now.plus({ days: 30 }),
  })

  return { accessToken, refreshToken }
}

type LegacyInsert = (table: string, row: Record<string, unknown>) => Promise<void>

test.group('sesame:upgrade command', () => {
  test('publishes every Lucid upgrade stub of a version', async ({ assert, cleanup }) => {
    const { command, root } = await runUpgradeCommand(['0.8'], cleanup)

    assert.equal(command.exitCode, 0)
    const stubs = await readdir(join(STUBS_ROOT, 'migrations/upgrade_0_8/lucid'))
    const published = await readdir(join(root, 'database/migrations'))
    assert.lengthOf(published, stubs.length)
    assert.isTrue(published.some((file) => /^\d+_upgrade_0_8_add_oauth_grants\.ts$/.test(file)))
    assert.isTrue(
      published.some((file) => /^\d+_upgrade_0_8_add_oauth_resource_columns\.ts$/.test(file))
    )
  })

  test('publishes the Kysely upgrade migrations', async ({ assert, cleanup }) => {
    const { command, root } = await runUpgradeCommand(['0.8.0', '--store=kysely'], cleanup)

    assert.equal(command.exitCode, 0)
    const contents = await readFile(
      join(root, 'database/kysely_migrations/sesame_v000800_add_oauth_grants.ts'),
      'utf8'
    )
    const source = await readFile(
      new URL('../src/storage/migrations/sesame_v000800_add_oauth_grants.ts', import.meta.url),
      'utf8'
    )
    assert.equal(contents.trimEnd(), source.trimEnd())

    const resourceContents = await readFile(
      join(root, 'database/kysely_migrations/sesame_v000800_add_oauth_resource_columns.ts'),
      'utf8'
    )
    const resourceSource = await readFile(
      new URL(
        '../src/storage/migrations/sesame_v000800_add_oauth_resource_columns.ts',
        import.meta.url
      ),
      'utf8'
    )
    assert.equal(resourceContents.trimEnd(), resourceSource.trimEnd())
  })

  test('keeps upgrade stub bodies free of template literal syntax', async ({ assert }) => {
    for (const store of ['lucid', 'kysely']) {
      const folder = join(STUBS_ROOT, 'migrations/upgrade_0_8', store)
      for (const file of await readdir(folder)) {
        const contents = await readFile(join(folder, file), 'utf8')
        const body = contents.slice(contents.indexOf('}}}') + 3)

        assert.notInclude(body, '`', file)
        assert.notInclude(body, '${', file)
      }
    }
  })

  test('fails for an unknown version or store', async ({ assert, cleanup }) => {
    const unknownVersion = await runUpgradeCommand(['0.1'], cleanup)
    assert.equal(unknownVersion.command.exitCode, 1)
    assert.isFalse(existsSync(join(unknownVersion.root, 'database')))

    const unknownStore = await runUpgradeCommand(['0.8', '--store=prisma'], cleanup)
    assert.equal(unknownStore.command.exitCode, 1)

    const malformed = await runUpgradeCommand(['../0.8'], cleanup)
    assert.equal(malformed.command.exitCode, 1)
  })
})

test.group('Upgrade 0.7 to 0.8 | Kysely', () => {
  test('migrates a 0.7 database, keeps legacy tokens working, and rolls back', async ({
    assert,
  }) => {
    const db = new Kysely<any>({
      dialect: new SqliteDialect({ database: new Database(':memory:') }),
    })

    try {
      await kyselyV07.up(db)
      const legacyStore = kyselyStore({ db }) as SesameStore
      const manager = new SesameManager(createTestConfig(), {} as any, legacyStore)
      await manager.createClient({ name: 'Legacy', redirectUris: [] })
      await db
        .updateTable('oauth_clients')
        .set({ client_id: 'test-client', grant_types: '["authorization_code","refresh_token"]' })
        .execute()
      const tokens = await seedLegacyTokens({
        manager,
        insert: async (table, row) => {
          await db
            .insertInto(table)
            .values(kyselyRow({ ...row, createdAt: DateTime.now(), updatedAt: DateTime.now() }))
            .execute()
        },
      })

      await kyselyUpgrade.up(db)
      await kyselyResourceUpgrade.up(db)
      assert.deepEqual(await kyselyResourceTables(db), [...RESOURCE_TABLES].sort())
      const tables = (await db.introspection.getTables()).map((table) => table.name)
      assert.include(tables, 'oauth_grants')
      assert.notInclude(tables, 'oauth_consents')

      await assertLegacyTokensWork({ manager, ...tokens, assert })

      await kyselyResourceUpgrade.down(db)
      assert.deepEqual(await kyselyResourceTables(db), [])
      await kyselyUpgrade.down(db)
      const restored = await db.introspection.getTables()
      assert.include(
        restored.map((table) => table.name),
        'oauth_consents'
      )
      const refreshColumns = restored
        .find((table) => table.name === 'oauth_refresh_tokens')!
        .columns.map((column) => column.name)
      assert.notInclude(refreshColumns, 'grant_id')
      await kyselyV07.down(db)
    } finally {
      await db.destroy()
    }
  })
})

/**
 * Encode a camelCase record for a raw SQLite insert.
 */
function kyselyRow(row: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(row).map(([field, value]) => {
      const column = field.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)
      if (DateTime.isDateTime(value)) return [column, value.toUTC().toISO()]
      if (Array.isArray(value)) return [column, JSON.stringify(value)]

      return [column, value]
    })
  )
}

test.group('Upgrade 0.7 to 0.8 | Lucid', () => {
  test('migrates a 0.7 database, keeps legacy tokens working, and rolls back', async ({
    assert,
    cleanup,
  }) => {
    const directory = fileURLToPath(
      new URL(`./tmp-upgrade-${crypto.randomUUID()}/`, import.meta.url)
    )
    await mkdir(directory, { recursive: true })
    cleanup(() => rm(directory, { recursive: true, force: true }))
    await cp(
      fileURLToPath(new URL('./fixtures/migrations_0_7/lucid/', import.meta.url)),
      directory,
      {
        recursive: true,
      }
    )

    const app = await createApp({ migrationsPaths: [directory] })
    cleanup(() => app.terminate())
    const db = await app.container.make('lucid.db')
    cleanup(() => db.manager.closeAll())

    await runLucidMigrations(app, 'up')
    await createTestClient()
    const manager = new SesameManager(createTestConfig(), {} as any, lucidStore())
    const tokens = await seedLegacyTokens({
      manager,
      insert: async (table, row) => {
        const model = table === 'oauth_access_tokens' ? OAuthAccessToken : OAuthRefreshToken
        await model.create(row)
      },
    })

    const stub = await (
      await app.stubs.create()
    ).build('migrations/upgrade_0_8/lucid/add_oauth_grants.stub', { source: STUBS_ROOT })
    const { contents } = await stub.prepare({ prefix: '0007' })
    await writeFile(join(directory, '0007_upgrade_0_8_add_oauth_grants.ts'), contents)
    const resourceStub = await (
      await app.stubs.create()
    ).build('migrations/upgrade_0_8/lucid/add_oauth_resource_columns.stub', {
      source: STUBS_ROOT,
    })
    const resourceMigration = await resourceStub.prepare({ prefix: '0008' })
    assert.match(resourceMigration.destination, /0008_upgrade_0_8_add_oauth_resource_columns\.ts$/)
    await writeFile(
      join(directory, '0008_upgrade_0_8_add_oauth_resource_columns.ts'),
      resourceMigration.contents
    )

    await runLucidMigrations(app, 'up')
    assert.isTrue(await db.connection().schema.hasTable('oauth_grants'))
    assert.isFalse(await db.connection().schema.hasTable('oauth_consents'))
    assert.isTrue(
      await db.connection().schema.hasColumn('oauth_authorization_codes', 'consumed_at')
    )
    for (const table of RESOURCE_TABLES) {
      assert.isTrue(await db.connection().schema.hasColumn(table, 'resource'), table)
    }

    await assertLegacyTokensWork({ manager, ...tokens, assert })

    await runLucidMigrations(app, 'down')
    assert.isFalse(await db.connection().schema.hasTable('oauth_grants'))
    assert.isFalse(await db.connection().schema.hasTable('oauth_clients'))
  })
})

/**
 * Run every pending Lucid migration, or roll every batch back.
 */
async function runLucidMigrations(app: ApplicationService, direction: 'up' | 'down') {
  const db = await app.container.make('lucid.db')
  const runner = new MigrationRunner(db, app, {
    direction,
    connectionName: 'sqlite',
    ...(direction === 'down' ? { batch: 0 } : {}),
  })
  await runner.run()
  if (runner.error) throw runner.error
}
