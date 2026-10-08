import { test } from '@japa/runner'
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import type { ApplicationService } from '@adonisjs/core/types'
import Database from 'better-sqlite3'
import { Kysely, SqliteDialect } from 'kysely'
import { up as createTables } from '../../src/storage/migrations/kysely.ts'
import { setupIntegrationGroup } from '../helpers/app.ts'

const STUBS_ROOT = new URL('../../stubs', import.meta.url).pathname
const TMP_DIR = new URL('./.tmp_upgrade_0_8/', import.meta.url).pathname
const RESOURCE_TABLES = [
  'oauth_pending_authorization_requests',
  'oauth_authorization_codes',
  'oauth_access_tokens',
  'oauth_refresh_tokens',
]

/**
 * Render a Sesame stub the way `codemods.makeUsingStub` does.
 */
async function renderStub(app: ApplicationService, stubPath: string) {
  const stubs = await app.stubs.create()
  const stub = await stubs.build(stubPath, { source: STUBS_ROOT })

  return stub.prepare({})
}

/**
 * Write rendered migration code inside the project so its imports resolve.
 */
async function importMigration(fileName: string, contents: string) {
  await mkdir(TMP_DIR, { recursive: true })
  const filePath = join(TMP_DIR, fileName)
  await writeFile(filePath, contents)

  return { filePath, module: await import(filePath) }
}

test.group('Upgrade 0.8 | resource columns', (group) => {
  const ctx = setupIntegrationGroup(group)

  group.teardown(async () => {
    await rm(TMP_DIR, { recursive: true, force: true })
  })

  test('keeps stub bodies free of template literal syntax', async ({ assert }) => {
    for (const stubPath of [
      'migrations/upgrade_0_8/lucid/add_oauth_resource_columns.stub',
      'migrations/upgrade_0_8/kysely/add_oauth_resource_columns.stub',
    ]) {
      const contents = await readFile(join(STUBS_ROOT, stubPath), 'utf8')
      const body = contents.slice(contents.indexOf('}}}') + 3)

      assert.notInclude(body, '`', stubPath)
      assert.notInclude(body, '${', stubPath)
    }
  })

  test('sorts the Kysely migration after the create-table migration', async ({ assert }) => {
    const prepared = await renderStub(
      ctx.app,
      'migrations/upgrade_0_8/kysely/add_oauth_resource_columns.stub'
    )
    const fileName = basename(prepared.destination)

    assert.equal(fileName, 'sesame_v000800_add_oauth_resource_columns.ts')
    assert.deepEqual([fileName, 'create_oauth_tables.ts'].sort(), [
      'create_oauth_tables.ts',
      fileName,
    ])
  })

  test('publishes the Lucid migration in the migrations folder', async ({ assert }) => {
    const prepared = await renderStub(
      ctx.app,
      'migrations/upgrade_0_8/lucid/add_oauth_resource_columns.stub'
    )

    assert.match(prepared.destination, /database\/migrations\/\d+_add_oauth_resource_columns\.ts$/)
    assert.include(prepared.contents, "table.text('resource').nullable()")
  })

  test('adds and removes the Lucid resource columns', async ({ assert }) => {
    const prepared = await renderStub(
      ctx.app,
      'migrations/upgrade_0_8/lucid/add_oauth_resource_columns.stub'
    )
    const { filePath, module } = await importMigration('lucid_upgrade.ts', prepared.contents)
    const db = await ctx.app.container.make('lucid.db')
    const connection = db.connection()

    await new module.default(connection, filePath, false).execDown()
    for (const table of RESOURCE_TABLES) {
      assert.isFalse(await connection.schema.hasColumn(table, 'resource'), table)
    }

    await new module.default(connection, filePath, false).execUp()
    for (const table of RESOURCE_TABLES) {
      assert.isTrue(await connection.schema.hasColumn(table, 'resource'), table)
    }
  })

  test('upgrades a Kysely database created by Sesame 0.7', async ({ assert }) => {
    const prepared = await renderStub(
      ctx.app,
      'migrations/upgrade_0_8/kysely/add_oauth_resource_columns.stub'
    )
    const { module } = await importMigration('kysely_upgrade.ts', prepared.contents)
    const db = new Kysely<any>({
      dialect: new SqliteDialect({ database: new Database(':memory:') }),
    })

    try {
      await createTables(db)
      await module.down(db)
      const legacyTables = await db.introspection.getTables()
      const legacyColumns = legacyTables
        .filter((table) => RESOURCE_TABLES.includes(table.name))
        .flatMap((table) => table.columns.map((column) => column.name))
      assert.notInclude(legacyColumns, 'resource')

      await module.up(db)
      const tables = await db.introspection.getTables()
      for (const name of RESOURCE_TABLES) {
        const columns = tables.find((table) => table.name === name)!.columns
        const resource = columns.find((column) => column.name === 'resource')
        assert.isTrue(resource?.isNullable, name)
      }
    } finally {
      await db.destroy()
    }

    assert.match(
      prepared.destination,
      /database\/kysely_migrations\/sesame_v000800_add_oauth_resource_columns\.ts$/
    )
  })
})
