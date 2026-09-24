import { test } from '@japa/runner'
import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { promisify } from 'node:util'
import { defineConfig } from '../../src/define_config.ts'
import { stores } from '../../src/stores.ts'

const base = {
  issuer: 'https://auth.example.com',
  loginPage: '/login',
  consentPage: '/consent',
}

const execFileAsync = promisify(execFile)

test.group('Store configuration', () => {
  test('requires a store', ({ assert }) => {
    assert.throws(() => defineConfig(base as any), 'Missing "store" in Sesame config')
  })

  test('keeps the selected store provider', ({ assert }) => {
    const store = stores.lucid()
    const config = defineConfig({ ...base, store })

    assert.strictEqual(config.store, store)
  })

  test('publishes a standalone Kysely migration outside the Lucid folder', async ({ assert }) => {
    const stub = await readFile(
      new URL('../../stubs/migrations/kysely/create_oauth_tables.stub', import.meta.url),
      'utf8'
    )
    const source = await readFile(
      new URL('../../src/storage/migrations/kysely.ts', import.meta.url),
      'utf8'
    )

    assert.include(stub, 'database/kysely_migrations/create_oauth_tables.ts')
    assert.notInclude(stub, 'database/migrations/create_oauth_tables.ts')
    assert.equal(stub.slice(stub.indexOf('import type { Kysely }')), source)
  })

  test('imports and resolves the Kysely store without loading Lucid', async () => {
    const rootEntry = new URL('../../index.ts', import.meta.url).href
    const script = `
      import { registerHooks } from 'node:module'
      import Database from 'better-sqlite3'
      import { Kysely, SqliteDialect } from 'kysely'

      registerHooks({
        resolve(specifier, context, nextResolve) {
          if (specifier.startsWith('@adonisjs/lucid')) {
            throw new Error('Unexpected Lucid import: ' + specifier)
          }
          return nextResolve(specifier, context)
        },
      })

      const { stores } = await import(${JSON.stringify(rootEntry)})
      const db = new Kysely({ dialect: new SqliteDialect({ database: new Database(':memory:') }) })
      const store = await stores.kysely({ connection: db }).resolver({})
      if (typeof store.findClient !== 'function') throw new Error('Kysely store was not resolved')
      await db.destroy()
    `

    await execFileAsync(process.execPath, [
      '--import=@poppinss/ts-exec',
      '--input-type=module',
      '-e',
      script,
    ])
  })
})
