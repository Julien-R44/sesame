import { resolve } from 'node:path'
import { IgnitorFactory } from '@adonisjs/core/factories'
import type { ApplicationService } from '@adonisjs/core/types'
import { MigrationRunner } from '@adonisjs/lucid/migration'
import { defineConfig } from '../../src/define_config.ts'
import { SesameManager } from '../../src/sesame_manager.ts'

const BASE_URL = new URL('./', import.meta.url)

/**
 * Creates a resolved Sesame config with test defaults.
 *
 * Issuer: https://auth.example.com, scopes: read/write/openid/offline_access
 */
export function createTestConfig(overrides?: Record<string, any>) {
  return defineConfig({
    issuer: 'https://auth.example.com',
    scopes: {
      read: 'Read access',
      write: 'Write access',
      openid: 'OpenID Connect',
      offline_access: 'Offline access',
    },
    defaultScopes: ['read'],
    loginPage: '/login',
    consentPage: '/oauth/consent',
    allowDynamicRegistration: true,
    allowPublicRegistration: true,
    ...overrides,
  })
}

/**
 * Creates a SesameManager instance with test config.
 */
export function createManager(overrides?: Record<string, any>) {
  return new SesameManager(createTestConfig(overrides), {} as any)
}

/**
 * Boots an AdonisJS app with in-memory SQLite for integration tests.
 */
export async function createApp() {
  const ignitor = new IgnitorFactory()
    .withCoreProviders()
    .withCoreConfig()
    .merge({
      rcFileContents: {
        providers: [() => import('@adonisjs/lucid/database_provider')],
      },
      config: {
        database: {
          connection: 'sqlite',
          connections: {
            sqlite: {
              client: 'better-sqlite3',
              connection: { filename: ':memory:' },
              useNullAsDefault: true,
              migrations: {
                paths: [resolve(import.meta.dirname!, '..', 'migrations')],
              },
            },
          },
        },
        sesame: createTestConfig(),
      },
    })
    .create(BASE_URL)

  const app = ignitor.createApp('web')
  await app.init()
  await app.boot()

  return app
}

/**
 * Runs all migrations up on the test database.
 */
export async function setupDatabase(app: ApplicationService) {
  const db = await app.container.make('lucid.db')

  const runner = new MigrationRunner(db, app, {
    direction: 'up',
    connectionName: 'sqlite',
  })
  await runner.run()

  return db
}

/**
 * Rolls back all migrations and closes DB connections.
 */
export async function teardownDatabase(app: ApplicationService) {
  const db = await app.container.make('lucid.db')

  const runner = new MigrationRunner(db, app, {
    direction: 'down',
    connectionName: 'sqlite',
    batch: 0,
  })
  await runner.run()
  await db.manager.closeAll()
}
