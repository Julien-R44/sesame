import { resolve } from 'node:path'
import { createServer, type Server } from 'node:http'
import type { Group } from '@japa/runner/core'
import { IgnitorFactory } from '@adonisjs/core/factories'
import { ExceptionHandler } from '@adonisjs/core/http'
import type { ApplicationService } from '@adonisjs/core/types'
import { MigrationRunner } from '@adonisjs/lucid/migration'
import { defineConfig } from '../../src/define_config.ts'
import { SesameManager } from '../../src/sesame_manager.ts'
import { stores } from '../../src/stores.ts'
import { lucidStore } from '../../src/storage/drivers/lucid.ts'
import type { SesameStore } from '../../src/storage/types.ts'
import { OAuthGuard } from '../../src/guard/guard.ts'
import { FakeUserProvider, createFakeEmitter, type FakeUser } from './fakes.ts'
import { OAuthClient } from '../../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../../src/models/oauth_refresh_token.ts'
import { OAuthConsent } from '../../src/models/oauth_consent.ts'
import { OAuthPendingAuthorizationRequest } from '../../src/models/oauth_pending_authorization_request.ts'

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
    store: stores.lucid(),
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
  return new SesameManager(createTestConfig(overrides), {} as any, lucidStore())
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
        providers: [
          () => import('@adonisjs/lucid/database_provider'),
          () => import('../../providers/sesame_provider.ts'),
        ],
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

/**
 * Creates a real HTTP server backed by the full AdonisJS stack.
 *
 * Registers SesameManager in the container, registers OAuth routes
 * and well-known discovery routes, boots the HTTP server,
 * and listens on a random available port.
 */
export async function createHttpServer(
  app: ApplicationService,
  configOverrides?: Record<string, any>,
  options?: {
    routePrefix?: string
    skipOAuthRoutes?: boolean
    skipDiscoveryRoutes?: boolean
    setupRoutes?: (router: any, manager: SesameManager) => void
    store?: SesameStore
    /**
     * Build `ctx.auth` from the request's OAuth guard instead of the fake
     * authenticator, e.g. a real `@adonisjs/auth` Authenticator.
     */
    createAuth?: (options: { ctx: any; guard: OAuthGuard<any> }) => unknown
  }
) {
  const adonisServer = await app.container.make('server')
  const router = adonisServer.getRouter()

  adonisServer.use([
    () => import('@adonisjs/core/bodyparser_middleware'),
    /**
     * Fake auth middleware: wires `ctx.auth` with a real OAuthGuard
     * so scope middleware and controllers work.
     *
     * Reads `X-Test-User-Id` header for non-Bearer user identification
     * (authorize/consent flow). For Bearer token flows, the guard
     * authenticates from the Authorization header as usual.
     */
    async () => ({
      default: class {
        async handle(ctx: any, next: () => Promise<void>) {
          const mgr = await ctx.containerResolver.make(SesameManager)
          const users: FakeUser[] = [
            { id: 'user-1', name: 'Test User' },
            { id: 'user-2', name: 'Test User 2' },
          ]
          const provider = new FakeUserProvider(users)
          const emitter = createFakeEmitter()
          const guard = new OAuthGuard('oauth', ctx, emitter, provider, mgr)

          if (options?.createAuth) {
            ctx.auth = options.createAuth({ ctx, guard })
            return next()
          }

          const userId = ctx.request.header('x-test-user-id')
          ctx.auth = {
            user: userId ? { id: userId } : undefined,
            check: async () => !!userId,
            use: () => guard,
          }

          await next()
        }
      },
    }),
  ])
  adonisServer.errorHandler(async () => ({ default: ExceptionHandler }))

  const config = createTestConfig(configOverrides)
  const manager = new SesameManager(config, router, options?.store ?? lucidStore())
  app.container.singleton(SesameManager, () => manager)

  if (!options?.skipOAuthRoutes) {
    const prefix = options?.routePrefix ?? '/oauth'
    router.group(() => manager.registerRoutes()).prefix(prefix)
  }
  if (!options?.skipDiscoveryRoutes) manager.registerDiscoveryRoutes()
  options?.setupRoutes?.(router, manager)

  await adonisServer.boot()

  const httpServer: Server = createServer(adonisServer.handle.bind(adonisServer))

  const baseUrl = await new Promise<string>((resolve) => {
    httpServer.listen(0, () => {
      const addr = httpServer.address()!
      const port = typeof addr === 'string' ? addr : addr.port
      resolve(`http://localhost:${port}`)
    })
  })

  const close = () =>
    new Promise<void>((resolve) => {
      httpServer.close(() => resolve())
    })

  return { baseUrl, httpServer, close, manager }
}

/**
 * Deletes all OAuth models. Deletion order respects FK dependencies.
 */
function cleanModels() {
  return async () => {
    await OAuthPendingAuthorizationRequest.query().delete()
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  }
}

/**
 * Wires group lifecycle for integration tests that need
 * a booted AdonisJS app with an in-memory SQLite database.
 *
 * Cleans all OAuth models between each test.
 */
export function setupIntegrationGroup(group: Group) {
  const ctx = {} as { app: ApplicationService }

  group.setup(async () => {
    ctx.app = await createApp()
    await setupDatabase(ctx.app)

    return async () => {
      await teardownDatabase(ctx.app)
      await ctx.app.terminate()
    }
  })

  group.each.setup(cleanModels())

  return ctx
}

/**
 * Wires group lifecycle for HTTP integration tests.
 *
 * Boots the app, runs migrations, starts a real HTTP server
 * on a random port, and registers all Sesame routes.
 */
export function setupHttpGroup(
  group: Group,
  configOverrides?: Record<string, any>,
  httpOptions?: Parameters<typeof createHttpServer>[2]
) {
  const ctx = {} as { app: ApplicationService; baseUrl: string }

  group.setup(async () => {
    ctx.app = await createApp()
    await setupDatabase(ctx.app)
    const server = await createHttpServer(ctx.app, configOverrides, httpOptions)
    ctx.baseUrl = server.baseUrl

    return async () => {
      await server.close()
      await teardownDatabase(ctx.app)
      await ctx.app.terminate()
    }
  })

  group.each.setup(cleanModels())

  return ctx
}
