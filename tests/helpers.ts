import { resolve } from 'node:path'
import { DateTime } from 'luxon'
import { IgnitorFactory } from '@adonisjs/core/factories'
import type { ApplicationService } from '@adonisjs/core/types'
import { defineConfig } from '../src/define_config.ts'
import { SesameManager } from '../src/sesame_manager.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { ClientService } from '../src/services/client_service.ts'
import { TokenService } from '../src/services/token_service.ts'
import { MigrationRunner } from '@adonisjs/lucid/migration'

const BASE_URL = new URL('./', import.meta.url)

export type TestClientOverrides = Partial<Record<string, any>> & {
  rawClientSecret?: string
}

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

export function createManager(overrides?: Record<string, any>) {
  return new SesameManager(createTestConfig(overrides))
}

export async function createTestClient(overrides?: TestClientOverrides) {
  const clientService = new ClientService()
  const { rawClientSecret = 'test-secret', ...clientOverrides } = overrides ?? {}

  return OAuthClient.create({
    id: crypto.randomUUID(),
    clientId: 'test-client',
    clientSecret: clientService.hashSecret(rawClientSecret),
    name: 'Test Client',
    redirectUris: ['https://app.example.com/callback'],
    scopes: ['read', 'write', 'offline_access'],
    grantTypes: ['authorization_code', 'refresh_token'],
    isPublic: false,
    isDisabled: false,
    requirePkce: true,
    type: 'confidential',
    metadata: null,
    userId: null,
    ...clientOverrides,
  })
}

export async function createTestAuthCode(options: {
  clientId: string
  userId: string
  scopes: string[]
  redirectUri: string
  rawCode: string
  codeChallenge?: string
  codeChallengeMethod?: string
}) {
  const tokenService = new TokenService(createManager())

  return OAuthAuthorizationCode.create({
    id: crypto.randomUUID(),
    code: tokenService.hashToken(options.rawCode),
    clientId: options.clientId,
    userId: options.userId,
    scopes: options.scopes,
    redirectUri: options.redirectUri,
    codeChallenge: options.codeChallenge ?? null,
    codeChallengeMethod: options.codeChallengeMethod ?? null,
    expiresAt: DateTime.now().plus({ minutes: 10 }),
  })
}

export function mockCtx(
  options: {
    body?: Record<string, any>
    query?: Record<string, any>
    headers?: Record<string, string>
    manager?: SesameManager
    router?: {
      has(routeIdentifier: string): boolean
      makeUrl(name: string, params?: any, opts?: { prefixUrl?: string }): string
    }
    auth?: { user?: any }
  } = {}
) {
  const headers: Record<string, string> = { ...options.headers }
  const manager = options.manager ?? createManager()
  const responseHeaders: Record<string, string> = {}
  const routes: Record<string, string> = {
    'sesame.token': '/oauth/token',
    'sesame.authorize': '/oauth/authorize',
    'sesame.consent': '/oauth/consent',
    'sesame.clientInfo': '/oauth/client-info',
    'sesame.introspect': '/oauth/introspect',
    'sesame.revoke': '/oauth/revoke',
    'sesame.register': '/oauth/register',
  }

  const ctx: any = {
    request: {
      body: () => options.body ?? {},
      qs: () => options.query ?? {},
      header: (name: string) => headers[name.toLowerCase()],
    },
    response: {
      header(name: string, value: string) {
        responseHeaders[name] = value
      },
      status(code: number) {
        ctx.__responseStatus = code
        return {
          json(data: any) {
            ctx.__responseBody = data
          },
        }
      },
      ok: (data: any) => data,
      json: (data: any) => data,
      redirect: () => ({ toPath: (url: string) => ({ redirectUrl: url }) }),
      send: (data: any) => data,
    },
    auth: options.auth
      ? { ...options.auth, check: async () => {} }
      : (options.body?.__auth ?? undefined),
    containerResolver: {
      make: async (binding: any) => {
        if (binding === SesameManager) return manager

        if (binding === 'router') {
          if (options.router) return options.router

          return {
            has(name: string) {
              return name in routes
            },
            makeUrl(name: string, _params: any, opts?: { prefixUrl?: string }) {
              const path = routes[name]
              if (!path) throw new Error(`Unknown route: ${name}`)

              return opts?.prefixUrl ? `${opts.prefixUrl}${path}` : path
            },
          }
        }

        throw new Error(`Unknown binding: ${binding}`)
      },
    },
    __responseHeaders: responseHeaders,
    __responseStatus: 0,
    __responseBody: undefined as any,
  }

  return ctx
}

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
                paths: [resolve(import.meta.dirname!, 'migrations')],
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

export async function setupDatabase(app: ApplicationService) {
  const db = await app.container.make('lucid.db')

  const runner = new MigrationRunner(db, app, {
    direction: 'up',
    connectionName: 'sqlite',
  })
  await runner.run()

  return db
}

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
