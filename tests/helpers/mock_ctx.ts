import { SesameManager } from '../../src/sesame_manager.ts'
import { createManager } from './app.ts'

/**
 * Creates a mock AdonisJS HttpContext for unit-testing controllers and grants.
 *
 * Provides stubbed request (body, qs, headers), response (status, json, redirect),
 * auth, and containerResolver (resolves SesameManager and router).
 *
 * Response state is accessible via `ctx.__responseStatus`, `ctx.__responseBody`,
 * and `ctx.__responseHeaders`.
 */
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
    'sesame.userinfo': '/oauth/userinfo',
    'sesame.jwks': '/jwks',
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
