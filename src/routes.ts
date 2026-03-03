import type { HttpContext } from '@adonisjs/core/http'
import { Router } from '@adonisjs/core/http'
import type { ResourceServerMetadata } from './types.ts'

/**
 * Lazy-loaded controller imports for all OAuth 2.1 endpoints.
 * Using lazy imports ensures controllers are only loaded when
 * their routes are hit.
 */
const controllers = {
  token: () => import('./controllers/token_controller.ts'),
  authorize: () => import('./controllers/authorize_controller.ts'),
  consent: () => import('./controllers/consent_controller.ts'),
  introspect: () => import('./controllers/introspect_controller.ts'),
  revoke: () => import('./controllers/revoke_controller.ts'),
  register: () => import('./controllers/register_controller.ts'),
  metadata: () => import('./controllers/metadata_controller.ts'),
  clientInfo: () => import('./controllers/client_info_controller.ts'),
}

/**
 * Register all OAuth 2.1 routes on the given AdonisJS router.
 *
 * Endpoints registered:
 * - `POST /oauth/token` — Token endpoint (RFC 6749 §3.2)
 * - `GET /oauth/authorize` — Authorization endpoint (RFC 6749 §3.1)
 * - `POST /oauth/consent` — User consent submission
 * - `POST /oauth/introspect` — Token introspection (RFC 7662)
 * - `POST /oauth/revoke` — Token revocation (RFC 7009)
 * - `POST /oauth/register` — Dynamic client registration (RFC 7591)
 * - `GET /oauth/client-info` — Public client information (RFC 6819 §4.4.1.4)
 * - `GET /.well-known/oauth-authorization-server` — Server metadata (RFC 8414)
 * - `GET /.well-known/openid-configuration` — OpenID Connect discovery
 * - `GET /.well-known/oauth-protected-resource` — Protected resource metadata (RFC 9728)
 */
export function registerRoutes(router: Router) {
  router.post('/oauth/token', [controllers.token]).as('sesame.token')
  router.get('/oauth/authorize', [controllers.authorize]).as('sesame.authorize')
  router.post('/oauth/consent', [controllers.consent]).as('sesame.consent')
  router.get('/oauth/client-info', [controllers.clientInfo]).as('sesame.clientInfo')
  router.post('/oauth/introspect', [controllers.introspect]).as('sesame.introspect')
  router.post('/oauth/revoke', [controllers.revoke]).as('sesame.revoke')
  router.post('/oauth/register', [controllers.register]).as('sesame.register')

  router
    .get('/.well-known/oauth-authorization-server', [controllers.metadata, 'authServer'])
    .as('sesame.metadata.authServer')
  router
    .get('/.well-known/openid-configuration', [controllers.metadata, 'oidc'])
    .as('sesame.metadata.oidc')
  router
    .get('/.well-known/oauth-protected-resource', [controllers.metadata, 'protectedResource'])
    .as('sesame.metadata.protectedResource')
}

/**
 * Register a `/.well-known/oauth-protected-resource` endpoint for a
 * specific resource path (RFC 9728). Useful for MCP servers that need
 * per-resource discovery.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9728
 */
export function registerProtectedResource(
  router: Router,
  options: { resource: string; scopes?: string[] }
) {
  const wellKnownPath = `/.well-known/oauth-protected-resource${options.resource}`

  router.get(wellKnownPath, async (ctx: HttpContext): Promise<ResourceServerMetadata> => {
    const { SesameManager } = await import('./sesame_manager.ts')
    const manager = await ctx.containerResolver.make(SesameManager)
    const issuer = manager.config.issuer

    ctx.response.header(
      'Cache-Control',
      'public, max-age=15, stale-while-revalidate=15, stale-if-error=86400'
    )

    return {
      resource: `${issuer}${options.resource}`,
      authorization_servers: [issuer],
      scopes_supported: options.scopes ?? Object.keys(manager.config.scopes),
      bearer_methods_supported: ['header'],
    }
  })
}
