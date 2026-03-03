import { Router } from '@adonisjs/core/http'

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
 * Register OAuth 2.1 endpoint routes on the given router.
 *
 * Paths are relative (no prefix) — the user wraps the call
 * in a `router.group().prefix('/oauth')` to control the mount point.
 *
 * Endpoints registered:
 * - `POST /token` — Token endpoint (RFC 6749 §3.2)
 * - `GET /authorize` — Authorization endpoint (RFC 6749 §3.1)
 * - `POST /consent` — User consent submission
 * - `POST /introspect` — Token introspection (RFC 7662)
 * - `POST /revoke` — Token revocation (RFC 7009)
 * - `POST /register` — Dynamic client registration (RFC 7591)
 * - `GET /client-info` — Public client information (RFC 6819 §4.4.1.4)
 */
export function registerOAuthRoutes(router: Router) {
  router.post('/token', [controllers.token]).as('sesame.token')
  router.get('/authorize', [controllers.authorize]).as('sesame.authorize')
  router.post('/consent', [controllers.consent]).as('sesame.consent')
  router.get('/client-info', [controllers.clientInfo]).as('sesame.clientInfo')
  router.post('/introspect', [controllers.introspect]).as('sesame.introspect')
  router.post('/revoke', [controllers.revoke]).as('sesame.revoke')
  router.post('/register', [controllers.register]).as('sesame.register')
}

/**
 * Register well-known discovery routes at the root level.
 *
 * These must be registered outside any prefix group so they
 * remain at `/.well-known/...`.
 *
 * Endpoints registered:
 * - `GET /.well-known/oauth-authorization-server` — Server metadata (RFC 8414)
 * - `GET /.well-known/openid-configuration` — OpenID Connect discovery
 * - `GET /.well-known/oauth-protected-resource` — Protected resource metadata (RFC 9728)
 */
export function registerWellKnownRoutes(router: Router) {
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