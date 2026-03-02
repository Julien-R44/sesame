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
  jwks: () => import('./controllers/jwks_controller.ts'),
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
 * - `GET /oauth/jwks` — JSON Web Key Set (RFC 7517 §5)
 * - `GET /.well-known/oauth-authorization-server` — Server metadata (RFC 8414)
 * - `GET /.well-known/openid-configuration` — OpenID Connect discovery
 * - `GET /.well-known/oauth-protected-resource` — Protected resource metadata (RFC 9728)
 */
export function registerRoutes(router: any) {
  router.post('/oauth/token', [controllers.token])
  router.get('/oauth/authorize', [controllers.authorize])
  router.post('/oauth/consent', [controllers.consent])
  router.post('/oauth/introspect', [controllers.introspect])
  router.post('/oauth/revoke', [controllers.revoke])
  router.post('/oauth/register', [controllers.register])
  router.get('/oauth/jwks', [controllers.jwks])

  router.get('/.well-known/oauth-authorization-server', [controllers.metadata, 'authServer'])
  router.get('/.well-known/openid-configuration', [controllers.metadata, 'oidc'])
  router.get('/.well-known/oauth-protected-resource', [controllers.metadata, 'protectedResource'])
}
