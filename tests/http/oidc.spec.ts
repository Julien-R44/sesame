import { test } from '@japa/runner'
import { setupHttpGroup } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createTestAccessToken } from '../helpers/create_test_access_token.ts'
import { getTestJwk, FakeUserProvider, type FakeUser } from '../helpers/fakes.ts'

const users: FakeUser[] = [{ id: 'user-1', name: 'Test User' }]
const jwk = await getTestJwk()

test.group('HTTP | UserInfo Endpoint', (group) => {
  const ctx = setupHttpGroup(group, { jwk, oidcProvider: new FakeUserProvider(users) })

  group.each.setup(async () => {
    await createTestClient({ scopes: ['read', 'openid', 'offline_access'] })
  })

  test('returns sub for valid token with openid scope', async ({ client }) => {
    const { raw } = await createTestAccessToken({ scopes: ['openid', 'read'] })

    const response = await client.get(`${ctx.baseUrl}/oauth/userinfo`).bearerToken(raw)

    response.assertStatus(200)
    response.assertBodyContains({ sub: 'user-1' })
  })

  test('accepts POST body access_token', async ({ client }) => {
    const { raw } = await createTestAccessToken({ scopes: ['openid', 'read'] })

    const response = await client.post(`${ctx.baseUrl}/oauth/userinfo`).json({ access_token: raw })

    response.assertStatus(200)
    response.assertBodyContains({ sub: 'user-1' })
  })

  test('rejects request without Bearer token', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/oauth/userinfo`)

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_request' })
  })

  test('rejects token without openid scope', async ({ client }) => {
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/oauth/userinfo`).bearerToken(raw)

    response.assertStatus(403)
    response.assertBodyContains({ error: 'insufficient_scope' })
  })

  test('rejects token when the OIDC user can no longer be resolved', async ({ client }) => {
    const { raw } = await createTestAccessToken({
      scopes: ['openid', 'read'],
      userId: 'user-999',
    })

    const response = await client.get(`${ctx.baseUrl}/oauth/userinfo`).bearerToken(raw)

    response.assertStatus(401)
    response.assertBodyContains({ error: 'invalid_token' })
  })
})

test.group('HTTP | OIDC Metadata', (group) => {
  const ctx = setupHttpGroup(group, { jwk, oidcProvider: new FakeUserProvider([]) })

  test('returns complete OIDC metadata when configured', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/openid-configuration`)

    response.assertStatus(200)
    response.assertBodyContains({
      issuer: 'https://auth.example.com',
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
    })
  })
})

test.group('HTTP | OIDC Metadata — not configured', (group) => {
  const ctx = setupHttpGroup(group)

  test('returns 404 when OIDC is not configured', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/openid-configuration`)

    response.assertStatus(404)
  })
})

test.group('HTTP | OIDC Metadata — JWK without provider', (group) => {
  const ctx = setupHttpGroup(group, { jwk })

  test('returns 404 when JWK is configured without an OIDC provider', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/openid-configuration`)

    response.assertStatus(404)
  })
})

test.group('HTTP | JWKS Endpoint', (group) => {
  const ctx = setupHttpGroup(group, { jwk, oidcProvider: new FakeUserProvider([]) })

  test('returns public JWKS', async ({ client, assert }) => {
    const response = await client.get(`${ctx.baseUrl}/jwks`)

    response.assertStatus(200)
    response.assertHeader('content-type', 'application/jwk-set+json')

    const body = response.body()
    assert.isArray(body.keys)
    assert.equal(body.keys.length, 1)
    assert.equal(body.keys[0].alg, 'RS256')
    assert.notProperty(body.keys[0], 'd')
  })
})

test.group('HTTP | OIDC Metadata — missing OIDC routes', (group) => {
  const ctx = setupHttpGroup(
    group,
    { jwk, oidcProvider: new FakeUserProvider([]) },
    {
      skipOAuthRoutes: true,
      skipDiscoveryRoutes: true,
      setupRoutes(router) {
        const controllers = {
          metadata: () => import('../../src/controllers/metadata_controller.ts'),
        }
        router
          .get('/.well-known/openid-configuration', [controllers.metadata, 'oidc'])
          .as('sesame.metadata.oidc')
      },
    }
  )

  test('returns 500 when OIDC routes are missing', async ({ client }) => {
    const response = await client
      .get(`${ctx.baseUrl}/.well-known/openid-configuration`)
      .header('accept', 'application/json')

    response.assertStatus(500)
    response.assertBodyContains({ error: 'server_error' })
  })
})
