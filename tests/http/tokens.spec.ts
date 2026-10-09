import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { setupHttpGroup } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createTestAccessToken } from '../helpers/create_test_access_token.ts'
import { createTestRefreshToken } from '../helpers/create_test_refresh_token.ts'
import { OAuthAccessToken } from '../../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../../src/models/oauth_refresh_token.ts'
import { TokenService } from '../../src/services/token_service.ts'
import { createManager } from '../helpers/app.ts'

test.group('HTTP | Token Endpoint Dispatch', (group) => {
  const ctx = setupHttpGroup(group)

  test('POST /oauth/token rejects unsupported grant type', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/token`).json({
      grant_type: 'password',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'unsupported_grant_type' })
  })

  test('POST /oauth/token rejects missing grant type', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/token`).json({})

    response.assertStatus(400)
    response.assertBodyContains({ error: 'unsupported_grant_type' })
  })
})

test.group('HTTP | Introspection', (group) => {
  const ctx = setupHttpGroup(group)

  test('introspects a valid access token', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
      token: raw,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    response.assertBodyContains({
      active: true,
      client_id: 'test-client',
      sub: 'user-1',
      scope: 'read',
    })
  })

  test('rejects introspection for a confidential client without a secret', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
      token: raw,
      client_id: 'test-client',
    })

    response.assertStatus(401)
    response.assertBodyContains({ error: 'invalid_client' })
  })

  test('returns inactive for revoked token', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({
      scopes: ['read'],
      revokedAt: DateTime.now(),
    })

    const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
      token: raw,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    response.assertBodyContains({ active: false })
  })

  test('returns inactive for unknown token', async ({ client }) => {
    await createTestClient()

    const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
      token: 'some-unknown-token',
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    response.assertBodyContains({ active: false })
  })

  test('returns inactive for missing token', async ({ client }) => {
    await createTestClient()

    const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    response.assertBodyContains({ active: false })
  })

  test('introspects a valid refresh token', async ({ client }) => {
    await createTestClient()
    const { rawRefreshToken } = await createTestRefreshToken({ scopes: ['read', 'write'] })

    const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
      token: rawRefreshToken,
      token_type_hint: 'refresh_token',
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    response.assertBodyContains({
      active: true,
      client_id: 'test-client',
      sub: 'user-1',
      scope: 'read write',
    })
  })

  test('returns inactive when another client introspects the token', async ({ client }) => {
    await createTestClient()
    await createTestClient({
      clientId: 'other-client',
      name: 'Other Client',
      redirectUris: ['https://other.example.com/callback'],
      rawClientSecret: 'other-secret',
    })

    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
      token: raw,
      client_id: 'other-client',
      client_secret: 'other-secret',
    })

    response.assertStatus(200)
    response.assertBodyContains({ active: false })
  })
})

test.group('HTTP | Revocation', (group) => {
  const ctx = setupHttpGroup(group)

  test('revokes an access token', async ({ client, assert }) => {
    await createTestClient()
    const { raw, hash } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.post(`${ctx.baseUrl}/oauth/revoke`).json({
      token: raw,
      token_type_hint: 'access_token',
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)

    const record = await OAuthAccessToken.query().where('tokenHash', hash).firstOrFail()
    assert.isNotNull(record.revokedAt)
  })

  test('rejects revocation for a confidential client without a secret', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.post(`${ctx.baseUrl}/oauth/revoke`).json({
      token: raw,
      token_type_hint: 'access_token',
      client_id: 'test-client',
    })

    response.assertStatus(401)
    response.assertBodyContains({ error: 'invalid_client' })
  })

  test('revokes a refresh token and associated access token', async ({ client, assert }) => {
    await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)
    const rawRefreshToken = 'revoke-me-refresh'

    const linkedAccessTokenId = crypto.randomUUID()
    await OAuthAccessToken.create({
      id: linkedAccessTokenId,
      tokenHash: 'linked-token-hash',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: linkedAccessTokenId,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const response = await client.post(`${ctx.baseUrl}/oauth/revoke`).json({
      token: rawRefreshToken,
      token_type_hint: 'refresh_token',
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)

    const refresh = await OAuthRefreshToken.query().where(
      'token',
      tokenService.hashToken(rawRefreshToken)
    )
    assert.lengthOf(refresh, 0)

    const access = await OAuthAccessToken.query()
      .where('tokenHash', 'linked-token-hash')
      .firstOrFail()
    assert.isNotNull(access.revokedAt)
  })

  test('returns 200 even for unknown tokens', async ({ client }) => {
    await createTestClient()

    const response = await client.post(`${ctx.baseUrl}/oauth/revoke`).json({
      token: 'totally-unknown-token',
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
  })
})

test.group('HTTP | WWW-Authenticate header', (group) => {
  const ctx = setupHttpGroup(group)

  test('sets WWW-Authenticate: Basic when client used Authorization header', async ({ client }) => {
    await createTestClient()

    const response = await client
      .post(`${ctx.baseUrl}/oauth/introspect`)
      .basicAuth('test-client', 'wrong-secret')
      .json({ token: 'whatever' })

    response.assertStatus(401)
    response.assertHeader('www-authenticate', 'Basic')
  })

  test('does not set WWW-Authenticate when client used POST body credentials', async ({
    client,
  }) => {
    await createTestClient()

    const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
      token: 'whatever',
      client_id: 'test-client',
      client_secret: 'wrong-secret',
    })

    response.assertStatus(401)
    response.assertHeaderMissing('www-authenticate')
  })
})
