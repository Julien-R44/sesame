import { test } from '@japa/runner'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createTestGuard } from './helpers/create_test_guard.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { ClientService } from '../src/services/client_service.ts'
import { ExchangeClientCredentialsAction } from '../src/actions/exchange_client_credentials.ts'

test.group('Integration | Client Credentials Grant', (group) => {
  setupIntegrationGroup(group)

  test('issues an access token for a confidential client', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const result = await new ExchangeClientCredentialsAction().execute(manager, {
      client,
      scope: 'read write',
    })

    assert.isDefined(result.access_token)
    assert.equal(result.token_type, 'Bearer')
    assert.equal(result.expires_in, 3600)
    assert.equal(result.scope, 'read write')
    assert.isUndefined((result as any).refresh_token)
  })

  test('does not issue a refresh token', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const result = await new ExchangeClientCredentialsAction().execute(manager, {
      client,
      scope: 'read',
    })

    assert.isUndefined((result as any).refresh_token)

    const refreshTokens = await OAuthRefreshToken.query().where('clientId', 'test-client')
    assert.lengthOf(refreshTokens, 0)
  })

  test('stores access token with the client owner userId', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    await new ExchangeClientCredentialsAction().execute(manager, {
      client,
      scope: 'read',
    })

    const tokens = await OAuthAccessToken.query().where('clientId', 'test-client')
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].userId, 'user-1')
    assert.deepEqual(tokens[0].scopes, ['read'])
  })

  test('authenticates the issued token with OAuthGuard', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const result = await new ExchangeClientCredentialsAction().execute(manager, {
      client,
      scope: 'read',
    })

    const { guard } = createTestGuard({
      manager,
      bearerToken: result.access_token,
      users: [{ id: 'user-1', name: 'Service Account' }],
    })

    const user = await guard.authenticate()

    assert.deepEqual(user, { id: 'user-1', name: 'Service Account' })
    assert.deepEqual(guard.scopes, ['read'])
    assert.equal(guard.clientId, 'test-client')
  })

  test('uses non-built-in client scopes when no scope is requested', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({
      grantTypes: ['client_credentials'],
      scopes: ['read', 'offline_access', 'write'],
      userId: 'user-1',
    })

    const result = await new ExchangeClientCredentialsAction().execute(manager, { client })

    assert.equal(result.scope, 'read write')
  })

  test('rejects clients without an associated user', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['client_credentials'], userId: null })

    await assertOAuthError(
      assert,
      () => new ExchangeClientCredentialsAction().execute(manager, { client, scope: 'read' }),
      'invalid_client'
    )
  })

  test('rejects public clients', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({
      grantTypes: ['client_credentials'],
      isPublic: true,
      clientSecret: null,
      type: 'public',
    })

    await assertOAuthError(
      assert,
      () => new ExchangeClientCredentialsAction().execute(manager, { client }),
      'invalid_client'
    )
  })

  test('rejects client not allowed to use client_credentials grant', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['authorization_code'] })

    await assertOAuthError(
      assert,
      () => new ExchangeClientCredentialsAction().execute(manager, { client, scope: 'read' }),
      'invalid_client'
    )
  })

  test('rejects invalid client secret', async ({ assert }) => {
    await createTestClient({ grantTypes: ['client_credentials'] })

    const clientService = new ClientService()
    await assertOAuthError(
      assert,
      () =>
        clientService.authenticateClient({
          authorizationHeader: undefined,
          bodyClientId: 'test-client',
          bodyClientSecret: 'wrong-secret',
        }),
      'invalid_client'
    )
  })

  test('rejects offline_access scope (OIDC scopes are meaningless in M2M)', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['client_credentials'] })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeClientCredentialsAction().execute(manager, {
          client,
          scope: 'read offline_access',
        }),
      'invalid_scope',
      'offline_access'
    )
  })

  test('rejects openid/profile/email scopes (OIDC user scopes are meaningless in M2M)', async ({
    assert,
  }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({
      grantTypes: ['client_credentials'],
      scopes: ['read', 'openid', 'profile', 'email'],
      userId: 'user-1',
    })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeClientCredentialsAction().execute(manager, {
          client,
          scope: 'read openid profile email',
        }),
      'invalid_scope',
      ['openid', 'profile', 'email']
    )
  })

  test('rejects scopes not allowed for the client', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['client_credentials'], scopes: ['read'] })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeClientCredentialsAction().execute(manager, {
          client,
          scope: 'read write',
        }),
      'invalid_scope'
    )
  })

  test('rejects unknown scopes', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({ grantTypes: ['client_credentials'] })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeClientCredentialsAction().execute(manager, {
          client,
          scope: 'read admin',
        }),
      'invalid_scope'
    )
  })

  test('does not inherit OIDC scopes from client defaults when no scope is requested', async ({
    assert,
  }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    const client = await createTestClient({
      grantTypes: ['client_credentials'],
      scopes: ['read', 'openid', 'profile', 'email', 'offline_access', 'write'],
      userId: 'user-1',
    })

    const result = await new ExchangeClientCredentialsAction().execute(manager, { client })

    assert.equal(result.scope, 'read write')

    const tokens = await OAuthAccessToken.query().where('clientId', 'test-client')
    assert.lengthOf(tokens, 1)
    assert.deepEqual(tokens[0].scopes, ['read', 'write'])
  })

  test('uses clientCredentialsAccessTokenTtl when configured', async ({ assert }) => {
    const manager = createManager({
      grantTypes: ['client_credentials'],
      clientCredentialsAccessTokenTtl: '2h',
    })
    const client = await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const result = await new ExchangeClientCredentialsAction().execute(manager, {
      client,
      scope: 'read',
    })

    assert.equal(result.expires_in, 7200)
  })

  test('supports Basic auth for client authentication', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const clientService = new ClientService()
    const encoded = Buffer.from('test-client:test-secret').toString('base64')
    const client = await clientService.authenticateClient({
      authorizationHeader: `Basic ${encoded}`,
      bodyClientId: undefined,
      bodyClientSecret: undefined,
    })

    const result = await new ExchangeClientCredentialsAction().execute(manager, {
      client,
      scope: 'read',
    })

    assert.isDefined(result.access_token)
    assert.equal(result.scope, 'read')
  })
})
