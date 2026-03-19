import { test } from '@japa/runner'
import type { ApplicationService } from '@adonisjs/core/types'
import { createApp, setupDatabase, teardownDatabase, createManager } from './helpers/app.ts'
import { mockCtx } from './helpers/mock_ctx.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createTestGuard } from './helpers/create_test_guard.ts'
import { cleanModels } from './helpers/clean_models.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { handleClientCredentialsGrant } from '../src/grants/client_credentials_grant.ts'

let app: ApplicationService

test.group('Integration | Client Credentials Grant', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(cleanModels())

  test('issues an access token for a confidential client', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read write',
      },
    })

    const result = await handleClientCredentialsGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.equal(result.token_type, 'Bearer')
    assert.equal(result.expires_in, 3600)
    assert.equal(result.scope, 'read write')
    assert.isUndefined((result as any).refresh_token)
  })

  test('does not issue a refresh token', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read',
      },
    })

    const result = await handleClientCredentialsGrant(ctx, manager)

    assert.isUndefined((result as any).refresh_token)

    const refreshTokens = await OAuthRefreshToken.query().where('clientId', 'test-client')
    assert.lengthOf(refreshTokens, 0)
  })

  test('stores access token with the client owner userId', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read',
      },
    })

    await handleClientCredentialsGrant(ctx, manager)

    const tokens = await OAuthAccessToken.query().where('clientId', 'test-client')
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].userId, 'user-1')
    assert.deepEqual(tokens[0].scopes, ['read'])
  })

  test('authenticates the issued token with OAuthGuard', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read',
      },
    })

    const result = await handleClientCredentialsGrant(ctx, manager)

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
    await createTestClient({
      grantTypes: ['client_credentials'],
      scopes: ['read', 'offline_access', 'write'],
      userId: 'user-1',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const result = await handleClientCredentialsGrant(ctx, manager)

    assert.equal(result.scope, 'read write')
  })

  test('rejects clients without an associated user', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'], userId: null })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read',
      },
    })

    await assertOAuthError(
      assert,
      () => handleClientCredentialsGrant(ctx, manager),
      'invalid_client'
    )
  })

  test('rejects public clients', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({
      grantTypes: ['client_credentials'],
      isPublic: true,
      clientSecret: null,
      type: 'public',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
      },
    })

    await assertOAuthError(
      assert,
      () => handleClientCredentialsGrant(ctx, manager),
      'invalid_client'
    )
  })

  test('rejects client not allowed to use client_credentials grant', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['authorization_code'] })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read',
      },
    })

    await assertOAuthError(
      assert,
      () => handleClientCredentialsGrant(ctx, manager),
      'invalid_client'
    )
  })

  test('rejects invalid client secret', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'] })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'wrong-secret',
        scope: 'read',
      },
    })

    await assertOAuthError(
      assert,
      () => handleClientCredentialsGrant(ctx, manager),
      'invalid_client'
    )
  })

  test('rejects offline_access scope (OIDC scopes are meaningless in M2M)', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'] })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read offline_access',
      },
    })

    await assertOAuthError(
      assert,
      () => handleClientCredentialsGrant(ctx, manager),
      'invalid_scope',
      'offline_access'
    )
  })

  test('rejects openid/profile/email scopes (OIDC user scopes are meaningless in M2M)', async ({
    assert,
  }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({
      grantTypes: ['client_credentials'],
      scopes: ['read', 'openid', 'profile', 'email'],
      userId: 'user-1',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read openid profile email',
      },
    })

    await assertOAuthError(
      assert,
      () => handleClientCredentialsGrant(ctx, manager),
      'invalid_scope',
      ['openid', 'profile', 'email']
    )
  })

  test('rejects scopes not allowed for the client', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'], scopes: ['read'] })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read write',
      },
    })

    await assertOAuthError(
      assert,
      () => handleClientCredentialsGrant(ctx, manager),
      'invalid_scope'
    )
  })

  test('rejects unknown scopes', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'] })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read admin',
      },
    })

    await assertOAuthError(
      assert,
      () => handleClientCredentialsGrant(ctx, manager),
      'invalid_scope'
    )
  })

  test('does not inherit OIDC scopes from client defaults when no scope is requested', async ({
    assert,
  }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({
      grantTypes: ['client_credentials'],
      scopes: ['read', 'openid', 'profile', 'email', 'offline_access', 'write'],
      userId: 'user-1',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const result = await handleClientCredentialsGrant(ctx, manager)

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
    await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'client_credentials',
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read',
      },
    })

    const result = await handleClientCredentialsGrant(ctx, manager)

    assert.equal(result.expires_in, 7200)
  })

  test('supports Basic auth for client authentication', async ({ assert }) => {
    const manager = createManager({ grantTypes: ['client_credentials'] })
    await createTestClient({ grantTypes: ['client_credentials'], userId: 'user-1' })

    const encoded = Buffer.from('test-client:test-secret').toString('base64')
    const ctx = mockCtx({
      manager,
      headers: { authorization: `Basic ${encoded}` },
      body: {
        grant_type: 'client_credentials',
        scope: 'read',
      },
    })

    const result = await handleClientCredentialsGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.equal(result.scope, 'read')
  })
})
