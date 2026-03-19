import { test } from '@japa/runner'
import type { ApplicationService } from '@adonisjs/core/types'
import {
  createApp,
  setupDatabase,
  teardownDatabase,
  createManager,
  createTestClient,
  mockCtx,
  FakeUserProvider,
  createFakeEmitter,
} from './helpers.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { handleClientCredentialsGrant } from '../src/grants/client_credentials_grant.ts'
import { OAuthError } from '../src/oauth_error.ts'
import { OAuthGuard } from '../src/guard/guard.ts'

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

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthClient.query().delete()
  })

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

    const authCtx = mockCtx({
      headers: { authorization: `Bearer ${result.access_token}` },
    })
    const guard = new OAuthGuard(
      'oauth',
      authCtx,
      createFakeEmitter(),
      new FakeUserProvider([{ id: 'user-1', name: 'Service Account' }]),
      manager
    )

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

    try {
      await handleClientCredentialsGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client')
    }
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

    try {
      await handleClientCredentialsGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client')
    }
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

    try {
      await handleClientCredentialsGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client')
    }
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

    try {
      await handleClientCredentialsGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client')
    }
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

    try {
      await handleClientCredentialsGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
      assert.include(error.message, 'offline_access')
    }
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

    try {
      await handleClientCredentialsGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
      assert.include(error.message, 'openid')
      assert.include(error.message, 'profile')
      assert.include(error.message, 'email')
    }
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

    try {
      await handleClientCredentialsGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
    }
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

    try {
      await handleClientCredentialsGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
    }
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
