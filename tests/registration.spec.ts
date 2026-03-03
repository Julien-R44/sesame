import { test } from '@japa/runner'
import type { ApplicationService } from '@adonisjs/core/types'
import {
  createApp,
  setupDatabase,
  teardownDatabase,
  createManager,
  createTestClient,
  mockCtx,
} from './helpers.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import RegisterController from '../src/controllers/register_controller.ts'
import ClientInfoController from '../src/controllers/client_info_controller.ts'
import { OAuthError } from '../src/oauth_error.ts'

let app: ApplicationService

test.group('Integration | Dynamic Registration', (group) => {
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
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('registers a new confidential client', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'My MCP Client',
        redirect_uris: ['https://mcp-client.example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    assert.isDefined(result.client_secret)
    assert.equal(result.client_name, 'My MCP Client')
    assert.deepEqual(result.redirect_uris, ['https://mcp-client.example.com/callback'])
    assert.equal(result.client_secret_expires_at, 0)

    const client = await OAuthClient.query().where('clientId', result.client_id).firstOrFail()
    assert.equal(client.name, 'My MCP Client')
    assert.notOk(client.isPublic)
  })

  test('registers a public client', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Public MCP Client',
        redirect_uris: ['https://mcp-client.example.com/callback'],
        token_endpoint_auth_method: 'none',
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    assert.isUndefined(result.client_secret)
    assert.equal(result.token_endpoint_auth_method, 'none')

    const client = await OAuthClient.query().where('clientId', result.client_id).firstOrFail()
    assert.ok(client.isPublic)
  })

  test('returns all registered metadata in response (RFC 7591 §3.2.1)', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Full Metadata Client',
        redirect_uris: ['https://example.com/callback'],
        token_endpoint_auth_method: 'none',
        client_uri: 'https://example.com',
        logo_uri: 'https://example.com/logo.png',
        contacts: ['admin@example.com'],
        tos_uri: 'https://example.com/tos',
        policy_uri: 'https://example.com/privacy',
        software_id: 'my-app',
        software_version: '1.0.0',
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.equal(result.client_uri, 'https://example.com')
    assert.equal(result.logo_uri, 'https://example.com/logo.png')
    assert.deepEqual(result.contacts, ['admin@example.com'])
    assert.equal(result.tos_uri, 'https://example.com/tos')
    assert.equal(result.policy_uri, 'https://example.com/privacy')
    assert.equal(result.software_id, 'my-app')
    assert.equal(result.software_version, '1.0.0')
  })

  test('rejects registration when disabled', async ({ assert }) => {
    const manager = createManager({ allowDynamicRegistration: false })

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'access_denied')
    }
  })

  test('rejects invalid redirect URIs', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['not-a-valid-url'],
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('rejects missing redirect URIs', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: { client_name: 'Test' },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('rejects javascript: scheme', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['javascript:alert(1)'],
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('rejects data: scheme', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['data:text/html,<script>'],
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('rejects HTTP for non-localhost hosts', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['http://evil.com/callback'],
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('rejects fragments in redirect URI', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb#frag'],
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('accepts HTTP localhost', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Localhost App',
        redirect_uris: ['http://localhost:3000/callback'],
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    const client = await OAuthClient.query().where('clientId', result.client_id).firstOrFail()
    assert.equal(client.name, 'Localhost App')
  })

  test('accepts HTTPS', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'HTTPS App',
        redirect_uris: ['https://example.com/callback'],
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    const client = await OAuthClient.query().where('clientId', result.client_id).firstOrFail()
    assert.equal(client.name, 'HTTPS App')
  })

  test('accepts custom scheme for native apps', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Native App',
        redirect_uris: ['com.example.app:/callback'],
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    const client = await OAuthClient.query().where('clientId', result.client_id).firstOrFail()
    assert.equal(client.name, 'Native App')
  })

  test('rejects javascript: scheme in client_uri', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        client_uri: 'javascript:alert(1)',
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('rejects data: scheme in logo_uri', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        logo_uri: 'data:image/png;base64,abc',
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('accepts client_uri with different host than redirect_uris', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        client_uri: 'https://other-domain.com/about',
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    assert.equal(result.client_uri, 'https://other-domain.com/about')
  })

  test('accepts CLI client with localhost redirect and external client_uri', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'OpenCode',
        redirect_uris: ['http://127.0.0.1:19876/mcp/oauth/callback'],
        client_uri: 'https://opencode.ai',
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    assert.equal(result.client_uri, 'https://opencode.ai')
  })

  test('rejects invalid contact email', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        contacts: ['not-an-email'],
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client_metadata')
    }
  })

  test('accepts valid contacts', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        contacts: ['admin@example.com', 'support@example.com'],
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
  })

  test('ignores unknown metadata fields instead of rejecting', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        some_future_field: 'value',
        another_unknown: ['a', 'b'],
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
  })

  test('accepts registration without optional metadata', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        redirect_uris: ['https://example.com/cb'],
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    assert.equal(result.client_name, 'Unnamed Client')
  })

  test('rejects registration with unknown scopes', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        scope: 'read unknown_scope',
      },
    })

    const controller = new RegisterController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
    }
  })

  test('accepts registration with valid scopes', async ({ assert }) => {
    const manager = createManager()

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        scope: 'read write',
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    assert.equal(result.scope, 'read write')
  })

  test('rejects unknown scopes when config.scopes is empty', async ({ assert }) => {
    const manager = createManager({ scopes: {} })

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
        scope: 'anything custom_scope',
      },
    })

    const controller = new RegisterController()
    await assert.rejects(() => controller.handle(ctx), /Unknown scopes/)
  })

  test('accepts empty scopes when config.scopes is empty', async ({ assert }) => {
    const manager = createManager({ scopes: {}, defaultScopes: [] })

    const ctx = mockCtx({
      manager,
      body: {
        client_name: 'Test',
        redirect_uris: ['https://example.com/cb'],
      },
    })

    const controller = new RegisterController()
    const result = await controller.handle(ctx)

    assert.isDefined(result.client_id)
    assert.equal(result.scope, '')
  })
})

test.group('Integration | Client Info', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(async () => {
    await OAuthClient.query().delete()
  })

  test('returns public info for a valid client', async ({ assert }) => {
    const client = await createTestClient({ name: 'Claude Code' })
    const controller = new ClientInfoController()
    const ctx = mockCtx({ query: { client_id: client.clientId } })

    const result = await controller.handle(ctx)

    assert.deepEqual(result, { client_id: client.clientId, client_name: 'Claude Code' })
  })

  test('throws E_INVALID_REQUEST when client_id is missing', async ({ assert }) => {
    const controller = new ClientInfoController()
    const ctx = mockCtx({ query: {} })

    try {
      await controller.handle(ctx)
      assert.fail('Expected E_INVALID_REQUEST to be thrown')
    } catch (error: any) {
      assert.equal(error.code, 'E_INVALID_REQUEST')
    }
  })

  test('throws E_INVALID_CLIENT when client does not exist', async ({ assert }) => {
    const controller = new ClientInfoController()
    const ctx = mockCtx({ query: { client_id: 'non-existent' } })

    try {
      await controller.handle(ctx)
      assert.fail('Expected E_INVALID_CLIENT to be thrown')
    } catch (error: any) {
      assert.equal(error.code, 'E_INVALID_CLIENT')
    }
  })

  test('does not expose client_secret', async ({ assert }) => {
    const client = await createTestClient()
    const controller = new ClientInfoController()
    const ctx = mockCtx({ query: { client_id: client.clientId } })

    const result = (await controller.handle(ctx)) as Record<string, any>

    assert.notProperty(result, 'client_secret')
    assert.notProperty(result, 'clientSecret')
  })
})
