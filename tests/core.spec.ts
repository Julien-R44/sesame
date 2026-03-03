import { test } from '@japa/runner'
import { createHash } from 'node:crypto'
import { DateTime } from 'luxon'
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
import { OAuthPendingAuthorizationRequest } from '../src/models/oauth_pending_authorization_request.ts'
import { TokenService } from '../src/services/token_service.ts'
import MetadataController from '../src/controllers/metadata_controller.ts'
import {
  OAuthError,
  E_INVALID_CLIENT,
  E_INVALID_CLIENT_METADATA,
  E_SERVER_ERROR,
} from '../src/oauth_error.ts'
import { ClientService } from '../src/services/client_service.ts'
import AuthorizeController from '../src/controllers/authorize_controller.ts'
import RegisterController from '../src/controllers/register_controller.ts'

let app: ApplicationService

test.group('Integration | Metadata Endpoints', () => {
  test('returns OAuth authorization server metadata', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.authServer(ctx)

    assert.equal(result.issuer, 'https://auth.example.com')
    assert.equal(result.authorization_endpoint, 'https://auth.example.com/oauth/authorize')
    assert.equal(result.token_endpoint, 'https://auth.example.com/oauth/token')
    assert.deepEqual(result.response_types_supported, ['code'])
    assert.deepEqual(result.code_challenge_methods_supported, ['S256'])
    assert.isTrue(result.authorization_response_iss_parameter_supported)
    assert.isDefined(result.registration_endpoint)
  })

  test('returns protected resource metadata for MCP', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.protectedResource(ctx)

    assert.equal(result.resource, 'https://auth.example.com')
    assert.deepEqual(result.authorization_servers, ['https://auth.example.com'])
    assert.isArray(result.scopes_supported)
    assert.deepEqual(result.bearer_methods_supported, ['header'])
  })

  test('returns OIDC metadata', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.oidc(ctx)

    assert.equal(result.issuer, 'https://auth.example.com')
    assert.deepEqual(result.subject_types_supported, ['public'])
    assert.isArray(result.scopes_supported)
  })

  test('advertises none auth method for all endpoints', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.authServer(ctx)

    const allEndpoints = [
      result.token_endpoint_auth_methods_supported,
      result.introspection_endpoint_auth_methods_supported,
      result.revocation_endpoint_auth_methods_supported,
    ]
    for (const methods of allEndpoints) assert.include(methods!, 'none')
  })

  test('hides registration endpoint when disabled', async ({ assert }) => {
    const manager = createManager({ allowDynamicRegistration: false })
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.authServer(ctx)
    assert.isUndefined(result.registration_endpoint)
  })

  test('uses router-generated URLs for discovery metadata', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({
      manager,
      router: {
        has(name: string) {
          return [
            'sesame.authorize',
            'sesame.token',
            'sesame.register',
            'sesame.introspect',
            'sesame.revoke',
          ].includes(name)
        },
        makeUrl(name: string, _params: any, opts?: { prefixUrl?: string }) {
          const paths: Record<string, string> = {
            'sesame.authorize': '/auth/authorize',
            'sesame.token': '/auth/token',
            'sesame.register': '/auth/register',
            'sesame.introspect': '/auth/introspect',
            'sesame.revoke': '/auth/revoke',
          }

          return `${opts?.prefixUrl ?? ''}${paths[name]}`
        },
      },
    })

    const controller = new MetadataController()
    const result = await controller.authServer(ctx)

    assert.equal(result.authorization_endpoint, 'https://auth.example.com/auth/authorize')
    assert.equal(result.token_endpoint, 'https://auth.example.com/auth/token')
    assert.equal(result.registration_endpoint, 'https://auth.example.com/auth/register')
    assert.equal(result.introspection_endpoint, 'https://auth.example.com/auth/introspect')
    assert.equal(result.revocation_endpoint, 'https://auth.example.com/auth/revoke')
  })

  test('throws a clear server error when OAuth routes are missing from discovery', async ({
    assert,
  }) => {
    const manager = createManager()
    const ctx = mockCtx({
      manager,
      router: {
        has() {
          return false
        },
        makeUrl(): string {
          throw new Error('makeUrl should not be called when required routes are missing')
        },
      },
    })

    try {
      await new MetadataController().authServer(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, E_SERVER_ERROR)
      assert.include(error.message, 'OAuth discovery is misconfigured')
      assert.include(error.message, 'sesame.authorize')
      assert.include(error.message, 'sesame.token')
      assert.include(error.message, 'sesame.introspect')
      assert.include(error.message, 'sesame.revoke')
    }
  })
})

test.group('Integration | OAuth Error Handling', () => {
  test('OAuthError has correct properties', ({ assert }) => {
    const error = new E_INVALID_CLIENT('Client authentication failed')

    assert.equal(error.status, 401)
    assert.equal(error.oauthCode, 'invalid_client')
    assert.equal(error.message, 'Client authentication failed')
    assert.instanceOf(error, OAuthError)
  })
})

test.group('Integration | TokenService', () => {
  test('createAccessToken returns raw, hash and expiresAt', ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)

    const { raw, hash, expiresAt } = tokenService.createAccessToken()

    assert.isString(raw)
    assert.isString(hash)
    assert.notEqual(raw, hash)
    assert.instanceOf(expiresAt, Date)
    assert.equal(hash, tokenService.hashToken(raw))
  })
})

test.group('Integration | SesameManager', () => {
  test('validates scopes', ({ assert }) => {
    const manager = createManager()

    assert.deepEqual(manager.validateScopes(['read', 'write']), [])
    assert.deepEqual(manager.validateScopes(['read', 'admin']), ['admin'])
  })

  test('checks grant type support', ({ assert }) => {
    const manager = createManager()

    assert.isTrue(manager.isGrantTypeEnabled('authorization_code'))
    assert.isTrue(manager.isGrantTypeEnabled('refresh_token'))
    assert.isFalse(manager.isGrantTypeEnabled('client_credentials'))
  })
})

test.group('Integration | revokeAllForUser', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(async () => {
    await OAuthPendingAuthorizationRequest.query().delete()
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('revokes all tokens, codes and consents for a user', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const tokenService = new TokenService(manager)

    // Create access token
    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'at-1',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    // Create refresh token
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('rt-1'),
      accessTokenId: 'at-1',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    // Create authorization code
    const revokeVerifier = 'revoke-all-verifier'
    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken('code-1'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: createHash('sha256').update(revokeVerifier).digest('base64url'),
      codeChallengeMethod: 'S256',
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    // Create consent
    await OAuthConsent.create({
      id: crypto.randomUUID(),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
    })

    await manager.revokeAllForUser('user-1')

    const accessToken = await OAuthAccessToken.query().where('tokenHash', 'at-1').firstOrFail()
    assert.isNotNull(accessToken.revokedAt)

    const refreshToken = await OAuthRefreshToken.query()
      .where('accessTokenId', 'at-1')
      .firstOrFail()
    assert.isNotNull(refreshToken.revokedAt)

    const codes = await OAuthAuthorizationCode.query().where('userId', 'user-1')
    assert.lengthOf(codes, 0)

    const consents = await OAuthConsent.query().where('userId', 'user-1')
    assert.lengthOf(consents, 0)
  })

  test('revokes pending authorization requests for a user', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const tokenService = new TokenService(manager)

    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('pending-1'),
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('pending-2'),
      clientId: client.clientId,
      userId: 'user-2',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    await manager.revokeAllForUser('user-1')

    const user1Pending = await OAuthPendingAuthorizationRequest.query().where('userId', 'user-1')
    assert.lengthOf(user1Pending, 0)

    const user2Pending = await OAuthPendingAuthorizationRequest.query().where('userId', 'user-2')
    assert.lengthOf(user2Pending, 1)
  })

  test('does not affect other users', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'at-user1',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'at-user2',
      clientId: client.clientId,
      userId: 'user-2',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await manager.revokeAllForUser('user-1')

    const revokedToken = await OAuthAccessToken.query().where('tokenHash', 'at-user1').firstOrFail()
    assert.isNotNull(revokedToken.revokedAt)

    const untouchedToken = await OAuthAccessToken.query()
      .where('tokenHash', 'at-user2')
      .firstOrFail()
    assert.isNull(untouchedToken.revokedAt)
  })
})

test.group('Security | Scope validation bypass (C1/C2)', () => {
  test('C1: validateScopes rejects all scopes when server scopes config is empty', ({ assert }) => {
    const manager = createManager({ scopes: {} })
    const invalid = manager.validateScopes(['admin', 'superuser', 'delete_all'])
    assert.deepEqual(invalid, ['admin', 'superuser', 'delete_all'])
  })

  test('C1: validateScopes allows empty scope list when server scopes config is empty', ({
    assert,
  }) => {
    const manager = createManager({ scopes: {} })
    assert.deepEqual(manager.validateScopes([]), [])
  })

  test('C2: validateClientScopes rejects any scope when client scopes are empty', ({ assert }) => {
    const service = new ClientService()
    assert.throws(
      () => service.validateClientScopes(['admin', 'delete_all'], []),
      'Scope not allowed'
    )
  })

  test('C2: validateClientScopes allows empty request when client scopes are empty', ({
    assert,
  }) => {
    const service = new ClientService()
    assert.doesNotThrow(() => service.validateClientScopes([], []))
  })
})

test.group('Security | Scope validation bypass (C1/C2) — Integration', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(async () => {
    await OAuthPendingAuthorizationRequest.query().delete()
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('C1+C2: authorize endpoint rejects arbitrary scopes with empty configs', async ({
    assert,
  }) => {
    const manager = createManager({ scopes: {}, defaultScopes: [] })
    const codeVerifier = 'a'.repeat(43)
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    const clientService = new ClientService()
    await OAuthClient.create({
      id: crypto.randomUUID(),
      clientId: 'bypass-client',
      clientSecret: clientService.hashSecret('secret'),
      name: 'Bypass Client',
      redirectUris: ['https://evil.example.com/callback'],
      scopes: [],
      grantTypes: ['authorization_code'],
      isPublic: false,
      isDisabled: false,
      requirePkce: true,
      type: 'confidential',
      metadata: null,
      userId: null,
    })

    // Pre-create consent (should never be reached due to scope rejection)
    await OAuthConsent.create({
      id: crypto.randomUUID(),
      clientId: 'bypass-client',
      userId: 'user-1',
      scopes: ['admin', 'superuser'],
    })

    const ctx = mockCtx({
      query: {
        client_id: 'bypass-client',
        response_type: 'code',
        redirect_uri: 'https://evil.example.com/callback',
        scope: 'admin superuser',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
      manager,
    })

    const result = (await new AuthorizeController().handle(ctx)) as any

    // C1 rejects unknown scopes → redirect with invalid_scope error
    assert.include(result.redirectUrl, 'error=invalid_scope')

    // No auth code should have been created
    const authCodes = await OAuthAuthorizationCode.query()
      .where('clientId', 'bypass-client')
      .where('userId', 'user-1')
    assert.lengthOf(authCodes, 0)
  })

  test('B5: registration rejects client_name longer than 255 characters', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({
      body: {
        redirect_uris: ['https://app.example.com/callback'],
        token_endpoint_auth_method: 'none',
        client_name: 'A'.repeat(256),
      },
      manager,
    })

    await assert.rejects(() => new RegisterController().handle(ctx), E_INVALID_CLIENT_METADATA)
  })

  test('B5: registration trims client_name whitespace', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({
      body: {
        redirect_uris: ['https://app.example.com/callback'],
        token_endpoint_auth_method: 'none',
        client_name: '  My App  ',
      },
      manager,
    })

    const result = await new RegisterController().handle(ctx)
    assert.equal(result.client_name, 'My App')
  })

  test('B5: registration accepts client_name at exactly 255 characters', async ({ assert }) => {
    const manager = createManager()
    const name = 'A'.repeat(255)
    const ctx = mockCtx({
      body: {
        redirect_uris: ['https://app.example.com/callback'],
        token_endpoint_auth_method: 'none',
        client_name: name,
      },
      manager,
    })

    const result = await new RegisterController().handle(ctx)
    assert.equal(result.client_name, name)
  })

  test('C1+C2: dynamic registration → authorize rejects arbitrary scopes', async ({ assert }) => {
    const manager = createManager({ scopes: {}, defaultScopes: [] })
    const codeChallenge = createHash('sha256').update('b'.repeat(43)).digest('base64url')

    // Step 1: Register a public client (no scopes → gets defaultScopes = [])
    const registerCtx = mockCtx({
      body: {
        redirect_uris: ['https://attacker.example.com/callback'],
        token_endpoint_auth_method: 'none',
      },
      manager,
    })
    const registerResult = await new RegisterController().handle(registerCtx)
    assert.isDefined(registerResult.client_id)

    // Step 2: Authorize with arbitrary scopes — should be rejected by C1
    const authorizeCtx = mockCtx({
      query: {
        client_id: registerResult.client_id,
        response_type: 'code',
        redirect_uri: 'https://attacker.example.com/callback',
        scope: 'admin superuser',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
      manager,
    })
    const authorizeResult = (await new AuthorizeController().handle(authorizeCtx)) as any

    // Attack chain broken at authorize: scopes rejected
    assert.include(authorizeResult.redirectUrl, 'error=invalid_scope')
    assert.include(authorizeResult.redirectUrl, 'admin')

    // No auth code or token should exist
    const authCodes = await OAuthAuthorizationCode.query().where('userId', 'user-1')
    assert.lengthOf(authCodes, 0)
    const accessTokens = await OAuthAccessToken.query().where('userId', 'user-1')
    assert.lengthOf(accessTokens, 0)
  })
})
