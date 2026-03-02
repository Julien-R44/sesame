import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { createHash } from 'node:crypto'
import { rm } from 'node:fs/promises'
import { resolve } from 'node:path'
import type { ApplicationService } from '@adonisjs/core/types'
import { createApp, setupDatabase, teardownDatabase, createManager } from './helpers.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { TokenService } from '../src/services/token_service.ts'
import { ClientService } from '../src/services/client_service.ts'
import { SesameManager } from '../src/sesame_manager.ts'
import { handleAuthorizationCodeGrant } from '../src/grants/authorization_code_grant.ts'
import { handleRefreshTokenGrant } from '../src/grants/refresh_token_grant.ts'
import TokenController from '../src/controllers/token_controller.ts'
import AuthorizeController from '../src/controllers/authorize_controller.ts'
import ConsentController from '../src/controllers/consent_controller.ts'
import IntrospectController from '../src/controllers/introspect_controller.ts'
import RevokeController from '../src/controllers/revoke_controller.ts'
import RegisterController from '../src/controllers/register_controller.ts'
import MetadataController from '../src/controllers/metadata_controller.ts'
import { OAuthError, E_INVALID_CLIENT } from '../src/oauth_error.ts'

let app: ApplicationService

type TestClientOverrides = Partial<Record<string, any>> & {
  rawClientSecret?: string
}

async function createTestClient(overrides?: TestClientOverrides) {
  const clientService = new ClientService()
  const { rawClientSecret = 'test-secret', ...clientOverrides } = overrides ?? {}

  return OAuthClient.create({
    id: crypto.randomUUID(),
    clientId: 'test-client',
    clientSecret: clientService.hashSecret(rawClientSecret),
    name: 'Test Client',
    redirectUris: ['https://app.example.com/callback'],
    scopes: ['read', 'write', 'offline_access'],
    grantTypes: ['authorization_code', 'refresh_token'],
    isPublic: false,
    isDisabled: false,
    requirePkce: true,
    type: 'confidential',
    metadata: null,
    userId: null,
    ...clientOverrides,
  })
}

async function createTestAuthCode(options: {
  clientId: string
  userId: string
  scopes: string[]
  redirectUri: string
  rawCode: string
  codeChallenge?: string
  codeChallengeMethod?: string
}) {
  const tokenService = new TokenService(createManager())

  return OAuthAuthorizationCode.create({
    id: crypto.randomUUID(),
    code: tokenService.hashToken(options.rawCode),
    clientId: options.clientId,
    userId: options.userId,
    scopes: options.scopes,
    redirectUri: options.redirectUri,
    codeChallenge: options.codeChallenge ?? null,
    codeChallengeMethod: options.codeChallengeMethod ?? null,
    expiresAt: DateTime.now().plus({ minutes: 10 }),
  })
}

function mockCtx(options: {
  body?: Record<string, any>
  query?: Record<string, any>
  headers?: Record<string, string>
  manager?: SesameManager
  auth?: { user?: any }
  session?: {
    put: (key: string, value: any) => void
    pull: (key: string) => any
    forget: (keys: string | string[]) => void
  }
}) {
  const headers: Record<string, string> = { ...options.headers }
  const manager = options.manager ?? createManager()

  return {
    request: {
      body: () => options.body ?? {},
      qs: () => options.query ?? {},
      header: (name: string) => headers[name.toLowerCase()],
    },
    response: {
      header: () => {},
      status: () => {},
      ok: (data: any) => data,
      json: (data: any) => data,
      redirect: () => ({ toPath: (url: string) => ({ redirectUrl: url }) }),
      send: (data: any) => data,
    },
    auth: options.auth ?? options.body?.__auth ?? undefined,
    session: options.session,
    containerResolver: {
      make: async (binding: any) => {
        if (binding === SesameManager) return manager
        throw new Error(`Unknown binding: ${binding}`)
      },
    },
  } as any
}

function createMockSession() {
  const store = new Map<string, any>()

  return {
    put(key: string, value: any) {
      store.set(key, value)
    },
    pull(key: string) {
      const value = store.get(key)
      store.delete(key)
      return value
    },
    forget(keys: string | string[]) {
      const values = Array.isArray(keys) ? keys : [keys]
      for (const key of values) store.delete(key)
    },
  }
}

test.group('Integration | Authorization Flow', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
  })

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('stores an authorization request server-side and consumes it during consent', async ({
    assert,
  }) => {
    const manager = createManager()
    await createTestClient()
    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()
    const session = createMockSession()

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'opaque-state',
        code_challenge: createHash('sha256').update('consent-verifier').digest('base64url'),
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
      session,
    })

    const authorizeResult = (await authorizeController.handle(authorizeCtx)) as any
    const consentUrl = new URL(authorizeResult.redirectUrl, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    assert.isString(authToken)
    assert.isNotNull(authToken)

    const consentCtx = mockCtx({
      manager,
      body: {
        accept: true,
        auth_token: authToken,
      },
      auth: { user: { id: 'user-1' } },
      session,
    })

    const consentResult = (await consentController.handle(consentCtx)) as any
    const redirectUrl = new URL(consentResult.redirectUrl)
    const authCode = redirectUrl.searchParams.get('code')

    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'https://app.example.com/callback')
    assert.equal(redirectUrl.searchParams.get('state'), 'opaque-state')
    assert.isString(authCode)
    assert.isNotNull(await OAuthAuthorizationCode.query().where('clientId', 'test-client').first())
  })

  test('ignores forged OAuth parameters on consent and uses the stored request instead', async ({
    assert,
  }) => {
    const manager = createManager()
    await createTestClient()
    await createTestClient({
      clientId: 'attacker-client',
      name: 'Attacker Client',
      redirectUris: ['https://attacker.example.com/callback'],
      rawClientSecret: 'attacker-secret',
    })

    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()
    const legitCodeChallenge = createHash('sha256').update('legit-verifier').digest('base64url')
    const session = createMockSession()

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'legit-state',
        code_challenge: legitCodeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
      session,
    })

    const authorizeResult = (await authorizeController.handle(authorizeCtx)) as any
    const consentUrl = new URL(authorizeResult.redirectUrl, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    const consentCtx = mockCtx({
      manager,
      body: {
        accept: true,
        auth_token: authToken,
        client_id: 'attacker-client',
        redirect_uri: 'https://attacker.example.com/callback',
        scope: 'write offline_access',
        state: 'attacker-state',
        code_challenge: createHash('sha256').update('attacker-verifier').digest('base64url'),
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
      session,
    })

    const consentResult = (await consentController.handle(consentCtx)) as any
    const redirectUrl = new URL(consentResult.redirectUrl)

    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'https://app.example.com/callback')
    assert.equal(redirectUrl.searchParams.get('state'), 'legit-state')
    assert.notEqual(
      redirectUrl.origin + redirectUrl.pathname,
      'https://attacker.example.com/callback'
    )

    const storedCode = await OAuthAuthorizationCode.query()
      .where('clientId', 'test-client')
      .firstOrFail()
    assert.equal(storedCode.redirectUri, 'https://app.example.com/callback')
    assert.deepEqual(storedCode.scopes, ['read'])
    assert.equal(storedCode.codeChallenge, legitCodeChallenge)
    assert.equal(storedCode.codeChallengeMethod, 'S256')

    const attackerCode = await OAuthAuthorizationCode.query()
      .where('clientId', 'attacker-client')
      .first()
    assert.isNull(attackerCode)
  })
})

test.group('Integration | Authorization Code Grant', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
  })

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('exchanges authorization code for tokens', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const rawCode = 'test-auth-code-123'

    const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read', 'write'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    const result = await handleAuthorizationCodeGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.equal(result.token_type, 'Bearer')
    assert.equal(result.expires_in, 3600)
    assert.equal(result.scope, 'read write')
    assert.isUndefined(result.refresh_token)
  })

  test('issues refresh token with offline_access scope', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const rawCode = 'test-code-with-refresh'
    const codeVerifier = 'another-verifier-value-for-testing'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read', 'offline_access'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    const result = await handleAuthorizationCodeGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
    assert.include(result.scope, 'offline_access')
  })

  test('rejects expired authorization code', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()
    const rawCode = 'expired-code'
    const codeVerifier = 'verifier-for-expired'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken(rawCode),
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge,
      codeChallengeMethod: 'S256',
      expiresAt: DateTime.now().minus({ minutes: 5 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    await assert.rejects(
      () => handleAuthorizationCodeGrant(ctx, manager),
      'Authorization code has expired'
    )
  })

  test('rejects invalid PKCE verifier', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'pkce-test-code'
    const codeChallenge = createHash('sha256').update('correct-verifier').digest('base64url')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: 'wrong-verifier',
      },
    })

    await assert.rejects(
      () => handleAuthorizationCodeGrant(ctx, manager),
      'PKCE verification failed'
    )
  })

  test('rejects invalid client secret', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'secret-test-code'

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'wrong-secret',
      },
    })

    await assert.rejects(() => handleAuthorizationCodeGrant(ctx, manager), 'Invalid client secret')
  })

  test('rejects authorization code exchange when granted scopes exceed client scopes', async ({
    assert,
  }) => {
    const manager = createManager()
    const client = await createTestClient({ scopes: ['read'] })
    const rawCode = 'client-scope-bypass'
    const codeVerifier = 'client-scope-verifier'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['write'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: client.clientId,
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    try {
      await handleAuthorizationCodeGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
    }
  })

  test('authorization code is single-use', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'single-use-code'
    const codeVerifier = 'single-use-verifier'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const makeCtx = () =>
      mockCtx({
        manager,
        body: {
          grant_type: 'authorization_code',
          code: rawCode,
          redirect_uri: 'https://app.example.com/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
          code_verifier: codeVerifier,
        },
      })

    const result = await handleAuthorizationCodeGrant(makeCtx(), manager)
    assert.isDefined(result.access_token)

    await assert.rejects(
      () => handleAuthorizationCodeGrant(makeCtx(), manager),
      'Authorization code not found'
    )
  })

  test('rejects concurrent reuse of the same authorization code', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'racy-auth-code'
    const codeVerifier = 'racy-auth-code-verifier'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const makeCtx = () =>
      mockCtx({
        manager,
        body: {
          grant_type: 'authorization_code',
          code: rawCode,
          redirect_uri: 'https://app.example.com/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
          code_verifier: codeVerifier,
        },
      })

    const results = await Promise.allSettled([
      handleAuthorizationCodeGrant(makeCtx(), manager),
      handleAuthorizationCodeGrant(makeCtx(), manager),
    ])

    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1)
    assert.equal(results.filter((result) => result.status === 'rejected').length, 1)
  })

  test('creates access token record in database', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'db-token-code'
    const codeVerifier = 'db-token-verifier'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    await handleAuthorizationCodeGrant(ctx, manager)

    const tokens = await OAuthAccessToken.query().where('clientId', 'test-client')
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].userId, 'user-1')
    assert.deepEqual(tokens[0].scopes, ['read'])
  })
})

test.group('Integration | Refresh Token Grant', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
  })

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('exchanges refresh token for new tokens', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'test-refresh-token'
    const hashedRefreshToken = tokenService.hashToken(rawRefreshToken)

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      jti: 'old-jti',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write', 'offline_access'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: hashedRefreshToken,
      accessTokenId: 'old-jti',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write', 'offline_access'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const result = await handleRefreshTokenGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
    assert.equal(result.token_type, 'Bearer')
    assert.notEqual(result.refresh_token, rawRefreshToken)
  })

  test('rejects refresh token grant when the client is not allowed to use it', async ({
    assert,
  }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    const client = await createTestClient({ grantTypes: ['authorization_code'] })

    const rawRefreshToken = 'grant-type-bypass-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'grant-type-bypass-jti',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: client.clientId,
        client_secret: 'test-secret',
      },
    })

    try {
      await handleRefreshTokenGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.isTrue(
        ['invalid_client', 'unauthorized_client', 'unsupported_grant_type'].includes(
          error.oauthCode
        )
      )
    }
  })

  test('supports scope downgrading', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'downgrade-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'old-jti-2',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write', 'offline_access'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read',
      },
    })

    const result = await handleRefreshTokenGrant(ctx, manager)
    assert.equal(result.scope, 'read')
  })

  test('rejects scope escalation', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'escalation-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'old-jti-3',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read write',
      },
    })

    try {
      await handleRefreshTokenGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
    }
  })

  test('replay detection revokes all tokens', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'replayed-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'old-jti-4',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
      revokedAt: DateTime.now().minus({ minutes: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('other-valid-token'),
      accessTokenId: 'other-jti',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    try {
      await handleRefreshTokenGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_grant')
    }

    const remaining = await OAuthRefreshToken.query()
      .where('clientId', 'test-client')
      .where('userId', 'user-1')
    assert.lengthOf(remaining, 0)
  })

  test('rejects concurrent rotation of the same refresh token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'racy-refresh-token'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'racy-refresh-jti',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const makeCtx = () =>
      mockCtx({
        manager,
        body: {
          grant_type: 'refresh_token',
          refresh_token: rawRefreshToken,
          client_id: 'test-client',
          client_secret: 'test-secret',
        },
      })

    const results = await Promise.allSettled([
      handleRefreshTokenGrant(makeCtx(), manager),
      handleRefreshTokenGrant(makeCtx(), manager),
    ])

    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1)
    assert.equal(results.filter((result) => result.status === 'rejected').length, 1)
  })

  test('rejects expired refresh token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'expired-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'old-jti-5',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().minus({ days: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    await assert.rejects(() => handleRefreshTokenGrant(ctx, manager), 'Refresh token has expired')
  })
})

test.group('Integration | Token Endpoint Dispatch', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
  })

  test('rejects unsupported grant type', async ({ assert }) => {
    const manager = createManager()
    const controller = new TokenController()
    const ctx = mockCtx({ manager, body: { grant_type: 'password' } })

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'unsupported_grant_type')
    }
  })

  test('rejects missing grant type', async ({ assert }) => {
    const manager = createManager()
    const controller = new TokenController()
    const ctx = mockCtx({ manager, body: {} })

    await assert.rejects(() => controller.handle(ctx), 'Missing required parameter: grant_type')
  })
})

test.group('Integration | Introspection', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
  })

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('introspects a valid JWT access token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { token, jti } = await tokenService.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      jti,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = (await controller.handle(ctx)) as any

    assert.isTrue(result.active)
    assert.equal(result.client_id, 'test-client')
    assert.equal(result.sub, 'user-1')
    assert.equal(result.scope, 'read')
  })

  test('rejects introspection for a confidential client without a secret', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { token, jti } = await tokenService.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      jti,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token,
        client_id: 'test-client',
      },
    })

    const controller = new IntrospectController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client')
    }
  })

  test('returns inactive for revoked token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { token, jti } = await tokenService.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      jti,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
      revokedAt: DateTime.now(),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = await controller.handle(ctx)
    assert.isFalse(result.active)
  })

  test('returns inactive when the JWT access token row is missing', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { token } = await tokenService.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
    })

    const ctx = mockCtx({
      manager,
      body: {
        token,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = await controller.handle(ctx)
    assert.isFalse(result.active)
  })

  test('returns inactive for missing token', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()

    const ctx = mockCtx({
      manager,
      body: {
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = await controller.handle(ctx)
    assert.isFalse(result.active)
  })

  test('introspects a valid refresh token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'introspect-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'some-jti',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: rawRefreshToken,
        token_type_hint: 'refresh_token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = (await controller.handle(ctx)) as any

    assert.isTrue(result.active)
    assert.equal(result.client_id, 'test-client')
    assert.equal(result.sub, 'user-1')
    assert.equal(result.scope, 'read write')
  })

  test('returns inactive when another client introspects the access token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()
    await createTestClient({
      clientId: 'other-client',
      name: 'Other Client',
      redirectUris: ['https://other.example.com/callback'],
      rawClientSecret: 'other-secret',
    })

    const { token, jti } = await tokenService.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      jti,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token,
        client_id: 'other-client',
        client_secret: 'other-secret',
      },
    })

    const controller = new IntrospectController()
    const result = await controller.handle(ctx)
    assert.isFalse(result.active)
  })
})

test.group('Integration | Revocation', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
  })

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('revokes a JWT access token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { token, jti } = await tokenService.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      jti,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token,
        token_type_hint: 'access_token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new RevokeController()
    await controller.handle(ctx)

    const record = await OAuthAccessToken.query().where('jti', jti).firstOrFail()
    assert.isNotNull(record.revokedAt)
  })

  test('rejects revocation for a confidential client without a secret', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { token, jti } = await tokenService.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      jti,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token,
        token_type_hint: 'access_token',
        client_id: 'test-client',
      },
    })

    const controller = new RevokeController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client')
    }
  })

  test('revokes a refresh token and associated access token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'revoke-me-refresh'

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      jti: 'linked-jti',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'linked-jti',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: rawRefreshToken,
        token_type_hint: 'refresh_token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new RevokeController()
    await controller.handle(ctx)

    const refresh = await OAuthRefreshToken.query()
      .where('token', tokenService.hashToken(rawRefreshToken))
      .firstOrFail()
    assert.isNotNull(refresh.revokedAt)

    const access = await OAuthAccessToken.query().where('jti', 'linked-jti').firstOrFail()
    assert.isNotNull(access.revokedAt)
  })

  test('always returns 200 even for unknown tokens', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()

    let statusCode: number | undefined
    const ctx = mockCtx({
      manager,
      body: {
        token: 'totally-unknown-token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })
    ctx.response.ok = (data: any) => {
      statusCode = 200
      return data
    }

    const controller = new RevokeController()
    await controller.handle(ctx)
    assert.equal(statusCode, 200)
  })
})

test.group('Integration | Dynamic Registration', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
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
})

test.group('Integration | Metadata Endpoints', () => {
  test('returns OAuth authorization server metadata', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.authServer(ctx)

    assert.equal(result.issuer, 'https://auth.example.com')
    assert.equal(result.authorization_endpoint, 'https://auth.example.com/oauth/authorize')
    assert.equal(result.token_endpoint, 'https://auth.example.com/oauth/token')
    assert.equal(result.jwks_uri, 'https://auth.example.com/oauth/jwks')
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
    assert.deepEqual(result.id_token_signing_alg_values_supported, ['RS256'])
    assert.isArray(result.scopes_supported)
  })

  test('hides registration endpoint when disabled', async ({ assert }) => {
    const manager = createManager({ allowDynamicRegistration: false })
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.authServer(ctx)
    assert.isUndefined(result.registration_endpoint)
  })
})

test.group('Integration | OAuth Error Handling', () => {
  test('OAuthError has correct properties', ({ assert }) => {
    const error = new E_INVALID_CLIENT('Client not found')

    assert.equal(error.status, 401)
    assert.equal(error.oauthCode, 'invalid_client')
    assert.equal(error.message, 'Client not found')
    assert.instanceOf(error, OAuthError)
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

  test('parses TTL strings', ({ assert }) => {
    const manager = createManager()

    assert.equal(manager.parseTtl('1h'), 3600)
    assert.equal(manager.parseTtl('30m'), 1800)
    assert.equal(manager.parseTtl('10d'), 864000)
    assert.equal(manager.parseTtl('60s'), 60)
  })

  test('throws on invalid TTL', ({ assert }) => {
    const manager = createManager()

    assert.throws(() => manager.parseTtl('invalid'))
    assert.throws(() => manager.parseTtl('10x'))
  })
})
