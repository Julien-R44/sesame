import { test } from '@japa/runner'
import { HttpContextFactory, RequestFactory } from '@adonisjs/core/factories/http'
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  jwtVerify,
} from 'jose'
import { createManager, createTestConfig, setupIntegrationGroup } from './helpers/app.ts'
import { SesameManager } from '../src/sesame_manager.ts'
import { lucidStore } from '../src/storage/drivers/lucid.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createAuthCodeExchange } from './helpers/create_auth_code_exchange.ts'
import { createTestRefreshToken } from './helpers/create_test_refresh_token.ts'
import { createFakeEmitter, FakeUserProvider, getTestJwk } from './helpers/fakes.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthGuard } from '../src/guard/guard.ts'
import { TokenService } from '../src/services/token_service.ts'
import { ExchangeAuthorizationCodeAction } from '../src/actions/exchange_authorization_code.ts'
import { ExchangeRefreshTokenAction } from '../src/actions/exchange_refresh_token.ts'
import { ExchangeClientCredentialsAction } from '../src/actions/exchange_client_credentials.ts'
import type { AccessTokenClaimsContext } from '../src/types.ts'

async function createJwtManager(overrides?: Record<string, any>) {
  return createManager({ jwk: await getTestJwk(), accessTokenFormat: 'jwt', ...overrides })
}

/**
 * Verifies a token the way a resource server would: against the
 * published JWKS only.
 */
async function verifyAsResourceServer(
  manager: Awaited<ReturnType<typeof createJwtManager>>,
  token: string
) {
  const jwks = createLocalJWKSet(manager.keyService.getPublicJwks())
  return jwtVerify(token, jwks, { issuer: 'https://auth.example.com', typ: 'at+jwt' })
}

test.group('JWT access tokens | config', () => {
  test('requires a jwk', ({ assert }) => {
    assert.throws(
      () => createTestConfig({ accessTokenFormat: 'jwt', jwk: undefined }),
      /requires "jwk"/
    )
  })

  test('requires a jwk for previous keys', async ({ assert }) => {
    assert.throws(
      () => createTestConfig({ previousJwks: [{ kty: 'RSA' }] }),
      /"previousJwks" requires "jwk"/
    )
  })

  test('rejects an invalid external resource', ({ assert }) => {
    assert.throws(
      () => createTestConfig({ externalResources: ['vis'] }),
      /Invalid external resource "vis"/
    )
  })

  test('keeps opaque access tokens by default', async ({ assert }) => {
    const manager = createManager({ jwk: await getTestJwk() })
    const tokenService = new TokenService(manager)

    const { raw } = await tokenService.createAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
      resource: null,
      grantId: null,
      expiresAt: tokenService.accessTokenExpiresAt(),
    })

    assert.notInclude(raw, '.')
  })
})

test.group('JWT access tokens | issuance', (group) => {
  setupIntegrationGroup(group)

  test('exchanges a code for an at+jwt verifiable against the JWKS', async ({ assert }) => {
    const contexts: AccessTokenClaimsContext[] = []
    const manager = await createJwtManager({
      accessTokenClaims: (context: AccessTokenClaimsContext) => {
        contexts.push(context)
        return { vis_user_id: 42, sub: 'spoofed', scope: 'admin' }
      },
    })
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      userId: 'user-7',
      scopes: ['read'],
      resource: 'https://api.example.com/vis',
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    assert.equal(decodeProtectedHeader(result.access_token).typ, 'at+jwt')
    const { payload } = await verifyAsResourceServer(manager, result.access_token)
    assert.equal(payload.sub, 'user-7')
    assert.equal(payload.client_id, 'test-client')
    assert.equal(payload.scope, 'read')
    assert.equal(payload.aud, 'https://api.example.com/vis')
    assert.equal(payload.vis_user_id, 42)
    assert.isString(payload.jti)
    assert.closeTo(payload.exp! - payload.iat!, 3600, 1)

    // The hook sees the grant the token is stored under.
    const stored = await OAuthAccessToken.query().where('userId', 'user-7').firstOrFail()
    assert.lengthOf(contexts, 1)
    assert.equal(contexts[0].grantId, stored.grantId)
    assert.equal(stored.tokenHash, new TokenService(manager).hashToken(result.access_token))
  })

  test('defaults the audience of an unbound token to the issuer', async ({ assert }) => {
    const manager = await createJwtManager()
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({ manager })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    const jwks = createLocalJWKSet(manager.keyService.getPublicJwks())
    const { payload } = await jwtVerify(result.access_token, jwks, {
      issuer: 'https://auth.example.com',
      audience: 'https://auth.example.com',
      typ: 'at+jwt',
    })
    assert.equal(payload.aud, 'https://auth.example.com')
  })

  test('stores the default audience so guards agree with the signed aud', async ({ assert }) => {
    const manager = new SesameManager(
      createTestConfig({ jwk: await getTestJwk(), accessTokenFormat: 'jwt' }),
      { get: () => {} } as any,
      lucidStore()
    )
    manager.registerProtectedResource({ resource: '/api-a' })
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({ manager })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    // The access token is bound to the issuer; the refresh token stays unbound.
    const stored = await OAuthAccessToken.query().where('userId', 'user-1').firstOrFail()
    assert.equal(stored.resource, 'https://auth.example.com')
    const refresh = await OAuthRefreshToken.query().where('userId', 'user-1').firstOrFail()
    assert.isNull(refresh.resource)

    const authenticate = (resource: string) => {
      const request = new RequestFactory().merge({ url: '/' }).create()
      request.request.headers.authorization = `Bearer ${result.access_token}`
      const ctx = new HttpContextFactory().merge({ request }).create()
      const provider = new FakeUserProvider([{ id: 'user-1', name: 'Jane' }])
      return new OAuthGuard('oauth', ctx, createFakeEmitter(), provider, manager, {
        resource,
        requireAudience: resource === '/',
      }).check()
    }

    assert.isTrue(await authenticate('/'))
    assert.isFalse(await authenticate('/api-a'))
  })

  test('keeps the stored audience when the token format changes', async ({ assert }) => {
    const jwtManager = await createJwtManager()
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager: jwtManager,
    })
    await new ExchangeAuthorizationCodeAction().execute(jwtManager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    // Opaque issuance before the switch stays unbound, the JWT stays bound.
    const opaqueManager = createManager({ jwk: await getTestJwk() })
    const opaque = await createAuthCodeExchange({ manager: opaqueManager, userId: 'user-2' })
    await new ExchangeAuthorizationCodeAction().execute(opaqueManager, {
      client,
      code: opaque.rawCode,
      redirectUri: opaque.redirectUri,
      codeVerifier: opaque.codeVerifier,
    })

    const jwtRow = await OAuthAccessToken.query().where('userId', 'user-1').firstOrFail()
    const opaqueRow = await OAuthAccessToken.query().where('userId', 'user-2').firstOrFail()
    assert.equal(jwtRow.resource, 'https://auth.example.com')
    assert.isNull(opaqueRow.resource)
  })

  test('ignores every reserved claim returned by the hook', async ({ assert }) => {
    const reserved = ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'client_id', 'scope']
    const manager = await createJwtManager({
      accessTokenClaims: () => ({
        ...Object.fromEntries(reserved.map((claim) => [claim, 'spoofed'])),
        tenant: 't-1',
      }),
    })
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({ manager })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    const { payload } = await verifyAsResourceServer(manager, result.access_token)
    assert.equal(payload.tenant, 't-1')
    for (const claim of reserved) assert.notEqual(payload[claim], 'spoofed', claim)
  })

  test('cannot change the token through the hook context', async ({ assert }) => {
    const manager = await createJwtManager({
      accessTokenClaims: (context: AccessTokenClaimsContext) => {
        context.userId = 'attacker'
        context.clientId = 'other-client'
        context.resource = 'https://evil.example.com'
        context.scopes.push('admin')
        return {}
      },
    })
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      scopes: ['read'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    const { payload } = await verifyAsResourceServer(manager, result.access_token)
    assert.equal(payload.sub, 'user-1')
    assert.equal(payload.client_id, 'test-client')
    assert.equal(payload.scope, 'read')
    assert.equal(payload.aud, 'https://auth.example.com')
    const stored = await OAuthAccessToken.query().where('userId', 'user-1').firstOrFail()
    assert.deepEqual(stored.scopes, ['read'])
  })

  test('binds a token to an external resource requested at the token endpoint', async ({
    assert,
  }) => {
    const manager = await createJwtManager({ externalResources: ['https://API.example.org/'] })
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({ manager })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
      resource: 'https://api.example.org/vis',
    })

    // RFC 8707 lets a resource map to the more general one configured.
    const { payload } = await verifyAsResourceServer(manager, result.access_token)
    assert.equal(payload.aud, 'https://api.example.org')
  })

  test('rejects a resource that is neither served nor external', async ({ assert }) => {
    const manager = await createJwtManager({ externalResources: ['https://api.example.org'] })
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({ manager })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri,
          codeVerifier,
          resource: 'https://api.example.org.evil.com',
        }),
      'invalid_target'
    )
  })

  test('issues a JWT on refresh, in the refreshed grant', async ({ assert }) => {
    const grantIds: Array<string | null> = []
    const manager = await createJwtManager({
      accessTokenClaims: ({ grantId }: AccessTokenClaimsContext) => {
        grantIds.push(grantId)
        return {}
      },
    })
    const client = await createTestClient()
    const { rawRefreshToken, grantId } = await createTestRefreshToken({ manager })

    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: rawRefreshToken,
    })

    const { payload } = await verifyAsResourceServer(manager, result.access_token)
    assert.equal(payload.sub, 'user-1')
    assert.deepEqual(grantIds, [grantId])
  })

  test('keeps tokens signed with a previous key verifiable after a rotation', async ({
    assert,
  }) => {
    const oldJwk = await getTestJwk()
    const { privateKey } = await generateKeyPair('RS256', { extractable: true })
    const newJwk = await exportJWK(privateKey)
    const oldTokenService = new TokenService(await createJwtManager())
    const { raw: oldToken } = await oldTokenService.createAccessToken({
      userId: 'user-1',
      clientId: 'test-client',
      scopes: ['read'],
      resource: null,
      grantId: null,
      expiresAt: oldTokenService.accessTokenExpiresAt(),
    })

    // Previous keys only verify, so their public half is enough.
    const oldPublicJwk = { kty: oldJwk.kty, n: oldJwk.n, e: oldJwk.e }
    const rotated = await createJwtManager({ jwk: newJwk, previousJwks: [oldPublicJwk] })
    const { payload } = await verifyAsResourceServer(rotated, oldToken)
    assert.equal(payload.sub, 'user-1')

    const withoutPrevious = await createJwtManager({ jwk: newJwk })
    await assert.rejects(() => verifyAsResourceServer(withoutPrevious, oldToken))
  })

  test('authenticates a JWT access token with OAuthGuard', async ({ assert }) => {
    const manager = await createJwtManager()
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({ manager })
    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    const request = new RequestFactory().merge({ url: '/' }).create()
    request.request.headers.authorization = `Bearer ${result.access_token}`
    const ctx = new HttpContextFactory().merge({ request }).create()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Jane' }])
    const guard = new OAuthGuard('oauth', ctx, createFakeEmitter(), provider, manager)

    assert.deepEqual(await guard.authenticate(), { id: 'user-1', name: 'Jane' })
  })

  test('issues a client_credentials JWT without a grant', async ({ assert }) => {
    const grantIds: Array<string | null> = []
    const manager = await createJwtManager({
      grantTypes: ['client_credentials'],
      clientCredentialsAccessTokenTtl: '5m',
      accessTokenClaims: ({ grantId }: AccessTokenClaimsContext) => {
        grantIds.push(grantId)
        return {}
      },
    })
    const client = await createTestClient({ grantTypes: ['client_credentials'], userId: 'svc-1' })

    const result = await new ExchangeClientCredentialsAction().execute(manager, {
      client,
      scope: 'read',
    })

    const { payload } = await verifyAsResourceServer(manager, result.access_token)
    assert.equal(payload.sub, 'svc-1')
    assert.closeTo(payload.exp! - payload.iat!, 300, 1)
    assert.deepEqual(grantIds, [null])
  })
})
