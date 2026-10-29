import { test } from '@japa/runner'
import { HttpContextFactory, RequestFactory } from '@adonisjs/core/factories/http'
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose'
import { createManager, createTestConfig, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createAuthCodeExchange } from './helpers/create_auth_code_exchange.ts'
import { createTestRefreshToken } from './helpers/create_test_refresh_token.ts'
import { createFakeEmitter, FakeUserProvider, getTestJwk } from './helpers/fakes.ts'
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

  test('omits aud for a token bound to no resource', async ({ assert }) => {
    const manager = await createJwtManager()
    const client = await createTestClient()
    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({ manager })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    const { payload } = await verifyAsResourceServer(manager, result.access_token)
    assert.notProperty(payload, 'aud')
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
