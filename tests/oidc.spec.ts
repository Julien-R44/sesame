import { test } from '@japa/runner'
import { createHash } from 'node:crypto'
import { DateTime } from 'luxon'
import { jwtVerify } from 'jose'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { mockCtx } from './helpers/mock_ctx.ts'
import { getTestJwk, FakeUserProvider, type FakeUser } from './helpers/fakes.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createTestAccessToken } from './helpers/create_test_access_token.ts'
import { createAuthCodeExchange } from './helpers/create_auth_code_exchange.ts'
import { KeyService } from '../src/services/key_service.ts'
import { IdTokenService } from '../src/services/id_token_service.ts'
import { TokenService } from '../src/services/token_service.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import MetadataController from '../src/controllers/metadata_controller.ts'
import JwksController from '../src/controllers/jwks_controller.ts'
import UserinfoController from '../src/controllers/userinfo_controller.ts'
import { ExchangeAuthorizationCodeAction } from '../src/actions/exchange_authorization_code.ts'
import { ExchangeRefreshTokenAction } from '../src/actions/exchange_refresh_token.ts'
import { OIDC_SCOPES, RESERVED_OIDC_CLAIMS } from '../src/types.ts'

// --- KeyService ---

test.group('KeyService', () => {
  test('loads JWK and signs a JWT', async ({ assert }) => {
    const jwk = await getTestJwk()
    const service = new KeyService(jwk)

    const token = await service.sign({ sub: 'user-1', iss: 'https://example.com' })

    assert.isString(token)
    assert.isTrue(token.split('.').length === 3)
  })

  test('computes kid from public components', async ({ assert }) => {
    const jwk = await getTestJwk()
    const service = new KeyService(jwk)

    assert.isString(service.kid)
    assert.isTrue(service.kid.length > 0)
  })

  test('exports public JWKS without private components', async ({ assert }) => {
    const jwk = await getTestJwk()
    const service = new KeyService(jwk)
    const jwks = service.getPublicJwks()

    assert.isArray(jwks.keys)
    assert.equal(jwks.keys.length, 1)

    const publicKey = jwks.keys[0]
    assert.equal(publicKey.kty, 'RSA')
    assert.equal(publicKey.use, 'sig')
    assert.equal(publicKey.alg, 'RS256')
    assert.isString(publicKey.kid)
    assert.isString(publicKey.n)
    assert.isString(publicKey.e)

    // Must NOT contain private components
    assert.notProperty(publicKey, 'd')
    assert.notProperty(publicKey, 'p')
    assert.notProperty(publicKey, 'q')
    assert.notProperty(publicKey, 'dp')
    assert.notProperty(publicKey, 'dq')
    assert.notProperty(publicKey, 'qi')
  })

  test('uses provided kid if present in JWK', async ({ assert }) => {
    const jwk = await getTestJwk()
    const service = new KeyService({ ...jwk, kid: 'my-custom-kid' })

    assert.equal(service.kid, 'my-custom-kid')
    assert.equal(service.getPublicJwks().keys[0].kid, 'my-custom-kid')
  })
})

// --- IdTokenService ---

test.group('IdTokenService', () => {
  test('computes at_hash correctly', ({ assert }) => {
    const accessToken = 'test-access-token-value'
    const hash = createHash('sha256').update(accessToken).digest()
    const expected = hash.subarray(0, hash.length / 2).toString('base64url')

    assert.equal(IdTokenService.computeAtHash(accessToken), expected)
  })

  test('filters reserved claims', ({ assert }) => {
    const claims = {
      sub: 'should-be-removed',
      iss: 'should-be-removed',
      name: 'Julien',
      email: 'julien@example.com',
      nonce: 'should-be-removed',
      custom_claim: 'keep-me',
    }

    const filtered = IdTokenService.filterReservedClaims(claims)

    assert.notProperty(filtered, 'sub')
    assert.notProperty(filtered, 'iss')
    assert.notProperty(filtered, 'nonce')
    assert.equal(filtered.name, 'Julien')
    assert.equal(filtered.email, 'julien@example.com')
    assert.equal(filtered.custom_claim, 'keep-me')
  })

  test('signs an id_token with correct claims', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk, idTokenTtl: '1h' })
    const service = new IdTokenService(manager)

    const token = await service.sign({
      sub: 'user-123',
      clientId: 'client-abc',
      scopes: ['openid', 'profile'],
      accessToken: 'raw-access-token',
      user: { id: 'user-123' },
      nonce: 'test-nonce',
    })

    assert.isString(token)

    // Verify the JWT
    const keyService = new KeyService(jwk)
    const jwks = keyService.getPublicJwks()
    const publicKey = await import('jose').then((j) => j.importJWK(jwks.keys[0], 'RS256'))

    const { payload } = await jwtVerify(token, publicKey as any)

    assert.equal(payload.iss, 'https://auth.example.com')
    assert.equal(payload.sub, 'user-123')
    assert.equal(payload.aud, 'client-abc')
    assert.equal(payload.nonce, 'test-nonce')
    assert.isString(payload.at_hash)
    assert.isNumber(payload.iat)
    assert.isNumber(payload.exp)
  })

  test('omits nonce when not provided', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })
    const service = new IdTokenService(manager)

    const token = await service.sign({
      sub: 'user-123',
      clientId: 'client-abc',
      scopes: ['openid'],
      accessToken: 'raw-access-token',
      user: { id: 'user-123' },
    })

    const keyService = new KeyService(jwk)
    const publicKey = await import('jose').then((j) =>
      j.importJWK(keyService.getPublicJwks().keys[0], 'RS256')
    )
    const { payload } = await jwtVerify(token, publicKey as any)

    assert.notProperty(payload, 'nonce')
  })

  test('includes user claims from OidcSubject', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })
    const service = new IdTokenService(manager)

    const user = {
      id: 'user-123',
      getOidcClaims(scopes: string[]) {
        const claims: Record<string, unknown> = {}
        if (scopes.includes('profile')) claims.name = 'Julien'
        if (scopes.includes('email')) claims.email = 'julien@example.com'

        return claims
      },
    }

    const token = await service.sign({
      sub: 'user-123',
      clientId: 'client-abc',
      scopes: ['openid', 'profile', 'email'],
      accessToken: 'raw-token',
      user,
    })

    const keyService = new KeyService(jwk)
    const publicKey = await import('jose').then((j) =>
      j.importJWK(keyService.getPublicJwks().keys[0], 'RS256')
    )
    const { payload } = await jwtVerify(token, publicKey as any)

    assert.equal(payload.name, 'Julien')
    assert.equal(payload.email, 'julien@example.com')
  })

  test('reserved claims from getOidcClaims are filtered out', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })
    const service = new IdTokenService(manager)

    const user = {
      id: 'user-123',
      getOidcClaims() {
        return { sub: 'evil-override', iss: 'evil-issuer', name: 'Julien' }
      },
    }

    const token = await service.sign({
      sub: 'user-123',
      clientId: 'client-abc',
      scopes: ['openid'],
      accessToken: 'raw-token',
      user,
    })

    const keyService = new KeyService(jwk)
    const publicKey = await import('jose').then((j) =>
      j.importJWK(keyService.getPublicJwks().keys[0], 'RS256')
    )
    const { payload } = await jwtVerify(token, publicKey as any)

    assert.equal(payload.sub, 'user-123')
    assert.equal(payload.iss, 'https://auth.example.com')
    assert.equal(payload.name, 'Julien')
  })
})

// --- Scope validation ---

test.group('OIDC Scopes', () => {
  test('openid, profile, email are accepted as server-recognized scopes', ({ assert }) => {
    const manager = createManager()
    const invalid = manager.validateScopes(['openid', 'profile', 'email', 'read'])

    assert.deepEqual(invalid, [])
  })

  test('profile and email require openid', ({ assert }) => {
    const manager = createManager()

    assert.deepEqual(manager.validateScopes(['profile']), ['profile'])
    assert.deepEqual(manager.validateScopes(['email']), ['email'])
    assert.deepEqual(manager.validateScopes(['read', 'profile', 'email']), ['profile', 'email'])
  })

  test('OIDC_SCOPES contains expected scopes', ({ assert }) => {
    assert.isTrue(OIDC_SCOPES.has('openid'))
    assert.isTrue(OIDC_SCOPES.has('profile'))
    assert.isTrue(OIDC_SCOPES.has('email'))
    assert.isFalse(OIDC_SCOPES.has('offline_access'))
  })

  test('RESERVED_OIDC_CLAIMS contains protocol claims', ({ assert }) => {
    assert.isTrue(RESERVED_OIDC_CLAIMS.has('sub'))
    assert.isTrue(RESERVED_OIDC_CLAIMS.has('iss'))
    assert.isTrue(RESERVED_OIDC_CLAIMS.has('aud'))
    assert.isTrue(RESERVED_OIDC_CLAIMS.has('nonce'))
    assert.isTrue(RESERVED_OIDC_CLAIMS.has('at_hash'))
    assert.isFalse(RESERVED_OIDC_CLAIMS.has('name'))
    assert.isFalse(RESERVED_OIDC_CLAIMS.has('email'))
  })
})

// --- SesameManager OIDC ---

test.group('SesameManager OIDC', () => {
  test('isOidcEnabled is false without JWK', ({ assert }) => {
    const manager = createManager()
    assert.isFalse(manager.isOidcEnabled)
  })

  test('isOidcEnabled is false with JWK but without OIDC provider', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })
    assert.isFalse(manager.isOidcEnabled)
  })

  test('isOidcEnabled is true with JWK and OIDC provider', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk, oidcProvider: new FakeUserProvider([]) })
    assert.isTrue(manager.isOidcEnabled)
  })

  test('keyService throws when no JWK configured', ({ assert }) => {
    const manager = createManager()
    assert.throws(() => manager.keyService, 'OIDC requires a JWK')
  })

  test('keyService returns KeyService when JWK configured', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })
    assert.instanceOf(manager.keyService, KeyService)
  })

  test('findUserById uses the OIDC provider from config', async ({ assert }) => {
    const oidcProvider = new FakeUserProvider([{ id: 'user-1', name: 'OIDC User' }])
    const manager = createManager({ oidcProvider })

    const user = (await manager.findUserById('user-1')) as FakeUser | null

    assert.deepEqual(user, { id: 'user-1', name: 'OIDC User' })
  })
})

// --- OIDC Metadata ---

test.group('OIDC Metadata', () => {
  test('returns 404 when OIDC is not configured', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.oidc(ctx)

    assert.equal(ctx.__responseStatus, 404)
    assert.deepEqual(result, { error: 'OIDC is not configured' })
  })

  test('returns 404 when JWK is configured without an OIDC provider', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.oidc(ctx)

    assert.equal(ctx.__responseStatus, 404)
    assert.deepEqual(result, { error: 'OIDC is not configured' })
  })

  test('returns complete OIDC metadata when configured', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk, oidcProvider: new FakeUserProvider([]) })
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = (await controller.oidc(ctx)) as any

    assert.equal(result.issuer, 'https://auth.example.com')
    assert.deepEqual(result.subject_types_supported, ['public'])
    assert.deepEqual(result.id_token_signing_alg_values_supported, ['RS256'])
    assert.include(result.scopes_supported, 'openid')
    assert.include(result.scopes_supported, 'profile')
    assert.include(result.scopes_supported, 'email')
    assert.isString(result.jwks_uri)
    assert.isString(result.userinfo_endpoint)
    assert.isArray(result.claims_supported)
    assert.include(result.claims_supported, 'sub')
    assert.include(result.claims_supported, 'at_hash')
  })

  test('throws a clear server error when OIDC routes are missing from discovery', async ({
    assert,
  }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk, oidcProvider: new FakeUserProvider([]) })
    const ctx = mockCtx({
      manager,
      router: {
        has(name: string) {
          return !['sesame.userinfo', 'sesame.jwks'].includes(name)
        },
        makeUrl(name: string, _params?: any, opts?: { prefixUrl?: string }) {
          const path = name === 'sesame.userinfo' ? '/oauth/userinfo' : '/jwks'
          return opts?.prefixUrl ? `${opts.prefixUrl}${path}` : path
        },
      },
    })

    const controller = new MetadataController()

    await assert.rejects(
      () => controller.oidc(ctx),
      'OIDC discovery is misconfigured. Missing named route(s): sesame.userinfo, sesame.jwks. Register OAuth routes with sesame.registerRoutes(router) and sesame.registerWellKnownRoutes(router) before exposing OpenID discovery.'
    )
  })
})

// --- JWKS Endpoint ---

test.group('JWKS Endpoint', () => {
  test('returns 404 when OIDC is not configured', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new JwksController()
    const result = await controller.handle(ctx)

    assert.equal(ctx.__responseStatus, 404)
    assert.deepEqual(result, { error: 'OIDC is not configured' })
  })

  test('returns public JWKS', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk, oidcProvider: new FakeUserProvider([]) })
    const ctx = mockCtx({ manager })

    const controller = new JwksController()
    const result = await controller.handle(ctx)
    assert.notProperty(result, 'error')

    const jwks = result as { keys: import('jose').JWK[] }
    assert.isArray(jwks.keys)
    assert.equal(jwks.keys.length, 1)
    assert.equal(jwks.keys[0].alg, 'RS256')
    assert.notProperty(jwks.keys[0], 'd')
    assert.equal(ctx.__responseHeaders['Content-Type'], 'application/jwk-set+json')
    assert.include(ctx.__responseHeaders['Cache-Control'], 'public')
  })
})

// --- Integration: Authorization Code Grant with openid ---

test.group('Authorization Code Grant — OIDC', (group) => {
  setupIntegrationGroup(group)
  const users: FakeUser[] = [{ id: 'user-1', name: 'Test User' }]

  test('returns id_token when openid scope is present', async ({ assert }) => {
    const jwk = await getTestJwk()
    const userProvider = new FakeUserProvider(users)
    const manager = createManager({ jwk, oidcProvider: userProvider })

    const client = await createTestClient({
      scopes: ['read', 'openid', 'offline_access'],
    })

    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      clientId: client.clientId,
      scopes: ['openid', 'read'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    assert.isString(result.access_token)
    assert.isString(result.id_token)
    assert.equal(result.token_type, 'Bearer')

    // Verify the id_token
    const keyService = new KeyService(jwk)
    const publicKey = await import('jose').then((j) =>
      j.importJWK(keyService.getPublicJwks().keys[0], 'RS256')
    )
    const { payload } = await jwtVerify(result.id_token!, publicKey as any)

    assert.equal(payload.sub, 'user-1')
    assert.equal(payload.aud, client.clientId)
    assert.isString(payload.at_hash)
  })

  test('does not return id_token without openid scope', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })

    const client = await createTestClient({
      clientId: 'client-no-oidc',
      scopes: ['read', 'write'],
    })

    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      clientId: client.clientId,
      scopes: ['read'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    assert.isString(result.access_token)
    assert.notProperty(result, 'id_token')
  })

  test('rejects openid exchange when OIDC user cannot be resolved', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })

    const client = await createTestClient({
      clientId: 'client-missing-user-provider',
      scopes: ['read', 'openid', 'offline_access'],
    })

    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      clientId: client.clientId,
      scopes: ['openid', 'read'],
    })

    await assert.rejects(
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri,
          codeVerifier,
        }),
      'OIDC user not found'
    )
  })

  test('does not consume the code or persist tokens when id_token generation fails', async ({
    assert,
  }) => {
    const jwk = await getTestJwk()
    const userProvider = new FakeUserProvider([
      {
        id: 'user-1',
        name: 'Broken User',
        async getOidcClaims() {
          throw new Error('OIDC claims exploded')
        },
      } as FakeUser & { getOidcClaims(): Promise<Record<string, unknown>> },
    ])
    const manager = createManager({ jwk, oidcProvider: userProvider })

    const client = await createTestClient({
      clientId: 'client-oidc-signing-failure',
      scopes: ['read', 'openid', 'offline_access'],
    })

    const { rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      clientId: client.clientId,
      scopes: ['openid', 'offline_access', 'read'],
    })
    const hashedCode = new TokenService(manager).hashToken(rawCode)

    await assert.rejects(
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri,
          codeVerifier,
        }),
      'OIDC claims exploded'
    )

    const authCode = await OAuthAuthorizationCode.query()
      .where('code', hashedCode)
      .where('clientId', client.clientId)
      .first()
    const accessTokens = await OAuthAccessToken.query().where('clientId', client.clientId)
    const refreshTokens = await OAuthRefreshToken.query().where('clientId', client.clientId)

    assert.exists(authCode)
    assert.lengthOf(accessTokens, 0)
    assert.lengthOf(refreshTokens, 0)
  })
})

// --- Integration: Refresh Token Grant with openid ---

test.group('Refresh Token Grant — OIDC', (group) => {
  setupIntegrationGroup(group)

  test('rejects openid refresh when OIDC user cannot be resolved', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })

    const client = await createTestClient({
      clientId: 'client-refresh-missing-user',
      scopes: ['read', 'openid', 'offline_access'],
    })

    const tokenService = new TokenService(manager)
    const { hash: oldAccessTokenHash, expiresAt } = tokenService.createAccessToken()
    const { raw: refreshTokenRaw, hash: refreshTokenHash } = tokenService.createRefreshToken()

    const oldAccessTokenId = crypto.randomUUID()
    await OAuthAccessToken.create({
      id: oldAccessTokenId,
      tokenHash: oldAccessTokenHash,
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['openid', 'read'],
      expiresAt: DateTime.fromJSDate(expiresAt),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: refreshTokenHash,
      accessTokenId: oldAccessTokenId,
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['openid', 'read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    await assert.rejects(
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: refreshTokenRaw,
        }),
      'OIDC user not found'
    )
  })

  test('does not rotate tokens when id_token generation fails', async ({ assert }) => {
    const jwk = await getTestJwk()
    const userProvider = new FakeUserProvider([
      {
        id: 'user-1',
        name: 'Broken User',
        async getOidcClaims() {
          throw new Error('OIDC claims exploded')
        },
      } as FakeUser & { getOidcClaims(): Promise<Record<string, unknown>> },
    ])
    const manager = createManager({ jwk, oidcProvider: userProvider })

    const client = await createTestClient({
      clientId: 'client-refresh-oidc-signing-failure',
      scopes: ['read', 'openid', 'offline_access'],
    })

    const tokenService = new TokenService(manager)
    const { hash: oldAccessTokenHash, expiresAt } = tokenService.createAccessToken()
    const { raw: refreshTokenRaw, hash: refreshTokenHash } = tokenService.createRefreshToken()

    const oldAccessTokenId2 = crypto.randomUUID()
    await OAuthAccessToken.create({
      id: oldAccessTokenId2,
      tokenHash: oldAccessTokenHash,
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['openid', 'read'],
      expiresAt: DateTime.fromJSDate(expiresAt),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: refreshTokenHash,
      accessTokenId: oldAccessTokenId2,
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['openid', 'read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    await assert.rejects(
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: refreshTokenRaw,
        }),
      'OIDC claims exploded'
    )

    const accessTokens = await OAuthAccessToken.query().where('clientId', client.clientId)
    const refreshTokens = await OAuthRefreshToken.query().where('clientId', client.clientId)
    const originalAccessToken = accessTokens.find((token) => token.tokenHash === oldAccessTokenHash)
    const originalRefreshToken = refreshTokens.find((token) => token.token === refreshTokenHash)

    assert.lengthOf(accessTokens, 1)
    assert.lengthOf(refreshTokens, 1)
    assert.exists(originalAccessToken)
    assert.exists(originalRefreshToken)
    assert.isNull(originalAccessToken!.revokedAt)
    assert.isNull(originalRefreshToken!.revokedAt)
  })
})

// --- UserInfo Endpoint ---

test.group('UserInfo Endpoint', (group) => {
  setupIntegrationGroup(group)
  const users: FakeUser[] = [{ id: 'user-1', name: 'Test User' }]

  group.each.setup(async () => {
    await createTestClient({ scopes: ['read', 'openid', 'offline_access'] })
  })

  test('returns sub for valid token with openid scope', async ({ assert }) => {
    const jwk = await getTestJwk()
    const userProvider = new FakeUserProvider(users)
    const manager = createManager({ jwk, oidcProvider: userProvider })

    const { raw } = await createTestAccessToken({ manager, scopes: ['openid', 'read'] })

    const ctx = mockCtx({
      manager,
      headers: { authorization: `Bearer ${raw}` },
    })

    const controller = new UserinfoController()
    const result = await controller.handle(ctx)

    assert.equal(result.sub, 'user-1')
  })

  test('accepts POST body access_token', async ({ assert }) => {
    const jwk = await getTestJwk()
    const userProvider = new FakeUserProvider(users)
    const manager = createManager({ jwk, oidcProvider: userProvider })

    const { raw } = await createTestAccessToken({ manager, scopes: ['openid', 'read'] })

    const ctx = mockCtx({
      manager,
      body: { access_token: raw },
    })

    const controller = new UserinfoController()
    const result = await controller.handle(ctx)

    assert.equal(result.sub, 'user-1')
  })

  test('rejects request without Bearer token', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })
    const ctx = mockCtx({ manager })

    const controller = new UserinfoController()

    await assert.rejects(() => controller.handle(ctx), 'Missing Bearer token')
  })

  test('rejects token without openid scope', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk })

    const { raw } = await createTestAccessToken({ manager, scopes: ['read'] })

    const ctx = mockCtx({
      manager,
      headers: { authorization: `Bearer ${raw}` },
    })

    const controller = new UserinfoController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.equal(error.oauthCode, 'insufficient_scope')
      error.handle(error, ctx)
      assert.equal(ctx.__responseStatus, 403)
      assert.include(ctx.__responseHeaders['WWW-Authenticate'], 'error="insufficient_scope"')
      assert.include(ctx.__responseHeaders['WWW-Authenticate'], 'scope="openid"')
    }
  })

  test('rejects token when the OIDC user can no longer be resolved', async ({ assert }) => {
    const jwk = await getTestJwk()
    const manager = createManager({ jwk, oidcProvider: new FakeUserProvider([]) })

    const { raw } = await createTestAccessToken({ manager, scopes: ['openid', 'read'] })

    const ctx = mockCtx({
      manager,
      headers: { authorization: `Bearer ${raw}` },
    })

    const controller = new UserinfoController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.equal(error.oauthCode, 'invalid_token')
      error.handle(error, ctx)
      assert.equal(ctx.__responseStatus, 401)
      assert.include(ctx.__responseHeaders['WWW-Authenticate'], 'Bearer')
      assert.include(ctx.__responseHeaders['WWW-Authenticate'], 'error="invalid_token"')
      assert.include(ctx.__responseHeaders['WWW-Authenticate'], 'Invalid access token')
    }
  })
})
