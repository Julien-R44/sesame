import { test } from '@japa/runner'
import { rm } from 'node:fs/promises'
import { resolve } from 'node:path'
import { TokenService } from '../src/services/token_service.ts'
import { createManager } from './helpers.ts'

test.group('TokenService', (group) => {
  group.each.teardown(async () => {
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
  })

  test('creates a JWT access token', async ({ assert }) => {
    const manager = createManager()
    const service = new TokenService(manager)

    const { token, jti, expiresAt } = await service.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['read', 'write'],
    })

    assert.isString(token)
    assert.isString(jti)
    assert.instanceOf(expiresAt, Date)
    assert.isTrue(token.split('.').length === 3) // JWT format
  })

  test('verifies a valid JWT access token', async ({ assert }) => {
    const manager = createManager()
    const service = new TokenService(manager)

    const { token } = await service.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['read'],
    })

    const payload = await service.verifyJwtAccessToken(token)
    assert.equal(payload.sub, 'user-1')
    assert.equal(payload.azp, 'client-1')
    assert.equal(payload.scope, 'read')
    assert.equal(payload.iss, 'https://auth.example.com')
  })

  test('rejects a tampered JWT', async ({ assert }) => {
    const manager = createManager()
    const service = new TokenService(manager)

    const { token } = await service.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['read'],
    })

    await assert.rejects(async () => {
      await service.verifyJwtAccessToken(token + 'tampered')
    })
  })

  test('rejects JWT with wrong issuer', async ({ assert }) => {
    const manager1 = createManager({ issuer: 'https://issuer1.com' })
    const manager2 = createManager({
      issuer: 'https://issuer2.com',
      jwksPath: resolve(import.meta.dirname!, '.tmp/test-keys-2.json'),
    })

    const service1 = new TokenService(manager1)
    const { token } = await service1.createJwtAccessToken({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['read'],
    })

    const service2 = new TokenService(manager2)
    await assert.rejects(async () => {
      await service2.verifyJwtAccessToken(token)
    })
  })

  test('creates opaque refresh tokens', ({ assert }) => {
    const manager = createManager()
    const service = new TokenService(manager)

    const { raw, hash } = service.createRefreshToken()

    assert.isString(raw)
    assert.isString(hash)
    assert.notEqual(raw, hash)
  })

  test('hash is deterministic', ({ assert }) => {
    const manager = createManager()
    const service = new TokenService(manager)

    const token = 'test-token-value'
    const hash1 = service.hashToken(token)
    const hash2 = service.hashToken(token)

    assert.equal(hash1, hash2)
  })

  test('different tokens produce different hashes', ({ assert }) => {
    const manager = createManager()
    const service = new TokenService(manager)

    const hash1 = service.hashToken('token-a')
    const hash2 = service.hashToken('token-b')

    assert.notEqual(hash1, hash2)
  })

  test('generates unique opaque tokens', ({ assert }) => {
    const manager = createManager()
    const service = new TokenService(manager)

    const tokens = new Set<string>()
    for (let i = 0; i < 100; i++) tokens.add(service.generateOpaqueToken())

    assert.equal(tokens.size, 100)
  })
})
