import { test } from '@japa/runner'
import { TokenService } from '../src/services/token_service.ts'
import { createManager } from './helpers/app.ts'

test.group('TokenService', () => {
  test('creates an opaque access token', ({ assert }) => {
    const manager = createManager()
    const service = new TokenService(manager)

    const { raw, hash, expiresAt } = service.createAccessToken()

    assert.isString(raw)
    assert.isString(hash)
    assert.notEqual(raw, hash)
    assert.instanceOf(expiresAt, Date)
    assert.isTrue(expiresAt.getTime() > Date.now())
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
