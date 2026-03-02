import { test } from '@japa/runner'
import { resolve } from 'node:path'
import { rm } from 'node:fs/promises'
import { KeyService } from '../src/services/key_service.ts'

const TEST_KEY_PATH = resolve(import.meta.dirname!, '.tmp/test-keys-ks.json')

test.group('KeyService', (group) => {
  group.each.teardown(async () => {
    await rm(resolve(import.meta.dirname!, '.tmp'), { recursive: true, force: true })
  })

  test('generates keys and writes to disk', async ({ assert }) => {
    const ks = new KeyService(TEST_KEY_PATH)
    await ks.generateKeys({ force: true })

    const privateKey = await ks.getPrivateKey()
    assert.isDefined(privateKey)

    const kid = await ks.getKid()
    assert.isString(kid)
    assert.isNotEmpty(kid)
  })

  test('loads keys from disk', async ({ assert }) => {
    const ks1 = new KeyService(TEST_KEY_PATH)
    await ks1.generateKeys({ force: true })
    const kid1 = await ks1.getKid()

    const ks2 = new KeyService(TEST_KEY_PATH)
    await ks2.loadKeys()
    const kid2 = await ks2.getKid()

    assert.equal(kid1, kid2)
  })

  test('generates keys automatically on loadKeys if none exist', async ({ assert }) => {
    const ks = new KeyService(TEST_KEY_PATH)
    await ks.loadKeys()

    const privateKey = await ks.getPrivateKey()
    assert.isDefined(privateKey)
  })

  test('does not overwrite existing keys without force', async ({ assert }) => {
    const ks = new KeyService(TEST_KEY_PATH)
    await ks.generateKeys({ force: true })
    const kid1 = await ks.getKid()

    await ks.generateKeys({ force: false })
    const kid2 = await ks.getKid()

    assert.equal(kid1, kid2)
  })

  test('overwrites keys with force', async ({ assert }) => {
    const ks1 = new KeyService(TEST_KEY_PATH)
    await ks1.generateKeys({ force: true })
    const kid1 = await ks1.getKid()

    const ks2 = new KeyService(TEST_KEY_PATH)
    await ks2.generateKeys({ force: true })
    const kid2 = await ks2.getKid()

    assert.notEqual(kid1, kid2)
  })

  test('returns valid JWKS with public key only', async ({ assert }) => {
    const ks = new KeyService(TEST_KEY_PATH)
    await ks.generateKeys({ force: true })

    const jwks = await ks.getJwks()
    assert.isArray(jwks.keys)
    assert.lengthOf(jwks.keys, 1)

    const key = jwks.keys[0]
    assert.equal(key.alg, 'RS256')
    assert.equal(key.use, 'sig')
    assert.isDefined(key.kid)
    assert.isDefined(key.n)
    assert.isDefined(key.e)

    // No private key fields
    assert.isUndefined(key.d)
    assert.isUndefined(key.p)
    assert.isUndefined(key.q)
    assert.isUndefined(key.dp)
    assert.isUndefined(key.dq)
    assert.isUndefined(key.qi)
  })
})
