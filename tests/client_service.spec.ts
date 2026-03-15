import { test } from '@japa/runner'
import { ClientService } from '../src/services/client_service.ts'

test.group('ClientService', () => {
  test('parses Basic auth header', ({ assert }) => {
    const service = new ClientService()
    const encoded = Buffer.from('my-client:my-secret').toString('base64')
    const result = service.parseBasicAuth(`Basic ${encoded}`)

    assert.deepEqual(result, { clientId: 'my-client', clientSecret: 'my-secret' })
  })

  test('handles URL-encoded values in Basic auth', ({ assert }) => {
    const service = new ClientService()
    const encoded = Buffer.from(
      `${encodeURIComponent('client:with:colons')}:${encodeURIComponent('secret/special')}`
    ).toString('base64')
    const result = service.parseBasicAuth(`Basic ${encoded}`)

    assert.deepEqual(result, {
      clientId: 'client:with:colons',
      clientSecret: 'secret/special',
    })
  })

  test('returns null for non-Basic auth header', ({ assert }) => {
    const service = new ClientService()
    assert.isNull(service.parseBasicAuth('Bearer some-token'))
  })

  test('returns null for malformed Basic auth', ({ assert }) => {
    const service = new ClientService()
    const encoded = Buffer.from('no-colon-here').toString('base64')
    assert.isNull(service.parseBasicAuth(`Basic ${encoded}`))
  })

  test('rejects mixed client authentication methods', ({ assert }) => {
    const service = new ClientService()
    const encoded = Buffer.from('header-client:header-secret').toString('base64')

    assert.throws(
      () =>
        service.extractCredentials({
          authorizationHeader: `Basic ${encoded}`,
          bodyClientId: 'body-client',
          bodyClientSecret: 'body-secret',
        }),
      'Multiple client authentication methods are not allowed'
    )
  })

  test('allows body client_id with non-Basic auth header', ({ assert }) => {
    const service = new ClientService()

    const result = service.extractCredentials({
      authorizationHeader: 'Bearer some-token',
      bodyClientId: 'body-client',
      bodyClientSecret: 'body-secret',
    })

    assert.deepEqual(result, { clientId: 'body-client', clientSecret: 'body-secret' })
  })

  test('falls back to body credentials', ({ assert }) => {
    const service = new ClientService()

    const result = service.extractCredentials({
      bodyClientId: 'body-client',
      bodyClientSecret: 'body-secret',
    })

    assert.deepEqual(result, { clientId: 'body-client', clientSecret: 'body-secret' })
  })

  test('returns null when no credentials', ({ assert }) => {
    const service = new ClientService()
    assert.isNull(service.extractCredentials({}))
  })

  test('hashes and verifies client secrets', ({ assert }) => {
    const service = new ClientService()
    const secret = 'my-super-secret'

    const hashed = service.hashSecret(secret)
    assert.isTrue(service.verifySecret(secret, hashed))
    assert.isFalse(service.verifySecret('wrong-secret', hashed))
  })

  test('validates client scopes', ({ assert }) => {
    const service = new ClientService()

    // Empty client scopes = no scope allowed
    assert.throws(() => service.validateClientScopes(['read', 'write'], []))

    // Empty request with empty client scopes = ok
    assert.doesNotThrow(() => service.validateClientScopes([], []))

    // Valid scopes
    assert.doesNotThrow(() => service.validateClientScopes(['read'], ['read', 'write']))

    // Invalid scope
    assert.throws(() => service.validateClientScopes(['admin'], ['read', 'write']))
  })

  test('offline_access is always allowed even when not in client scopes', ({ assert }) => {
    const service = new ClientService()

    assert.doesNotThrow(() => service.validateClientScopes(['read', 'offline_access'], ['read']))
    assert.doesNotThrow(() => service.validateClientScopes(['offline_access'], []))
  })

  test('offline_access bypass does not allow other invalid scopes through', ({ assert }) => {
    const service = new ClientService()

    assert.throws(() => service.validateClientScopes(['offline_access', 'admin'], ['read']))
  })

  test('generates unique client IDs', ({ assert }) => {
    const service = new ClientService()
    const ids = new Set<string>()
    for (let i = 0; i < 50; i++) ids.add(service.generateClientId())

    assert.equal(ids.size, 50)
  })

  test('generates unique client secrets', ({ assert }) => {
    const service = new ClientService()
    const secrets = new Set<string>()
    for (let i = 0; i < 50; i++) secrets.add(service.generateClientSecret())

    assert.equal(secrets.size, 50)
  })
})
