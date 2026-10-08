import { test } from '@japa/runner'
import { ClientMetadataDocumentResolutionCache } from '../../src/client_id_metadata_documents/resolution_cache.ts'

const client = {
  name: 'Example',
  redirectUris: ['http://127.0.0.1/callback'],
  scopes: [],
  grantTypes: ['authorization_code'],
  metadata: {},
}

test.group('CIMD | resolution cache', () => {
  test('returns entries until they expire', ({ assert }) => {
    let now = 1000
    const cache = new ClientMetadataDocumentResolutionCache({ now: () => now })

    cache.setClient({ clientId: 'a', client, ttlMs: 100 })
    cache.setError({ clientId: 'b', message: 'Unable to fetch', ttlMs: 50 })

    assert.deepInclude(cache.get('a'), { client })
    assert.deepInclude(cache.get('b'), { error: 'Unable to fetch' })

    now = 1060
    assert.isNull(cache.get('b'))
    assert.isNotNull(cache.get('a'))

    now = 1100
    assert.isNull(cache.get('a'))
    assert.equal(cache.size, 0)
  })

  test('evicts the least recently used entry past the bound', ({ assert }) => {
    const cache = new ClientMetadataDocumentResolutionCache({ maxEntries: 2 })

    cache.setClient({ clientId: 'a', client, ttlMs: 60_000 })
    cache.setClient({ clientId: 'b', client, ttlMs: 60_000 })
    cache.get('a')
    cache.setClient({ clientId: 'c', client, ttlMs: 60_000 })

    assert.equal(cache.size, 2)
    assert.isNotNull(cache.get('a'))
    assert.isNull(cache.get('b'))
    assert.isNotNull(cache.get('c'))
  })
})
