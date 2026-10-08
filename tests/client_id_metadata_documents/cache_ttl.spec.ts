import { test } from '@japa/runner'
import { computeCacheTtl } from '../../src/client_id_metadata_documents/cache_ttl.ts'

const bounds = { minTtl: 300, maxTtl: 86_400, expires: null, date: null }

test.group('CIMD | cache TTL', () => {
  test('uses max-age within bounds', ({ assert }) => {
    assert.equal(computeCacheTtl({ ...bounds, cacheControl: 'public, max-age=3600' }), 3600)
  })

  test('clamps max-age to the bounds', ({ assert }) => {
    assert.equal(computeCacheTtl({ ...bounds, cacheControl: 'max-age=10' }), 300)
    assert.equal(computeCacheTtl({ ...bounds, cacheControl: 'max-age=999999' }), 86_400)
  })

  test('uses the minimum for {0}')
    .with([null, 'no-store', 'no-cache', 'max-age=0', 'max-age=abc', 'public'])
    .run(({ assert }, cacheControl) => {
      assert.equal(computeCacheTtl({ ...bounds, cacheControl }), 300)
    })

  test('falls back to Expires relative to Date', ({ assert }) => {
    const date = 'Wed, 01 Jan 2025 00:00:00 GMT'
    const expires = 'Wed, 01 Jan 2025 02:00:00 GMT'

    assert.equal(computeCacheTtl({ ...bounds, cacheControl: null, date, expires }), 7200)
  })

  test('ignores an invalid Expires header', ({ assert }) => {
    assert.equal(computeCacheTtl({ ...bounds, cacheControl: null, expires: 'nope' }), 300)
  })
})
