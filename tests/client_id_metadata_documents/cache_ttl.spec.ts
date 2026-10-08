import { test } from '@japa/runner'
import { computeCacheTtl } from '../../src/client_id_metadata_documents/cache_ttl.ts'

const now = Date.parse('Wed, 01 Jan 2025 12:00:00 GMT')
const bounds = { minTtl: 300, maxTtl: 86_400, expires: null, date: null, age: null, now }

function httpDate(offsetSeconds: number) {
  return new Date(now + offsetSeconds * 1000).toUTCString()
}

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

  test('subtracts the Age header from max-age', ({ assert }) => {
    const options = { ...bounds, cacheControl: 'max-age=7200' }

    assert.equal(computeCacheTtl({ ...options, age: '3600' }), 3600)
    assert.equal(computeCacheTtl({ ...options, age: '7000' }), 300)
    assert.equal(computeCacheTtl({ ...options, age: '99999' }), 300)
  })

  test('subtracts the apparent age from a stale Date', ({ assert }) => {
    const options = { ...bounds, cacheControl: 'max-age=7200', date: httpDate(-3600) }

    assert.equal(computeCacheTtl(options), 3600)
  })

  test('ignores a Date in the future (clock skew)', ({ assert }) => {
    const options = { ...bounds, cacheControl: 'max-age=3600', date: httpDate(600) }

    assert.equal(computeCacheTtl(options), 3600)
  })

  test('uses the remaining lifetime of Expires', ({ assert }) => {
    const options = {
      ...bounds,
      cacheControl: null,
      date: httpDate(-3600),
      expires: httpDate(3600),
    }

    assert.equal(computeCacheTtl(options), 3600)
  })

  test('uses Expires relative to the response time without Date', ({ assert }) => {
    assert.equal(computeCacheTtl({ ...bounds, cacheControl: null, expires: httpDate(7200) }), 7200)
  })

  test('uses the minimum for an already expired response', ({ assert }) => {
    const options = {
      ...bounds,
      cacheControl: null,
      date: httpDate(-7200),
      expires: httpDate(-3600),
    }

    assert.equal(computeCacheTtl(options), 300)
  })

  test('ignores an invalid Expires header', ({ assert }) => {
    assert.equal(computeCacheTtl({ ...bounds, cacheControl: null, expires: 'nope' }), 300)
  })
})
