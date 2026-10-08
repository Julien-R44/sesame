import { test } from '@japa/runner'
import { SesameManager } from '../src/sesame_manager.ts'
import { lucidStore } from '../src/storage/drivers/lucid.ts'
import {
  matchResourceIndicator,
  normalizeResourceIndicator,
  resolveGrantResource,
} from '../src/resource_indicators.ts'
import { createTestConfig } from './helpers/app.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'

const RESOURCES = ['https://auth.example.com', 'https://auth.example.com/mcp']

/**
 * Manager with a router stub so protected resources can be registered.
 */
function createManagerWithResources(paths: string[] = []) {
  const router = { get: () => {} } as any
  const manager = new SesameManager(createTestConfig(), router, lucidStore())
  for (const path of paths) manager.registerProtectedResource({ resource: path })

  return manager
}

test.group('Resource indicators | normalizeResourceIndicator', () => {
  test('lowercases scheme and host and drops default ports', ({ assert }) => {
    assert.equal(
      normalizeResourceIndicator('HTTPS://Auth.Example.COM:443/mcp'),
      'https://auth.example.com/mcp'
    )
  })

  test('removes a single trailing slash', ({ assert }) => {
    assert.equal(
      normalizeResourceIndicator('https://auth.example.com/'),
      'https://auth.example.com'
    )
    assert.equal(
      normalizeResourceIndicator('https://auth.example.com/mcp/'),
      'https://auth.example.com/mcp'
    )
  })

  test('keeps non-default ports, paths, and queries', ({ assert }) => {
    assert.equal(
      normalizeResourceIndicator('https://auth.example.com:8443/mcp?tenant=a'),
      'https://auth.example.com:8443/mcp?tenant=a'
    )
  })

  test('rejects values that are not absolute http(s) URIs', ({ assert }) => {
    assert.isNull(normalizeResourceIndicator('/mcp'))
    assert.isNull(normalizeResourceIndicator('auth.example.com'))
    assert.isNull(normalizeResourceIndicator('urn:example:resource'))
    assert.isNull(normalizeResourceIndicator('ftp://auth.example.com'))
  })

  test('rejects fragments, including empty ones', ({ assert }) => {
    assert.isNull(normalizeResourceIndicator('https://auth.example.com/mcp#section'))
    assert.isNull(normalizeResourceIndicator('https://auth.example.com/mcp?#'))
  })

  test('rejects whitespace, control characters, and backslashes', ({ assert }) => {
    const values = [
      'https://auth.example.com/m\tcp',
      'https://auth.example.com/m\ncp',
      'https://auth.example.com/m\rcp',
      'https://auth.example.com/m cp',
      ' https://auth.example.com/mcp',
      'https://auth.example.com\\mcp',
      'https://auth.example.com/m\u0000cp',
      'https://auth.example.com/m\u007fcp',
      'https://auth.example.com/m\u00a0cp',
    ]

    for (const value of values)
      assert.isNull(normalizeResourceIndicator(value), JSON.stringify(value))
  })

  test('rejects credentials', ({ assert }) => {
    assert.isNull(normalizeResourceIndicator('https://user:pass@auth.example.com/mcp'))
  })
})

test.group('Resource indicators | matchResourceIndicator', () => {
  test('matches a registered resource exactly', ({ assert }) => {
    const value = 'https://auth.example.com/mcp/'

    assert.equal(matchResourceIndicator({ value, resources: RESOURCES }), RESOURCES[1])
  })

  test('maps a sub-path to the most specific registered resource', ({ assert }) => {
    const value = 'https://auth.example.com/mcp/tools'

    assert.equal(matchResourceIndicator({ value, resources: RESOURCES }), RESOURCES[1])
  })

  test('falls back to the root resource on a segment boundary', ({ assert }) => {
    const value = 'https://auth.example.com/mcp-v2'

    assert.equal(matchResourceIndicator({ value, resources: RESOURCES }), RESOURCES[0])
  })

  test('rejects resources on another origin', ({ assert }) => {
    assert.isNull(
      matchResourceIndicator({ value: 'https://auth.example.com:8443/mcp', resources: RESOURCES })
    )
    assert.isNull(
      matchResourceIndicator({ value: 'https://auth.example.com.evil.com', resources: RESOURCES })
    )
  })

  test('only matches resources with a query exactly', ({ assert }) => {
    const value = 'https://auth.example.com/mcp?tenant=a'

    assert.isNull(matchResourceIndicator({ value, resources: RESOURCES }))
  })
})

test.group('Resource indicators | resolveGrantResource', () => {
  test('inherits the granted resource when none is requested', ({ assert }) => {
    assert.equal(resolveGrantResource({ requested: null, granted: RESOURCES[1] }), RESOURCES[1])
    assert.isNull(resolveGrantResource({ requested: null, granted: null }))
  })

  test('binds an unbound grant to the requested resource', ({ assert }) => {
    assert.equal(resolveGrantResource({ requested: RESOURCES[1], granted: null }), RESOURCES[1])
  })

  test('accepts the granted resource', ({ assert }) => {
    assert.equal(
      resolveGrantResource({ requested: RESOURCES[1], granted: RESOURCES[1] }),
      RESOURCES[1]
    )
  })

  test('rejects another resource than the granted one', async ({ assert }) => {
    await assertOAuthError(
      assert,
      async () => resolveGrantResource({ requested: RESOURCES[0], granted: RESOURCES[1] }),
      'invalid_target'
    )
  })
})

test.group('Resource indicators | SesameManager.resolveResource', () => {
  test('returns null when the parameter is absent or empty', ({ assert }) => {
    const manager = createManagerWithResources()

    assert.isNull(manager.resolveResource(undefined))
    assert.isNull(manager.resolveResource(''))
  })

  test('always serves the issuer as the root resource', ({ assert }) => {
    const manager = createManagerWithResources()

    assert.equal(manager.resolveResource('https://AUTH.example.com/'), 'https://auth.example.com')
  })

  test('serves resources registered as protected resources', ({ assert }) => {
    const manager = createManagerWithResources(['/mcp-a', '/mcp-b'])

    assert.equal(
      manager.resolveResource('https://auth.example.com/mcp-b'),
      'https://auth.example.com/mcp-b'
    )
    assert.equal(
      manager.resolveResource(['https://auth.example.com/mcp-a']),
      RESOURCES[0] + '/mcp-a'
    )
  })

  test('rejects repeated resource parameters', async ({ assert }) => {
    const manager = createManagerWithResources(['/mcp'])

    await assertOAuthError(
      assert,
      async () => manager.resolveResource([RESOURCES[0], RESOURCES[1]]),
      'invalid_target',
      'Only one resource'
    )
  })

  test('rejects malformed and unknown resources', async ({ assert }) => {
    const manager = createManagerWithResources(['/mcp'])

    await assertOAuthError(
      assert,
      async () => manager.resolveResource({ nested: 'value' }),
      'invalid_target'
    )
    await assertOAuthError(
      assert,
      async () => manager.resolveResource('https://auth.example.com/mcp#x'),
      'invalid_target',
      'absolute http(s) URI'
    )
    await assertOAuthError(
      assert,
      async () => manager.resolveResource('https://auth.example.com/m\tcp'),
      'invalid_target'
    )
    await assertOAuthError(
      assert,
      async () => manager.resolveResource('https://other.example.com/mcp'),
      'invalid_target',
      'not served'
    )
  })

  test('builds canonical identifiers for guard resources', ({ assert }) => {
    const manager = createManagerWithResources()

    assert.equal(manager.resourceIdentifier(), 'https://auth.example.com')
    assert.equal(manager.resourceIdentifier('/mcp/'), 'https://auth.example.com/mcp')
  })
})
