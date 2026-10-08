import { test } from '@japa/runner'
import { buildBearerChallenge, mergeScopes } from '../src/bearer_challenge.ts'

test.group('buildBearerChallenge', () => {
  test('serializes parameters in a stable order', ({ assert }) => {
    const header = buildBearerChallenge({
      error: 'insufficient_scope',
      scopes: ['read', 'write'],
      resourceMetadata: 'https://app.test/.well-known/oauth-protected-resource',
      errorDescription: 'Missing scope',
    })

    assert.equal(
      header,
      'Bearer resource_metadata="https://app.test/.well-known/oauth-protected-resource", scope="read write", error="insufficient_scope", error_description="Missing scope"'
    )
  })

  test('omits empty parameters', ({ assert }) => {
    assert.equal(buildBearerChallenge({ scopes: [] }), 'Bearer')
    assert.equal(buildBearerChallenge({ error: 'invalid_token' }), 'Bearer error="invalid_token"')
  })

  test('escapes quotes and backslashes', ({ assert }) => {
    const header = buildBearerChallenge({ errorDescription: 'bad "token" \\ here' })

    assert.equal(header, 'Bearer error_description="bad \\"token\\" \\\\ here"')
  })
})

test.group('mergeScopes', () => {
  test('keeps first-seen order without duplicates', ({ assert }) => {
    assert.deepEqual(mergeScopes(['read', 'write'], ['write', 'admin']), ['read', 'write', 'admin'])
  })
})
