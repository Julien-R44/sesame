import { test } from '@japa/runner'
import { isRedirectUriAllowed } from '../src/redirect_uri.ts'

test.group('isRedirectUriAllowed', () => {
  test('accepts an exact match', ({ assert }) => {
    const registered = ['https://app.example.com/callback']

    assert.isTrue(
      isRedirectUriAllowed({ registered, requested: 'https://app.example.com/callback' })
    )
  })

  test('rejects a different port for non-loopback hosts', ({ assert }) => {
    const registered = ['https://app.example.com/callback']

    assert.isFalse(
      isRedirectUriAllowed({ registered, requested: 'https://app.example.com:8443/callback' })
    )
  })

  test('ignores the port for loopback redirect URIs ({0})')
    .with([
      ['http://127.0.0.1/callback', 'http://127.0.0.1:51234/callback'],
      ['http://127.0.0.1:33418/', 'http://127.0.0.1:40000/'],
      ['http://localhost/callback', 'http://localhost:3118/callback'],
      ['http://[::1]/callback', 'http://[::1]:8080/callback'],
      ['http://localhost:3000/cb?x=1', 'http://localhost/cb?x=1'],
    ])
    .run(({ assert }, [registered, requested]) => {
      assert.isTrue(isRedirectUriAllowed({ registered: [registered], requested }))
    })

  test('still compares host, path and query for loopback URIs ({0})')
    .with([
      ['http://127.0.0.1/callback', 'http://localhost:3000/callback'],
      ['http://localhost/callback', 'http://localhost:3000/other'],
      ['http://localhost/callback', 'http://localhost:3000/callback?x=1'],
      ['http://localhost/callback', 'http://localhost:3000/callback#frag'],
      ['http://localhost/callback', 'https://localhost:3000/callback'],
      ['http://localhost/callback', 'http://localhost.evil.com:3000/callback'],
      ['http://localhost/callback', 'http://localhost:99999/callback'],
      ['https://app.example.com/callback', 'http://localhost:3000/callback'],
    ])
    .run(({ assert }, [registered, requested]) => {
      assert.isFalse(isRedirectUriAllowed({ registered: [registered], requested }))
    })
})
