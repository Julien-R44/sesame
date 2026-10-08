import { test } from '@japa/runner'
import {
  describeInvalidClientIdUrl,
  isClientIdMetadataDocumentUrl,
  isHostAllowed,
} from '../../src/client_id_metadata_documents/client_id_url.ts'

test.group('CIMD | client_id URL', () => {
  test('detects URL client ids', ({ assert }) => {
    assert.isTrue(
      isClientIdMetadataDocumentUrl('https://claude.ai/oauth/claude-code-client-metadata')
    )
    assert.isFalse(isClientIdMetadataDocumentUrl('a1b2c3d4e5f6'))
    assert.isFalse(isClientIdMetadataDocumentUrl('http://example.com/client.json'))
  })

  test('accepts a valid client identifier URL ({0})')
    .with([
      'https://claude.ai/oauth/claude-code-client-metadata',
      'https://vscode.dev/oauth/client-metadata.json',
      'https://app.example.com:8443/client.json',
    ])
    .run(({ assert }, clientId) => {
      assert.isNull(describeInvalidClientIdUrl(clientId))
    })

  test('rejects {0}')
    .with([
      ['https://example.com', 'must contain a path'],
      ['https://example.com/', 'must contain a path'],
      ['https://example.com/client.json?v=1', 'must not contain a query'],
      ['https://example.com/client.json#frag', 'must not contain a fragment'],
      ['https://user:pass@example.com/client.json', 'must not contain userinfo'],
      ['https://example.com/a/../client.json', 'canonical form'],
      ['https://example.com/a/%2e%2e/client.json', 'canonical form'],
      ['https://example.com/./client.json', 'canonical form'],
      ['https://EXAMPLE.com/client.json', 'canonical form'],
      ['https://example.com:443/client.json', 'canonical form'],
      ['https://127.0.0.1/client.json', 'must use a domain name'],
      ['https://[::1]/client.json', 'must use a domain name'],
      ['https://10.0.0.1/client.json', 'must use a domain name'],
      [`https://example.com/${'a'.repeat(250)}`, 'must not exceed 255 characters'],
      ['https://exa mple.com/client.json', 'not a valid URL'],
    ])
    .run(({ assert }, [clientId, message]) => {
      assert.include(describeInvalidClientIdUrl(clientId), message)
    })

  test('matches allowed hosts', ({ assert }) => {
    const allowedHosts = ['claude.ai', '*.example.com']

    assert.isTrue(isHostAllowed({ hostname: 'claude.ai', allowedHosts }))
    assert.isTrue(isHostAllowed({ hostname: 'app.example.com', allowedHosts }))
    assert.isTrue(isHostAllowed({ hostname: 'a.b.example.com', allowedHosts }))
    assert.isFalse(isHostAllowed({ hostname: 'example.com', allowedHosts }))
    assert.isFalse(isHostAllowed({ hostname: 'evilexample.com', allowedHosts }))
    assert.isFalse(isHostAllowed({ hostname: 'claude.ai.evil.com', allowedHosts }))
    assert.isTrue(isHostAllowed({ hostname: 'anything.dev', allowedHosts: null }))
  })
})
