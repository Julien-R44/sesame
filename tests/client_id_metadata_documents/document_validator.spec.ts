import { test } from '@japa/runner'
import { validateClientMetadataDocument } from '../../src/client_id_metadata_documents/document_validator.ts'
import { assertOAuthError } from '../helpers/assert_oauth_error.ts'

const clientId = 'https://app.example.com/client.json'

function document(overrides?: Record<string, unknown>) {
  return {
    client_id: clientId,
    client_name: 'Example MCP Client',
    redirect_uris: ['http://127.0.0.1/callback'],
    ...overrides,
  }
}

test.group('CIMD | document validation', () => {
  test('accepts a minimal document', async ({ assert }) => {
    const result = await validateClientMetadataDocument({ body: document(), clientId })

    assert.equal(result.client_name, 'Example MCP Client')
    assert.deepEqual(result.redirect_uris, ['http://127.0.0.1/callback'])
  })

  test('accepts the VS Code document (unknown grant types and properties)', async ({ assert }) => {
    const body = {
      client_name: 'Visual Studio Code',
      logo_uri: 'https://code.visualstudio.com/assets/branding/code-stable.png',
      grant_types: [
        'authorization_code',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      application_type: 'native',
      client_id: 'https://vscode.dev/oauth/client-metadata.json',
      client_uri: 'https://vscode.dev/product',
      redirect_uris: ['http://127.0.0.1:33418/', 'https://vscode.dev/redirect'],
    }

    const result = await validateClientMetadataDocument({ body, clientId: body.client_id })

    assert.equal(result.logo_uri, body.logo_uri)
  })

  test('rejects {0}')
    .with([
      ['a non-object body', ['not', 'an', 'object'], 'must be a JSON object'],
      ['a null body', null, 'must be a JSON object'],
      [
        'a mismatched client_id',
        document({ client_id: 'https://evil.example.com/client.json' }),
        'client_id does not match',
      ],
      [
        'a client_id differing only by trailing slash',
        document({ client_id: `${clientId}/` }),
        'client_id does not match',
      ],
      ['a client_secret', document({ client_secret: 'secret' }), 'client_secret must not'],
      [
        'client_secret_expires_at',
        document({ client_secret_expires_at: 0 }),
        'client_secret_expires_at must not',
      ],
      [
        'a shared secret auth method',
        document({ token_endpoint_auth_method: 'client_secret_basic' }),
        'must be "none"',
      ],
      [
        'private_key_jwt',
        document({ token_endpoint_auth_method: 'private_key_jwt' }),
        'private_key_jwt client authentication is not supported',
      ],
      [
        'an auth method named like an Object.prototype member',
        document({ token_endpoint_auth_method: 'toString' }),
        'must be "none"',
      ],
      [
        'a non-string auth method',
        document({ token_endpoint_auth_method: { method: 'none' } }),
        'must be "none"',
      ],
      ['a missing client_name', document({ client_name: undefined }), 'client_name'],
      ['an empty client_name', document({ client_name: '  ' }), 'client_name'],
      ['missing redirect_uris', document({ redirect_uris: undefined }), 'redirect_uris'],
      ['empty redirect_uris', document({ redirect_uris: [] }), 'redirect_uris'],
      [
        'an http redirect URI on a public host',
        document({ redirect_uris: ['http://evil.example.com/callback'] }),
        'must use HTTPS',
      ],
      [
        'a javascript: redirect URI',
        document({ redirect_uris: ['javascript:alert(1)'] }),
        'disallowed scheme',
      ],
      [
        'response_types without code',
        document({ response_types: ['token'] }),
        'response_types must include "code"',
      ],
      ['a non-https logo_uri', document({ logo_uri: 'http://example.com/logo.png' }), 'logo_uri'],
    ])
    .run(async ({ assert }, [, body, message]) => {
      await assertOAuthError(
        assert,
        () => validateClientMetadataDocument({ body, clientId }),
        'invalid_client',
        ['Invalid client metadata document', message as string]
      )
    })
})
