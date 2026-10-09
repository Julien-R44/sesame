import { test } from '@japa/runner'
import type { ApiClient } from '@japa/api-client'
import { DateTime } from 'luxon'
import { setupHttpGroup } from '../helpers/app.ts'
import { createPkce } from '../helpers/create_pkce.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { FakeClientMetadataDocumentFetcher } from '../helpers/fake_client_metadata_fetcher.ts'
import { ClientMetadataDocumentFetcher } from '../../src/client_id_metadata_documents/fetcher.ts'
import { ClientMetadataDocumentResolutionCache } from '../../src/client_id_metadata_documents/resolution_cache.ts'
import { OAuthClient } from '../../src/models/oauth_client.ts'
import { lucidStore } from '../../src/storage/drivers/lucid.ts'
import { caseInsensitiveClientStore } from '../helpers/store_overrides.ts'
import { createManager } from '../helpers/app.ts'
import { TokenService } from '../../src/services/token_service.ts'

const CLAUDE_CODE_ID = 'https://claude.ai/oauth/claude-code-client-metadata'
const VSCODE_ID = 'https://vscode.dev/oauth/client-metadata.json'

const claudeCodeDocument = {
  client_id: CLAUDE_CODE_ID,
  client_name: 'Claude Code',
  client_uri: 'https://claude.ai',
  redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  token_endpoint_auth_method: 'none',
}

const vscodeDocument = {
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
  client_id: VSCODE_ID,
  client_uri: 'https://vscode.dev/product',
  redirect_uris: ['http://127.0.0.1:33418/', 'https://vscode.dev/redirect'],
}

type AuthorizeOptions = {
  baseUrl: string
  clientId: string
  redirectUri: string
  userId?: string
  scope?: string
}

function authorize(client: ApiClient, options: AuthorizeOptions) {
  const { codeChallenge } = createPkce('cimd-verifier-cimd-verifier-cimd-verifier-1234')
  const request = client
    .get(`${options.baseUrl}/oauth/authorize`)
    .qs({
      client_id: options.clientId,
      response_type: 'code',
      redirect_uri: options.redirectUri,
      scope: options.scope ?? 'read',
      state: 'cimd-state',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    })
    .redirects(0)

  if (options.userId) request.header('X-Test-User-Id', options.userId)

  return request
}

/**
 * Swap the document fetcher with an in-memory fake for each test.
 */
function useFakeFetcher(
  group: Parameters<typeof setupHttpGroup>[0],
  ctx: ReturnType<typeof setupHttpGroup>
) {
  const fetcher = new FakeClientMetadataDocumentFetcher()

  group.each.setup(async () => {
    fetcher.reset()
    const cache = await ctx.app.container.make(ClientMetadataDocumentResolutionCache)
    cache.clear()
    ctx.app.container.swap(ClientMetadataDocumentFetcher, () => fetcher)

    return () => ctx.app.container.restore(ClientMetadataDocumentFetcher)
  })

  return fetcher
}

test.group('HTTP | Client ID Metadata Documents', (group) => {
  const ctx = setupHttpGroup(group, { clientIdMetadataDocuments: true })
  const fetcher = useFakeFetcher(group, ctx)

  test('advertises client_id_metadata_document_supported', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    response.assertStatus(200)
    response.assertBodyContains({ client_id_metadata_document_supported: true })
  })

  test('completes the Claude Code flow with an ephemeral loopback port', async ({
    client,
    assert,
  }) => {
    fetcher.serve(CLAUDE_CODE_ID, claudeCodeDocument, { cacheControl: 'max-age=4200', age: '600' })
    const redirectUri = 'http://localhost:3118/callback'

    const authorizeResponse = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri,
      userId: 'user-1',
    })

    authorizeResponse.assertStatus(302)
    const consentUrl = new URL(authorizeResponse.header('location')!, 'https://auth.example.com')
    assert.equal(consentUrl.pathname, '/oauth/consent')

    const stored = await OAuthClient.query().where('clientId', CLAUDE_CODE_ID).firstOrFail()
    assert.equal(stored.name, 'Claude Code')
    assert.isTrue(Boolean(stored.isPublic))
    assert.isNull(stored.clientSecret)
    assert.isNull(stored.userId)
    assert.deepEqual(stored.grantTypes, ['authorization_code', 'refresh_token'])
    assert.deepEqual(stored.scopes, ['read'])
    assert.equal(stored.metadata!.client_uri, 'https://claude.ai')
    assert.notProperty(stored.metadata, 'token_endpoint_auth_method')
    assert.notProperty(stored.metadata, 'registration')

    const expiresAt = DateTime.fromISO(stored.metadata!.client_id_metadata_document.expires_at)
    assert.closeTo(expiresAt.diffNow('seconds').seconds, 3600, 5)

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: consentUrl.searchParams.get('auth_token') })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse.assertStatus(302)
    const callback = new URL(consentResponse.header('location')!)
    assert.equal(callback.origin + callback.pathname, redirectUri)

    const tokenResponse = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'authorization_code',
      client_id: CLAUDE_CODE_ID,
      code: callback.searchParams.get('code'),
      redirect_uri: redirectUri,
      code_verifier: 'cimd-verifier-cimd-verifier-cimd-verifier-1234',
    })

    tokenResponse.assertStatus(200)
    assert.isString(tokenResponse.body().access_token)
    assert.isString(tokenResponse.body().refresh_token)

    const refreshResponse = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'refresh_token',
      client_id: CLAUDE_CODE_ID,
      refresh_token: tokenResponse.body().refresh_token,
    })

    refreshResponse.assertStatus(200)
    assert.deepEqual(fetcher.calls, [CLAUDE_CODE_ID])
  })

  test('validates without persisting for unauthenticated requests', async ({ client, assert }) => {
    fetcher.serve(CLAUDE_CODE_ID, claudeCodeDocument)

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://127.0.0.1:4000/callback',
    })

    response.assertStatus(302)
    assert.isTrue(response.header('location')!.startsWith('/login'))
    assert.deepEqual(fetcher.calls, [CLAUDE_CODE_ID])
    assert.isNull(await OAuthClient.query().where('clientId', CLAUDE_CODE_ID).first())
  })

  test('caches anonymous resolutions across requests', async ({ client, assert }) => {
    fetcher.serve(CLAUDE_CODE_ID, claudeCodeDocument)
    const options = {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://127.0.0.1:4000/callback',
    }

    await authorize(client, options)
    await authorize(client, options)
    const response = await authorize(client, { ...options, userId: 'user-1' })

    response.assertStatus(302)
    assert.deepEqual(fetcher.calls, [CLAUDE_CODE_ID])
    assert.isNotNull(await OAuthClient.query().where('clientId', CLAUDE_CODE_ID).first())
  })

  test('throttles repeated anonymous failures', async ({ client, assert }) => {
    fetcher.fail(CLAUDE_CODE_ID, 'connect ECONNREFUSED 203.0.113.10:443')
    const options = {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://127.0.0.1:4000/callback',
    }

    const first = await authorize(client, options)
    const second = await authorize(client, options)

    first.assertStatus(401)
    second.assertStatus(401)
    assert.equal(second.body().error_description, 'Unable to fetch client metadata document')
    assert.lengthOf(fetcher.calls, 1)
  })

  test('rejects an unknown redirect_uri without redirecting', async ({ client }) => {
    fetcher.serve(CLAUDE_CODE_ID, claudeCodeDocument)

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'https://evil.example.com/callback',
      userId: 'user-1',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_request' })
  })

  test('rejects an invalid document with invalid_client', async ({ client, assert }) => {
    fetcher.serve(CLAUDE_CODE_ID, { ...claudeCodeDocument, client_id: VSCODE_ID })

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
    })

    response.assertStatus(401)
    response.assertBodyContains({ error: 'invalid_client' })
    assert.include(response.body().error_description, 'client_id does not match')
    assert.isNull(await OAuthClient.query().where('clientId', CLAUDE_CODE_ID).first())
  })

  test('rejects with invalid_client when the document cannot be fetched', async ({
    client,
    assert,
  }) => {
    fetcher.fail(CLAUDE_CODE_ID, 'Request timed out after 5000ms')

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
    })

    response.assertStatus(401)
    assert.equal(response.body().error_description, 'Unable to fetch client metadata document')
  })

  test('rejects {0} before fetching')
    .with([
      ['a client_id with a query', 'https://claude.ai/client.json?v=1', 'must not contain a query'],
      ['a non-canonical client_id', 'https://claude.ai/a/../client.json', 'canonical form'],
      ['an IP literal client_id', 'https://127.0.0.1/client.json', 'must use a domain name'],
      [
        'a client_id longer than 255 characters',
        `https://claude.ai/${'a'.repeat(250)}`,
        'must not exceed 255 characters',
      ],
    ])
    .run(async ({ client, assert }, [, clientId, message]) => {
      const response = await authorize(client, {
        baseUrl: ctx.baseUrl,
        clientId,
        redirectUri: 'http://localhost:3118/callback',
        userId: 'user-1',
      })

      response.assertStatus(401)
      assert.include(response.body().error_description, message)
      assert.lengthOf(fetcher.calls, 0)
    })

  test('reuses the stored client while fresh and refreshes it once stale', async ({
    client,
    assert,
  }) => {
    fetcher.serve(CLAUDE_CODE_ID, claudeCodeDocument)
    const options = {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
    }

    await authorize(client, options)
    await authorize(client, options)
    assert.lengthOf(fetcher.calls, 1)

    const stored = await OAuthClient.query().where('clientId', CLAUDE_CODE_ID).firstOrFail()
    stored.metadata = {
      ...stored.metadata,
      client_id_metadata_document: { expires_at: DateTime.now().minus({ minutes: 1 }).toISO() },
    }
    await stored.save()

    fetcher.serve(CLAUDE_CODE_ID, { ...claudeCodeDocument, client_name: 'Claude Code v2' })
    const response = await authorize(client, options)

    response.assertStatus(302)
    assert.lengthOf(fetcher.calls, 2)

    const clients = await OAuthClient.query().where('clientId', CLAUDE_CODE_ID)
    assert.lengthOf(clients, 1)
    assert.equal(clients[0].name, 'Claude Code v2')
    assert.equal(clients[0].id, stored.id)
  })

  test('aborts when a stale client can no longer be fetched', async ({ client, assert }) => {
    await createTestClient({
      clientId: CLAUDE_CODE_ID,
      clientSecret: null,
      isPublic: true,
      redirectUris: ['http://localhost/callback'],
      metadata: { client_id_metadata_document: { expires_at: '2020-01-01T00:00:00.000Z' } },
    })
    fetcher.fail(CLAUDE_CODE_ID, 'Expected HTTP 200, received HTTP 500')

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
    })

    response.assertStatus(401)
    assert.equal(response.body().error_description, 'Unable to fetch client metadata document')
  })

  test('keeps an administrator-disabled client disabled without fetching', async ({
    client,
    assert,
  }) => {
    await createTestClient({ clientId: CLAUDE_CODE_ID, isDisabled: true })
    fetcher.serve(CLAUDE_CODE_ID, claudeCodeDocument)

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
    })

    response.assertStatus(401)
    assert.include(response.body().error_description, 'Client is disabled')
    assert.lengthOf(fetcher.calls, 0)
  })

  test('ignores unsupported grant types listed by the document', async ({ client, assert }) => {
    fetcher.serve(VSCODE_ID, vscodeDocument)

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: VSCODE_ID,
      redirectUri: 'http://127.0.0.1:51000/',
      userId: 'user-1',
    })

    response.assertStatus(302)
    const stored = await OAuthClient.query().where('clientId', VSCODE_ID).firstOrFail()
    assert.deepEqual(stored.grantTypes, ['authorization_code', 'refresh_token'])
  })

  test('keeps only the document scopes known by the server', async ({ client, assert }) => {
    fetcher.serve(CLAUDE_CODE_ID, { ...claudeCodeDocument, scope: 'write unknown:scope' })

    await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
      scope: 'write',
    })

    const stored = await OAuthClient.query().where('clientId', CLAUDE_CODE_ID).firstOrFail()
    assert.deepEqual(stored.scopes, ['write'])
  })

  test('exposes display information on client-info', async ({ client }) => {
    fetcher.serve(VSCODE_ID, vscodeDocument)
    await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: VSCODE_ID,
      redirectUri: 'https://vscode.dev/redirect',
      userId: 'user-1',
    })

    const response = await client
      .get(`${ctx.baseUrl}/oauth/client-info`)
      .qs({ client_id: VSCODE_ID })

    response.assertStatus(200)
    response.assertBody({
      client_id: VSCODE_ID,
      client_name: 'Visual Studio Code',
      client_uri: 'https://vscode.dev/product',
      logo_uri: 'https://code.visualstudio.com/assets/branding/code-stable.png',
      client_id_metadata_document: true,
      client_id_host: 'vscode.dev',
    })
  })

  test('client-info flags regular clients as not metadata documents', async ({ client }) => {
    await createTestClient()

    const response = await client
      .get(`${ctx.baseUrl}/oauth/client-info`)
      .qs({ client_id: 'test-client' })

    response.assertBody({
      client_id: 'test-client',
      client_name: 'Test Client',
      client_id_metadata_document: false,
    })
  })
})

test.group('HTTP | Client ID Metadata Documents (allowedHosts)', (group) => {
  const ctx = setupHttpGroup(group, {
    clientIdMetadataDocuments: { allowedHosts: ['claude.ai'] },
  })
  const fetcher = useFakeFetcher(group, ctx)

  test('accepts an allowed host', async ({ client }) => {
    fetcher.serve(CLAUDE_CODE_ID, claudeCodeDocument)

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
    })

    response.assertStatus(302)
  })

  test('rejects other hosts without fetching', async ({ client, assert }) => {
    fetcher.serve(VSCODE_ID, vscodeDocument)

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: VSCODE_ID,
      redirectUri: 'https://vscode.dev/redirect',
      userId: 'user-1',
    })

    response.assertStatus(401)
    assert.include(response.body().error_description, 'host is not allowed')
    assert.lengthOf(fetcher.calls, 0)
  })

  test('rejects a stored client whose host was removed at the token endpoint', async ({
    client,
  }) => {
    await createTestClient({ clientId: VSCODE_ID, clientSecret: null, isPublic: true })

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'refresh_token',
      client_id: VSCODE_ID,
      refresh_token: 'whatever',
    })

    response.assertStatus(401)
    response.assertBodyContains({ error_description: 'Client ID host is not allowed' })
  })

  test('rejects a pending consent for a host removed from the list', async ({ client }) => {
    await createTestClient({
      clientId: VSCODE_ID,
      clientSecret: null,
      isPublic: true,
      redirectUris: ['https://vscode.dev/redirect'],
    })
    const manager = createManager()
    await manager.store.createPendingAuthorizationRequest({
      id: crypto.randomUUID(),
      token: new TokenService(manager).hashToken('pending-token'),
      userId: 'user-1',
      clientId: VSCODE_ID,
      redirectUri: 'https://vscode.dev/redirect',
      scopes: ['read'],
      codeChallenge: 'challenge',
      codeChallengeMethod: 'S256',
      expiresAt: DateTime.now().plus({ minutes: 5 }),
    })

    const response = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: 'pending-token' })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    response.assertStatus(401)
    response.assertBodyContains({ error_description: 'Client ID host is not allowed' })
  })

  test('rejects client-info for a host not in the list', async ({ client }) => {
    await createTestClient({ clientId: VSCODE_ID })

    const response = await client
      .get(`${ctx.baseUrl}/oauth/client-info`)
      .qs({ client_id: VSCODE_ID })

    response.assertStatus(401)
  })
})

test.group('HTTP | Client ID Metadata Documents (disabled)', (group) => {
  const ctx = setupHttpGroup(group)
  const fetcher = useFakeFetcher(group, ctx)

  test('does not advertise support', async ({ client, assert }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    assert.notProperty(response.body(), 'client_id_metadata_document_supported')
  })

  test('rejects URL client ids at authorize even when stored', async ({ client, assert }) => {
    await createTestClient({
      clientId: CLAUDE_CODE_ID,
      clientSecret: null,
      isPublic: true,
      redirectUris: ['http://localhost/callback'],
    })
    fetcher.serve(CLAUDE_CODE_ID, claudeCodeDocument)

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID,
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
    })

    response.assertStatus(401)
    assert.include(response.body().error_description, 'not supported')
    assert.lengthOf(fetcher.calls, 0)
  })

  test('rejects URL client ids at the token endpoint', async ({ client }) => {
    await createTestClient({
      clientId: CLAUDE_CODE_ID,
      clientSecret: null,
      isPublic: true,
      redirectUris: ['http://localhost/callback'],
    })

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'refresh_token',
      client_id: CLAUDE_CODE_ID,
      refresh_token: 'whatever',
    })

    response.assertStatus(401)
    response.assertBodyContains({ error: 'invalid_client' })
  })

  test('rejects URL client ids on client-info', async ({ client }) => {
    await createTestClient({ clientId: CLAUDE_CODE_ID })

    const response = await client
      .get(`${ctx.baseUrl}/oauth/client-info`)
      .qs({ client_id: CLAUDE_CODE_ID })

    response.assertStatus(401)
  })
})

test.group('HTTP | Client ID Metadata Documents (case-insensitive store)', (group) => {
  const ctx = setupHttpGroup(
    group,
    { clientIdMetadataDocuments: true },
    { store: caseInsensitiveClientStore(lucidStore()) }
  )
  const fetcher = useFakeFetcher(group, ctx)

  test('rejects an uppercase scheme before any lookup or fetch', async ({ client, assert }) => {
    await createTestClient({
      clientId: CLAUDE_CODE_ID,
      redirectUris: ['http://localhost/callback'],
    })

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: CLAUDE_CODE_ID.replace('https://', 'HTTPS://'),
      redirectUri: 'http://localhost:3118/callback',
      userId: 'user-1',
    })

    response.assertStatus(401)
    assert.include(response.body().error_description, 'canonical form')
    assert.lengthOf(fetcher.calls, 0)
  })

  test('does not hijack a client whose URL only differs by case', async ({ client, assert }) => {
    const aliceId = 'https://host.example.com/~alice/client.json'
    const attackerId = 'https://host.example.com/~Alice/client.json'
    await createTestClient({
      clientId: aliceId,
      clientSecret: null,
      isPublic: true,
      redirectUris: ['https://alice.example.com/callback'],
    })
    fetcher.serve(attackerId, {
      client_id: attackerId,
      client_name: 'Totally Alice',
      redirect_uris: ['https://attacker.example.com/callback'],
    })

    const response = await authorize(client, {
      baseUrl: ctx.baseUrl,
      clientId: attackerId,
      redirectUri: 'https://attacker.example.com/callback',
      userId: 'user-1',
    })

    response.assertStatus(401)
    response.assertBodyContains({ error: 'invalid_client' })

    const alice = await OAuthClient.query().where('clientId', aliceId).firstOrFail()
    assert.deepEqual(alice.redirectUris, ['https://alice.example.com/callback'])
  })

  test('rejects case variants of a client_id at the token endpoint', async ({ client }) => {
    await createTestClient({ clientSecret: null, isPublic: true })

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'refresh_token',
      client_id: 'TEST-CLIENT',
      refresh_token: 'whatever',
    })

    response.assertStatus(401)
    response.assertBodyContains({ error: 'invalid_client' })
  })
})

test.group('HTTP | Client ID Metadata Documents (disabled, case-insensitive store)', (group) => {
  const ctx = setupHttpGroup(group, {}, { store: caseInsensitiveClientStore(lucidStore()) })

  test('keeps the kill switch for an uppercase scheme ({0})')
    .with(['authorize', 'token'] as const)
    .run(async ({ client, assert }, endpoint) => {
      await createTestClient({
        clientId: CLAUDE_CODE_ID,
        clientSecret: null,
        isPublic: true,
        redirectUris: ['http://localhost/callback'],
      })
      const clientId = CLAUDE_CODE_ID.replace('https://', 'HTTPS://')

      const response =
        endpoint === 'authorize'
          ? await authorize(client, {
              baseUrl: ctx.baseUrl,
              clientId,
              redirectUri: 'http://localhost:3118/callback',
              userId: 'user-1',
            })
          : await client.post(`${ctx.baseUrl}/oauth/token`).form({
              grant_type: 'refresh_token',
              client_id: clientId,
              refresh_token: 'whatever',
            })

      response.assertStatus(401)
      assert.include(response.body().error_description, 'not supported')
    })
})
