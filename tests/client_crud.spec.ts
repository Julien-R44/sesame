import { test } from '@japa/runner'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthGrant } from '../src/models/oauth_grant.ts'
import { createTestGrant } from './helpers/create_test_grant.ts'
import { OAuthPendingAuthorizationRequest } from '../src/models/oauth_pending_authorization_request.ts'
import { ClientService } from '../src/services/client_service.ts'
import { TokenService } from '../src/services/token_service.ts'
import { DateTime } from 'luxon'

test.group('Integration | Client CRUD | createClient', (group) => {
  setupIntegrationGroup(group)

  test('creates a confidential client with defaults', async ({ assert }) => {
    const manager = createManager()

    const { client, clientSecret } = await manager.createClient({
      name: 'My App',
      redirectUris: ['https://example.com/callback'],
    })

    assert.equal(client.name, 'My App')
    assert.isString(client.id)
    assert.equal(client.id, (await manager.findClient(client.clientId))?.id)
    assert.deepEqual(client.redirectUris, ['https://example.com/callback'])
    assert.isFalse(client.isPublic)
    assert.isFalse(client.isDisabled)
    assert.isTrue(client.requirePkce)
    assert.equal(client.type, 'confidential')
    assert.deepEqual(client.grantTypes, ['authorization_code'])
    assert.isNotNull(clientSecret)
    assert.isString(clientSecret)

    // Secret is stored hashed
    const clientService = new ClientService()
    assert.isTrue(clientService.verifySecret(clientSecret!, client.clientSecret!))
  })

  test('creates a public client', async ({ assert }) => {
    const manager = createManager()

    const { client, clientSecret } = await manager.createClient({
      name: 'SPA',
      redirectUris: ['https://spa.example.com/callback'],
      isPublic: true,
    })

    assert.isTrue(client.isPublic)
    assert.equal(client.type, 'public')
    assert.isNull(clientSecret)
    assert.isNull(client.clientSecret)
  })

  test('creates a client with custom scopes and grant types', async ({ assert }) => {
    const manager = createManager()

    const { client } = await manager.createClient({
      name: 'M2M Service',
      redirectUris: [],
      scopes: ['read', 'write'],
      grantTypes: ['client_credentials'],
      userId: 'user-42',
    })

    assert.deepEqual(client.scopes, ['read', 'write'])
    assert.deepEqual(client.grantTypes, ['client_credentials'])
    assert.equal(client.userId, 'user-42')
  })

  test('uses default scopes from config when not specified', async ({ assert }) => {
    const manager = createManager({ defaultScopes: ['read'] })

    const { client } = await manager.createClient({
      name: 'Default Scopes App',
      redirectUris: ['https://example.com/cb'],
    })

    assert.deepEqual(client.scopes, ['read'])
  })

  test('creates client with metadata', async ({ assert }) => {
    const manager = createManager()

    const { client } = await manager.createClient({
      name: 'Rich Client',
      redirectUris: ['https://example.com/cb'],
      metadata: { client_uri: 'https://example.com', logo_uri: 'https://example.com/logo.png' },
    })

    assert.deepEqual(client.metadata, {
      client_uri: 'https://example.com',
      logo_uri: 'https://example.com/logo.png',
    })
  })

  test('each client gets a unique clientId', async ({ assert }) => {
    const manager = createManager()

    const { client: c1 } = await manager.createClient({
      name: 'App 1',
      redirectUris: ['https://a.com/cb'],
    })
    const { client: c2 } = await manager.createClient({
      name: 'App 2',
      redirectUris: ['https://b.com/cb'],
    })

    assert.notEqual(c1.clientId, c2.clientId)
  })
})

test.group('Integration | Client CRUD | findClient', (group) => {
  setupIntegrationGroup(group)

  test('finds an existing client', async ({ assert }) => {
    const client = await createTestClient({ name: 'Findable' })
    const manager = createManager()

    const found = await manager.findClient(client.clientId)

    assert.isNotNull(found)
    assert.equal(found!.name, 'Findable')
  })

  test('returns null for unknown clientId', async ({ assert }) => {
    const manager = createManager()

    const found = await manager.findClient('non-existent')

    assert.isNull(found)
  })
})

test.group('Integration | Client CRUD | listClients', (group) => {
  setupIntegrationGroup(group)

  test('lists all clients', async ({ assert }) => {
    const manager = createManager()
    await manager.createClient({ name: 'App A', redirectUris: ['https://a.com/cb'] })
    await manager.createClient({ name: 'App B', redirectUris: ['https://b.com/cb'] })

    const clients = await manager.listClients()

    assert.lengthOf(clients, 2)
  })

  test('filters by userId', async ({ assert }) => {
    const manager = createManager()
    await manager.createClient({
      name: 'User 1 App',
      redirectUris: ['https://a.com/cb'],
      userId: 'user-1',
    })
    await manager.createClient({
      name: 'User 2 App',
      redirectUris: ['https://b.com/cb'],
      userId: 'user-2',
    })

    const clients = await manager.listClients({ userId: 'user-1' })

    assert.lengthOf(clients, 1)
    assert.equal(clients[0].name, 'User 1 App')
  })

  test('returns empty array when no clients exist', async ({ assert }) => {
    const manager = createManager()

    const clients = await manager.listClients()

    assert.lengthOf(clients, 0)
  })
})

test.group('Integration | Client CRUD | updateClient', (group) => {
  setupIntegrationGroup(group)

  test('updates client name', async ({ assert }) => {
    const client = await createTestClient({ name: 'Old Name' })
    const manager = createManager()

    const updated = await manager.updateClient(client.clientId, { name: 'New Name' })

    assert.isNotNull(updated)
    assert.equal(updated!.name, 'New Name')

    const fromDb = await OAuthClient.query().where('clientId', client.clientId).firstOrFail()
    assert.equal(fromDb.name, 'New Name')
  })

  test('updates multiple fields', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()

    const updated = await manager.updateClient(client.clientId, {
      redirectUris: ['https://new.example.com/cb'],
      scopes: ['admin'],
      isDisabled: true,
    })

    assert.deepEqual(updated!.redirectUris, ['https://new.example.com/cb'])
    assert.deepEqual(updated!.scopes, ['admin'])
    assert.isTrue(updated!.isDisabled)
  })

  test('returns null for unknown clientId', async ({ assert }) => {
    const manager = createManager()

    const result = await manager.updateClient('non-existent', { name: 'X' })

    assert.isNull(result)
  })

  test('does not change fields that are not provided', async ({ assert }) => {
    const client = await createTestClient({ name: 'Keep Me' })
    const manager = createManager()

    const updated = await manager.updateClient(client.clientId, { isDisabled: true })

    assert.equal(updated!.name, 'Keep Me')
    assert.ok(updated!.isDisabled)
  })
})

test.group('Integration | Client CRUD | deleteClient', (group) => {
  setupIntegrationGroup(group)

  test('deletes a client', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()

    const result = await manager.deleteClient(client.clientId)

    assert.isTrue(result)
    const fromDb = await OAuthClient.query().where('clientId', client.clientId).first()
    assert.isNull(fromDb)
  })

  test('returns false for unknown clientId', async ({ assert }) => {
    const manager = createManager()

    const result = await manager.deleteClient('non-existent')

    assert.isFalse(result)
  })

  test('cascades deletion to tokens, codes, and consents', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const tokenService = new TokenService(manager)

    // Create access token
    const accessTokenId = crypto.randomUUID()
    await OAuthAccessToken.create({
      id: accessTokenId,
      tokenHash: 'at-crud-test',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    // Create refresh token
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('rt-crud-test'),
      accessTokenId,
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    // Create authorization code
    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken('code-crud-test'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    // Create consent
    await createTestGrant({
      id: crypto.randomUUID(),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
    })

    // Create pending authorization request
    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('pending-crud-test'),
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    await manager.deleteClient(client.clientId)

    assert.lengthOf(await OAuthAccessToken.query().where('clientId', client.clientId), 0)
    assert.lengthOf(await OAuthRefreshToken.query().where('clientId', client.clientId), 0)
    assert.lengthOf(await OAuthAuthorizationCode.query().where('clientId', client.clientId), 0)
    assert.lengthOf(await OAuthGrant.query().where('clientId', client.clientId), 0)
    assert.lengthOf(
      await OAuthPendingAuthorizationRequest.query().where('clientId', client.clientId),
      0
    )
  })

  test('does not affect other clients', async ({ assert }) => {
    const manager = createManager()
    const client1 = await createTestClient({ clientId: 'client-1' })
    const client2 = await createTestClient({ clientId: 'client-2' })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'at-client2',
      clientId: client2.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await manager.deleteClient(client1.clientId)

    const remaining = await OAuthClient.query().where('clientId', client2.clientId).first()
    assert.isNotNull(remaining)

    const tokens = await OAuthAccessToken.query().where('clientId', client2.clientId)
    assert.lengthOf(tokens, 1)
  })
})

test.group('Integration | Client CRUD | rotateClientSecret', (group) => {
  setupIntegrationGroup(group)

  test('rotates secret for a confidential client', async ({ assert }) => {
    const client = await createTestClient()
    const oldHash = client.clientSecret
    const manager = createManager()

    const newSecret = await manager.rotateClientSecret(client.clientId)

    assert.isNotNull(newSecret)
    assert.isString(newSecret)

    const fromDb = await OAuthClient.query().where('clientId', client.clientId).firstOrFail()
    assert.notEqual(fromDb.clientSecret, oldHash)

    const clientService = new ClientService()
    assert.isTrue(clientService.verifySecret(newSecret!, fromDb.clientSecret!))
  })

  test('returns null for a public client', async ({ assert }) => {
    const manager = createManager()
    const { client } = await manager.createClient({
      name: 'Public',
      redirectUris: ['https://example.com/cb'],
      isPublic: true,
    })

    const result = await manager.rotateClientSecret(client.clientId)

    assert.isNull(result)
  })

  test('returns null for unknown clientId', async ({ assert }) => {
    const manager = createManager()

    const result = await manager.rotateClientSecret('non-existent')

    assert.isNull(result)
  })
})
