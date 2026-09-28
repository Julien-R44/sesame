import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { TokenService } from '../src/services/token_service.ts'

test.group('Integration | Pending authorization requests', (group) => {
  setupIntegrationGroup(group)

  test('reads raw consent tokens repeatedly without consuming the request', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const token = 'raw-consent-token'
    const hash = new TokenService(manager).hashToken(token)
    await manager.store.createPendingAuthorizationRequest({
      id: crypto.randomUUID(),
      token: hash,
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read', 'write'],
      state: 'oauth-state',
      expiresAt: DateTime.now().plus({ minutes: 5 }),
    })

    const options = { token, userId: 'user-1' }
    const request = await manager.findPendingAuthorizationRequest(options)
    assert.equal(request?.clientId, client.clientId)
    assert.deepEqual(request?.scopes, ['read', 'write'])
    assert.equal(request?.state, 'oauth-state')
    assert.equal(request?.redirectUri, 'https://app.example.com/callback')
    assert.isNull(request?.nonce)
    assert.isTrue(DateTime.isDateTime(request?.expiresAt))
    assert.equal((await manager.findPendingAuthorizationRequest(options))?.id, request?.id)

    const storedOptions = { token: hash, userId: 'user-1', now: DateTime.now() }
    assert.equal(
      (await manager.store.consumePendingAuthorizationRequest(storedOptions))?.id,
      request?.id
    )
    assert.isNull(await manager.store.consumePendingAuthorizationRequest(storedOptions))
    assert.isNull(await manager.findPendingAuthorizationRequest(options))
  })

  test('rejects unknown tokens, token hashes, other users and expired requests', async ({
    assert,
  }) => {
    const manager = createManager()
    const client = await createTestClient()
    const token = 'raw-consent-token'
    const hash = new TokenService(manager).hashToken(token)
    const expiresAt = DateTime.now().plus({ minutes: 5 })
    await manager.store.createPendingAuthorizationRequest({
      id: crypto.randomUUID(),
      token: hash,
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      expiresAt,
    })

    assert.isNull(
      await manager.findPendingAuthorizationRequest({ token: 'unknown', userId: 'user-1' })
    )
    assert.isNull(await manager.findPendingAuthorizationRequest({ token: hash, userId: 'user-1' }))
    assert.isNull(await manager.findPendingAuthorizationRequest({ token, userId: 'user-2' }))
    assert.isNull(
      await manager.store.findPendingAuthorizationRequest({
        token: hash,
        userId: 'user-1',
        now: expiresAt,
      })
    )
    assert.isNotNull(await manager.findPendingAuthorizationRequest({ token, userId: 'user-1' }))

    const expiredToken = 'expired-token'
    await manager.store.createPendingAuthorizationRequest({
      id: crypto.randomUUID(),
      token: new TokenService(manager).hashToken(expiredToken),
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      expiresAt: DateTime.now().minus({ seconds: 1 }),
    })

    assert.isNull(
      await manager.findPendingAuthorizationRequest({ token: expiredToken, userId: 'user-1' })
    )
  })
})
