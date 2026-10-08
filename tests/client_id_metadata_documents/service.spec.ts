import { test } from '@japa/runner'
import { createTestConfig, setupIntegrationGroup } from '../helpers/app.ts'
import { FakeClientMetadataDocumentFetcher } from '../helpers/fake_client_metadata_fetcher.ts'
import { SesameManager } from '../../src/sesame_manager.ts'
import { lucidStore } from '../../src/storage/drivers/lucid.ts'
import type { CreateClientRecord, SesameStore } from '../../src/storage/types.ts'
import { caseInsensitiveClientStore, overrideStore } from '../helpers/store_overrides.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { ClientIdMetadataDocumentService } from '../../src/services/client_id_metadata_document_service.ts'
import { OAuthClient } from '../../src/models/oauth_client.ts'
import { ClientMetadataDocumentResolutionCache } from '../../src/client_id_metadata_documents/resolution_cache.ts'

const CLIENT_ID = 'https://app.example.com/client.json'

const document = {
  client_id: CLIENT_ID,
  client_name: 'Example Client',
  redirect_uris: ['http://127.0.0.1/callback'],
}

function createService(store: SesameStore, options?: { logger?: any }) {
  const config = createTestConfig({ clientIdMetadataDocuments: true })
  const manager = new SesameManager(config, {} as any, store)
  const fetcher = new FakeClientMetadataDocumentFetcher()
  fetcher.serve(CLIENT_ID, document)
  const cache = new ClientMetadataDocumentResolutionCache()

  const service = new ClientIdMetadataDocumentService({
    manager,
    fetcher,
    cache,
    logger: options?.logger,
  })

  return { service, fetcher, cache }
}

test.group('CIMD | ClientIdMetadataDocumentService', (group) => {
  setupIntegrationGroup(group)

  test('returns a transient client without writing when persist is false', async ({ assert }) => {
    const client = await createService(lucidStore()).service.resolve({
      clientId: CLIENT_ID,
      persist: false,
    })

    assert.equal(client.clientId, CLIENT_ID)
    assert.equal(client.name, 'Example Client')
    assert.isTrue(client.isPublic)
    assert.isNull(await OAuthClient.query().where('clientId', CLIENT_ID).first())
  })

  test('falls back to an update when a concurrent request inserted first', async ({ assert }) => {
    const store = lucidStore()
    const racingStore = overrideStore(store, {
      async createClient(data: CreateClientRecord) {
        await store.createClient({ ...data, id: crypto.randomUUID(), name: 'Concurrent' })
        throw new Error('UNIQUE constraint failed: oauth_clients.client_id')
      },
    })

    const client = await createService(racingStore).service.resolve({
      clientId: CLIENT_ID,
      persist: true,
    })

    assert.equal(client.name, 'Example Client')
    assert.lengthOf(await OAuthClient.query().where('clientId', CLIENT_ID), 1)
  })

  test('rethrows insert errors that are not caused by a concurrent insert', async ({ assert }) => {
    const failingStore = overrideStore(lucidStore(), {
      async createClient() {
        throw new Error('database is down')
      },
    })

    await assert.rejects(
      () => createService(failingStore).service.resolve({ clientId: CLIENT_ID, persist: true }),
      'database is down'
    )
  })

  test('never uses nor overwrites a client whose id only differs by case', async ({ assert }) => {
    const aliceId = 'https://app.example.com/~alice/client.json'
    await createTestClient({
      clientId: aliceId,
      redirectUris: ['https://alice.example.com/callback'],
    })

    const { service } = createService(caseInsensitiveClientStore(lucidStore()))
    const error = await service
      .resolve({ clientId: 'https://app.example.com/~Alice/client.json', persist: true })
      .catch((err) => err)

    assert.equal(error.oauthCode, 'invalid_client')
    assert.include(error.message, 'conflicts with a registered client')

    const alice = await OAuthClient.query().where('clientId', aliceId).firstOrFail()
    assert.deepEqual(alice.redirectUris, ['https://alice.example.com/callback'])
  })

  test('does not overwrite a case variant after a conflicting insert', async ({ assert }) => {
    const store = lucidStore()
    await createTestClient({
      clientId: CLIENT_ID.toUpperCase().replace('HTTPS://', 'https://'),
      redirectUris: ['https://victim.example.com/callback'],
    })

    const insensitive = caseInsensitiveClientStore(store)
    let lookups = 0
    const racingStore = overrideStore(insensitive, {
      async findClient(clientId: string) {
        lookups++

        return lookups === 1 ? null : insensitive.findClient(clientId)
      },
    })

    const error = await createService(racingStore)
      .service.resolve({ clientId: CLIENT_ID, persist: true })
      .catch((err) => err)

    assert.equal(error.oauthCode, 'invalid_client')

    const clients = await OAuthClient.all()
    assert.lengthOf(clients, 1)
    assert.deepEqual(clients[0].redirectUris, ['https://victim.example.com/callback'])
  })

  test('caches anonymous resolutions and reuses them when persisting', async ({ assert }) => {
    const { service, fetcher } = createService(lucidStore())

    await service.resolve({ clientId: CLIENT_ID, persist: false })
    await service.resolve({ clientId: CLIENT_ID, persist: false })
    const client = await service.resolve({ clientId: CLIENT_ID, persist: true })

    assert.lengthOf(fetcher.calls, 1)
    assert.equal(client.name, 'Example Client')
    assert.isNotNull(await OAuthClient.query().where('clientId', CLIENT_ID).first())
  })

  test('caches anonymous failures briefly with a generic message', async ({ assert }) => {
    const warnings: Array<{ payload: any; message: string }> = []
    const logger = { warn: (payload: any, message: string) => warnings.push({ payload, message }) }
    const { service, fetcher } = createService(lucidStore(), { logger })
    fetcher.fail(CLIENT_ID, 'connect ECONNREFUSED 203.0.113.10:443')

    for (let attempt = 0; attempt < 2; attempt++) {
      const error = await service
        .resolve({ clientId: CLIENT_ID, persist: false })
        .catch((err) => err)

      assert.equal(error.oauthCode, 'invalid_client')
      assert.equal(error.message, 'Unable to fetch client metadata document')
    }

    assert.lengthOf(fetcher.calls, 1)
    assert.lengthOf(warnings, 1)
    assert.include(warnings[0].payload.err.message, 'ECONNREFUSED')
    assert.equal(warnings[0].payload.clientId, CLIENT_ID)
  })

  test('does not cache authenticated resolutions in memory', async ({ assert }) => {
    const { service, fetcher, cache } = createService(lucidStore())
    fetcher.fail(CLIENT_ID, 'Request timed out after 5000ms')

    await service.resolve({ clientId: CLIENT_ID, persist: true }).catch(() => {})
    await service.resolve({ clientId: CLIENT_ID, persist: true }).catch(() => {})

    assert.lengthOf(fetcher.calls, 2)
    assert.equal(cache.size, 0)
  })
})
