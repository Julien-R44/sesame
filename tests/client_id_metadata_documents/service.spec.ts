import { test } from '@japa/runner'
import { createTestConfig, setupIntegrationGroup } from '../helpers/app.ts'
import { FakeClientMetadataDocumentFetcher } from '../helpers/fake_client_metadata_fetcher.ts'
import { SesameManager } from '../../src/sesame_manager.ts'
import { lucidStore } from '../../src/storage/drivers/lucid.ts'
import type { CreateClientRecord, SesameStore } from '../../src/storage/types.ts'
import { ClientIdMetadataDocumentService } from '../../src/services/client_id_metadata_document_service.ts'
import { OAuthClient } from '../../src/models/oauth_client.ts'

const CLIENT_ID = 'https://app.example.com/client.json'

const document = {
  client_id: CLIENT_ID,
  client_name: 'Example Client',
  redirect_uris: ['http://127.0.0.1/callback'],
}

/**
 * Wrap a store, replacing some methods while keeping the others bound
 * to the original instance (stores rely on private fields).
 */
function overrideStore(store: SesameStore, overrides: Partial<SesameStore>): SesameStore {
  return new Proxy(store, {
    get(target, property) {
      if (property in overrides) return overrides[property as keyof SesameStore]

      const value = Reflect.get(target, property, target)

      return typeof value === 'function' ? value.bind(target) : value
    },
  })
}

function createService(store: SesameStore) {
  const config = createTestConfig({ clientIdMetadataDocuments: true })
  const manager = new SesameManager(config, {} as any, store)
  const fetcher = new FakeClientMetadataDocumentFetcher()
  fetcher.serve(CLIENT_ID, document)

  return new ClientIdMetadataDocumentService({ manager, fetcher })
}

test.group('CIMD | ClientIdMetadataDocumentService', (group) => {
  setupIntegrationGroup(group)

  test('returns a transient client without writing when persist is false', async ({ assert }) => {
    const client = await createService(lucidStore()).resolve({
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

    const client = await createService(racingStore).resolve({ clientId: CLIENT_ID, persist: true })

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
      () => createService(failingStore).resolve({ clientId: CLIENT_ID, persist: true }),
      'database is down'
    )
  })
})
