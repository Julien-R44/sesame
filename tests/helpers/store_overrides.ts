import type { CreateClientRecord, SesameStore } from '../../src/storage/types.ts'

/**
 * Wrap a store, replacing some methods while keeping the others bound
 * to the original instance (stores rely on private fields).
 */
export function overrideStore(store: SesameStore, overrides: Partial<SesameStore>): SesameStore {
  return new Proxy(store, {
    get(target, property) {
      if (property in overrides) return overrides[property as keyof SesameStore]

      const value = Reflect.get(target, property, target)

      return typeof value === 'function' ? value.bind(target) : value
    },
  })
}

/**
 * Simulate a MySQL/MariaDB case-insensitive collation on `client_id`:
 * lookups ignore case and inserts conflict with any case variant.
 */
export function caseInsensitiveClientStore(store: SesameStore): SesameStore {
  const findInsensitive = async (clientId: string) => {
    const clients = await store.listClients()

    return (
      clients.find((client) => client.clientId.toLowerCase() === clientId.toLowerCase()) ?? null
    )
  }

  return overrideStore(store, {
    findClient: findInsensitive,
    async createClient(data: CreateClientRecord) {
      if (await findInsensitive(data.clientId)) {
        throw new Error(`Duplicate entry '${data.clientId}' for key 'oauth_clients.client_id'`)
      }

      return store.createClient(data)
    },
  })
}
