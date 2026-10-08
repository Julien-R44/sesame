import type {
  ClientMetadataDocumentClient,
  ResolutionCacheEntry,
  ResolutionCacheOptions,
} from './types.ts'

/**
 * Bounded in-memory LRU cache for document resolutions that are not
 * persisted (unauthenticated authorize requests). Prevents an anonymous
 * caller from turning the authorization server into a fetch amplifier.
 *
 * Bound as a container singleton by the Sésame provider.
 */
export class ClientMetadataDocumentResolutionCache {
  #entries = new Map<string, ResolutionCacheEntry>()
  #maxEntries: number
  #now: () => number

  constructor(options: ResolutionCacheOptions = {}) {
    this.#maxEntries = options.maxEntries ?? 500
    this.#now = options.now ?? Date.now
  }

  #set(clientId: string, entry: ResolutionCacheEntry) {
    this.#entries.delete(clientId)
    this.#entries.set(clientId, entry)

    for (const key of this.#entries.keys()) {
      if (this.#entries.size <= this.#maxEntries) break
      this.#entries.delete(key)
    }
  }

  /**
   * Return a live entry and mark it as recently used.
   */
  get(clientId: string): ResolutionCacheEntry | null {
    const entry = this.#entries.get(clientId)
    if (!entry) return null

    this.#entries.delete(clientId)
    if (entry.expiresAt <= this.#now()) return null

    this.#entries.set(clientId, entry)

    return entry
  }

  setClient(options: { clientId: string; client: ClientMetadataDocumentClient; ttlMs: number }) {
    this.#set(options.clientId, {
      client: options.client,
      expiresAt: this.#now() + options.ttlMs,
    })
  }

  setError(options: { clientId: string; message: string; ttlMs: number }) {
    this.#set(options.clientId, {
      error: options.message,
      expiresAt: this.#now() + options.ttlMs,
    })
  }

  get size() {
    return this.#entries.size
  }

  clear() {
    this.#entries.clear()
  }
}
