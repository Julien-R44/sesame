import type { LookupAddress } from 'node:dns'

/**
 * Limits applied when fetching a Client ID Metadata Document.
 */
export interface FetchClientMetadataDocumentOptions {
  url: URL
  timeoutMs: number
  maxResponseSize: number
}

/**
 * Raw result of a successful document fetch.
 */
export interface FetchedClientMetadataDocument {
  body: unknown
  cacheControl: string | null
  expires: string | null
  date: string | null
  age: string | null
}

/**
 * Low-level overrides for the fetcher transport. Only meant for tests:
 * relaxing `isAddressAllowed` disables the SSRF protection.
 */
export interface ClientMetadataDocumentFetcherOptions {
  isAddressAllowed?: (address: string) => boolean
  ca?: string | Buffer
}

/**
 * Callback signature of `dns.lookup`, as invoked by `net.connect`.
 */
export type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number
) => void

/**
 * Cache lifetime inputs taken from the document response.
 */
export interface CacheTtlOptions {
  cacheControl: string | null
  expires: string | null
  date: string | null
  age: string | null
  minTtl: number
  maxTtl: number

  /**
   * Response time in milliseconds. Defaults to `Date.now()`.
   */
  now?: number
}

/**
 * Client fields derived from a validated Client ID Metadata Document.
 */
export interface ClientMetadataDocumentClient {
  name: string
  redirectUris: string[]
  scopes: string[]
  grantTypes: string[]
  metadata: Record<string, any>
}
