import { isIP } from 'node:net'
import { request } from 'node:https'
import type { IncomingMessage } from 'node:http'
import { lookup as dnsLookup, type LookupOptions } from 'node:dns'
import { isSpecialUseAddress } from './special_use_addresses.ts'
import type {
  ClientMetadataDocumentFetcherOptions,
  FetchClientMetadataDocumentOptions,
  FetchedClientMetadataDocument,
  LookupCallback,
} from './types.ts'

export { isSpecialUseAddress } from './special_use_addresses.ts'
export type {
  ClientMetadataDocumentFetcherOptions,
  FetchClientMetadataDocumentOptions,
  FetchedClientMetadataDocument,
} from './types.ts'

/**
 * Media types accepted for documents: `application/json` or any
 * `application/*+json` type.
 */
const JSON_MEDIA_TYPE = /^application\/([\w.-]+\+)?json$/

/**
 * Raised when a Client ID Metadata Document cannot be fetched.
 * Its message is safe to expose in an OAuth error description.
 */
export class ClientMetadataDocumentFetchError extends Error {}

/**
 * Fetches Client ID Metadata Documents while preventing SSRF.
 *
 * - Every resolved address is checked at connection time against
 *   special-use ranges, so DNS rebinding cannot bypass the check
 * - Redirects are never followed and only `200` is accepted
 * - The whole exchange is bounded by a timeout and a byte limit
 *
 * Resolved from the container, so applications can swap it, e.g. to
 * reach a local document server during development or to trust an
 * internal certificate authority.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.6
 */
export class ClientMetadataDocumentFetcher {
  #isAddressAllowed: (address: string) => boolean
  #ca?: ClientMetadataDocumentFetcherOptions['ca']

  constructor(options: ClientMetadataDocumentFetcherOptions = {}) {
    this.#isAddressAllowed =
      options.isAddressAllowed ?? ((address) => !isSpecialUseAddress(address))
    this.#ca = options.ca
  }

  /**
   * DNS lookup used by the socket. Resolves every address and refuses
   * the connection when any of them is not allowed.
   */
  #lookup(hostname: string, options: LookupOptions, callback: LookupCallback) {
    dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err, [])

      const blocked = addresses.some((entry) => !this.#isAddressAllowed(entry.address))
      if (blocked || addresses.length === 0) {
        return callback(
          new ClientMetadataDocumentFetchError('Host resolves to a non-public address'),
          []
        )
      }

      if (options.all) return callback(null, addresses)

      callback(null, addresses[0].address, addresses[0].family)
    })
  }

  /**
   * IP literals skip the lookup hook, so they are checked upfront.
   */
  #assertIpLiteralAllowed(url: URL) {
    const hostname = url.hostname.replace(/^\[|\]$/g, '')
    if (isIP(hostname) === 0) return
    if (this.#isAddressAllowed(hostname)) return

    throw new ClientMetadataDocumentFetchError('Host is a non-public address')
  }

  #send(options: { url: URL; signal: AbortSignal }): Promise<IncomingMessage> {
    return new Promise((resolve, reject) => {
      const req = request(
        options.url,
        {
          method: 'GET',
          agent: false,
          ca: this.#ca,
          signal: options.signal,
          headers: { 'accept': 'application/json', 'user-agent': 'Sesame OAuth Server' },
          lookup: (hostname, lookupOptions, callback) =>
            this.#lookup(hostname, lookupOptions, callback as LookupCallback),
        },
        resolve
      )

      req.on('error', reject)
      req.end()
    })
  }

  /**
   * Reject non-200 responses (including redirects), non-JSON media
   * types, encoded bodies and announced oversized bodies.
   */
  #assertResponse(response: IncomingMessage, maxResponseSize: number) {
    if (response.statusCode !== 200) {
      throw new ClientMetadataDocumentFetchError(
        `Expected HTTP 200, received HTTP ${response.statusCode}`
      )
    }

    const mediaType = (response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase()
    if (!JSON_MEDIA_TYPE.test(mediaType)) {
      throw new ClientMetadataDocumentFetchError('Response is not served as JSON')
    }

    const encoding = response.headers['content-encoding']
    if (encoding && encoding !== 'identity') {
      throw new ClientMetadataDocumentFetchError('Encoded responses are not supported')
    }

    if (Number(response.headers['content-length'] ?? 0) > maxResponseSize) {
      throw new ClientMetadataDocumentFetchError(`Document exceeds ${maxResponseSize} bytes`)
    }
  }

  /**
   * Read the body, aborting as soon as the byte limit is exceeded.
   */
  #readBody(response: IncomingMessage, maxResponseSize: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = []
      let size = 0

      response.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > maxResponseSize) {
          response.destroy(
            new ClientMetadataDocumentFetchError(`Document exceeds ${maxResponseSize} bytes`)
          )
          return
        }

        chunks.push(chunk)
      })

      response.on('error', reject)
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
      response.on('close', () => {
        if (!response.complete) reject(new ClientMetadataDocumentFetchError('Response aborted'))
      })
    })
  }

  #parseJson(raw: string): unknown {
    try {
      return JSON.parse(raw)
    } catch {
      throw new ClientMetadataDocumentFetchError('Response is not valid JSON')
    }
  }

  #toFetchError(options: { error: unknown; signal: AbortSignal; timeoutMs: number }) {
    if (options.error instanceof ClientMetadataDocumentFetchError) return options.error

    const cause = (options.error as { cause?: unknown })?.cause
    if (cause instanceof ClientMetadataDocumentFetchError) return cause

    if (options.signal.aborted) {
      return new ClientMetadataDocumentFetchError(`Request timed out after ${options.timeoutMs}ms`)
    }

    const message = options.error instanceof Error ? options.error.message : 'Unknown error'

    return new ClientMetadataDocumentFetchError(`Request failed: ${message}`, {
      cause: options.error,
    })
  }

  /**
   * Fetch and parse a document. Throws `ClientMetadataDocumentFetchError`
   * on any network, policy or parsing failure.
   */
  async fetch(options: FetchClientMetadataDocumentOptions): Promise<FetchedClientMetadataDocument> {
    const signal = AbortSignal.timeout(options.timeoutMs)

    try {
      this.#assertIpLiteralAllowed(options.url)

      const response = await this.#send({ url: options.url, signal })
      try {
        this.#assertResponse(response, options.maxResponseSize)
      } catch (error) {
        response.destroy()
        throw error
      }

      const raw = await this.#readBody(response, options.maxResponseSize)

      return {
        body: this.#parseJson(raw),
        cacheControl: response.headers['cache-control'] ?? null,
        expires: response.headers['expires'] ?? null,
        date: response.headers['date'] ?? null,
        age: response.headers['age'] ?? null,
      }
    } catch (error) {
      throw this.#toFetchError({ error, signal, timeoutMs: options.timeoutMs })
    }
  }
}
