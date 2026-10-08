import {
  ClientMetadataDocumentFetcher,
  ClientMetadataDocumentFetchError,
} from '../../src/client_id_metadata_documents/fetcher.ts'
import type {
  FetchClientMetadataDocumentOptions,
  FetchedClientMetadataDocument,
} from '../../src/client_id_metadata_documents/types.ts'

/**
 * In-memory fetcher serving canned documents. Swap it in the container
 * to test Client ID Metadata Document flows without network access.
 */
export class FakeClientMetadataDocumentFetcher extends ClientMetadataDocumentFetcher {
  #responses = new Map<string, FetchedClientMetadataDocument | Error>()
  calls: string[] = []

  serve(url: string, body: unknown, options?: { cacheControl?: string }) {
    this.#responses.set(url, {
      body,
      cacheControl: options?.cacheControl ?? null,
      expires: null,
      date: null,
    })
  }

  fail(url: string, message: string) {
    this.#responses.set(url, new ClientMetadataDocumentFetchError(message))
  }

  reset() {
    this.#responses.clear()
    this.calls = []
  }

  async fetch(options: FetchClientMetadataDocumentOptions) {
    this.calls.push(options.url.href)

    const response = this.#responses.get(options.url.href)
    if (!response)
      throw new ClientMetadataDocumentFetchError('Expected HTTP 200, received HTTP 404')
    if (response instanceof Error) throw response

    return response
  }
}
