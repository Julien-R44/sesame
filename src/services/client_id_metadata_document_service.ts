import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
import type { OAuthClientRecord } from '../storage/types.ts'
import { E_INVALID_CLIENT } from '../oauth_error.ts'
import { OIDC_SCOPES, type ResolvedClientIdMetadataDocumentsConfig } from '../types.ts'
import { computeCacheTtl } from '../client_id_metadata_documents/cache_ttl.ts'
import {
  describeInvalidClientIdUrl,
  isHostAllowed,
} from '../client_id_metadata_documents/client_id_url.ts'
import {
  validateClientMetadataDocument,
  type ClientMetadataDocument,
} from '../client_id_metadata_documents/document_validator.ts'
import {
  ClientMetadataDocumentFetchError,
  type ClientMetadataDocumentFetcher,
} from '../client_id_metadata_documents/fetcher.ts'
import type { ClientMetadataDocumentClient } from '../client_id_metadata_documents/types.ts'

/**
 * Grant types a metadata document client can use. Other values listed
 * in a document (e.g. device code) are ignored rather than rejected.
 */
const SUPPORTED_GRANT_TYPES = new Set(['authorization_code', 'refresh_token'])

/**
 * Same defaults as dynamic client registration.
 */
const DEFAULT_GRANT_TYPES = ['authorization_code', 'refresh_token']

/**
 * Optional document properties kept in the client metadata for display.
 */
const DISPLAY_PROPERTIES = [
  'client_uri',
  'logo_uri',
  'tos_uri',
  'policy_uri',
  'software_id',
  'software_version',
] as const

/**
 * Resolves `client_id` URLs into OAuth clients by fetching and validating
 * their Client ID Metadata Document.
 *
 * The client row in `oauth_clients` doubles as the cache: it is reused
 * until `metadata.client_id_metadata_document.expires_at`, then refreshed.
 * Rows are only written for authenticated requests so anonymous hits on
 * the authorize endpoint never create clients. Fetch and validation
 * failures abort the request and are never cached.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/
 */
export class ClientIdMetadataDocumentService {
  #manager: SesameManager
  #config: ResolvedClientIdMetadataDocumentsConfig
  #fetcher: ClientMetadataDocumentFetcher

  constructor(options: { manager: SesameManager; fetcher: ClientMetadataDocumentFetcher }) {
    const config = options.manager.config.clientIdMetadataDocuments
    if (!config) throw new E_INVALID_CLIENT('Client ID Metadata Documents are not supported')

    this.#manager = options.manager
    this.#config = config
    this.#fetcher = options.fetcher
  }

  /**
   * Validate the URL shape and the host allowlist before any network call.
   */
  #parseClientId(clientId: string) {
    const invalid = describeInvalidClientIdUrl(clientId)
    if (invalid) throw new E_INVALID_CLIENT(invalid)

    const url = new URL(clientId)
    if (!isHostAllowed({ hostname: url.hostname, allowedHosts: this.#config.allowedHosts })) {
      throw new E_INVALID_CLIENT('Client ID host is not allowed')
    }

    return url
  }

  #isFresh(client: OAuthClientRecord) {
    const expiresAt = client.metadata?.client_id_metadata_document?.expires_at
    if (typeof expiresAt !== 'string') return false

    return DateTime.fromISO(expiresAt) > DateTime.now()
  }

  async #fetchDocument(url: URL) {
    try {
      return await this.#fetcher.fetch({
        url,
        timeoutMs: string.milliseconds.parse(this.#config.fetchTimeout),
        maxResponseSize: this.#config.maxResponseSize,
      })
    } catch (error) {
      if (!(error instanceof ClientMetadataDocumentFetchError)) throw error

      throw new E_INVALID_CLIENT(`Unable to fetch client metadata document: ${error.message}`)
    }
  }

  /**
   * Keep supported and enabled grant types. The client must at least be
   * able to use the authorization code grant.
   */
  #resolveGrantTypes(document: ClientMetadataDocument) {
    const requested = document.grant_types ?? DEFAULT_GRANT_TYPES
    const grantTypes = requested.filter(
      (grantType) =>
        SUPPORTED_GRANT_TYPES.has(grantType) && this.#manager.isGrantTypeEnabled(grantType)
    )

    if (!grantTypes.includes('authorization_code')) {
      throw new E_INVALID_CLIENT(
        'Invalid client metadata document: grant_types must include "authorization_code"'
      )
    }

    return grantTypes
  }

  /**
   * Keep the document scopes known by this server, or fall back to
   * `defaultScopes` when the document does not declare any.
   */
  #resolveScopes(document: ClientMetadataDocument) {
    if (!document.scope) return this.#manager.config.defaultScopes

    const requested = document.scope.split(' ').filter(Boolean)
    const invalid = new Set(this.#manager.validateScopes(requested))

    return requested.filter((scope) => {
      if (invalid.has(scope)) return false

      return this.#manager.isOidcEnabled || !OIDC_SCOPES.has(scope)
    })
  }

  #buildMetadata(options: { document: ClientMetadataDocument; ttl: number }) {
    const display = DISPLAY_PROPERTIES.filter((property) => options.document[property]).map(
      (property) => [property, options.document[property]]
    )
    const fetchedAt = DateTime.now()

    return {
      token_endpoint_auth_method: 'none',
      response_types: ['code'],
      ...Object.fromEntries(display),
      client_id_metadata_document: {
        fetched_at: fetchedAt.toISO(),
        expires_at: fetchedAt.plus({ seconds: options.ttl }).toISO(),
      },
    }
  }

  /**
   * Fetch, validate and map a document to client fields.
   */
  async #loadClient(options: {
    url: URL
    clientId: string
  }): Promise<ClientMetadataDocumentClient> {
    const fetched = await this.#fetchDocument(options.url)
    const document = await validateClientMetadataDocument({
      body: fetched.body,
      clientId: options.clientId,
    })

    const ttl = computeCacheTtl({
      cacheControl: fetched.cacheControl,
      expires: fetched.expires,
      date: fetched.date,
      age: fetched.age,
      minTtl: string.seconds.parse(this.#config.cache.minTtl),
      maxTtl: string.seconds.parse(this.#config.cache.maxTtl),
    })

    return {
      name: document.client_name,
      redirectUris: document.redirect_uris,
      scopes: this.#resolveScopes(document),
      grantTypes: this.#resolveGrantTypes(document),
      metadata: this.#buildMetadata({ document, ttl }),
    }
  }

  /**
   * In-memory client used for anonymous requests, which must not write.
   */
  #transientClient(options: {
    clientId: string
    client: ClientMetadataDocumentClient
    existing: OAuthClientRecord | null
  }): OAuthClientRecord {
    const now = DateTime.now()

    return {
      id: options.existing?.id ?? crypto.randomUUID(),
      clientId: options.clientId,
      clientSecret: null,
      ...options.client,
      isPublic: true,
      isDisabled: false,
      requirePkce: true,
      type: 'public',
      userId: null,
      createdAt: options.existing?.createdAt ?? now,
      updatedAt: now,
    }
  }

  /**
   * Find the stored client for this exact URL. Stores with case-insensitive
   * collations (MySQL/MariaDB) can return another client, e.g. `~alice`
   * for `~Alice`: that client must never be used nor overwritten.
   */
  async #findStoredClient(clientId: string) {
    const client = await this.#manager.store.findClient(clientId)
    if (!client) return null

    if (client.clientId !== clientId) {
      throw new E_INVALID_CLIENT('Client ID conflicts with a registered client')
    }

    return client
  }

  async #reload(clientId: string) {
    const client = await this.#findStoredClient(clientId)
    if (!client) throw new E_INVALID_CLIENT('Client not found')

    return client
  }

  /**
   * Insert or refresh the client row. A concurrent first insert for the
   * same URL loses on the unique `client_id` and falls back to an update,
   * unless the conflicting row belongs to another client id.
   * `isDisabled` is never touched so administrators keep their kill switch.
   */
  async #persist(options: {
    clientId: string
    client: ClientMetadataDocumentClient
    existing: OAuthClientRecord | null
  }) {
    const store = this.#manager.store

    if (options.existing) {
      await store.updateClient({ id: options.existing.id, data: options.client })

      return this.#reload(options.clientId)
    }

    try {
      return await store.createClient({
        id: crypto.randomUUID(),
        clientId: options.clientId,
        clientSecret: null,
        ...options.client,
        isPublic: true,
        isDisabled: false,
        requirePkce: true,
        type: 'public',
        userId: null,
      })
    } catch (error) {
      const concurrent = await this.#findStoredClient(options.clientId)
      if (!concurrent) throw error

      await store.updateClient({ id: concurrent.id, data: options.client })

      return this.#reload(options.clientId)
    }
  }

  /**
   * Resolve a `client_id` URL into a client. Reuses the stored client while
   * its document is fresh, otherwise fetches it again. Pass `persist: false`
   * for unauthenticated requests to validate without writing.
   */
  async resolve(options: { clientId: string; persist: boolean }): Promise<OAuthClientRecord> {
    const url = this.#parseClientId(options.clientId)

    const existing = await this.#findStoredClient(options.clientId)
    if (existing?.isDisabled) throw new E_INVALID_CLIENT('Client is disabled')
    if (existing && this.#isFresh(existing)) return existing

    const client = await this.#loadClient({ url, clientId: options.clientId })
    if (!options.persist) {
      return this.#transientClient({ clientId: options.clientId, client, existing })
    }

    return this.#persist({ clientId: options.clientId, client, existing })
  }
}
