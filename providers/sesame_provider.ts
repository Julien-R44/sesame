import type { ApplicationService } from '@adonisjs/core/types'
import { SesameManager } from '../src/sesame_manager.ts'
import { ClientMetadataDocumentResolutionCache } from '../src/client_id_metadata_documents/resolution_cache.ts'
import type { ResolvedSesameConfig } from '../src/types.ts'

/**
 * AdonisJS service provider for the Sésame OAuth 2.1 server.
 */
export default class SesameProvider {
  #app: ApplicationService

  constructor(app: ApplicationService) {
    this.#app = app
  }

  /**
   * Register `SesameManager` as a singleton binding.
   * The manager is resolved from the `sesame` config key.
   *
   * The Client ID Metadata Document resolution cache is a process-wide
   * singleton so anonymous resolutions are shared across requests.
   */
  register() {
    this.#app.container.singleton(SesameManager, async () => {
      const config = this.#app.config.get<ResolvedSesameConfig>('sesame')
      const router = await this.#app.container.make('router')
      const store = await config.store.resolver(this.#app)

      return new SesameManager(config, router, store)
    })

    this.#app.container.singleton(
      ClientMetadataDocumentResolutionCache,
      () => new ClientMetadataDocumentResolutionCache()
    )
  }
}
