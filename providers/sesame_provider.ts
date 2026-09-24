import type { ApplicationService } from '@adonisjs/core/types'
import { SesameManager } from '../src/sesame_manager.ts'
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
   */
  register() {
    this.#app.container.singleton(SesameManager, async () => {
      const config = this.#app.config.get<ResolvedSesameConfig>('sesame')
      const router = await this.#app.container.make('router')
      const store = await config.store.resolver(this.#app)

      return new SesameManager(config, router, store)
    })
  }
}
