import type { ApplicationService } from '@adonisjs/core/types'
import { SesameManager } from '../src/sesame_manager.ts'
import type { ResolvedSesameConfig } from '../src/types.ts'

/**
 * AdonisJS service provider for the Sésame OAuth 2.1 server.
 *
 * - `register()`: Binds `SesameManager` as a singleton in the IoC
 *   container, reading the resolved config from `config/sesame.ts`.
 * - `boot()`: Registers all OAuth routes on the AdonisJS router.
 */
export default class SesameProvider {
  constructor(protected app: ApplicationService) {}

  /**
   * Register `SesameManager` as a singleton binding.
   * The manager is resolved from the `sesame` config key.
   */
  register() {
    this.app.container.singleton(SesameManager, () => {
      const config = this.app.config.get<ResolvedSesameConfig>('sesame')
      return new SesameManager(config)
    })
  }

  /**
   * Boot the provider by registering all OAuth 2.1 routes.
   */
  async boot() {
    const router = await this.app.container.make('router')
    const { registerRoutes } = await import('../src/routes.ts')

    registerRoutes(router)
  }
}
