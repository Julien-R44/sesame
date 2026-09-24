import { configProvider } from '@adonisjs/core'
import type { ApplicationService, ConfigProvider } from '@adonisjs/core/types'
import type { Kysely } from 'kysely'
import type { SesameStore } from './storage/types.ts'
import type { KyselyDialect } from './storage/drivers/kysely.ts'

export interface KyselyStoreConfig<DB> {
  connection: Kysely<DB> | ((app: ApplicationService) => Kysely<DB> | Promise<Kysely<DB>>)
  dialect?: KyselyDialect
}

/**
 * Store driver factories resolved by the AdonisJS service provider.
 */
export const stores = {
  /**
   * Use the application's Lucid connection for OAuth persistence.
   */
  lucid(): ConfigProvider<SesameStore> {
    return configProvider.create(async (app) => {
      await app.container.make('lucid.db')
      const { lucidStore } = await import('./storage/drivers/lucid.ts')

      return lucidStore()
    })
  },

  /**
   * Use an existing Kysely connection for OAuth persistence.
   */
  kysely<DB>(options: KyselyStoreConfig<DB>): ConfigProvider<SesameStore> {
    return configProvider.create(async (app) => {
      const connection =
        typeof options.connection === 'function'
          ? await options.connection(app)
          : options.connection
      const { kyselyStore } = await import('./storage/drivers/kysely.ts')

      return kyselyStore({ db: connection, dialect: options.dialect })
    })
  },
}
