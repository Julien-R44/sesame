import type { HttpContext } from '@adonisjs/core/http'
import { symbols } from '@adonisjs/auth'
import type { GuardConfigProvider } from '@adonisjs/auth/types'
import type { EmitterLike } from '@adonisjs/core/types/events'
import type { LucidModel } from '@adonisjs/lucid/types/model'
import { OAuthGuard } from './guard.ts'
import { OAuthLucidUserProvider } from './user_provider.ts'
import type {
  OAuthGuardEvents,
  OAuthLucidUserProviderOptions,
  OAuthUserProviderContract,
} from './types.ts'

export { OAuthGuard } from './guard.ts'
export { OAuthLucidUserProvider } from './user_provider.ts'
export type {
  OAuthGuardUser,
  OAuthGuardEvents,
  OAuthUserProviderContract,
  OAuthLucidUserProviderOptions,
} from './types.ts'

/**
 * Configure the OAuth guard for `@adonisjs/auth`.
 */
export function oauthGuard<UserProvider extends OAuthUserProviderContract<unknown>>(config: {
  provider: UserProvider
}): GuardConfigProvider<(ctx: HttpContext) => OAuthGuard<UserProvider>> {
  return {
    async resolver(name, app) {
      const emitter = await app.container.make('emitter')
      const { SesameManager } = await import('../sesame_manager.ts')
      const manager = await app.container.make(SesameManager)

      return (ctx) =>
        new OAuthGuard(
          name,
          ctx,
          emitter as EmitterLike<OAuthGuardEvents<UserProvider[typeof symbols.PROVIDER_REAL_USER]>>,
          config.provider,
          manager
        )
    },
  }
}

/**
 * Create a Lucid-based user provider for the OAuth guard.
 */
export function oauthUserProvider<Model extends LucidModel>(
  options: OAuthLucidUserProviderOptions<Model>
): OAuthLucidUserProvider<Model> {
  return new OAuthLucidUserProvider(options)
}
