import type { HttpContext } from '@adonisjs/core/http'
import { symbols } from '@adonisjs/auth'
import type { GuardConfigProvider } from '@adonisjs/auth/types'
import type { EmitterLike } from '@adonisjs/core/types/events'
import { OAuthGuard } from './guard.ts'
import type { OAuthGuardEvents, OAuthUserProviderContract } from './types.ts'

export { OAuthGuard } from './guard.ts'
export type { OAuthGuardUser, OAuthGuardEvents, OAuthUserProviderContract } from './types.ts'

/**
 * Configure the OAuth guard for `@adonisjs/auth`.
 */
export function oauthGuard<UserProvider extends OAuthUserProviderContract<unknown>>(config: {
  provider: UserProvider
  resource?: string
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
          manager,
          config.resource
        )
    },
  }
}
