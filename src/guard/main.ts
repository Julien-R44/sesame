import type { HttpContext } from '@adonisjs/core/http'
import { symbols } from '@adonisjs/auth'
import type { GuardConfigProvider } from '@adonisjs/auth/types'
import type { EmitterLike } from '@adonisjs/core/types/events'
import { OAuthGuard } from './guard.ts'
import type { OAuthGuardEvents, OAuthGuardOptions, OAuthUserProviderContract } from './types.ts'

export { OAuthGuard } from './guard.ts'
export type {
  OAuthAuthenticateAsClientOptions,
  OAuthAuthenticateOptions,
  OAuthGuardAccessToken,
  OAuthGuardUser,
  OAuthGuardEvents,
  OAuthGuardOptions,
  OAuthUserProviderContract,
} from './types.ts'

/**
 * Configure the OAuth guard for `@adonisjs/auth`.
 *
 * Set `resource` on guards protecting an MCP server (or any resource
 * registered with `registerProtectedResource()`) so tokens issued for
 * another resource are rejected.
 */
export function oauthGuard<UserProvider extends OAuthUserProviderContract<unknown>>(
  config: OAuthGuardOptions & { provider: UserProvider }
): GuardConfigProvider<(ctx: HttpContext) => OAuthGuard<UserProvider>> {
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
          { resource: config.resource, requireAudience: config.requireAudience }
        )
    },
  }
}
