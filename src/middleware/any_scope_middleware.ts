/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import type { Scope } from '../types.ts'
import type { OAuthGuard } from '../guard/guard.ts'

/**
 * Any-scope middleware requires ANY of the listed scopes on the
 * authenticated OAuth token. Throws 403 if none match.
 *
 * @example
 * router.get('/data', [DataController]).use(middleware.anyScope({ scopes: ['read', 'read-all'] }))
 */
export default class AnyScopeMiddleware {
  async handle(ctx: HttpContext, next: NextFn, options: { scopes: Scope[] }) {
    const guard = ctx.auth.use('oauth') as OAuthGuard<any>
    const challenge = { scopes: options.scopes, match: 'any' } as const

    // Fast path: OAuth guard already ran and succeeded
    if (guard.isAuthenticated) {
      if (!guard.hasAnyScope(...options.scopes)) throw guard.insufficientScopeError(options.scopes)
      return next()
    }

    // Bearer token present → OAuth flow with scope enforcement
    if (ctx.request.header('authorization')) {
      await guard.authenticate(challenge)
      if (!guard.hasAnyScope(...options.scopes)) throw guard.insufficientScopeError(options.scopes)
      return next()
    }

    // No Bearer token → session users bypass scope checks (TransientToken behavior)
    if (await ctx.auth.check()) return next()

    // No auth at all → 401 with WWW-Authenticate
    await guard.authenticate(challenge)
  }
}
