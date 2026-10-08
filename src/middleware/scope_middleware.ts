/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import type { Scope } from '../types.ts'
import type { OAuthGuard } from '../guard/guard.ts'

/**
 * Scope middleware requires ALL listed scopes on the authenticated
 * OAuth token. Throws 403 if any scope is missing.
 *
 * @example
 * router.get('/admin', [AdminController]).use(middleware.scopes({ scopes: ['admin', 'manage'] }))
 */
export default class ScopeMiddleware {
  async handle(ctx: HttpContext, next: NextFn, options: { scopes: Scope[] }) {
    const guard = ctx.auth.use('oauth') as OAuthGuard<any>
    const challenge = { scopes: options.scopes, match: 'all' } as const

    // Fast path: OAuth guard already ran and succeeded
    if (guard.isAuthenticated) {
      if (!guard.hasScope(...options.scopes)) throw guard.insufficientScopeError(options.scopes)
      return next()
    }

    // Bearer token present → OAuth flow with scope enforcement
    if (ctx.request.header('authorization')) {
      await guard.authenticate(challenge)
      if (!guard.hasScope(...options.scopes)) throw guard.insufficientScopeError(options.scopes)
      return next()
    }

    // No Bearer token → session users bypass scope checks (TransientToken behavior)
    if (await ctx.auth.check()) return next()

    // No auth at all → 401 with WWW-Authenticate
    await guard.authenticate(challenge)
  }
}
