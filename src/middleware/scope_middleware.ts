/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import type { Scope } from '../types.ts'
import type { OAuthGuard } from '../guard/guard.ts'
import { E_INSUFFICIENT_SCOPE } from '../oauth_error.ts'

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
    await guard.authenticate()

    if (!guard.hasScope(...options.scopes)) throw new E_INSUFFICIENT_SCOPE(options.scopes)

    return next()
  }
}
