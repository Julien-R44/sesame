/// <reference types="@adonisjs/auth/initialize_auth_middleware" />

import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import type { Scope } from '../types.ts'
import type { OAuthGuard } from '../guard/guard.ts'
import { E_INSUFFICIENT_SCOPE } from '../oauth_error.ts'

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
    await guard.authenticate()

    if (!guard.hasAnyScope(...options.scopes)) throw new E_INSUFFICIENT_SCOPE(options.scopes)

    return next()
  }
}
