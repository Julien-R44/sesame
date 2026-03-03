import type { SesameConfig, ResolvedSesameConfig } from './types.ts'

/**
 * Resolve user-supplied `SesameConfig` into a `ResolvedSesameConfig`
 * by applying sensible defaults for all optional fields.
 *
 * Defaults:
 * - `scopes`: `{}`
 * - `defaultScopes`: `[]`
 * - `grantTypes`: `['authorization_code', 'refresh_token']`
 * - `accessTokenTtl`: `'1h'`
 * - `refreshTokenTtl`: `'30d'`
 * - `authorizationCodeTtl`: `'10m'`
 * - `allowDynamicRegistration`: `false`
 * - `allowPublicRegistration`: `false`
 */
export function defineConfig(config: SesameConfig): ResolvedSesameConfig {
  return {
    issuer: config.issuer,
    scopes: config.scopes ?? {},
    defaultScopes: config.defaultScopes ?? [],
    grantTypes: config.grantTypes ?? ['authorization_code', 'refresh_token'],
    accessTokenTtl: config.accessTokenTtl ?? '1h',
    refreshTokenTtl: config.refreshTokenTtl ?? '30d',
    authorizationCodeTtl: config.authorizationCodeTtl ?? '10m',
    authorizationRequestTtl: config.authorizationRequestTtl ?? config.authorizationCodeTtl ?? '10m',
    loginPage: config.loginPage,
    consentPage: config.consentPage,
    allowDynamicRegistration: config.allowDynamicRegistration ?? false,
    allowPublicRegistration: config.allowPublicRegistration ?? false,
  }
}
