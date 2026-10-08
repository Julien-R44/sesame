import { InvalidArgumentsException } from '@adonisjs/core/exceptions'
import type {
  ClientIdMetadataDocumentsConfig,
  ResolvedClientIdMetadataDocumentsConfig,
  SesameConfig,
  ResolvedSesameConfig,
} from './types.ts'

/**
 * Apply defaults to the Client ID Metadata Documents options.
 * Returns null when the feature is disabled.
 */
function resolveClientIdMetadataDocuments(
  config?: boolean | ClientIdMetadataDocumentsConfig
): ResolvedClientIdMetadataDocumentsConfig | null {
  if (!config) return null

  const options = config === true ? {} : config

  return {
    allowedHosts: options.allowedHosts?.map((host) => host.toLowerCase()) ?? null,
    cache: {
      minTtl: options.cache?.minTtl ?? '5m',
      maxTtl: options.cache?.maxTtl ?? '24h',
    },
    fetchTimeout: options.fetchTimeout ?? '5s',
    maxResponseSize: options.maxResponseSize ?? 5120,
  }
}

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
 * - `clientIdMetadataDocuments`: disabled
 */
export function defineConfig<const TScopes extends Record<string, string>>(
  config: Omit<SesameConfig, 'scopes' | 'defaultScopes'> & {
    scopes?: TScopes
    defaultScopes?: Array<Extract<keyof TScopes, string>>
  }
): Omit<ResolvedSesameConfig, 'scopes'> & { scopes: TScopes } {
  if (!config.store) throw new InvalidArgumentsException('Missing "store" in Sesame config')

  return {
    store: config.store,
    issuer: config.issuer,
    scopes: config.scopes ?? ({} as TScopes),
    defaultScopes: (config.defaultScopes ?? []) as string[],
    grantTypes: config.grantTypes ?? ['authorization_code', 'refresh_token'],
    accessTokenTtl: config.accessTokenTtl ?? '1h',
    clientCredentialsAccessTokenTtl:
      config.clientCredentialsAccessTokenTtl ?? config.accessTokenTtl ?? '1h',
    refreshTokenTtl: config.refreshTokenTtl ?? '30d',
    refreshTokenRotationGracePeriod: config.refreshTokenRotationGracePeriod ?? 120,
    authorizationCodeTtl: config.authorizationCodeTtl ?? '10m',
    authorizationRequestTtl: config.authorizationRequestTtl ?? config.authorizationCodeTtl ?? '10m',
    loginPage: config.loginPage,
    consentPage: config.consentPage,
    allowDynamicRegistration: config.allowDynamicRegistration ?? false,
    allowPublicRegistration: config.allowPublicRegistration ?? false,
    clientIdMetadataDocuments: resolveClientIdMetadataDocuments(config.clientIdMetadataDocuments),
    jwk: config.jwk,
    oidcProvider: config.oidcProvider,
    idTokenTtl: config.idTokenTtl ?? '1h',
  } as Omit<ResolvedSesameConfig, 'scopes'> & { scopes: TScopes }
}
