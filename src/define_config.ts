import { InvalidArgumentsException } from '@adonisjs/core/exceptions'
import { normalizeResourceIndicator } from './resource_indicators.ts'
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
 * Normalize external resource identifiers, rejecting invalid ones at boot
 * rather than when a client first requests them.
 */
function resolveExternalResources(resources: string[] = []): string[] {
  return resources.map((resource) => {
    const normalized = normalizeResourceIndicator(resource)
    if (!normalized) {
      throw new InvalidArgumentsException(
        `Invalid external resource "${resource}": use an absolute http(s) URI without a fragment`
      )
    }

    return normalized
  })
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
 * - `previousJwks`: `[]`
 * - `accessTokenFormat`: `'opaque'`
 */
export function defineConfig<const TScopes extends Record<string, string>>(
  config: Omit<SesameConfig, 'scopes' | 'defaultScopes'> & {
    scopes?: TScopes
    defaultScopes?: Array<Extract<keyof TScopes, string>>
  }
): Omit<ResolvedSesameConfig, 'scopes'> & { scopes: TScopes } {
  if (!config.store) throw new InvalidArgumentsException('Missing "store" in Sesame config')
  if (config.accessTokenFormat === 'jwt' && !config.jwk) {
    throw new InvalidArgumentsException('"accessTokenFormat: jwt" requires "jwk" in Sesame config')
  }
  if (config.previousJwks?.length && !config.jwk) {
    throw new InvalidArgumentsException('"previousJwks" requires "jwk" in Sesame config')
  }

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
    previousJwks: config.previousJwks ?? [],
    oidcProvider: config.oidcProvider,
    idTokenTtl: config.idTokenTtl ?? '1h',
    accessTokenFormat: config.accessTokenFormat ?? 'opaque',
    accessTokenClaims: config.accessTokenClaims,
    externalResources: resolveExternalResources(config.externalResources),
  } as Omit<ResolvedSesameConfig, 'scopes'> & { scopes: TScopes }
}
