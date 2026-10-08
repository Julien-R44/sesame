import { isIP } from 'node:net'
import { E_INVALID_CLIENT } from '../oauth_error.ts'
import type { ResolvedSesameConfig } from '../types.ts'

/**
 * Matches the `oauth_clients.client_id` column size.
 */
export const MAX_CLIENT_ID_URL_LENGTH = 255

/**
 * URL schemes are case-insensitive, so `HTTPS://` must not bypass
 * the metadata document checks.
 */
const HTTPS_SCHEME = /^https:\/\//i

/**
 * Whether a `client_id` must be resolved through a Client ID Metadata
 * Document. Sésame-generated client ids are hex strings, so they never
 * start with `https://` (draft §7.1).
 */
export function isClientIdMetadataDocumentUrl(clientId: string) {
  return HTTPS_SCHEME.test(clientId)
}

/**
 * Gate every endpoint resolving a client: URL client ids are rejected
 * when the feature is disabled (even if a client row already exists) or
 * when their host is not in `allowedHosts`, so removing a host cuts its
 * refresh tokens, pending consents and client info as well.
 */
export function assertClientIdMetadataDocumentAllowed(options: {
  clientId: string
  config: ResolvedSesameConfig
}) {
  if (!isClientIdMetadataDocumentUrl(options.clientId)) return

  const config = options.config.clientIdMetadataDocuments
  if (!config) throw new E_INVALID_CLIENT('Client ID Metadata Documents are not supported')
  if (!URL.canParse(options.clientId))
    throw new E_INVALID_CLIENT('Client ID URL is not a valid URL')

  const { hostname } = new URL(options.clientId)
  if (isHostAllowed({ hostname, allowedHosts: config.allowedHosts })) return

  throw new E_INVALID_CLIENT('Client ID host is not allowed')
}

/**
 * Describe why a client identifier URL is invalid, or return null.
 *
 * The URL must be in canonical form (`new URL(id).href === id`), which
 * rules out dot segments, empty userinfo or ports, and uppercase hosts
 * since ids are compared as plain strings.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-3
 */
export function describeInvalidClientIdUrl(clientId: string): string | null {
  if (clientId.length > MAX_CLIENT_ID_URL_LENGTH) {
    return `Client ID URL must not exceed ${MAX_CLIENT_ID_URL_LENGTH} characters`
  }

  if (!URL.canParse(clientId)) return 'Client ID URL is not a valid URL'

  const url = new URL(clientId)
  const rules: Array<[boolean, string]> = [
    [url.protocol !== 'https:', 'Client ID URL must use the https scheme'],
    [!!url.username || !!url.password, 'Client ID URL must not contain userinfo'],
    [!!url.hash, 'Client ID URL must not contain a fragment'],
    [!!url.search, 'Client ID URL must not contain a query'],
    [url.pathname === '/', 'Client ID URL must contain a path'],
    [isIpLiteral(url.hostname), 'Client ID URL must use a domain name'],
    [url.href !== clientId, 'Client ID URL must be in canonical form'],
  ]

  const failed = rules.find(([invalid]) => invalid)

  return failed ? failed[1] : null
}

/**
 * Whether the host is an IPv4 or bracketed IPv6 literal.
 */
function isIpLiteral(hostname: string) {
  return hostname.startsWith('[') || isIP(hostname) !== 0
}

/**
 * Match a host against an allowlist of exact hosts or leftmost
 * wildcards (`*.example.com` matches subdomains only).
 */
export function isHostAllowed(options: { hostname: string; allowedHosts: string[] | null }) {
  if (!options.allowedHosts) return true

  const hostname = options.hostname.toLowerCase()

  return options.allowedHosts.some((allowed) => {
    if (!allowed.startsWith('*.')) return hostname === allowed

    return hostname.endsWith(allowed.slice(1))
  })
}
