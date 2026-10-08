/**
 * Parameters of a `Bearer` challenge sent in the `WWW-Authenticate` header.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3
 * @see https://datatracker.ietf.org/doc/html/rfc9728#section-5.1
 */
export interface BearerChallenge {
  resourceMetadata?: string
  scopes?: string[]
  error?: string
  errorDescription?: string
}

/**
 * Escape a value for an HTTP quoted-string (RFC 9110 §5.6.4).
 */
function quote(value: string): string {
  return `"${value.replace(/["\\]/g, '\\$&')}"`
}

/**
 * Serialize a `Bearer` challenge. Empty parameters are omitted,
 * including an empty scope list.
 */
export function buildBearerChallenge(challenge: BearerChallenge): string {
  const params = [
    ['resource_metadata', challenge.resourceMetadata],
    ['scope', challenge.scopes?.length ? challenge.scopes.join(' ') : undefined],
    ['error', challenge.error],
    ['error_description', challenge.errorDescription],
  ].filter((param): param is [string, string] => Boolean(param[1]))

  if (!params.length) return 'Bearer'

  return `Bearer ${params.map(([name, value]) => `${name}=${quote(value)}`).join(', ')}`
}

/**
 * Merge scope lists, preserving first-seen order and dropping duplicates.
 */
export function mergeScopes(...lists: string[][]): string[] {
  return [...new Set(lists.flat())]
}
