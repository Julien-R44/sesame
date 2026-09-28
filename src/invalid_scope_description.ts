import { OIDC_SCOPES } from './types.ts'

/**
 * Explain invalid scopes, including OIDC scopes requested without openid.
 */
export function describeInvalidScopes(invalidScopes: string[]): string {
  const description = `Invalid scopes: ${invalidScopes.join(', ')}`
  const oidcScopes = invalidScopes.filter((scope) => OIDC_SCOPES.has(scope))
  if (!oidcScopes.length) return description

  return `${description}. OIDC scopes (${oidcScopes.join(', ')}) require the openid scope`
}
