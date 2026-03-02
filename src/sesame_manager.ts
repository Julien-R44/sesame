import { DateTime } from 'luxon'
import type { ResolvedSesameConfig } from './types.ts'
import { OAuthAccessToken } from './models/oauth_access_token.ts'
import { OAuthRefreshToken } from './models/oauth_refresh_token.ts'
import { OAuthAuthorizationCode } from './models/oauth_authorization_code.ts'
import { OAuthConsent } from './models/oauth_consent.ts'

export interface PurgeResult {
  accessTokens: number
  refreshTokens: number
  authorizationCodes: number
}

/**
 * Central manager for the Sésame OAuth 2.1 server.
 *
 * Holds the resolved configuration. Registered as a singleton
 * in the AdonisJS IoC container by `SesameProvider`.
 */
export class SesameManager {
  #config: ResolvedSesameConfig

  constructor(config: ResolvedSesameConfig) {
    this.#config = config
  }

  get config() {
    return this.#config
  }

  /**
   * Check if a scope is registered in the server configuration.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
   */
  hasScope(scope: string): boolean {
    return scope in this.#config.scopes
  }

  /**
   * Return the list of scopes that are not registered in the
   * server configuration. When no scopes are configured, all
   * requested scopes are considered unknown per RFC 6749 §3.3
   * (`invalid_scope` — "The requested scope is invalid, unknown,
   * or malformed").
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
   */
  validateScopes(scopes: string[]): string[] {
    if (Object.keys(this.#config.scopes).length === 0) return scopes

    return scopes.filter((s) => !this.hasScope(s))
  }

  /**
   * Check if a grant type is enabled in the server configuration.
   */
  isGrantTypeEnabled(grantType: string): boolean {
    return this.#config.grantTypes.includes(grantType as any)
  }

  /**
   * Revoke all OAuth artifacts for a given user.
   *
   * Call this when a user is deleted or deactivated to ensure
   * none of their tokens remain usable. Revokes access tokens
   * and refresh tokens, and deletes authorization codes and
   * consent records.
   */
  async revokeAllForUser(userId: string): Promise<void> {
    const now = DateTime.now()

    await OAuthAccessToken.query()
      .where('userId', userId)
      .whereNull('revokedAt')
      .update({ revokedAt: now.toSQL() })

    await OAuthRefreshToken.query()
      .where('userId', userId)
      .whereNull('revokedAt')
      .update({ revokedAt: now.toSQL() })

    await OAuthAuthorizationCode.query().where('userId', userId).delete()
    await OAuthConsent.query().where('userId', userId).delete()
  }

  /**
   * Purge revoked and/or expired tokens and authorization codes.
   *
   * Returns the total number of deleted records. Expired tokens are
   * retained for `retentionHours` (default 168 = 7 days) to allow
   * for debugging and audit trails.
   *
   * Inspired by Laravel Passport's `passport:purge` command.
   */
  async purgeTokens(options?: {
    revokedOnly?: boolean
    expiredOnly?: boolean
    retentionHours?: number
  }): Promise<PurgeResult> {
    const revokedOnly = options?.revokedOnly ?? false
    const expiredOnly = options?.expiredOnly ?? false
    const retentionHours = options?.retentionHours ?? 168
    const purgeRevoked = revokedOnly || !expiredOnly
    const purgeExpired = expiredOnly || !revokedOnly
    const cutoff = DateTime.now().minus({ hours: retentionHours })

    let accessTokens = 0
    let refreshTokens = 0
    let authorizationCodes = 0

    if (purgeRevoked) {
      accessTokens += await this.#deleteCount(
        OAuthAccessToken.query().whereNotNull('revokedAt').delete()
      )
      refreshTokens += await this.#deleteCount(
        OAuthRefreshToken.query().whereNotNull('revokedAt').delete()
      )
    }

    if (purgeExpired) {
      accessTokens += await this.#deleteCount(
        OAuthAccessToken.query()
          .where('expiresAt', '<', cutoff.toSQL()!)
          .whereNull('revokedAt')
          .delete()
      )
      refreshTokens += await this.#deleteCount(
        OAuthRefreshToken.query()
          .where('expiresAt', '<', cutoff.toSQL()!)
          .whereNull('revokedAt')
          .delete()
      )
      authorizationCodes += await this.#deleteCount(
        OAuthAuthorizationCode.query().where('expiresAt', '<', cutoff.toSQL()!).delete()
      )
    }

    return { accessTokens, refreshTokens, authorizationCodes }
  }

  #deleteCount(result: Promise<unknown>): Promise<number> {
    return result.then((r) => (Array.isArray(r) ? Number(r[0] ?? 0) : Number(r)))
  }

  /**
   * Parse a duration string like '1h', '30m', '10d' into seconds.
   * Supported units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days).
   */
  parseTtl(ttl: string): number {
    const match = ttl.match(/^(\d+)(s|m|h|d)$/)
    if (!match) throw new Error(`Invalid TTL format: ${ttl}`)

    const value = Number.parseInt(match[1], 10)
    const unitMap: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 }

    return value * unitMap[match[2]]
  }
}
