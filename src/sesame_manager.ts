import type { ResolvedSesameConfig } from './types.ts'
import { KeyService } from './services/key_service.ts'

/**
 * Central manager for the Sésame OAuth 2.1 server.
 *
 * Holds the resolved configuration and lazily initializes the
 * KeyService for JWK management. Registered as a singleton in
 * the AdonisJS IoC container by `SesameProvider`.
 */
export class SesameManager {
  #config: ResolvedSesameConfig
  #keyService: KeyService | null = null

  constructor(config: ResolvedSesameConfig) {
    this.#config = config
  }

  get config() {
    return this.#config
  }

  /**
   * Lazily initialized KeyService for JWK/JWKS operations.
   * The key service handles RS256 key pair generation, storage,
   * and retrieval for JWT signing and verification.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc7517
   */
  get keyService(): KeyService {
    if (!this.#keyService) {
      this.#keyService = new KeyService(this.#config.jwksPath)
    }

    return this.#keyService
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
   * server configuration. Returns an empty array when no scopes
   * are configured (open scope policy).
   */
  validateScopes(scopes: string[]): string[] {
    if (Object.keys(this.#config.scopes).length === 0) return scopes

    const invalid = scopes.filter((s) => !this.hasScope(s))
    return invalid
  }

  /**
   * Check if a grant type is enabled in the server configuration.
   */
  isGrantTypeEnabled(grantType: string): boolean {
    return this.#config.grantTypes.includes(grantType as any)
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
