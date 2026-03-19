import { createHash } from 'node:crypto'
import string from '@adonisjs/core/helpers/string'
import { RESERVED_OIDC_CLAIMS } from '../types.ts'
import type { SesameManager } from '../sesame_manager.ts'

/**
 * Builds and signs OIDC `id_token` JWTs.
 */
export class IdTokenService {
  #manager: SesameManager

  constructor(manager: SesameManager) {
    this.#manager = manager
  }

  /**
   * Compute `at_hash` — left half of SHA-256 hash of the access token, base64url-encoded.
   * @see OIDC Core §3.1.3.6
   */
  static computeAtHash(accessToken: string): string {
    const hash = createHash('sha256').update(accessToken).digest()

    return hash.subarray(0, hash.length / 2).toString('base64url')
  }

  /**
   * Filter out reserved claims that the server owns.
   */
  static filterReservedClaims(claims: Record<string, unknown>): Record<string, unknown> {
    const filtered: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(claims)) {
      if (!RESERVED_OIDC_CLAIMS.has(key)) filtered[key] = value
    }

    return filtered
  }

  /**
   * Resolve user OIDC claims by calling `getOidcClaims` if present,
   * then filtering out reserved protocol claims.
   */
  static async resolveUserClaims(
    user: unknown,
    scopes: string[]
  ): Promise<Record<string, unknown>> {
    const rawClaims =
      typeof (user as any)?.getOidcClaims === 'function'
        ? await (user as any).getOidcClaims(scopes)
        : {}

    return IdTokenService.filterReservedClaims(rawClaims)
  }

  async sign(options: {
    sub: string
    clientId: string
    scopes: string[]
    accessToken: string
    user: unknown
    nonce?: string
  }): Promise<string> {
    const now = Math.floor(Date.now() / 1000)
    const ttlSeconds = string.seconds.parse(this.#manager.config.idTokenTtl)

    const userClaims = await IdTokenService.resolveUserClaims(options.user, options.scopes)

    const payload: Record<string, unknown> = {
      ...userClaims,
      iss: this.#manager.config.issuer,
      sub: String(options.sub),
      aud: options.clientId,
      iat: now,
      exp: now + ttlSeconds,
      at_hash: IdTokenService.computeAtHash(options.accessToken),
    }

    if (options.nonce) payload.nonce = options.nonce

    return this.#manager.keyService.sign(payload)
  }
}
