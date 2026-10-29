import { createHash, randomBytes, randomUUID } from 'node:crypto'
import string from '@adonisjs/core/helpers/string'
import { RESERVED_ACCESS_TOKEN_CLAIMS, type AccessTokenClaimsContext } from '../types.ts'
import type { SesameManager } from '../sesame_manager.ts'

export interface CreateAccessTokenOptions extends AccessTokenClaimsContext {
  expiresAt: Date
}

/**
 * Handles token generation for access tokens, refresh tokens,
 * and authorization codes.
 *
 * Refresh tokens and codes are random opaque values. Access tokens are
 * opaque too, or RFC 9068 JWTs with `accessTokenFormat: 'jwt'`. Only
 * SHA-256 hashes are stored in the database, so the raw tokens cannot
 * be reconstructed from a database leak.
 */
export class TokenService {
  #manager: SesameManager

  constructor(manager: SesameManager) {
    this.#manager = manager
  }

  /**
   * Expiration date of an access token issued now. Computed before the
   * token itself, since the grant it belongs to is extended to it.
   */
  accessTokenExpiresAt(ttl = this.#manager.config.accessTokenTtl): Date {
    return new Date(Date.now() + string.seconds.parse(ttl) * 1000)
  }

  /**
   * Create an access token. Returns the raw token (sent to the
   * client), its SHA-256 hash (stored in DB), its expiration date, and
   * the resource to store with it. RFC 9068 requires `aud` on JWT access
   * tokens, so an unbound JWT is bound to the issuer, and that audience
   * is stored so guards and introspection agree with the signed claim.
   * Unbound opaque tokens stay unbound.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9068#section-3
   */
  async createAccessToken(
    options: CreateAccessTokenOptions
  ): Promise<{ raw: string; hash: string; expiresAt: Date; resource: string | null }> {
    if (this.#manager.config.accessTokenFormat !== 'jwt') {
      const raw = this.generateOpaqueToken()
      return {
        raw,
        hash: this.hashToken(raw),
        expiresAt: options.expiresAt,
        resource: options.resource,
      }
    }

    const resource = options.resource ?? this.#manager.resourceIdentifier()
    const raw = await this.#signAccessToken(options, resource)

    return { raw, hash: this.hashToken(raw), expiresAt: options.expiresAt, resource }
  }

  /**
   * Create an opaque refresh token. Returns the raw token
   * (sent to the client) and its SHA-256 hash (stored in DB).
   */
  createRefreshToken(): { raw: string; hash: string } {
    const raw = this.generateOpaqueToken()
    return { raw, hash: this.hashToken(raw) }
  }

  /**
   * Generate a cryptographically random opaque token
   * (32 bytes, base64url-encoded).
   */
  generateOpaqueToken(): string {
    return randomBytes(32).toString('base64url')
  }

  /**
   * Sign an RFC 9068 access token for `audience`. The hook gets a copy
   * of the context, so it cannot change the protocol claims.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9068#section-2.2
   */
  async #signAccessToken(options: CreateAccessTokenOptions, audience: string): Promise<string> {
    const { expiresAt, ...context } = options
    const extraClaims =
      (await this.#manager.config.accessTokenClaims?.({
        ...context,
        scopes: [...context.scopes],
      })) ?? {}
    const now = Math.floor(Date.now() / 1000)

    const payload: Record<string, unknown> = {
      ...Object.fromEntries(
        Object.entries(extraClaims).filter(([key]) => !RESERVED_ACCESS_TOKEN_CLAIMS.has(key))
      ),
      iss: this.#manager.config.issuer,
      sub: context.userId,
      client_id: context.clientId,
      scope: context.scopes.join(' '),
      iat: now,
      exp: Math.floor(expiresAt.getTime() / 1000),
      jti: randomUUID(),
      aud: audience,
    }

    return this.#manager.keyService.sign(payload, 'at+jwt')
  }

  /**
   * SHA-256 hash a token value for secure storage.
   * All tokens (codes, access tokens, refresh tokens) are stored
   * as hashes so raw values cannot be reconstructed from a DB leak.
   */
  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('base64url')
  }
}
