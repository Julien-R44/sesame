import { createHash, randomBytes } from 'node:crypto'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'

/**
 * Handles opaque token generation for access tokens, refresh tokens,
 * and authorization codes.
 *
 * All tokens are random opaque values. Only their SHA-256 hashes
 * are stored in the database, so the raw tokens cannot be
 * reconstructed from a database leak.
 */
export class TokenService {
  #manager: SesameManager

  constructor(manager: SesameManager) {
    this.#manager = manager
  }

  /**
   * Create an opaque access token. Returns the raw token
   * (sent to the client), its SHA-256 hash (stored in DB),
   * and the computed expiration date.
   */
  createAccessToken(): { raw: string; hash: string; expiresAt: Date } {
    const raw = this.generateOpaqueToken()
    const ttlSeconds = string.seconds.parse(this.#manager.config.accessTokenTtl)

    return {
      raw,
      hash: this.hashToken(raw),
      expiresAt: new Date(Date.now() + ttlSeconds * 1000),
    }
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
   * SHA-256 hash a token value for secure storage.
   * All tokens (codes, access tokens, refresh tokens) are stored
   * as hashes so raw values cannot be reconstructed from a DB leak.
   */
  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('base64url')
  }
}
