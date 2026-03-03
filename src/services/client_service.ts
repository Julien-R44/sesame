import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { E_INVALID_REQUEST, E_INVALID_SCOPE } from '../oauth_error.ts'

/**
 * Extracted client credentials from a request.
 */
export interface ClientCredentials {
  clientId: string
  clientSecret?: string
}

/**
 * Handles OAuth client authentication and credential management.
 *
 * Supports the client authentication methods defined in RFC 6749 §2.3:
 * - `client_secret_basic`: HTTP Basic auth with client_id:client_secret
 * - `client_secret_post`: credentials in the request body
 * - `none`: public clients (no secret)
 *
 * Client secrets are stored as SHA-256 hashes and compared using
 * timing-safe equality to prevent timing attacks.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
 */
export class ClientService {
  /**
   * Parse an HTTP Basic Authorization header into client credentials.
   * Follows RFC 6749 §2.3.1 — the client_id and client_secret are
   * URL-decoded after base64 decoding.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
   */
  parseBasicAuth(header: string): ClientCredentials | null {
    if (!header.startsWith('Basic ')) return null

    try {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf-8')
      const colonIndex = decoded.indexOf(':')
      if (colonIndex === -1) return null

      return {
        clientId: decodeURIComponent(decoded.slice(0, colonIndex)),
        clientSecret: decodeURIComponent(decoded.slice(colonIndex + 1)),
      }
    } catch {
      return null
    }
  }

  /**
   * Extract client credentials from a request. Checks the
   * Authorization header first (Basic auth), then falls back
   * to POST body parameters (`client_id` / `client_secret`).
   */
  extractCredentials(options: {
    authorizationHeader?: string
    bodyClientId?: string
    bodyClientSecret?: string
  }): ClientCredentials | null {
    const basic = options.authorizationHeader
      ? this.parseBasicAuth(options.authorizationHeader)
      : null

    if (basic && options.bodyClientId) {
      throw new E_INVALID_REQUEST('Multiple client authentication methods are not allowed')
    }

    if (basic) return basic

    if (options.bodyClientId) {
      return {
        clientId: options.bodyClientId,
        clientSecret: options.bodyClientSecret,
      }
    }

    return null
  }

  /**
   * Validate that requested scopes are within the client's
   * allowed scopes. Throws `E_INVALID_SCOPE` if any scope
   * is not permitted. An empty `clientScopes` array means the
   * client has no scope permissions (RFC 6749 §2, §3.3).
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
   */
  validateClientScopes(requestedScopes: string[], clientScopes: string[]): void {
    if (clientScopes.length === 0 && requestedScopes.length > 0) {
      throw new E_INVALID_SCOPE(`Scope not allowed: ${requestedScopes.join(', ')}`)
    }

    const allowedSet = new Set(clientScopes)
    const invalid = requestedScopes.filter((s) => !allowedSet.has(s))
    if (invalid.length > 0) {
      throw new E_INVALID_SCOPE(`Scope not allowed: ${invalid.join(', ')}`)
    }
  }

  /**
   * Hash a client secret for storage using SHA-256
   * (base64url-encoded).
   */
  hashSecret(secret: string): string {
    return createHash('sha256').update(secret).digest('base64url')
  }

  /**
   * Verify a client secret against its stored hash using
   * timing-safe comparison to prevent timing attacks.
   */
  verifySecret(secret: string, storedHash: string): boolean {
    const hash = this.hashSecret(secret)

    try {
      return timingSafeEqual(Buffer.from(hash), Buffer.from(storedHash))
    } catch {
      return false
    }
  }

  /**
   * Generate a random client ID (16 bytes, hex-encoded).
   */
  generateClientId(): string {
    return randomBytes(16).toString('hex')
  }

  /**
   * Generate a random client secret (32 bytes, base64url-encoded).
   */
  generateClientSecret(): string {
    return randomBytes(32).toString('base64url')
  }
}
