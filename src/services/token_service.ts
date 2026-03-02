import * as jose from 'jose'
import { createHash, randomBytes } from 'node:crypto'
import type { SesameManager } from '../sesame_manager.ts'

/**
 * Options for creating a JWT access token.
 */
export interface CreateAccessTokenOptions {
  userId?: string | number
  clientId: string
  scopes: string[]
}

/**
 * Options for creating a refresh token.
 */
export interface CreateRefreshTokenOptions {
  userId: string | number
  clientId: string
  scopes: string[]
  accessTokenJti: string
}

/**
 * Decoded JWT access token payload structure.
 *
 * Follows the JWT Access Token Profile (RFC 9068) with:
 * - `sub`: resource owner identifier
 * - `azp`: authorized party (client_id)
 * - `scope`: space-delimited scope string
 * - `jti`: unique token identifier
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9068#section-2.2
 */
export interface AccessTokenPayload {
  sub?: string
  azp: string
  scope: string
  jti: string
  iss: string
  iat: number
  exp: number
}

/**
 * Handles JWT access token creation/verification and opaque
 * token generation for refresh tokens and authorization codes.
 *
 * Access tokens are signed JWTs following the JWT Access Token
 * Profile (RFC 9068), using RS256 with keys from the KeyService.
 *
 * Refresh tokens and authorization codes are opaque random values.
 * Only their SHA-256 hashes are stored in the database, so the
 * raw tokens cannot be reconstructed from a database leak.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9068
 * @see https://datatracker.ietf.org/doc/html/rfc7519
 */
export class TokenService {
  #manager: SesameManager

  constructor(manager: SesameManager) {
    this.#manager = manager
  }

  /**
   * Create and sign a JWT access token using RS256.
   *
   * The JWT includes standard claims (`iss`, `sub`, `iat`, `exp`, `jti`)
   * plus `azp` (authorized party / client_id) and `scope`.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9068#section-2.2
   */
  async createJwtAccessToken(options: CreateAccessTokenOptions): Promise<{
    token: string
    jti: string
    expiresAt: Date
  }> {
    const keyService = this.#manager.keyService
    const privateKey = await keyService.getPrivateKey()
    const kid = await keyService.getKid()
    const ttlSeconds = this.#manager.parseTtl(this.#manager.config.accessTokenTtl)
    const jti = this.generateOpaqueToken()
    const now = Math.floor(Date.now() / 1000)

    const jwt = await new jose.SignJWT({
      azp: options.clientId,
      scope: options.scopes.join(' '),
    })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuedAt(now)
      .setExpirationTime(now + ttlSeconds)
      .setIssuer(this.#manager.config.issuer)
      .setJti(jti)
      .setSubject(options.userId != null ? String(options.userId) : '')
      .sign(privateKey)

    return {
      token: jwt,
      jti,
      expiresAt: new Date((now + ttlSeconds) * 1000),
    }
  }

  /**
   * Verify a JWT access token's signature and standard claims
   * (issuer, algorithm, expiration).
   */
  async verifyJwtAccessToken(token: string): Promise<AccessTokenPayload> {
    const publicKey = await this.#manager.keyService.getPublicKey()

    const { payload } = await jose.jwtVerify(token, publicKey, {
      issuer: this.#manager.config.issuer,
      algorithms: ['RS256'],
    })

    return payload as unknown as AccessTokenPayload
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
   * All tokens (codes, refresh tokens) are stored as hashes
   * so raw values cannot be reconstructed from a DB leak.
   */
  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('base64url')
  }
}
