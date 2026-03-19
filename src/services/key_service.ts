import { createHash } from 'node:crypto'
import { importJWK, SignJWT, type JWK, type CryptoKey } from 'jose'

/**
 * Manages the RSA key pair used to sign ID tokens.
 * Accepts a JWK from config, caches the imported private key
 * and public JWK for JWKS export.
 */
export class KeyService {
  #privateKey: CryptoKey | null = null
  #publicJwk: JWK
  #kid: string
  #jwk: JWK

  constructor(jwk: JWK) {
    this.#jwk = jwk
    this.#kid = jwk.kid ?? KeyService.computeKid(jwk)
    this.#publicJwk = { kty: jwk.kty, n: jwk.n, e: jwk.e, kid: this.#kid, use: 'sig', alg: 'RS256' }
  }

  /**
   * Compute a `kid` from public key components (SHA-256, base64url).
   * Same approach as node-oidc-provider.
   */
  static computeKid(jwk: JWK): string {
    const components = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })

    return createHash('sha256').update(components).digest('base64url')
  }

  async #getPrivateKey(): Promise<CryptoKey> {
    if (this.#privateKey) return this.#privateKey
    this.#privateKey = (await importJWK(this.#jwk, 'RS256')) as CryptoKey

    return this.#privateKey
  }

  async sign(payload: Record<string, unknown>): Promise<string> {
    const key = await this.#getPrivateKey()

    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: this.#kid, typ: 'JWT' })
      .sign(key)
  }

  getPublicJwks(): { keys: JWK[] } {
    return { keys: [this.#publicJwk] }
  }

  get kid(): string {
    return this.#kid
  }
}
