import { createHash } from 'node:crypto'
import { importJWK, SignJWT, type JWK, type CryptoKey } from 'jose'

/**
 * Manages the RSA keys used to sign ID tokens and JWT access tokens.
 * Signs with the current key and publishes it in the JWKS together
 * with previous keys, which stay verifiable during a key rotation.
 *
 * ```ts
 * new KeyService(currentJwk, [previousJwk])
 * ```
 */
export class KeyService {
  #privateKey: CryptoKey | null = null
  #publicJwks: JWK[]
  #kid: string
  #jwk: JWK

  constructor(jwk: JWK, previousJwks: JWK[] = []) {
    this.#jwk = jwk
    this.#publicJwks = [jwk, ...previousJwks].map((key) => KeyService.#toPublicJwk(key))
    this.#kid = this.#publicJwks[0].kid!

    const kids = new Set(this.#publicJwks.map((key) => key.kid))
    if (kids.size !== this.#publicJwks.length) {
      throw new Error('Sesame signing keys must have distinct `kid` values')
    }
  }

  /**
   * Compute a `kid` from public key components (SHA-256, base64url).
   * Same approach as node-oidc-provider.
   */
  static computeKid(jwk: JWK): string {
    const components = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })

    return createHash('sha256').update(components).digest('base64url')
  }

  static #toPublicJwk(jwk: JWK): JWK {
    const kid = jwk.kid ?? KeyService.computeKid(jwk)

    return { kty: jwk.kty, n: jwk.n, e: jwk.e, kid, use: 'sig', alg: 'RS256' }
  }

  async #getPrivateKey(): Promise<CryptoKey> {
    if (this.#privateKey) return this.#privateKey
    this.#privateKey = (await importJWK(this.#jwk, 'RS256')) as CryptoKey

    return this.#privateKey
  }

  /**
   * Sign a JWT with the current key. `typ` defaults to `JWT`; access
   * tokens use `at+jwt` (RFC 9068 §2.1) so they cannot be mistaken
   * for ID tokens.
   */
  async sign(payload: Record<string, unknown>, typ = 'JWT'): Promise<string> {
    const key = await this.#getPrivateKey()

    return new SignJWT(payload).setProtectedHeader({ alg: 'RS256', kid: this.#kid, typ }).sign(key)
  }

  /**
   * Public JWKS: the current key first, then previous keys.
   */
  getPublicJwks(): { keys: JWK[] } {
    return { keys: this.#publicJwks }
  }

  /**
   * `kid` of the current signing key.
   */
  get kid(): string {
    return this.#kid
  }
}
