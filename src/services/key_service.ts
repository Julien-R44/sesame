import * as jose from 'jose'
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { dirname } from 'node:path'

/**
 * Shape of the key set stored on disk as a JWK Set (RFC 7517 §5).
 */
interface StoredKeySet {
  keys: jose.JWK[]
}

/**
 * Manages RS256 key pairs for JWT signing and verification.
 *
 * Keys are stored on disk as a JWK Set (RFC 7517 §5) and lazily
 * loaded on first use. If no key file exists, a new 2048-bit RSA
 * key pair is automatically generated.
 *
 * The public portion of the key is exposed via the `/oauth/jwks`
 * endpoint so clients and resource servers can verify JWT access
 * tokens without shared secrets.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7517
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
 */
export class KeyService {
  #jwksPath: string
  #privateKey: CryptoKey | null = null
  #publicKey: CryptoKey | null = null
  #kid: string | null = null

  constructor(jwksPath: string) {
    this.#jwksPath = jwksPath
  }

  /**
   * Load keys from the configured file path. If the file does
   * not exist or is unreadable, a new key pair is generated.
   */
  async loadKeys(): Promise<void> {
    try {
      const content = await readFile(this.#jwksPath, 'utf-8')
      const stored: StoredKeySet = JSON.parse(content)
      const jwk = stored.keys[0]

      this.#kid = jwk.kid ?? 'default'
      this.#privateKey = (await jose.importJWK(jwk, 'RS256')) as CryptoKey

      const publicJwk = { ...jwk }
      delete publicJwk.d
      delete publicJwk.p
      delete publicJwk.q
      delete publicJwk.dp
      delete publicJwk.dq
      delete publicJwk.qi
      this.#publicKey = (await jose.importJWK(publicJwk, 'RS256')) as CryptoKey
    } catch {
      await this.generateKeys()
    }
  }

  /**
   * Generate a new RS256 key pair and persist it to disk as a
   * JWK Set. Skips generation if the key file already exists
   * unless `force` is set.
   */
  async generateKeys(options?: { force?: boolean }): Promise<void> {
    if (!options?.force) {
      try {
        await readFile(this.#jwksPath)
        return
      } catch {}
    }

    const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
      modulusLength: 2048,
      extractable: true,
    })

    const kid = jose.base64url.encode(crypto.getRandomValues(new Uint8Array(16)))
    const privateJwk = await jose.exportJWK(privateKey)
    privateJwk.kid = kid
    privateJwk.use = 'sig'
    privateJwk.alg = 'RS256'

    await mkdir(dirname(this.#jwksPath), { recursive: true })
    await writeFile(this.#jwksPath, JSON.stringify({ keys: [privateJwk] }, null, 2))

    this.#privateKey = privateKey as CryptoKey
    this.#publicKey = publicKey as CryptoKey
    this.#kid = kid
  }

  /**
   * Get the public JWK Set for the `/oauth/jwks` endpoint.
   * Only public key components are included (no private exponents).
   */
  async getJwks(): Promise<{ keys: jose.JWK[] }> {
    if (!this.#publicKey) await this.loadKeys()

    const publicJwk = await jose.exportJWK(this.#publicKey!)
    publicJwk.kid = this.#kid!
    publicJwk.use = 'sig'
    publicJwk.alg = 'RS256'

    return { keys: [publicJwk] }
  }

  /**
   * Get the private key for signing JWT access tokens.
   */
  async getPrivateKey(): Promise<CryptoKey> {
    if (!this.#privateKey) await this.loadKeys()
    return this.#privateKey!
  }

  /**
   * Get the key ID (`kid`) for the current signing key.
   */
  async getKid(): Promise<string> {
    if (!this.#kid) await this.loadKeys()
    return this.#kid!
  }

  /**
   * Get the public key for JWT signature verification.
   */
  async getPublicKey(): Promise<CryptoKey> {
    if (!this.#publicKey) await this.loadKeys()
    return this.#publicKey!
  }
}
