import { DateTime } from 'luxon'
import type { SesameManager } from '../sesame_manager.ts'
import type { GrantAdoption, OAuthGrantRecord, TokenGrantWrite } from '../storage/types.ts'
import { E_INVALID_GRANT } from '../oauth_error.ts'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Credential (code or refresh token) about to issue new tokens.
 * `adopt` lists the rows attached to the grant when a legacy
 * credential gets a new one.
 */
export interface TokenGrantSource {
  grantId: string | null
  clientId: string
  userId: string
  scopes: string[]
  expiresAt: DateTime
  adopt: GrantAdoption
}

/**
 * Grant attached to newly issued tokens and the store write that goes with it.
 */
export interface ResolvedTokenGrant {
  grantId: string
  write: TokenGrantWrite
}

/**
 * Ensure an application context is a plain JSON object or null.
 */
export function assertGrantContext(context: unknown): void {
  if (context === null || context === undefined) return
  if (typeof context === 'object' && !Array.isArray(context)) return

  throw new TypeError('Grant context must be a plain object or null')
}

/**
 * Check whether a grant identifier can exist. Grant ids are UUIDs, and
 * some databases reject anything else in a native UUID column.
 */
export function isGrantId(value: string): boolean {
  return UUID_PATTERN.test(value)
}

/**
 * Check that a token's grant is still active. Tokens without a grant
 * (client_credentials, issued before grants existed) are not affected.
 */
export function hasActiveGrant(token: {
  grantId: string | null
  grant: OAuthGrantRecord | null
}): boolean {
  if (!token.grantId) return true
  if (!token.grant) return false

  return token.grant.expiresAt.toMillis() > Date.now()
}

/**
 * Grant lifecycle shared by the code exchange and refresh flows.
 *
 * Tokens issued before grants existed have no `grantId`. They are
 * adopted into a new grant the next time they issue tokens, and keep
 * the former client+user replay family until then.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-4.3.1
 */
export class GrantService {
  #manager: SesameManager

  constructor(manager: SesameManager) {
    this.#manager = manager
  }

  /**
   * Reject credentials whose grant was revoked or has expired
   * ("validate that the grant corresponding to this refresh token is still active").
   */
  async assertActive(grantId: string | null): Promise<void> {
    if (!grantId) return

    if (!(await this.isActive(grantId))) {
      throw new E_INVALID_GRANT('Grant has been revoked or has expired')
    }
  }

  /**
   * Check that a credential's grant still exists and has not expired.
   * Credentials without a grant are always considered active.
   */
  async isActive(grantId: string | null): Promise<boolean> {
    if (!grantId) return true

    const grant = await this.#manager.store.findGrant(grantId)

    return hasActiveGrant({ grantId, grant })
  }

  /**
   * Extend the credential's grant until the new tokens expire, or adopt
   * a legacy credential into a new context-less grant. Adopting the
   * presented code or refresh token makes a later replay of it revoke
   * the new grant.
   */
  resolveTokenGrant(source: TokenGrantSource): ResolvedTokenGrant {
    if (source.grantId) {
      return {
        grantId: source.grantId,
        write: { type: 'extend', id: source.grantId, expiresAt: source.expiresAt },
      }
    }

    const grantId = crypto.randomUUID()

    return {
      grantId,
      write: {
        type: 'create',
        grant: {
          id: grantId,
          clientId: source.clientId,
          userId: source.userId,
          scopes: source.scopes,
          context: null,
          expiresAt: source.expiresAt,
        },
        adopt: source.adopt,
      },
    }
  }

  /**
   * Revoke the token family of a replayed credential: its grant, or the
   * grant-less tokens of the same client and user for legacy credentials.
   */
  async revokeFamily(source: Pick<TokenGrantSource, 'grantId' | 'clientId' | 'userId'>) {
    const store = this.#manager.store
    const now = DateTime.now()

    if (source.grantId) {
      await store.revokeGrant({ id: source.grantId, now })
      return
    }

    await store.revokeLegacyTokenFamily({ clientId: source.clientId, userId: source.userId, now })
  }
}
