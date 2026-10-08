import { DateTime } from 'luxon'
import type { SesameManager } from '../sesame_manager.ts'
import type { TokenGrantWrite } from '../storage/types.ts'
import { E_INVALID_GRANT } from '../oauth_error.ts'

/**
 * Credential (code or refresh token) about to issue new tokens.
 */
export interface TokenGrantSource {
  grantId: string | null
  clientId: string
  userId: string
  scopes: string[]
  expiresAt: DateTime
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

    const grant = await this.#manager.store.findGrant(grantId)
    if (!grant || grant.expiresAt < DateTime.now()) {
      throw new E_INVALID_GRANT('Grant has been revoked or has expired')
    }
  }

  /**
   * Extend the credential's grant until the new tokens expire, or adopt
   * a legacy credential into a new context-less grant.
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
