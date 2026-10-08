import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
import type { GrantContext } from '../types.ts'
import type { OAuthClientRecord } from '../storage/types.ts'
import { TokenService } from '../services/token_service.ts'
import { rejectDeletedClient } from '../storage/foreign_key_violation.ts'

export interface AuthorizationCodeInput {
  client: OAuthClientRecord
  userId: string
  scopes: string[]
  redirectUri: string
  codeChallenge?: string
  codeChallengeMethod?: string
  nonce?: string
  context?: GrantContext | null
}

/**
 * Create the grant for a completed authorization and persist its
 * authorization code. Returns the raw (unhashed) code to be sent
 * to the client.
 *
 * Every completed authorization gets its own grant, so tokens issued
 * to two installations of the same client, or with two different
 * contexts, never share a replay family.
 *
 * Shared between the authorize and consent flows to avoid
 * duplicating the code-issuance logic.
 */
export class IssueAuthorizationCodeAction {
  /**
   * Create the grant, generate an opaque authorization code, store
   * its SHA-256 hash, and return the raw value for the client redirect.
   */
  async execute(manager: SesameManager, input: AuthorizationCodeInput): Promise<string> {
    const tokenService = new TokenService(manager)
    const raw = tokenService.generateOpaqueToken()
    const hashed = tokenService.hashToken(raw)
    const ttl = string.seconds.parse(manager.config.authorizationCodeTtl)
    const expiresAt = DateTime.now().plus({ seconds: ttl })
    const grantId = crypto.randomUUID()

    const store = manager.store
    await rejectDeletedClient(async () => {
      await store.createGrant({
        id: grantId,
        clientId: input.client.clientId,
        userId: input.userId,
        scopes: input.scopes,
        context: input.context ?? null,
        expiresAt,
      })
      await store.createAuthorizationCode({
        id: crypto.randomUUID(),
        code: hashed,
        clientId: input.client.clientId,
        userId: input.userId,
        grantId,
        scopes: input.scopes,
        redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge ?? null,
        codeChallengeMethod: input.codeChallengeMethod ?? null,
        nonce: input.nonce ?? null,
        expiresAt,
      })
    })

    return raw
  }
}
