import { DateTime } from 'luxon'
import string from '@adonisjs/core/helpers/string'
import type { SesameManager } from '../sesame_manager.ts'
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
}

/**
 * Create and persist an authorization code in the database.
 * Returns the raw (unhashed) code to be sent to the client.
 *
 * Shared between the authorize and consent flows to avoid
 * duplicating the code-issuance logic.
 */
export class IssueAuthorizationCodeAction {
  /**
   * Generate an opaque authorization code, store its SHA-256
   * hash in the database, and return the raw value for the
   * client redirect.
   */
  async execute(manager: SesameManager, input: AuthorizationCodeInput): Promise<string> {
    const tokenService = new TokenService(manager)
    const raw = tokenService.generateOpaqueToken()
    const hashed = tokenService.hashToken(raw)
    const ttl = string.seconds.parse(manager.config.authorizationCodeTtl)

    const store = manager.store
    await rejectDeletedClient(() =>
      store.createAuthorizationCode({
        id: crypto.randomUUID(),
        code: hashed,
        clientId: input.client.clientId,
        userId: input.userId,
        scopes: input.scopes,
        redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge ?? null,
        codeChallengeMethod: input.codeChallengeMethod ?? null,
        nonce: input.nonce ?? null,
        expiresAt: DateTime.now().plus({ seconds: ttl }),
      })
    )

    return raw
  }
}
