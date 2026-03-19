import { SesameManager } from '../../src/sesame_manager.ts'
import { OAuthClient } from '../../src/models/oauth_client.ts'
import { createManager } from './app.ts'
import { createTestAuthCode } from './create_test_client.ts'
import { createPkce } from './create_pkce.ts'

/**
 * Creates an authorization code in DB and returns the structured
 * data needed to call `ExchangeAuthorizationCodeAction.execute()`.
 *
 * Does NOT create the OAuthClient — call `createTestClient()` first.
 *
 * Defaults: clientId='test-client', userId='user-1', scopes=['read','write'],
 * redirectUri='https://app.example.com/callback'
 */
export async function createAuthCodeExchange(options?: {
  manager?: SesameManager
  clientId?: string
  userId?: string
  scopes?: string[]
  rawCode?: string
  codeVerifier?: string
  redirectUri?: string
}) {
  const manager = options?.manager ?? createManager()
  const clientId = options?.clientId ?? 'test-client'
  const redirectUri = options?.redirectUri ?? 'https://app.example.com/callback'
  const rawCode = options?.rawCode ?? `test-code-${crypto.randomUUID().slice(0, 8)}`
  const { codeVerifier, codeChallenge } = createPkce(options?.codeVerifier)

  await createTestAuthCode({
    clientId,
    userId: options?.userId ?? 'user-1',
    scopes: options?.scopes ?? ['read', 'write'],
    redirectUri,
    rawCode,
    codeChallenge,
    codeChallengeMethod: 'S256',
  })

  const client = await OAuthClient.query().where('clientId', clientId).firstOrFail()

  return { client, rawCode, codeVerifier, codeChallenge, redirectUri, manager }
}
