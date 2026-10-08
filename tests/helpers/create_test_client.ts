import { DateTime } from 'luxon'
import { OAuthClient } from '../../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../../src/models/oauth_authorization_code.ts'
import { ClientService } from '../../src/services/client_service.ts'
import { TokenService } from '../../src/services/token_service.ts'
import { createManager } from './app.ts'
import { createTestGrant } from './create_test_grant.ts'

export type TestClientOverrides = Partial<Record<string, any>> & {
  rawClientSecret?: string
}

/**
 * Creates a confidential OAuthClient in the database with test defaults.
 *
 * Defaults: clientId='test-client', secret='test-secret', scopes=['read','write','offline_access'],
 * grantTypes=['authorization_code','refresh_token'], requirePkce=true
 *
 * Use `rawClientSecret` in overrides to set the pre-hash secret value.
 */
export async function createTestClient(overrides?: TestClientOverrides) {
  const clientService = new ClientService()
  const { rawClientSecret = 'test-secret', ...clientOverrides } = overrides ?? {}

  return OAuthClient.create({
    id: crypto.randomUUID(),
    clientId: 'test-client',
    clientSecret: clientService.hashSecret(rawClientSecret),
    name: 'Test Client',
    redirectUris: ['https://app.example.com/callback'],
    scopes: ['read', 'write', 'offline_access'],
    grantTypes: ['authorization_code', 'refresh_token'],
    isPublic: false,
    isDisabled: false,
    requirePkce: true,
    type: 'confidential',
    metadata: null,
    userId: null,
    ...clientOverrides,
  })
}

/**
 * Creates an OAuthAuthorizationCode in the database.
 *
 * The `rawCode` is hashed before storage (matches real behavior).
 * Expires in 10 minutes by default. A grant is created for the code
 * unless `grantId` is given; pass `null` for a pre-grant (legacy) code.
 */
export async function createTestAuthCode(options: {
  clientId: string
  userId: string
  scopes: string[]
  redirectUri: string
  rawCode: string
  codeChallenge?: string
  codeChallengeMethod?: string
  grantId?: string | null
  resource?: string | null
}) {
  const tokenService = new TokenService(createManager())
  const grantId =
    options.grantId === undefined
      ? (
          await createTestGrant({
            clientId: options.clientId,
            userId: options.userId,
            scopes: options.scopes,
            expiresAt: DateTime.now().plus({ minutes: 10 }),
          })
        ).id
      : options.grantId

  return OAuthAuthorizationCode.create({
    id: crypto.randomUUID(),
    code: tokenService.hashToken(options.rawCode),
    clientId: options.clientId,
    userId: options.userId,
    grantId,
    scopes: options.scopes,
    redirectUri: options.redirectUri,
    codeChallenge: options.codeChallenge ?? null,
    codeChallengeMethod: options.codeChallengeMethod ?? null,
    resource: options.resource ?? null,
    expiresAt: DateTime.now().plus({ minutes: 10 }),
  })
}
