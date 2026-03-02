import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'

/**
 * Database record for an OAuth 2.0 authorization code (RFC 6749 §4.1.2).
 *
 * Authorization codes are short-lived, single-use tokens issued
 * during the authorization flow. The `code` column stores the
 * SHA-256 hash of the raw code value sent to the client.
 *
 * When PKCE (RFC 7636) is used, the `codeChallenge` and
 * `codeChallengeMethod` (always S256) are stored alongside the
 * code for verification at the token endpoint.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 */
export class OAuthAuthorizationCode extends BaseModel {
  static table = 'oauth_authorization_codes'

  @column({ isPrimary: true })
  declare id: string

  @column()
  declare code: string

  @column()
  declare clientId: string

  @column()
  declare userId: string

  @column({ prepare: (v: string[]) => JSON.stringify(v), consume: (v: string) => JSON.parse(v) })
  declare scopes: string[]

  @column()
  declare redirectUri: string

  @column()
  declare codeChallenge: string | null

  @column()
  declare codeChallengeMethod: string | null

  @column.dateTime()
  declare expiresAt: DateTime

  @column.dateTime({ autoCreate: true })
  declare createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  declare updatedAt: DateTime
}
