import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'

/**
 * Database record for an issued OAuth 2.0 access token.
 *
 * Access tokens are JWTs (RFC 9068) signed with RS256. This model
 * stores the token's `jti` (unique identifier) for revocation
 * tracking and introspection — the JWT itself is not stored.
 *
 * A token is considered revoked when `revokedAt` is set.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9068
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 */
export class OAuthAccessToken extends BaseModel {
  static table = 'oauth_access_tokens'

  @column({ isPrimary: true })
  declare id: string

  @column()
  declare jti: string

  @column()
  declare clientId: string

  @column()
  declare userId: string | null

  @column({ prepare: (v: string[]) => JSON.stringify(v), consume: (v: string) => JSON.parse(v) })
  declare scopes: string[]

  @column.dateTime()
  declare expiresAt: DateTime

  @column.dateTime()
  declare revokedAt: DateTime | null

  @column.dateTime({ autoCreate: true })
  declare createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  declare updatedAt: DateTime
}
