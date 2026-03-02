import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { json } from '../decorators.js'

/**
 * Database record for an issued OAuth 2.0 access token.
 *
 * Access tokens are opaque random values. Only the SHA-256 hash
 * is stored so raw tokens cannot be reconstructed from a DB leak.
 * A token is considered revoked when `revokedAt` is set.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 */
export class OAuthAccessToken extends BaseModel {
  static table = 'oauth_access_tokens'

  @column({ isPrimary: true })
  declare id: string

  @column()
  declare tokenHash: string

  @column()
  declare clientId: string

  @column()
  declare userId: string | null

  @json()
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
