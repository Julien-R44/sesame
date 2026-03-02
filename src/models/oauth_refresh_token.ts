import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { json } from '../decorators.js'

/**
 * Database record for an OAuth 2.0 refresh token (RFC 6749 §6).
 *
 * The `token` column stores the SHA-256 hash of the raw refresh
 * token value. Refresh token rotation is enforced: each use
 * produces a new token and revokes the old one.
 *
 * Replay detection is implemented by checking `revokedAt` —
 * if a revoked token is presented, all tokens for that
 * client+user pair are deleted as a security measure.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.14.2
 */
export class OAuthRefreshToken extends BaseModel {
  static table = 'oauth_refresh_tokens'

  @column({ isPrimary: true })
  declare id: string

  @column({ serializeAs: null })
  declare token: string

  @column()
  declare accessTokenId: string

  @column()
  declare clientId: string

  @column()
  declare userId: string

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
