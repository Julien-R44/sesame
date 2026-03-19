import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { json } from '../decorators.js'

/**
 * Temporary server-side record for an in-flight OAuth authorization
 * request, created when the user is redirected to the consent page
 * and consumed (deleted) when the user approves or denies.
 *
 * Stored in the database instead of the HTTP session to avoid
 * last-write-wins race conditions when concurrent SPA requests
 * overwrite session data.
 *
 * The `token` column stores a SHA-256 hash of the raw auth_token
 * sent to the consent page, consistent with how authorization
 * codes are stored.
 */
export class OAuthPendingAuthorizationRequest extends BaseModel {
  static table = 'oauth_pending_authorization_requests'

  @column({ isPrimary: true })
  declare id: string

  @column()
  declare token: string

  @column()
  declare userId: string

  @column()
  declare clientId: string

  @column()
  declare redirectUri: string

  @json()
  declare scopes: string[]

  @column()
  declare state: string | null

  @column()
  declare codeChallenge: string | null

  @column()
  declare codeChallengeMethod: string | null

  @column()
  declare nonce: string | null

  @column.dateTime()
  declare expiresAt: DateTime

  @column.dateTime({ autoCreate: true })
  declare createdAt: DateTime
}
