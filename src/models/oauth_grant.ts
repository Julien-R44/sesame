import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { json } from '../decorators.js'
import type { GrantContext } from '../types.ts'

/**
 * One authorization given by a user to a client.
 *
 * Every completed authorization creates a grant. The authorization
 * code, the access tokens, and every rotated refresh token issued
 * from it reference it through `grantId`. Revoking the grant revokes
 * that whole token family, and refresh-token replay only affects it.
 *
 * `context` is free-form application data chosen at consent time
 * and exposed by the OAuth guard. `expiresAt` slides with the latest
 * token issued from the grant.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-4.3.1
 */
export class OAuthGrant extends BaseModel {
  static table = 'oauth_grants'
  static selfAssignPrimaryKey = true

  @column({ isPrimary: true })
  declare id: string

  @column()
  declare clientId: string

  @column()
  declare userId: string

  @json()
  declare scopes: string[]

  @json()
  declare context: GrantContext | null

  @column.dateTime()
  declare expiresAt: DateTime

  @column.dateTime({ autoCreate: true })
  declare createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  declare updatedAt: DateTime
}
