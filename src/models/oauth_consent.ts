import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'

/**
 * Tracks which scopes a user has approved for a given client.
 *
 * When a user grants consent during the authorization flow,
 * the approved scopes are persisted here. On subsequent
 * authorization requests, if the requested scopes are a subset
 * of previously approved scopes, the user is not prompted again.
 *
 * New scopes are merged into the existing record when the user
 * approves additional permissions.
 */
export class OAuthConsent extends BaseModel {
  static table = 'oauth_consents'

  @column({ isPrimary: true })
  declare id: string

  @column()
  declare clientId: string

  @column()
  declare userId: string

  @column({ prepare: (v: string[]) => JSON.stringify(v), consume: (v: string) => JSON.parse(v) })
  declare scopes: string[]

  @column.dateTime({ autoCreate: true })
  declare createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  declare updatedAt: DateTime
}
