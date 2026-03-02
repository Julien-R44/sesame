import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { json } from '../decorators.js'

/**
 * Represents a registered OAuth 2.0 client (RFC 6749 §2).
 *
 * Clients can be either confidential (with a hashed secret) or
 * public (no secret, e.g. SPAs, native apps). Public clients must
 * use PKCE (RFC 7636) for authorization code exchanges.
 *
 * Clients may be created manually or via dynamic client registration
 * (RFC 7591) through the `/oauth/register` endpoint.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2
 * @see https://datatracker.ietf.org/doc/html/rfc7591
 */
export class OAuthClient extends BaseModel {
  static table = 'oauth_clients'

  @column({ isPrimary: true })
  declare id: string

  @column()
  declare clientId: string

  @column({ serializeAs: null })
  declare clientSecret: string | null

  @column()
  declare name: string

  @json()
  declare redirectUris: string[]

  @json()
  declare scopes: string[]

  @json()
  declare grantTypes: string[]

  @column()
  declare isPublic: boolean

  @column()
  declare isDisabled: boolean

  @column()
  declare requirePkce: boolean

  @column()
  declare type: string | null

  @json()
  declare metadata: Record<string, any> | null

  @column()
  declare userId: string | null

  @column.dateTime({ autoCreate: true })
  declare createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  declare updatedAt: DateTime
}
