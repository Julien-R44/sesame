import { BaseSchema } from '@adonisjs/lucid/schema'

export default class extends BaseSchema {
  protected tableName = 'oauth_clients'

  async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.uuid('id').primary()
      table.string('client_id').unique().notNullable()
      table.text('client_secret').nullable()
      table.string('name').notNullable()
      table.json('redirect_uris').notNullable()
      table.json('scopes').notNullable().defaultTo('[]')
      table.json('grant_types').notNullable().defaultTo('[]')
      table.boolean('is_public').notNullable().defaultTo(false)
      table.boolean('is_disabled').notNullable().defaultTo(false)
      table.boolean('require_pkce').notNullable().defaultTo(true)
      table.string('type').nullable()
      table.json('metadata').nullable()
      table.string('user_id').nullable()
      table.timestamp('created_at').notNullable()
      table.timestamp('updated_at').notNullable()
    })
  }

  async down() {
    this.schema.dropTable(this.tableName)
  }
}
