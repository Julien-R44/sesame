import { BaseSchema } from '@adonisjs/lucid/schema'

export default class extends BaseSchema {
  protected tableName = 'oauth_grants'

  async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.uuid('id').primary()
      table
        .string('client_id')
        .notNullable()
        .references('client_id')
        .inTable('oauth_clients')
        .onDelete('CASCADE')
      table.string('user_id').notNullable()
      table.json('scopes').notNullable()
      table.json('context').nullable()
      table.timestamp('expires_at').notNullable()
      table.timestamp('created_at').notNullable()
      table.timestamp('updated_at').notNullable()

      table.index(['user_id', 'client_id'])
    })
  }

  async down() {
    this.schema.dropTable(this.tableName)
  }
}
