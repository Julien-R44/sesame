import { BaseSchema } from '@adonisjs/lucid/schema'

export default class extends BaseSchema {
  protected tableName = 'oauth_pending_authorization_requests'

  async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.uuid('id').primary()
      table.string('token').notNullable().index()
      table
        .string('client_id')
        .notNullable()
        .references('client_id')
        .inTable('oauth_clients')
        .onDelete('CASCADE')
      table.string('user_id').notNullable()
      table.json('scopes').notNullable()
      table.text('redirect_uri').notNullable()
      table.string('state').nullable()
      table.string('code_challenge').nullable()
      table.string('code_challenge_method').nullable()
      table.timestamp('expires_at').notNullable()
      table.timestamp('created_at').notNullable()
    })
  }

  async down() {
    this.schema.dropTable(this.tableName)
  }
}
