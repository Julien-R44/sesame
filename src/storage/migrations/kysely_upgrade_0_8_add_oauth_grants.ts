import { MysqlAdapter, type Kysely } from 'kysely'

const GRANT_TABLES = ['oauth_authorization_codes', 'oauth_access_tokens', 'oauth_refresh_tokens']

/**
 * Upgrade Sésame 0.7 OAuth tables to 0.8 grants. Existing codes and
 * tokens keep working without a grant; refresh tokens are attached to
 * a new grant on their next rotation.
 */
export async function up(db: Kysely<any>): Promise<void> {
  // A grant is one authorization given by a user to a client; its tokens reference it.
  await db.schema
    .createTable('oauth_grants')
    .addColumn('id', 'varchar(36)', (column) => column.primaryKey())
    .addColumn('client_id', 'varchar(255)', (column) =>
      column.notNull().references('oauth_clients.client_id').onDelete('cascade')
    )
    .addColumn('user_id', 'varchar(255)', (column) => column.notNull())
    .addColumn('scopes', 'json', (column) => column.notNull())
    .addColumn('context', 'json')
    .addColumn('expires_at', 'timestamp', (column) => column.notNull())
    .addColumn('created_at', 'timestamp', (column) => column.notNull())
    .addColumn('updated_at', 'timestamp', (column) => column.notNull())
    .execute()
  // List a user's grants, optionally for one client.
  await db.schema
    .createIndex('oauth_grants_user_id_client_id_idx')
    .on('oauth_grants')
    .columns(['user_id', 'client_id'])
    .execute()

  // Codes and tokens reference the grant they were issued from.
  for (const table of GRANT_TABLES) {
    await db.schema.alterTable(table).addColumn('grant_id', 'varchar(36)').execute()
    await db.schema
      .createIndex(table + '_grant_id_idx')
      .on(table)
      .column('grant_id')
      .execute()
  }

  // Exchanged codes are kept so a second redemption revokes their grant.
  await db.schema
    .alterTable('oauth_authorization_codes')
    .addColumn('consumed_at', 'timestamp')
    .execute()

  // Remembered consent is now derived from active grants.
  await db.schema.dropTable('oauth_consents').execute()
}

export async function down(db: Kysely<any>): Promise<void> {
  // Restore the consent table, empty: grants cannot be merged back into consents.
  await db.schema
    .createTable('oauth_consents')
    .addColumn('id', 'varchar(36)', (column) => column.primaryKey())
    .addColumn('client_id', 'varchar(255)', (column) =>
      column.notNull().references('oauth_clients.client_id').onDelete('cascade')
    )
    .addColumn('user_id', 'varchar(255)', (column) => column.notNull())
    .addColumn('scopes', 'json', (column) => column.notNull())
    .addColumn('created_at', 'timestamp', (column) => column.notNull())
    .addColumn('updated_at', 'timestamp', (column) => column.notNull())
    .execute()
  await db.schema
    .createIndex('oauth_consents_client_id_user_id_unique')
    .on('oauth_consents')
    .columns(['client_id', 'user_id'])
    .unique()
    .execute()

  await db.schema.alterTable('oauth_authorization_codes').dropColumn('consumed_at').execute()

  // MySQL scopes index names to their table.
  const isMysql = db.getExecutor().adapter instanceof MysqlAdapter
  for (const table of GRANT_TABLES) {
    const dropIndex = db.schema.dropIndex(table + '_grant_id_idx')
    await (isMysql ? dropIndex.on(table) : dropIndex).execute()
    await db.schema.alterTable(table).dropColumn('grant_id').execute()
  }

  await db.schema.dropTable('oauth_grants').execute()
}
