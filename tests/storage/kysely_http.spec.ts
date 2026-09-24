import { test } from '@japa/runner'
import Database from 'better-sqlite3'
import { Kysely, SqliteDialect } from 'kysely'
import { stores } from '../../src/stores.ts'
import { kyselyStore } from '../../src/storage/drivers/kysely.ts'
import { up } from '../../src/storage/migrations/kysely.ts'
import { createApp, createHttpServer, setupDatabase, teardownDatabase } from '../helpers/app.ts'

test('Kysely store serves token and introspection HTTP endpoints', async ({ client, assert }) => {
  const app = await createApp()
  await setupDatabase(app)
  const db = new Kysely<any>({ dialect: new SqliteDialect({ database: new Database(':memory:') }) })
  await up(db)
  const server = await createHttpServer(
    app,
    {
      store: stores.kysely({ connection: db }),
      grantTypes: ['client_credentials'],
    },
    { store: kyselyStore({ db }) }
  )

  try {
    const { client: oauthClient, clientSecret } = await server.manager.createClient({
      name: 'Kysely HTTP client',
      redirectUris: [],
      grantTypes: ['client_credentials'],
      userId: 'user-1',
    })

    const token = await client.post(`${server.baseUrl}/oauth/token`).form({
      grant_type: 'client_credentials',
      client_id: oauthClient.clientId,
      client_secret: clientSecret,
    })
    token.assertStatus(200)
    const accessToken = token.body().access_token
    assert.isString(accessToken)

    const introspection = await client.post(`${server.baseUrl}/oauth/introspect`).form({
      token: accessToken,
      client_id: oauthClient.clientId,
      client_secret: clientSecret,
    })
    introspection.assertStatus(200)
    introspection.assertBodyContains({ active: true, client_id: oauthClient.clientId })
  } finally {
    await server.close()
    await db.destroy()
    await teardownDatabase(app)
    await app.terminate()
  }
})
