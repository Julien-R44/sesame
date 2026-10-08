import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { createTestConfig, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createPkce } from './helpers/create_pkce.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { SesameManager } from '../src/sesame_manager.ts'
import { AuthorizeAction } from '../src/actions/authorize.ts'
import { IssueAuthorizationCodeAction } from '../src/actions/issue_authorization_code.ts'
import { lucidStore } from '../src/storage/drivers/lucid.ts'
import { isForeignKeyViolation, rejectDeletedClient } from '../src/storage/foreign_key_violation.ts'
import type { OAuthClientRecord } from '../src/storage/types.ts'

/**
 * Load a client, then delete it, as if a purge ran right after the lookup.
 */
async function createDeletedClient() {
  await createTestClient({ clientId: 'deleted-client' })
  const store = lucidStore()
  const client = (await store.findClient('deleted-client')) as OAuthClientRecord
  await store.deleteClient('deleted-client')

  const staleStore = { ...bindStore(store), findClient: async () => client }
  const manager = new SesameManager(createTestConfig(), {} as any, staleStore)

  return { client, manager }
}

/**
 * Copy the store methods so one of them can be overridden.
 */
function bindStore(store: any) {
  const methods: Record<string, unknown> = {}
  for (const name of Object.getOwnPropertyNames(Object.getPrototypeOf(store))) {
    if (name === 'constructor') continue
    methods[name] = store[name].bind(store)
  }

  return methods as any
}

test.group('Deleted client race', (group) => {
  setupIntegrationGroup(group)

  test('authorize reports invalid_client when the pending request insert fails', async ({
    assert,
  }) => {
    const { manager } = await createDeletedClient()
    const { codeChallenge } = createPkce()

    await assertOAuthError(
      assert,
      () =>
        new AuthorizeAction().execute(manager, {
          clientId: 'deleted-client',
          responseType: 'code',
          redirectUri: 'https://app.example.com/callback',
          scope: 'read',
          codeChallenge,
          codeChallengeMethod: 'S256',
          userId: 'user-1',
        }),
      'invalid_client',
      'Client not found'
    )
  })

  test('issuing a code reports invalid_client for a deleted client', async ({ assert }) => {
    const { client, manager } = await createDeletedClient()

    await assertOAuthError(
      assert,
      () =>
        new IssueAuthorizationCodeAction().execute(manager, {
          client,
          userId: 'user-1',
          scopes: ['read'],
          redirectUri: 'https://app.example.com/callback',
        }),
      'invalid_client'
    )
  })

  test('creating a grant reports invalid_client for a deleted client', async ({ assert }) => {
    const { manager } = await createDeletedClient()

    await assertOAuthError(
      assert,
      () =>
        rejectDeletedClient(() =>
          manager.store.createGrant({
            id: crypto.randomUUID(),
            clientId: 'deleted-client',
            userId: 'user-1',
            scopes: ['read'],
            expiresAt: DateTime.now().plus({ minutes: 10 }),
          })
        ),
      'invalid_client'
    )
  })

  test('rethrows other errors', async ({ assert }) => {
    await assert.rejects(() => rejectDeletedClient(() => Promise.reject(new Error('boom'))), 'boom')
  })
})

test.group('isForeignKeyViolation', () => {
  test('recognizes Postgres, MySQL, MariaDB, and SQLite errors', ({ assert }) => {
    assert.isTrue(isForeignKeyViolation({ code: '23503' }))
    assert.isTrue(isForeignKeyViolation({ code: 'ER_NO_REFERENCED_ROW_2', errno: 1452 }))
    assert.isTrue(isForeignKeyViolation({ errno: 1216 }))
    assert.isTrue(isForeignKeyViolation({ code: 'SQLITE_CONSTRAINT_FOREIGNKEY' }))
    assert.isTrue(isForeignKeyViolation({ cause: { code: '23503' } }))
  })

  test('ignores other errors', ({ assert }) => {
    assert.isFalse(isForeignKeyViolation({ code: '23505' }))
    assert.isFalse(isForeignKeyViolation({ code: 'SQLITE_CONSTRAINT_UNIQUE' }))
    assert.isFalse(isForeignKeyViolation(null))
    assert.isFalse(isForeignKeyViolation('boom'))
  })
})
