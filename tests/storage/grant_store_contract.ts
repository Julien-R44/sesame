import type { Assert } from '@japa/assert'
import { DateTime } from 'luxon'
import type { SesameStore, TokenGrantWrite } from '../../src/storage/types.ts'

/**
 * Assert two instants are equal, tolerating second-precision SQL timestamps.
 */
function assertSameInstant(assert: Assert, actual: DateTime | undefined, expected: DateTime) {
  assert.isTrue(DateTime.isDateTime(actual))
  assert.isBelow(Math.abs(actual!.toMillis() - expected.toMillis()), 1000)
}

/**
 * Persist a token pair for a user, optionally inside a grant or with a grant write.
 */
async function issuePair(
  store: SesameStore,
  options: { clientId: string; userId: string; grantId?: string; grant?: TokenGrantWrite }
) {
  const accessTokenId = crypto.randomUUID()
  const refreshTokenId = crypto.randomUUID()
  const accessHash = `access-${crypto.randomUUID()}`
  const refreshHash = `refresh-${crypto.randomUUID()}`
  const expiresAt = DateTime.now().plus({ hours: 1 })

  const issued = await store.issueTokenPair({
    grant: options.grant,
    accessToken: {
      id: accessTokenId,
      tokenHash: accessHash,
      clientId: options.clientId,
      userId: options.userId,
      grantId: options.grantId ?? null,
      scopes: ['read'],
      expiresAt,
    },
    refreshToken: {
      id: refreshTokenId,
      token: refreshHash,
      accessTokenId,
      clientId: options.clientId,
      userId: options.userId,
      grantId: options.grantId ?? null,
      scopes: ['read'],
      expiresAt,
    },
  })

  return { issued, accessTokenId, refreshTokenId, accessHash, refreshHash }
}

/**
 * Verify grant records: JSON context, listing filters, updates, and the
 * access-token lookup joined with its grant.
 */
export async function testGrantRecords(store: SesameStore, clientId: string, assert: Assert) {
  const now = DateTime.now()
  const userId = `grant-user-${crypto.randomUUID()}`
  const grantId = crypto.randomUUID()
  const plainGrantId = crypto.randomUUID()

  await store.createGrant({
    id: grantId,
    clientId,
    userId,
    scopes: ['read'],
    context: { teamId: 1, projectIds: [2, 3] },
    expiresAt: now.plus({ days: 1 }),
  })
  await store.createGrant({
    id: plainGrantId,
    clientId,
    userId,
    scopes: ['write'],
    expiresAt: now.plus({ days: 1 }),
  })
  await store.createGrant({
    id: crypto.randomUUID(),
    clientId,
    userId,
    scopes: ['read'],
    expiresAt: now.minus({ minutes: 1 }),
  })

  const grant = await store.findGrant(grantId)
  assert.deepEqual(grant?.context, { teamId: 1, projectIds: [2, 3] })
  assert.deepEqual(grant?.scopes, ['read'])
  assert.equal(grant?.userId, userId)
  assertSameInstant(assert, grant?.expiresAt, now.plus({ days: 1 }))
  assert.isNull((await store.findGrant(plainGrantId))?.context)
  assert.isNull(await store.findGrant(crypto.randomUUID()))

  assert.lengthOf(await store.listGrants({ userId }), 3)
  assert.sameMembers(
    (await store.listGrants({ userId, clientId, activeAt: now })).map((item) => item.id),
    [grantId, plainGrantId]
  )
  assert.lengthOf(await store.listGrants({ userId, clientId: 'unknown-client' }), 0)

  await store.updateGrant({ id: grantId, data: { context: { teamId: 2 } } })
  assert.deepEqual((await store.findGrant(grantId))?.context, { teamId: 2 })
  await store.updateGrant({ id: plainGrantId, data: {} })
  assert.isNull((await store.findGrant(plainGrantId))?.context)

  const { accessHash } = await issuePair(store, { clientId, userId, grantId })
  const token = await store.findAccessToken({ hash: accessHash, clientId })
  assert.equal(token?.grantId, grantId)
  assert.equal(token?.grant?.id, grantId)
  assert.deepEqual(token?.grant?.context, { teamId: 2 })
  assert.deepEqual(token?.grant?.scopes, ['read'])
  assert.deepEqual(token?.scopes, ['read'])
  assert.isTrue(DateTime.isDateTime(token?.grant?.expiresAt))

  const legacy = await issuePair(store, { clientId, userId })
  const legacyToken = await store.findAccessToken({ hash: legacy.accessHash })
  assert.isNull(legacyToken?.grantId)
  assert.isNull(legacyToken?.grant)

  await store.revokeGrants({ userId, now })
}

/**
 * Verify single-use code consumption, grant writes during issuance,
 * and revocation scoped to one grant.
 */
export async function testGrantRevocation(store: SesameStore, clientId: string, assert: Assert) {
  const now = DateTime.now()
  const userId = `grant-user-${crypto.randomUUID()}`
  const grantId = crypto.randomUUID()
  await store.createGrant({
    id: grantId,
    clientId,
    userId,
    scopes: ['read'],
    expiresAt: now.plus({ minutes: 5 }),
  })

  const codeId = crypto.randomUUID()
  const code = `code-${crypto.randomUUID()}`
  await store.createAuthorizationCode({
    id: codeId,
    code,
    clientId,
    userId,
    grantId,
    scopes: ['read'],
    redirectUri: 'https://app.example.com/callback',
    expiresAt: now.plus({ minutes: 5 }),
  })

  const accessTokenId = crypto.randomUUID()
  const accessHash = `access-${crypto.randomUUID()}`
  const refreshHash = `refresh-${crypto.randomUUID()}`
  const exchange = {
    codeId,
    consumedAt: now,
    grant: { type: 'extend' as const, id: grantId, expiresAt: now.plus({ days: 30 }) },
    accessToken: {
      id: accessTokenId,
      tokenHash: accessHash,
      clientId,
      userId,
      grantId,
      scopes: ['read'],
      expiresAt: now.plus({ hours: 1 }),
    },
    refreshToken: {
      id: crypto.randomUUID(),
      token: refreshHash,
      accessTokenId,
      clientId,
      userId,
      grantId,
      scopes: ['read'],
      expiresAt: now.plus({ days: 30 }),
    },
  }
  assert.isTrue(await store.exchangeAuthorizationCode(exchange))
  assert.isFalse(await store.exchangeAuthorizationCode(exchange))
  const consumed = await store.findAuthorizationCode({ code, clientId })
  assert.equal(consumed?.grantId, grantId)
  assert.isTrue(DateTime.isDateTime(consumed?.consumedAt))
  assertSameInstant(assert, (await store.findGrant(grantId))?.expiresAt, now.plus({ days: 30 }))

  const shorter = await issuePair(store, {
    clientId,
    userId,
    grantId,
    grant: { type: 'extend', id: grantId, expiresAt: now.plus({ hours: 1 }) },
  })
  assert.isTrue(shorter.issued)
  assertSameInstant(assert, (await store.findGrant(grantId))?.expiresAt, now.plus({ days: 30 }))

  const expiredGrantId = crypto.randomUUID()
  await store.createGrant({
    id: expiredGrantId,
    clientId,
    userId,
    scopes: ['read'],
    expiresAt: now.minus({ minutes: 1 }),
  })
  for (const inactiveId of [expiredGrantId, crypto.randomUUID()]) {
    const rejected = await issuePair(store, {
      clientId,
      userId,
      grantId: inactiveId,
      grant: { type: 'extend', id: inactiveId, expiresAt: now.plus({ days: 30 }) },
    })
    assert.isFalse(rejected.issued)
    assert.isNull(await store.findAccessToken({ hash: rejected.accessHash }))
    assert.isNull(await store.findRefreshToken({ hash: rejected.refreshHash, clientId }))
  }

  const legacy = await issuePair(store, { clientId, userId })
  const adopted = await issuePair(store, { clientId, userId })
  const adoptedGrantId = crypto.randomUUID()
  const adoption = await issuePair(store, {
    clientId,
    userId,
    grantId: adoptedGrantId,
    grant: {
      type: 'create',
      grant: {
        id: adoptedGrantId,
        clientId,
        userId,
        scopes: ['read'],
        expiresAt: now.plus({ days: 30 }),
      },
      adopt: { refreshTokenId: adopted.refreshTokenId, accessTokenId: adopted.accessTokenId },
    },
  })
  assert.isTrue(adoption.issued)
  assert.isNull((await store.findGrant(adoptedGrantId))?.context)
  assert.equal(
    (await store.findRefreshToken({ hash: adopted.refreshHash, clientId }))?.grantId,
    adoptedGrantId
  )
  assert.equal((await store.findAccessToken({ hash: adopted.accessHash }))?.grantId, adoptedGrantId)
  assert.isNull((await store.findRefreshToken({ hash: legacy.refreshHash, clientId }))?.grantId)

  assert.isTrue(await store.revokeGrant({ id: grantId, now }))
  assert.isFalse(await store.revokeGrant({ id: grantId, now }))
  assert.isNull(await store.findGrant(grantId))
  assert.isNull(await store.findAuthorizationCode({ code, clientId }))
  assert.isNull(await store.findRefreshToken({ hash: refreshHash, clientId }))
  const revokedToken = await store.findAccessToken({ hash: accessHash })
  assert.isNotNull(revokedToken?.revokedAt)
  assert.isNull(revokedToken?.grant)
  assert.isNull((await store.findAccessToken({ hash: legacy.accessHash }))?.revokedAt)

  await store.revokeLegacyTokenFamily({ clientId, userId, now })
  assert.isNull(await store.findRefreshToken({ hash: legacy.refreshHash, clientId }))
  assert.isNotNull((await store.findAccessToken({ hash: legacy.accessHash }))?.revokedAt)
  assert.isNotNull(await store.findGrant(adoptedGrantId))

  assert.equal(await store.revokeGrants({ userId, clientId, now }), 2)
  assert.equal(await store.revokeGrants({ userId, now }), 0)
  assert.lengthOf(await store.listGrants({ userId }), 0)
}
