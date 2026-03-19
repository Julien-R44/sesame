import { exportJWK, generateKeyPair, type JWK } from 'jose'
import type { EmitterLike } from '@adonisjs/core/types/events'
import { symbols } from '@adonisjs/auth'
import type {
  OAuthUserProviderContract,
  OAuthGuardUser,
  OAuthGuardEvents,
} from '../../src/guard/types.ts'

export type FakeUser = { id: string; name: string }

/**
 * Fake user provider that doesn't need a real Lucid model.
 * Maps user IDs to simple objects for testing.
 */
export class FakeUserProvider implements OAuthUserProviderContract<FakeUser> {
  declare [symbols.PROVIDER_REAL_USER]: FakeUser

  #users: Map<string, FakeUser>

  constructor(users: FakeUser[]) {
    this.#users = new Map(users.map((u) => [u.id, u]))
  }

  async createUserForGuard(user: FakeUser): Promise<OAuthGuardUser<FakeUser>> {
    return { getId: () => user.id, getOriginal: () => user }
  }

  async findById(identifier: string | number | BigInt): Promise<OAuthGuardUser<FakeUser> | null> {
    const user = this.#users.get(String(identifier))
    if (!user) return null

    return this.createUserForGuard(user)
  }
}

/**
 * Creates a fake event emitter that records all emitted events.
 *
 * Access captured events via `emitter.events` (array of `{ name, data }`).
 */
export function createFakeEmitter() {
  const events: { name: string; data: any }[] = []
  const emitter: EmitterLike<OAuthGuardEvents<FakeUser>> & {
    events: { name: string; data: any }[]
  } = {
    async emit(name: string, data: any) {
      events.push({ name, data })
    },
    async emitSerial(name: string, data: any) {
      events.push({ name, data })
    },
    listenerCount() {
      return 0
    },
    hasListeners() {
      return false
    },
    events,
  }

  return emitter
}

let cachedTestJwk: JWK | undefined

/**
 * Returns a cached RS256 JWK key pair for OIDC tests.
 *
 * Generated once per process to avoid slow key generation on every test.
 */
export async function getTestJwk(): Promise<JWK> {
  if (cachedTestJwk) return cachedTestJwk
  const { privateKey } = await generateKeyPair('RS256', { extractable: true })
  cachedTestJwk = await exportJWK(privateKey)

  return cachedTestJwk
}
