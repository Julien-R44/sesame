import { SesameManager } from '../../src/sesame_manager.ts'
import { OAuthGuard } from '../../src/guard/guard.ts'
import { createManager } from './app.ts'
import { mockCtx } from './mock_ctx.ts'
import { FakeUserProvider, createFakeEmitter, type FakeUser } from './fakes.ts'

/**
 * Creates a fully wired OAuthGuard for testing. Synchronous (no DB).
 *
 * Pass `bearerToken` to simulate an authenticated request.
 * Pass `users` to control the FakeUserProvider (defaults to [{id:'user-1', name:'Test User'}]).
 *
 * Returns `{ ctx, guard, emitter, provider, manager }`.
 */
export function createTestGuard(options?: {
  manager?: SesameManager
  bearerToken?: string
  users?: FakeUser[]
  headers?: Record<string, string>
}) {
  const manager = options?.manager ?? createManager()
  const headers = { ...options?.headers }
  if (options?.bearerToken) headers.authorization = `Bearer ${options.bearerToken}`

  const ctx = mockCtx({ headers, manager })
  const emitter = createFakeEmitter()
  const provider = new FakeUserProvider(options?.users ?? [{ id: 'user-1', name: 'Test User' }])
  const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

  return { ctx, guard, emitter, provider, manager }
}
