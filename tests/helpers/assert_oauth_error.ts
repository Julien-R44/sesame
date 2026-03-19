import type { Assert } from '@japa/assert'
import { OAuthError } from '../../src/oauth_error.ts'

/**
 * Asserts that an async function throws an OAuthError with the expected code.
 *
 * Replaces the verbose try/catch + assert.fail + assert.instanceOf + assert.equal pattern.
 *
 * Optionally checks that the error message includes one or more substrings.
 */
export async function assertOAuthError(
  assert: Assert,
  fn: () => Promise<any>,
  expectedCode: string,
  messageIncludes?: string | string[]
) {
  try {
    await fn()
    assert.fail('Expected OAuthError to be thrown')
  } catch (error: any) {
    assert.instanceOf(error, OAuthError)
    assert.equal(error.oauthCode, expectedCode)

    if (!messageIncludes) return

    const includes = Array.isArray(messageIncludes) ? messageIncludes : [messageIncludes]
    for (const substring of includes) assert.include(error.message, substring)
  }
}
