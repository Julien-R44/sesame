import { createHash } from 'node:crypto'

/**
 * Creates a PKCE verifier/challenge pair for tests.
 *
 * Short verifiers are auto-padded to 43 chars (RFC 7636 minimum).
 * Without arguments, returns a deterministic default pair.
 */
export function createPkce(verifier?: string) {
  const base = verifier ?? 'test-pkce-verifier-that-is-43-chars-long-xx'
  const codeVerifier = base.length < 43 ? base.padEnd(43, '-') : base
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

  return { codeVerifier, codeChallenge }
}
