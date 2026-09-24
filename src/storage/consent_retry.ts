const RETRYABLE_CODES = new Set([
  '23505',
  '40001',
  '40P01',
  'ER_DUP_ENTRY',
  'ER_LOCK_DEADLOCK',
  'ER_LOCK_WAIT_TIMEOUT',
  'SQLITE_BUSY',
  'SQLITE_BUSY_SNAPSHOT',
  'SQLITE_CONSTRAINT_UNIQUE',
])

const RETRYABLE_ERRNOS = new Set([1062, 1205, 1213])

/**
 * Identify database conflicts that can be retried in a fresh transaction.
 */
function isRetryableConsentConflict(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false

  const candidate = error as { code?: unknown; errno?: unknown; cause?: unknown }
  if (typeof candidate.code === 'string' && RETRYABLE_CODES.has(candidate.code)) return true
  if (typeof candidate.errno === 'number' && RETRYABLE_ERRNOS.has(candidate.errno)) return true

  return candidate.cause ? isRetryableConsentConflict(candidate.cause) : false
}

/**
 * Retry consent writes after uniqueness, serialization, or lock conflicts.
 */
export async function retryConsentConflict<T>(operation: () => Promise<T>): Promise<T> {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await operation()
    } catch (error) {
      if (attempt === 3 || !isRetryableConsentConflict(error)) throw error

      await new Promise((resolve) => setTimeout(resolve, attempt * 5))
    }
  }

  throw new Error('Consent retry limit exceeded')
}
