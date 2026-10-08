import { E_INVALID_CLIENT } from '../oauth_error.ts'

const FOREIGN_KEY_CODES = new Set([
  '23503',
  'ER_NO_REFERENCED_ROW',
  'ER_NO_REFERENCED_ROW_2',
  'SQLITE_CONSTRAINT_FOREIGNKEY',
])

const FOREIGN_KEY_ERRNOS = new Set([1216, 1452])

/**
 * Identify a foreign key violation raised by Postgres, MySQL/MariaDB, or SQLite.
 */
export function isForeignKeyViolation(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false

  const candidate = error as { code?: unknown; errno?: unknown; cause?: unknown }
  if (typeof candidate.code === 'string' && FOREIGN_KEY_CODES.has(candidate.code)) return true
  if (typeof candidate.errno === 'number' && FOREIGN_KEY_ERRNOS.has(candidate.errno)) return true

  return candidate.cause ? isForeignKeyViolation(candidate.cause) : false
}

/**
 * Run a write that references a client and report `invalid_client` when the
 * client was deleted in the meantime (e.g. by `sesame:purge --clients`).
 */
export async function rejectDeletedClient<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation()
  } catch (error) {
    if (!isForeignKeyViolation(error)) throw error

    throw new E_INVALID_CLIENT('Client not found')
  }
}
