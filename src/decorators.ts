import { column } from '@adonisjs/lucid/orm'

/**
 * Column decorator for JSON values (arrays, objects).
 *
 * Lucid ORM doesn't handle JSON serialization automatically —
 * `prepare` stringifies before INSERT/UPDATE, `consume` parses
 * after SELECT. The typeof check in consume handles both drivers
 * that return strings (SQLite, MySQL) and parsed objects (PostgreSQL JSONB).
 */
export function json(options?: Parameters<typeof column>[0]) {
  return column({
    ...options,
    prepare: (value: any) => (value == null ? null : JSON.stringify(value)),
    consume: (value: any) =>
      value == null ? null : typeof value === 'string' ? JSON.parse(value) : value,
  })
}
