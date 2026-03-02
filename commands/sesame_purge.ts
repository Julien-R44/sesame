import { BaseCommand, flags } from '@adonisjs/core/ace'
import type { CommandOptions } from '@adonisjs/core/types/ace'
import { SesameManager } from '../src/sesame_manager.ts'

/**
 * Purge revoked and/or expired OAuth tokens and authorization codes.
 *
 * By default, purges both revoked and expired records. Use `--revoked`
 * or `--expired` to target only one category. Expired tokens are
 * retained for a configurable period (default 168h / 7 days) to
 * allow for debugging and audit trails.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749
 */
export default class SesamePurge extends BaseCommand {
  static commandName = 'sesame:purge'
  static description = 'Purge revoked and/or expired tokens and authorization codes'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.boolean({ description: 'Only purge revoked tokens and authorization codes' })
  declare revoked: boolean

  @flags.boolean({ description: 'Only purge expired tokens and authorization codes' })
  declare expired: boolean

  @flags.number({
    description: 'Number of hours to retain expired tokens (default: 168 = 7 days)',
    default: 168,
  })
  declare hours: number

  async run() {
    const manager = await this.app.container.make(SesameManager)

    const result = await manager.purgeTokens({
      revokedOnly: this.revoked,
      expiredOnly: this.expired,
      retentionHours: this.hours,
    })

    const total = result.accessTokens + result.refreshTokens + result.authorizationCodes

    if (result.accessTokens > 0) this.logger.info(`  Access tokens: ${result.accessTokens}`)
    if (result.refreshTokens > 0) this.logger.info(`  Refresh tokens: ${result.refreshTokens}`)
    if (result.authorizationCodes > 0) this.logger.info(`  Authorization codes: ${result.authorizationCodes}`)

    this.logger.success(`Purged ${total} record(s).`)
  }
}
