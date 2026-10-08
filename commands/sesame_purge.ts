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
 * With `--clients`, also deletes dynamically registered clients that
 * were never used, after the tokens are purged.
 */
export default class SesamePurge extends BaseCommand {
  static commandName = 'sesame:purge'
  static description = 'Purge revoked and/or expired tokens, authorization codes, and grants'

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

  @flags.boolean({
    description: 'Also purge dynamically registered clients that were never used',
  })
  declare clients: boolean

  @flags.number({
    description: 'Minimum age in days of the unused clients to purge, at least 1 (default: 30)',
    default: 30,
  })
  declare clientDays: number

  async run() {
    const invalidClientDays = !Number.isInteger(this.clientDays) || this.clientDays < 1
    if (this.clients && invalidClientDays) {
      this.logger.error('--client-days must be a positive integer')
      this.exitCode = 1
      return
    }

    const manager = await this.app.container.make(SesameManager)

    const result = await manager.purgeTokens({
      revokedOnly: this.revoked,
      expiredOnly: this.expired,
      retentionHours: this.hours,
    })

    const clients = this.clients
      ? await manager.purgeUnusedClients({ olderThanDays: this.clientDays })
      : 0

    const total =
      result.accessTokens +
      result.refreshTokens +
      result.authorizationCodes +
      result.grants +
      clients

    if (result.accessTokens > 0) this.logger.info(`  Access tokens: ${result.accessTokens}`)
    if (result.refreshTokens > 0) this.logger.info(`  Refresh tokens: ${result.refreshTokens}`)
    if (result.authorizationCodes > 0)
      this.logger.info(`  Authorization codes: ${result.authorizationCodes}`)
    if (result.grants > 0) this.logger.info(`  Grants: ${result.grants}`)
    if (clients > 0) this.logger.info(`  Unused clients: ${clients}`)

    this.logger.success(`Purged ${total} record(s).`)
  }
}
