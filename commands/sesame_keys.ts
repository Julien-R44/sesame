import { BaseCommand, flags } from '@adonisjs/core/ace'
import type { CommandOptions } from '@adonisjs/core/types/ace'
import { SesameManager } from '../src/sesame_manager.ts'
import type { ResolvedSesameConfig } from '../src/types.ts'

export default class SesameKeys extends BaseCommand {
  static commandName = 'sesame:keys'
  static description = 'Generate JWK signing keys for Sésame OAuth server'
  static options: CommandOptions = { startApp: true }

  @flags.boolean({ description: 'Overwrite existing keys' })
  declare force: boolean

  async run() {
    const config = this.app.config.get<ResolvedSesameConfig>('sesame')
    const manager = new SesameManager(config)

    try {
      await manager.keyService.generateKeys({ force: this.force })
      this.logger.success(`Keys generated at ${config.jwksPath}`)
    } catch (error) {
      this.logger.error(`Failed to generate keys: ${(error as Error).message}`)
      this.exitCode = 1
    }
  }
}
