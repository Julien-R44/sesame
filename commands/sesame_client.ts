import { BaseCommand, flags } from '@adonisjs/core/ace'
import type { CommandOptions } from '@adonisjs/core/types/ace'
import { SesameManager } from '../src/sesame_manager.ts'

/**
 * Interactively create a new OAuth client.
 *
 * Prompts for name, redirect URIs, client type, and scopes,
 * then outputs the generated client_id and client_secret.
 */
export default class SesameClient extends BaseCommand {
  static commandName = 'sesame:client'
  static description = 'Create a new OAuth client'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.boolean({ description: 'Create a public client (no secret)' })
  declare public: boolean

  @flags.string({ description: 'Client name' })
  declare name: string

  @flags.array({ description: 'Redirect URIs (comma-separated)' })
  declare redirectUris: string[]

  @flags.array({ description: 'Scopes (comma-separated)' })
  declare scopes: string[]

  @flags.array({ description: 'Grant types (comma-separated)' })
  declare grantTypes: string[]

  @flags.string({ description: 'Owner user ID' })
  declare userId: string

  /**
   * Accept both repeated flags and comma-separated values.
   */
  #list(values: string[] | undefined): string[] {
    return (values ?? [])
      .flatMap((value) => value.split(','))
      .map((value) => value.trim())
      .filter(Boolean)
  }

  async run() {
    const manager = await this.app.container.make(SesameManager)

    const name =
      this.name || (await this.prompt.ask('Client name', { validate: (v) => !!v.trim() }))

    const redirectUris = this.#list(this.redirectUris)
    if (redirectUris.length === 0) {
      redirectUris.push(...this.#list([await this.prompt.ask('Redirect URIs (comma-separated)')]))
    }
    const scopes = this.#list(this.scopes)
    const grantTypes = this.#list(this.grantTypes)

    const isPublic =
      this.public || (await this.prompt.confirm('Public client (no secret)?', { default: false }))

    const { client, clientSecret } = await manager.createClient({
      name,
      redirectUris,
      isPublic,
      scopes: scopes.length > 0 ? scopes : undefined,
      grantTypes: grantTypes.length > 0 ? (grantTypes as any) : undefined,
      userId: this.userId || undefined,
    })

    this.logger.success('Client created!')
    this.logger.info(`  Client ID: ${client.clientId}`)

    if (clientSecret) {
      this.logger.info(`  Client Secret: ${clientSecret}`)
      this.logger.warning('  Save the secret now — it will not be shown again.')
    }
  }
}
