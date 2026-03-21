import { readFile, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { BaseCommand, flags } from '@adonisjs/core/ace'
import { generateKeyPair, exportJWK } from 'jose'

/**
 * Generate an RSA JWK key pair for signing OIDC ID tokens.
 */
export default class SesameKey extends BaseCommand {
  static commandName = 'sesame:key'
  static description = 'Generate an RSA JWK key pair for OIDC token signing'

  @flags.boolean({ description: 'Output only the raw JWK JSON (for piping)' })
  declare raw: boolean

  @flags.boolean({ description: 'Write OIDC_JWK to the .env file directly' })
  declare writeEnv: boolean

  async run() {
    const { privateKey } = await generateKeyPair('RS256', { extractable: true })
    const jwk = JSON.stringify(await exportJWK(privateKey))

    if (this.raw) return process.stdout.write(jwk + '\n')
    if (this.writeEnv) return this.#writeToEnv(jwk)

    this.logger.success('JWK generated successfully. Add it to your environment:')
    this.logger.info('')
    this.logger.info(`  OIDC_JWK='${jwk}'`)
    this.logger.info('')
    this.logger.warning('Never commit this key to version control.')
  }

  async #writeToEnv(jwk: string) {
    const envPath = join(this.app.appRoot.pathname, '.env')
    const line = `OIDC_JWK='${jwk}'`

    if (!existsSync(envPath)) {
      await writeFile(envPath, line + '\n')
      this.logger.success('Created .env with OIDC_JWK.')

      return
    }

    const content = await readFile(envPath, 'utf-8')
    const replaced = content.replace(/^OIDC_JWK=.*$/m, line)

    if (replaced !== content) {
      await writeFile(envPath, replaced)
      this.logger.success('Replaced existing OIDC_JWK in .env.')

      return
    }

    const separator = content.endsWith('\n') ? '' : '\n'
    await writeFile(envPath, content + separator + line + '\n')
    this.logger.success('Added OIDC_JWK to .env.')
  }
}
