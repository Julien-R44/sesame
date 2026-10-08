import { existsSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { args, BaseCommand, flags } from '@adonisjs/core/ace'

const STUBS_ROOT = join(import.meta.dirname, '..', 'stubs')
const STORES = ['lucid', 'kysely']

/**
 * Publish the database migrations required to upgrade Sésame.
 *
 * Every stub of `stubs/migrations/upgrade_<version>/<store>/` is
 * published, in file name order, so new releases only add stubs.
 *
 * @example
 * ```sh
 * node ace sesame:upgrade 0.8
 * node ace sesame:upgrade 0.8 --store=kysely
 * ```
 */
export default class SesameUpgrade extends BaseCommand {
  static commandName = 'sesame:upgrade'
  static description = 'Publish the database migrations needed to upgrade Sésame'

  @args.string({ description: 'Sésame version you are upgrading to (e.g. 0.8)' })
  declare version: string

  @flags.string({ description: 'Store driver used by the application (lucid or kysely)' })
  declare store?: string

  /**
   * List the upgrade stubs of a version and store, relative to the stubs root.
   */
  async #upgradeStubs(store: string): Promise<string[] | null> {
    const folder = join('migrations', `upgrade_${this.version.replaceAll('.', '_')}`, store)
    if (!existsSync(join(STUBS_ROOT, folder))) return null

    const files = await readdir(join(STUBS_ROOT, folder))

    return files
      .filter((file) => file.endsWith('.stub'))
      .sort()
      .map((file) => join(folder, file))
  }

  async run() {
    const store = this.store ?? 'lucid'
    if (!STORES.includes(store)) {
      this.logger.error(`Invalid store "${store}". Use --store=lucid or --store=kysely`)
      this.exitCode = 1
      return
    }

    const stubs = await this.#upgradeStubs(store)
    if (!stubs?.length) {
      this.logger.error(`No ${store} upgrade migrations for Sésame ${this.version}`)
      this.exitCode = 1
      return
    }

    const codemods = await this.createCodemods()
    const timestamp = Date.now()
    for (const [index, stub] of stubs.entries()) {
      await codemods.makeUsingStub(STUBS_ROOT, stub, { prefix: timestamp + index })
    }

    this.logger.info('Run your migrations before deploying the new version.')
  }
}
