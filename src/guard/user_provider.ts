import { RuntimeException } from '@adonisjs/core/exceptions'
import { symbols } from '@adonisjs/auth'
import type { LucidModel } from '@adonisjs/lucid/types/model'
import type { OAuthGuardUser, OAuthUserProviderContract } from './types.ts'

/**
 * Options for the Lucid-based OAuth user provider.
 */
export type OAuthLucidUserProviderOptions<Model extends LucidModel> = {
  model: () => Promise<{ default: Model }>
}

/**
 * Lucid-based user provider for the OAuth guard.
 * Lazily loads the model and wraps instances as guard users.
 */
export class OAuthLucidUserProvider<Model extends LucidModel> implements OAuthUserProviderContract<
  InstanceType<Model>
> {
  declare [symbols.PROVIDER_REAL_USER]: InstanceType<Model>

  #model?: Model
  #options: OAuthLucidUserProviderOptions<Model>

  constructor(options: OAuthLucidUserProviderOptions<Model>) {
    this.#options = options
  }

  async #getModel(): Promise<Model> {
    if (this.#model && !('hot' in import.meta)) return this.#model
    this.#model = (await this.#options.model()).default

    return this.#model
  }

  async createUserForGuard(
    user: InstanceType<Model>
  ): Promise<OAuthGuardUser<InstanceType<Model>>> {
    const model = await this.#getModel()
    if (user instanceof model === false) {
      throw new RuntimeException(
        `Invalid user object. It must be an instance of the "${model.name}" model`
      )
    }

    return {
      getId() {
        if (!user.$primaryKeyValue) {
          throw new RuntimeException(
            `Cannot use "${model.name}" model for authentication. The value of column "${model.primaryKey}" is undefined or null`
          )
        }

        return user.$primaryKeyValue
      },
      getOriginal() {
        return user
      },
    }
  }

  async findById(
    identifier: string | number | BigInt
  ): Promise<OAuthGuardUser<InstanceType<Model>> | null> {
    const model = await this.#getModel()
    const user = await model.find(identifier)
    if (!user) return null

    return this.createUserForGuard(user as InstanceType<Model>)
  }
}
