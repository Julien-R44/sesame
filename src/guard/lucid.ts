import type { LucidModel } from '@adonisjs/lucid/types/model'
import { OAuthLucidUserProvider, type OAuthLucidUserProviderOptions } from './user_provider.ts'

export { OAuthLucidUserProvider } from './user_provider.ts'
export type { OAuthLucidUserProviderOptions } from './user_provider.ts'

/**
 * Create a Lucid-based user provider for the OAuth guard.
 */
export function oauthUserProvider<Model extends LucidModel>(
  options: OAuthLucidUserProviderOptions<Model>
): OAuthLucidUserProvider<Model> {
  return new OAuthLucidUserProvider(options)
}
