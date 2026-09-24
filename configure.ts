import type Configure from '@adonisjs/core/commands/configure'
import { join } from 'node:path'

export async function configure(command: Configure) {
  const codemods = await command.createCodemods()
  const stubsRoot = join(import.meta.dirname, 'stubs')
  const store = command.parsedFlags.store ?? 'lucid'
  if (store !== 'lucid' && store !== 'kysely') {
    throw new Error('Invalid Sesame store. Use --store=lucid or --store=kysely')
  }

  // Publish config stub
  const configStub = store === 'kysely' ? 'config/sesame_kysely.stub' : 'config/sesame.stub'
  await codemods.makeUsingStub(stubsRoot, configStub, {})

  // Publish migration stubs
  const lucidMigrations = [
    'migrations/create_oauth_clients_table.stub',
    'migrations/create_oauth_authorization_codes_table.stub',
    'migrations/create_oauth_access_tokens_table.stub',
    'migrations/create_oauth_refresh_tokens_table.stub',
    'migrations/create_oauth_consents_table.stub',
    'migrations/create_oauth_pending_authorization_requests_table.stub',
  ]
  const migrationStubs =
    store === 'kysely' ? ['migrations/kysely/create_oauth_tables.stub'] : lucidMigrations

  for (const stub of migrationStubs) {
    await codemods.makeUsingStub(stubsRoot, stub, {})
  }

  // Register provider and commands
  await codemods.updateRcFile((rcFile) => {
    rcFile.addProvider('@julr/sesame/sesame_provider').addCommand('@julr/sesame/commands')
  })

  // Register named middleware
  await codemods.registerMiddleware('named', [
    {
      name: 'scopes',
      path: '@julr/sesame/scope_middleware',
    },
    {
      name: 'anyScope',
      path: '@julr/sesame/any_scope_middleware',
    },
  ])
}
