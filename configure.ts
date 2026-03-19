import type Configure from '@adonisjs/core/commands/configure'
import { join } from 'node:path'

export async function configure(command: Configure) {
  const codemods = await command.createCodemods()
  const stubsRoot = join(import.meta.dirname, 'stubs')

  // Publish config stub
  await codemods.makeUsingStub(stubsRoot, 'config/sesame.stub', {})

  // Publish migration stubs
  const migrationStubs = [
    'migrations/create_oauth_clients_table.stub',
    'migrations/create_oauth_authorization_codes_table.stub',
    'migrations/create_oauth_access_tokens_table.stub',
    'migrations/create_oauth_refresh_tokens_table.stub',
    'migrations/create_oauth_consents_table.stub',
    'migrations/create_oauth_pending_authorization_requests_table.stub',
  ]

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
