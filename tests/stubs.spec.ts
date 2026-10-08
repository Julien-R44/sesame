import { readdir } from 'node:fs/promises'
import { test } from '@japa/runner'
import { IgnitorFactory } from '@adonisjs/core/factories'

const STUBS_ROOT = new URL('../stubs/', import.meta.url)

/**
 * Boot a throwaway console app able to render package stubs.
 */
async function createStubsManager() {
  const app = new IgnitorFactory()
    .withCoreProviders()
    .withCoreConfig()
    .create(new URL('file:///tmp/sesame-stubs-app/'))
    .createApp('console')
  await app.init()
  await app.boot()

  return { app, stubs: await app.stubs.create() }
}

test.group('Lucid migration stubs', () => {
  test('render every migration into the migrations folder', async ({ assert }) => {
    const { app, stubs } = await createStubsManager()
    const files = (await readdir(new URL('migrations/', STUBS_ROOT))).filter((file) =>
      file.endsWith('.stub')
    )

    for (const file of files) {
      const stub = await stubs.build(`migrations/${file}`, { source: STUBS_ROOT.pathname })
      const output = await stub.prepare({ prefix: 1700000000000 })

      assert.equal(
        output.destination,
        app.migrationsPath(`1700000000000_${file.replace('.stub', '.ts')}`)
      )
      assert.match(output.contents, /^import \{ BaseSchema \} from '@adonisjs\/lucid\/schema'/)
    }
  })
})
