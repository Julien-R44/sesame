import { assert } from '@japa/assert'
import { apiClient } from '@japa/api-client'
import { expectTypeOf } from '@japa/expect-type'
import { configure, processCLIArgs, run } from '@japa/runner'

processCLIArgs(process.argv.splice(2))

configure({
  files: ['tests/**/*.spec.ts'],
  plugins: [assert(), expectTypeOf(), apiClient()],
})

await run()
