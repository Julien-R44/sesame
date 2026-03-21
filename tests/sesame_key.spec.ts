import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { test } from '@japa/runner'
import { importJWK, generateKeyPair, exportJWK } from 'jose'
import { AceFactory } from '@adonisjs/core/factories'
import SesameKey from '../commands/sesame_key.ts'

test.group('sesame:key command', () => {
  test('default output exits successfully', async ({ assert }) => {
    const ace = await new AceFactory().make(new URL('./', import.meta.url))
    await ace.boot()

    const command = await ace.create(SesameKey, [])
    await command.exec()

    assert.equal(command.exitCode, 0)
  })

  test('--raw outputs valid parseable JWK JSON', async ({ assert }) => {
    const ace = await new AceFactory().make(new URL('./', import.meta.url))
    await ace.boot()

    let output = ''
    const originalWrite = process.stdout.write.bind(process.stdout)
    process.stdout.write = (chunk: any) => {
      output += chunk.toString()
      return true
    }

    try {
      const command = await ace.create(SesameKey, ['--raw'])
      await command.exec()

      assert.equal(command.exitCode, 0)

      const jwk = JSON.parse(output.trim())
      assert.equal(jwk.kty, 'RSA')
      assert.isDefined(jwk.d)

      const key = await importJWK(jwk, 'RS256')
      assert.isDefined(key)
    } finally {
      process.stdout.write = originalWrite
    }
  })

  test('--write-env creates .env when it does not exist', async ({ assert, cleanup }) => {
    const tmp = await mkdtemp(join(tmpdir(), 'sesame-key-'))
    cleanup(() => rm(tmp, { recursive: true }))

    const ace = await new AceFactory().make(new URL(`file://${tmp}/`))
    await ace.boot()

    const command = await ace.create(SesameKey, ['--write-env'])
    await command.exec()

    assert.equal(command.exitCode, 0)

    const content = await readFile(join(tmp, '.env'), 'utf-8')
    assert.match(content, /^OIDC_JWK='{"kty":"RSA"/)
  })

  test('--write-env appends to existing .env', async ({ assert, cleanup }) => {
    const tmp = await mkdtemp(join(tmpdir(), 'sesame-key-'))
    cleanup(() => rm(tmp, { recursive: true }))

    await writeFile(join(tmp, '.env'), 'APP_KEY=some-key\nPORT=3333\n')

    const ace = await new AceFactory().make(new URL(`file://${tmp}/`))
    await ace.boot()

    const command = await ace.create(SesameKey, ['--write-env'])
    await command.exec()

    const content = await readFile(join(tmp, '.env'), 'utf-8')
    assert.include(content, 'APP_KEY=some-key')
    assert.include(content, 'PORT=3333')
    assert.match(content, /OIDC_JWK='{"kty":"RSA"/)
  })

  test('--write-env replaces existing OIDC_JWK', async ({ assert, cleanup }) => {
    const tmp = await mkdtemp(join(tmpdir(), 'sesame-key-'))
    cleanup(() => rm(tmp, { recursive: true }))

    await writeFile(join(tmp, '.env'), 'APP_KEY=some-key\nOIDC_JWK=old-value\nPORT=3333\n')

    const ace = await new AceFactory().make(new URL(`file://${tmp}/`))
    await ace.boot()

    const command = await ace.create(SesameKey, ['--write-env'])
    await command.exec()

    const content = await readFile(join(tmp, '.env'), 'utf-8')
    assert.notInclude(content, 'old-value')
    assert.match(content, /OIDC_JWK='{"kty":"RSA"/)
    assert.include(content, 'APP_KEY=some-key')
    assert.include(content, 'PORT=3333')

    // Only one OIDC_JWK line
    const matches = content.match(/^OIDC_JWK=/gm)
    assert.lengthOf(matches!, 1)
  })

  test('generates a valid RS256 JWK that can be re-imported', async ({ assert }) => {
    const { privateKey } = await generateKeyPair('RS256', { extractable: true })
    const jwk = await exportJWK(privateKey)

    assert.equal(jwk.kty, 'RSA')
    assert.isDefined(jwk.n)
    assert.isDefined(jwk.e)
    assert.isDefined(jwk.d)
    assert.isDefined(jwk.p)
    assert.isDefined(jwk.q)
    assert.isDefined(jwk.dp)
    assert.isDefined(jwk.dq)
    assert.isDefined(jwk.qi)

    const key = await importJWK(jwk, 'RS256')
    assert.isDefined(key)
  })
})
