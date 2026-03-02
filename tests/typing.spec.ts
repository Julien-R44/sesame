import { test } from '@japa/runner'
import { defineConfig } from '../src/define_config.ts'
import { SesameManager } from '../src/sesame_manager.ts'
import { OAuthGuard } from '../src/guard/guard.ts'
import type { Scope, InferScopes, SesameScopes } from '../src/types.ts'

/**
 * Type-level tests for the Scope system.
 *
 * These tests are skipped at runtime — they only need to compile
 * (or fail to compile via @ts-expect-error) to validate the types.
 */
test.group('Typing | Scope types', () => {
  test('Scope falls back to string when SesameScopes is not augmented', ({ expectTypeOf }) => {
    expectTypeOf<Scope>().toEqualTypeOf<string>()
  }).skip()

  test('InferScopes extracts scope keys from typeof config', ({ expectTypeOf }) => {
    const config = defineConfig({
      issuer: 'https://example.com',
      scopes: { read: 'Read', write: 'Write' },
      loginPage: '/login',
      consentPage: '/consent',
    })

    type Scopes = InferScopes<typeof config>

    expectTypeOf<Scopes>().toHaveProperty('read')
    expectTypeOf<Scopes>().toHaveProperty('write')
    // @ts-expect-error - 'admin' is not a scope key
    expectTypeOf<Scopes>().toHaveProperty('admin')
  }).skip()

  test('SesameScopes is an empty interface by default', ({ expectTypeOf }) => {
    expectTypeOf<keyof SesameScopes>().toBeNever()
  }).skip()
})

test.group('Typing | defineConfig', () => {
  test('defaultScopes autocompletes from scopes keys', () => {
    defineConfig({
      issuer: 'https://example.com',
      scopes: { read: 'Read', write: 'Write', admin: 'Admin' },
      defaultScopes: ['read', 'write'],
      loginPage: '/login',
      consentPage: '/consent',
    })

    defineConfig({
      issuer: 'https://example.com',
      scopes: { read: 'Read', write: 'Write' },
      // @ts-expect-error - 'invalid' is not a key of scopes
      defaultScopes: ['invalid'],
      loginPage: '/login',
      consentPage: '/consent',
    })
  }).skip()

  test('return type preserves scopes object via intersection', ({ expectTypeOf }) => {
    const config = defineConfig({
      issuer: 'https://example.com',
      scopes: { read: 'Read', write: 'Write' },
      loginPage: '/login',
      consentPage: '/consent',
    })

    expectTypeOf(config.scopes).toHaveProperty('read')
    expectTypeOf(config.scopes).toHaveProperty('write')
  }).skip()

  test('return type is assignable to ResolvedSesameConfig', ({ expectTypeOf }) => {
    const config = defineConfig({
      issuer: 'https://example.com',
      scopes: { read: 'Read' },
      loginPage: '/login',
      consentPage: '/consent',
    })

    expectTypeOf(config).toExtend<ConstructorParameters<typeof SesameManager>[0]>()
  }).skip()

  test('scopes defaults to Record<string, string> when omitted', ({ expectTypeOf }) => {
    const config = defineConfig({
      issuer: 'https://example.com',
      loginPage: '/login',
      consentPage: '/consent',
    })

    expectTypeOf(config.scopes).toExtend<Record<string, string>>()
  }).skip()
})

test.group('Typing | SesameManager', () => {
  test('hasScope accepts Scope type', () => {
    const manager = new SesameManager(
      defineConfig({
        issuer: 'https://example.com',
        scopes: { read: 'Read' },
        loginPage: '/login',
        consentPage: '/consent',
      }),
      {} as any
    )

    // Without augmentation, Scope = string, so any string works
    manager.hasScope('anything')
  }).skip()

  test('validateScopes accepts Scope[] and returns string[]', ({ expectTypeOf }) => {
    const manager = new SesameManager(
      defineConfig({
        issuer: 'https://example.com',
        scopes: { read: 'Read' },
        loginPage: '/login',
        consentPage: '/consent',
      }),
      {} as any
    )

    expectTypeOf(manager.validateScopes(['x'])).toEqualTypeOf<string[]>()
  }).skip()
})

test.group('Typing | OAuthGuard', () => {
  test('guard.scopes is Scope[]', ({ expectTypeOf }) => {
    expectTypeOf<OAuthGuard<any>['scopes']>().toEqualTypeOf<Scope[]>()
  }).skip()

  test('hasScope accepts Scope params', ({ expectTypeOf }) => {
    expectTypeOf<OAuthGuard<any>['hasScope']>().parameters.toEqualTypeOf<Scope[]>()
  }).skip()

  test('hasAnyScope accepts Scope params', ({ expectTypeOf }) => {
    expectTypeOf<OAuthGuard<any>['hasAnyScope']>().parameters.toEqualTypeOf<Scope[]>()
  }).skip()
})
