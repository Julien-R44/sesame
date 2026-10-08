import { test } from '@japa/runner'
import { createTestConfig } from '../helpers/app.ts'

test.group('CIMD | config', () => {
  test('is disabled by default', ({ assert }) => {
    assert.isNull(createTestConfig().clientIdMetadataDocuments)
    assert.isNull(createTestConfig({ clientIdMetadataDocuments: false }).clientIdMetadataDocuments)
  })

  test('applies defaults when enabled with true', ({ assert }) => {
    const config = createTestConfig({ clientIdMetadataDocuments: true })

    assert.deepEqual(config.clientIdMetadataDocuments, {
      allowedHosts: null,
      cache: { minTtl: '5m', maxTtl: '24h' },
      fetchTimeout: '5s',
      maxResponseSize: 5120,
    })
  })

  test('merges custom options and lowercases allowed hosts', ({ assert }) => {
    const config = createTestConfig({
      clientIdMetadataDocuments: {
        allowedHosts: ['Claude.AI', '*.Example.com'],
        cache: { maxTtl: '1h' },
        fetchTimeout: '2s',
      },
    })

    assert.deepEqual(config.clientIdMetadataDocuments, {
      allowedHosts: ['claude.ai', '*.example.com'],
      cache: { minTtl: '5m', maxTtl: '1h' },
      fetchTimeout: '2s',
      maxResponseSize: 5120,
    })
  })
})
