import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:https'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  ClientMetadataDocumentFetcher,
  ClientMetadataDocumentFetchError,
} from '../../src/client_id_metadata_documents/fetcher.ts'

const fixtures = new URL('../fixtures/tls/', import.meta.url)
const cert = await readFile(new URL('cert.pem', fixtures))
const key = await readFile(new URL('key.pem', fixtures))

type Handler = (req: IncomingMessage, res: ServerResponse) => void

const handlers: Record<string, Handler> = {
  '/client.json': (_req, res) => {
    res.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'public, max-age=600',
    })
    res.end(JSON.stringify({ client_id: 'x' }))
  },
  '/vendor.json': (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/oauth-client+json' })
    res.end('{"ok":true}')
  },
  '/redirect': (_req, res) => {
    res.writeHead(302, { location: '/client.json' })
    res.end()
  },
  '/missing': (_req, res) => {
    res.writeHead(404, { 'content-type': 'application/json' })
    res.end('{}')
  },
  '/html': (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<html></html>')
  },
  '/invalid-json': (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end('{nope')
  },
  '/announced-large': (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '10000' })
    res.end('x'.repeat(10_000))
  },
  '/streamed-large': (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.write(`"${'x'.repeat(3000)}`)
    setTimeout(() => res.end(`${'x'.repeat(3000)}"`), 20)
  },
  '/gzip': (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' })
    res.end('{}')
  },
  '/slow': () => {},
}

function startServer() {
  const server = createServer({ cert, key }, (req, res) => {
    const handler = handlers[req.url ?? ''] ?? handlers['/missing']
    handler(req, res)
  })

  return new Promise<Server>((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)))
}

test.group('CIMD | fetcher', (group) => {
  let server: Server
  let origin: string

  /**
   * Transport tests talk to a loopback server, so they explicitly
   * relax the address policy. SSRF tests use the default policy.
   */
  const trustingFetcher = new ClientMetadataDocumentFetcher({
    ca: cert,
    isAddressAllowed: () => true,
  })

  function fetchPath(path: string, fetcher = trustingFetcher) {
    return fetcher.fetch({
      url: new URL(path, origin),
      timeoutMs: 500,
      maxResponseSize: 5120,
    })
  }

  group.setup(async () => {
    server = await startServer()
    origin = `https://localhost:${(server.address() as AddressInfo).port}`

    return () => {
      server.closeAllConnections()
      server.close()
    }
  })

  test('fetches a JSON document with its cache headers', async ({ assert }) => {
    const result = await fetchPath('/client.json')

    assert.deepEqual(result.body, { client_id: 'x' })
    assert.equal(result.cacheControl, 'public, max-age=600')
  })

  test('accepts application/*+json media types', async ({ assert }) => {
    const result = await fetchPath('/vendor.json')

    assert.deepEqual(result.body, { ok: true })
  })

  test('rejects {0}')
    .with([
      ['redirects without following them', '/redirect', 'received HTTP 302'],
      ['non-200 responses', '/missing', 'received HTTP 404'],
      ['non-JSON media types', '/html', 'not served as JSON'],
      ['invalid JSON', '/invalid-json', 'not valid JSON'],
      ['an announced oversized body', '/announced-large', 'exceeds 5120 bytes'],
      ['a streamed oversized body', '/streamed-large', 'exceeds 5120 bytes'],
      ['encoded bodies', '/gzip', 'Encoded responses are not supported'],
      ['slow responses', '/slow', 'timed out after 500ms'],
    ])
    .run(async ({ assert }, [, path, message]) => {
      const error = await fetchPath(path).catch((err) => err)

      assert.instanceOf(error, ClientMetadataDocumentFetchError)
      assert.include(error.message, message)
    })

  test('blocks hosts resolving to loopback addresses (SSRF)', async ({ assert }) => {
    const error = await fetchPath(
      '/client.json',
      new ClientMetadataDocumentFetcher({ ca: cert })
    ).catch((err) => err)

    assert.instanceOf(error, ClientMetadataDocumentFetchError)
    assert.include(error.message, 'non-public address')
  })

  test('blocks IP literal {0} (SSRF)')
    .with(['https://127.0.0.1', 'https://[::1]', 'https://169.254.169.254', 'https://10.0.0.1'])
    .run(async ({ assert }, host) => {
      const fetcher = new ClientMetadataDocumentFetcher({ ca: cert })
      const error = await fetcher
        .fetch({ url: new URL(`${host}/client.json`), timeoutMs: 500, maxResponseSize: 5120 })
        .catch((err) => err)

      assert.instanceOf(error, ClientMetadataDocumentFetchError)
      assert.include(error.message, 'non-public address')
    })

  test('rejects untrusted certificates', async ({ assert }) => {
    const fetcher = new ClientMetadataDocumentFetcher({ isAddressAllowed: () => true })
    const error = await fetchPath('/client.json', fetcher).catch((err) => err)

    assert.instanceOf(error, ClientMetadataDocumentFetchError)
    assert.include(error.message, 'Request failed')
  })
})
