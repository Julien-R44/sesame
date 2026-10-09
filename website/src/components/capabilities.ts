export const cards = [
  {
    id: 'pkce',
    title: 'PKCE, for every client',
    text: 'S256 proof on every authorization request. Public or confidential.',
    tag: 'S256',
    href: '/guides/authorize-a-client/',
  },
  {
    id: 'rotation',
    title: 'Refresh. Rotate. Repeat.',
    text: 'New refresh tokens on use. Replay detection after the grace window.',
    tag: 'Token rotation',
    href: '/guides/manage-tokens/#rotation-and-replay',
  },
  {
    id: 'oidc',
    title: 'Identity, when you need it',
    text: 'Add OpenID Connect for signed ID tokens, UserInfo and JWKS.',
    tag: 'OpenID Connect',
    href: '/guides/enable-oidc/',
  },
  {
    id: 'stores',
    title: 'Your database. Your choice.',
    text: 'Use Lucid, Kysely, or implement your own storage driver.',
    tag: 'Lucid · Kysely',
    href: '/guides/install-kysely/',
  },
  {
    id: 'mcp',
    title: 'Ready for MCP',
    text: 'Resource discovery and dynamic registration for MCP clients.',
    tag: 'RFC 9728 · RFC 7591',
    href: '/guides/mcp/',
  },
  {
    id: 'hashed',
    title: 'Secrets stay secret',
    text: 'Tokens, authorization codes and client secrets are hashed at rest.',
    tag: 'SHA-256',
    href: '/guides/manage-tokens/#token-storage',
  },
]
