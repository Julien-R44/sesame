# Sésame

<p align="center">
  <img src="docs/assets/sesame-logo-readme.png" alt="Sésame" width="560" />
</p>

OAuth 2.1 + OpenID Connect server for AdonisJS.

Sésame adds OAuth endpoints to your application. You keep your user accounts, login page, and consent UI.

- Authorization code flow with mandatory PKCE
- Refresh token rotation, replay detection, and grant revocation
- Bearer token authentication with type-safe scopes
- OpenID Connect, client credentials, and dynamic client registration
- MCP support and Lucid or Kysely storage

## Get started

Requires AdonisJS 7, Node.js 24 or later, and `@adonisjs/auth`.

With Lucid and a session guard already configured:

```bash
node ace add @julr/sesame
node ace migration:run
```

Then configure your issuer and scopes in `config/sesame.ts`, mount the OAuth routes, and connect your login and consent pages.

See the [getting started guide](https://sesame.julr.dev/guides/getting-started/) for the full setup, or the [Kysely guide](https://sesame.julr.dev/guides/install-kysely/) for a Lucid-free application.

## Documentation

[Read the documentation](https://sesame.julr.dev) for guides, API reference, and examples. Upgrading an existing installation? Follow the [0.8 migration guide](https://sesame.julr.dev/migrations/0-7-to-0-8/) or the [0.7 migration guide](https://sesame.julr.dev/migrations/0-6-to-0-7/).

## License

MIT
