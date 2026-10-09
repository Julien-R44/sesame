import { writeFile } from 'node:fs/promises'

export const docRedirects = {
  '/guides/install-lucid/': '/guides/getting-started/#install-the-package',
  '/guides/configure-server/': '/guides/getting-started/#configure-the-server',
  '/guides/register-routes/': '/guides/getting-started/#register-the-routes',
  '/guides/custom-consent/': '/guides/login-and-consent/#customize-the-decision',
  '/guides/authorization-prompts/': '/guides/authorize-a-client/#control-browser-interaction',
  '/guides/resource-indicators/': '/guides/protect-api/#enforce-a-resource-audience',
  '/guides/custom-metadata-fetcher/':
    '/guides/client-metadata-documents/#configure-a-development-fetcher',
  '/explanations/inertia-redirects/': '/guides/login-and-consent/#submit-from-inertia',
  '/explanations/oauth-and-identity/': '/guides/enable-oidc/',
  '/explanations/token-lifecycle/': '/guides/manage-tokens/#rotation-and-replay',
  '/guides/migrate-to-0-7/': '/migrations/0-6-to-0-7/',
}

export function legacyDocRedirects() {
  return {
    name: 'legacy-doc-redirects',
    hooks: {
      'astro:build:done': async ({ dir }) => {
        const rules = Object.entries(docRedirects).flatMap(([source, destination]) => [
          `${source} ${destination} 301`,
          `${source.slice(0, -1)} ${destination} 301`,
        ])

        await writeFile(new URL('_redirects', dir), `${rules.join('\n')}\n`)
      },
    },
  }
}
