import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'
import { docRedirects, legacyDocRedirects } from './src/integrations/legacy-doc-redirects.mjs'

const repository = 'https://github.com/Julien-R44/sesame'

export default defineConfig({
  site: 'https://sesame.julr.dev',
  redirects: docRedirects,
  /**
   * Serve the brand assets straight from `docs/assets` so the website
   * always uses the exact same logo files as the README.
   */
  publicDir: '../docs/assets',
  devToolbar: { enabled: false },
  server: { host: '127.0.0.1', port: 4321 },
  integrations: [
    starlight({
      title: 'Sésame',
      description: 'OAuth 2.1 + OIDC server for AdonisJS',
      favicon: '/sesame-icon.png',
      head: [
        {
          tag: 'link',
          attrs: {
            rel: 'icon',
            href: '/sesame-icon-white.png',
            media: '(prefers-color-scheme: dark)',
          },
        },
      ],
      social: [{ icon: 'github', label: 'GitHub', href: repository }],
      editLink: { baseUrl: `${repository}/edit/main/website/` },
      customCss: [
        '@fontsource-variable/geist',
        '@fontsource-variable/geist-mono',
        '@fontsource-variable/bricolage-grotesque',
        '@fontsource/instrument-serif/400-italic.css',
        './src/styles/theme.css',
      ],
      components: {
        Header: './src/components/Header.astro',
        SiteTitle: './src/components/SiteTitle.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
        Hero: './src/components/Hero.astro',
      },
      expressiveCode: {
        themes: ['vitesse-dark', 'vitesse-light'],
        styleOverrides: {
          borderRadius: 'var(--sesame-radius)',
          borderColor: 'var(--sesame-code-border)',
          codeFontFamily: 'var(--sl-font-mono)',
          codeFontSize: '0.8125rem',
          codeLineHeight: '1.7',
          codeBackground: 'var(--sesame-code-bg)',
          uiFontFamily: 'var(--sl-font)',
          focusBorder: 'var(--sl-color-accent)',
          frames: {
            editorBackground: 'var(--sesame-code-bg)',
            editorTabBarBackground: 'var(--sesame-code-chrome)',
            editorActiveTabBackground: 'var(--sesame-code-bg)',
            editorActiveTabIndicatorTopColor: 'var(--sl-color-accent)',
            editorActiveTabIndicatorBottomColor: 'transparent',
            editorTabBarBorderBottomColor: 'var(--sesame-code-border)',
            terminalBackground: 'var(--sesame-code-bg)',
            terminalTitlebarBackground: 'var(--sesame-code-chrome)',
            terminalTitlebarBorderBottomColor: 'var(--sesame-code-border)',
            terminalTitlebarDotsForeground: 'var(--sesame-code-dots)',
            terminalTitlebarDotsOpacity: '1',
            frameBoxShadowCssValue: 'none',
            inlineButtonBorder: 'var(--sesame-code-border)',
            tooltipSuccessBackground: 'var(--sl-color-accent)',
            tooltipSuccessForeground: 'var(--sl-color-black)',
          },
        },
      },
      sidebar: [
        {
          label: 'Start here',
          items: [{ slug: 'guides/getting-started' }, { slug: 'guides/install-kysely' }],
        },
        {
          label: 'Guides',
          items: [
            { slug: 'guides/manage-clients' },
            { slug: 'guides/login-and-consent' },
            { slug: 'guides/authorize-a-client' },
            { slug: 'guides/protect-api' },
            { slug: 'guides/manage-grants' },
            { slug: 'guides/manage-tokens' },
            { slug: 'guides/enable-oidc' },
            { slug: 'guides/client-credentials' },
            { slug: 'guides/mcp' },
          ],
        },
        {
          label: 'Advanced',
          items: [
            { slug: 'guides/dynamic-registration' },
            { slug: 'guides/client-metadata-documents' },
            { slug: 'guides/custom-user-provider' },
            { slug: 'guides/test-and-operate' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { slug: 'reference/configuration' },
            { slug: 'reference/endpoints' },
            { slug: 'reference/commands' },
            { slug: 'reference/api' },
            { slug: 'reference/errors' },
            { slug: 'reference/client-metadata-documents' },
            { slug: 'reference/storage' },
          ],
        },
        {
          label: 'Migrations',
          items: [{ slug: 'migrations/0-7-to-0-8' }, { slug: 'migrations/0-6-to-0-7' }],
        },
      ],
    }),
    legacyDocRedirects(),
  ],
})
