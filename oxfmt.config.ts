import { julrPreset } from '@julr/tooling-configs/oxc/fmt'
import type { OxfmtConfig } from 'oxfmt'

const preset = julrPreset()

const config: OxfmtConfig = julrPreset({
  trailingComma: 'es5',
  arrowParens: 'always',
  sortPackageJson: false,
  overrides: [
    ...(preset.overrides ?? []),
    {
      files: ['website/src/content/docs/**/*.mdx'],
      options: { embeddedLanguageFormatting: 'off' },
    },
  ],
  ignorePatterns: [
    ...(preset.ignorePatterns ?? []),
    'docs/**',
    'coverage/**',
    '*.html',
    '.husky/**',
    'pnpm-lock.yaml',
    'website/.astro/**',
    'website/dist/**',
  ],
})

export default config
