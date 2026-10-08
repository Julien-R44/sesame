import { julrPreset } from '@julr/tooling-configs/oxc/fmt'
import type { OxfmtConfig } from 'oxfmt'

const preset = julrPreset()

const config: OxfmtConfig = julrPreset({
  trailingComma: 'es5',
  arrowParens: 'always',
  sortPackageJson: false,
  ignorePatterns: [
    ...(preset.ignorePatterns ?? []),
    'docs/**',
    'coverage/**',
    '*.html',
    '.husky/**',
    'pnpm-lock.yaml',
  ],
})

export default config
