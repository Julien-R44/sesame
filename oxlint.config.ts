import { defineConfig } from 'oxlint'
import { julrPreset } from '@julr/tooling-configs/oxc/lint'

export default defineConfig({
  extends: [julrPreset({ adonisjs: true })],
  plugins: ['promise'],
  options: {
    typeAware: true,
  },
})
