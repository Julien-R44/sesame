/**
 * Prototype only: the content shared by the quick start variants.
 */
export const title = 'Two commands to open the door'
export const lead = 'Install Sésame, run the migrations and register your OAuth routes.'
export const guide = '/guides/getting-started/'

export const install = 'node ace add @julr/sesame'
export const migrate = 'node ace migration:run'

/** What `node ace add` writes, as the Adonis codemods print it. */
export const installOutput = [
  ['CREATE', 'config/sesame.ts'],
  ['CREATE', 'database/migrations/…_create_oauth_*_table.ts', '6 files'],
  ['UPDATE', 'adonisrc.ts', 'provider, commands'],
  ['UPDATE', 'start/kernel.ts', 'scopes, anyScope'],
] as const

export const tables = [
  'oauth_clients',
  'oauth_authorization_codes',
  'oauth_access_tokens',
  'oauth_refresh_tokens',
  'oauth_grants',
  'oauth_pending_authorization_requests',
]

export const routes = `import router from '@adonisjs/core/services/router'
import sesame from '@julr/sesame/services/main'

router.group(() => {
  sesame.registerRoutes()
}).prefix('/oauth')

sesame.registerDiscoveryRoutes()`

export const routesHtml = `<span class="k">import</span> router <span class="k">from</span> <span class="s">'@adonisjs/core/services/router'</span>
<span class="k">import</span> sesame <span class="k">from</span> <span class="s">'@julr/sesame/services/main'</span>

router.<span class="f">group</span>(() =&gt; {
  sesame.<span class="f">registerRoutes</span>()     <span class="c">// /oauth/authorize, /oauth/token…</span>
}).<span class="f">prefix</span>(<span class="s">'/oauth'</span>)

sesame.<span class="f">registerDiscoveryRoutes</span>()  <span class="c">// /.well-known/*, JWKS</span>`
