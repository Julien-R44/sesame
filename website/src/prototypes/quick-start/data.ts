/**
 * Prototype only: the content shared by the quick start variants.
 */
export const title = 'Two commands to open the door'
export const lead = 'Install Sésame, run the migrations and register your OAuth routes.'
export const guide = '/guides/getting-started/'

export const install = 'node ace add @julr/sesame'
export const migrate = 'node ace migration:run'

export const commands = [
  { command: install, note: 'config/sesame.ts, migrations, provider, scope middleware' },
  { command: migrate, note: 'clients, codes, tokens, grants, pending requests' },
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
