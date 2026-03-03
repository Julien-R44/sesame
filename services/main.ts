import app from '@adonisjs/core/services/app'
import { SesameManager } from '../src/sesame_manager.ts'

let sesame: SesameManager

await app.booted(async () => {
  sesame = await app.container.make(SesameManager)
})

export { sesame as default }
