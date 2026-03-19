import { OAuthClient } from '../../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../../src/models/oauth_refresh_token.ts'
import { OAuthConsent } from '../../src/models/oauth_consent.ts'
import { OAuthPendingAuthorizationRequest } from '../../src/models/oauth_pending_authorization_request.ts'

/**
 * Returns a cleanup function that deletes all OAuth models.
 *
 * Usage: `group.each.setup(cleanModels())`
 *
 * Deletion order respects foreign key dependencies.
 */
export function cleanModels() {
  return async () => {
    await OAuthPendingAuthorizationRequest.query().delete()
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  }
}
