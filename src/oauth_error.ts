/**
 * OAuth 2.0 error classes following the error codes defined in
 * RFC 6749 §5.2 (https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)
 * and RFC 7591 §3.2.2 (https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2).
 *
 * Each error class extends AdonisJS Exception and self-renders via
 * the `handle()` method, producing a standard OAuth JSON error response.
 */

import { Exception } from '@adonisjs/core/exceptions'
import type { HttpContext } from '@adonisjs/core/http'

/**
 * Base class for all OAuth errors. Extends AdonisJS Exception
 * and renders the standard OAuth error response format:
 * `{ error: "<oauth_code>", error_description: "<message>" }`.
 *
 * Subclasses declare a static `oauthCode` matching the `error` field
 * defined by the OAuth 2.0 spec (e.g. `invalid_request`, `invalid_client`).
 */
export class OAuthError extends Exception {
  static oauthCode: string

  get oauthCode(): string {
    return (this.constructor as typeof OAuthError).oauthCode
  }

  handle(error: this, ctx: HttpContext) {
    ctx.response.status(error.status).json({
      error: error.oauthCode,
      error_description: error.message,
    })
  }
}

/**
 * The request is missing a required parameter, includes an unsupported
 * parameter value, repeats a parameter, or is otherwise malformed.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const E_INVALID_REQUEST = class extends OAuthError {
  static readonly status: number = 400
  static readonly code: string = 'E_INVALID_REQUEST'
  static readonly message: string = 'Invalid request'
  static readonly oauthCode: string = 'invalid_request'
}

/**
 * Client authentication failed (e.g. unknown client, no client
 * authentication included, or unsupported authentication method).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const E_INVALID_CLIENT = class extends OAuthError {
  static readonly status: number = 401
  static readonly code: string = 'E_INVALID_CLIENT'
  static readonly message: string = 'Invalid client'
  static readonly oauthCode: string = 'invalid_client'

  /**
   * If the client attempted to authenticate via the Authorization header
   * (Basic auth), the server MUST include WWW-Authenticate: Basic.
   *
   * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-3.2.4
   */
  handle(error: this, ctx: HttpContext) {
    const authHeader = ctx.request.header('authorization')
    if (authHeader?.startsWith('Basic ')) {
      ctx.response.header('WWW-Authenticate', 'Basic')
    }

    super.handle(error, ctx)
  }
}

/**
 * The provided authorization grant (authorization code, refresh token,
 * resource owner credentials) is invalid, expired, revoked, or does
 * not match the redirection URI used in the authorization request.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const E_INVALID_GRANT = class extends OAuthError {
  static readonly status: number = 400
  static readonly code: string = 'E_INVALID_GRANT'
  static readonly message: string = 'Invalid grant'
  static readonly oauthCode: string = 'invalid_grant'
}

/**
 * The requested scope is invalid, unknown, malformed, or exceeds
 * the scope granted by the resource owner.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const E_INVALID_SCOPE = class extends OAuthError {
  static readonly status: number = 400
  static readonly code: string = 'E_INVALID_SCOPE'
  static readonly message: string = 'Invalid scope'
  static readonly oauthCode: string = 'invalid_scope'
}

/**
 * The access token provided is expired, revoked, malformed,
 * or invalid for other reasons.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 */
export const E_INVALID_TOKEN = class extends OAuthError {
  static readonly status: number = 401
  static readonly code: string = 'E_INVALID_TOKEN'
  static readonly message: string = 'Invalid token'
  static readonly oauthCode: string = 'invalid_token'
}

/**
 * The authorization grant type is not supported by the
 * authorization server.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const E_UNSUPPORTED_GRANT_TYPE = class extends OAuthError {
  static readonly status: number = 400
  static readonly code: string = 'E_UNSUPPORTED_GRANT_TYPE'
  static readonly message: string = 'Unsupported grant type'
  static readonly oauthCode: string = 'unsupported_grant_type'
}

/**
 * The authorization server does not support obtaining an
 * authorization code using this response type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
export const E_UNSUPPORTED_RESPONSE_TYPE = class extends OAuthError {
  static readonly status: number = 400
  static readonly code: string = 'E_UNSUPPORTED_RESPONSE_TYPE'
  static readonly message: string = 'Unsupported response type'
  static readonly oauthCode: string = 'unsupported_response_type'
}

/**
 * The resource owner or authorization server denied the request.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
export const E_ACCESS_DENIED = class extends OAuthError {
  static readonly status: number = 403
  static readonly code: string = 'E_ACCESS_DENIED'
  static readonly message: string = 'Access denied'
  static readonly oauthCode: string = 'access_denied'
}

/**
 * The client metadata value is invalid, as defined in the dynamic
 * client registration protocol.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
 */
export const E_INVALID_CLIENT_METADATA = class extends OAuthError {
  static readonly status: number = 400
  static readonly code: string = 'E_INVALID_CLIENT_METADATA'
  static readonly message: string = 'Invalid client metadata'
  static readonly oauthCode: string = 'invalid_client_metadata'
}

/**
 * The authorization server encountered an unexpected condition
 * that prevented it from fulfilling the request.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
export const E_SERVER_ERROR = class extends OAuthError {
  static readonly status: number = 500
  static readonly code: string = 'E_SERVER_ERROR'
  static readonly message: string = 'Server error'
  static readonly oauthCode: string = 'server_error'
}

/**
 * The access token does not have the required scope(s) to access
 * the protected resource. Returns 403 with a WWW-Authenticate header
 * per RFC 6750 §3.1.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 */
export const E_INSUFFICIENT_SCOPE = class extends OAuthError {
  static readonly status: number = 403
  static readonly code: string = 'E_INSUFFICIENT_SCOPE'
  static readonly message: string = 'Insufficient scope'
  static readonly oauthCode: string = 'insufficient_scope'

  missingScopes: string[]

  constructor(missingScopes: string[], message?: string) {
    super(message ?? 'The token does not have the required scope(s)')
    this.missingScopes = missingScopes
  }

  handle(error: this, ctx: HttpContext) {
    const scope = error.missingScopes.join(' ')
    ctx.response.header(
      'WWW-Authenticate',
      `Bearer error="insufficient_scope", error_description="${error.message}", scope="${scope}"`
    )

    super.handle(error, ctx)
  }
}
