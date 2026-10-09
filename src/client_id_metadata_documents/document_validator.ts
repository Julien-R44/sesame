import vine from '@vinejs/vine'
import type { Infer } from '@vinejs/vine/types'
import { E_INVALID_CLIENT } from '../oauth_error.ts'
import { metadataUriRule, redirectUriRule } from '../rules.ts'

const httpsUri = vine
  .string()
  .url({ require_protocol: true, protocols: ['https'] })
  .use(metadataUriRule())
  .optional()

/**
 * Shape of a Client ID Metadata Document. Unknown properties are allowed
 * since documents are shared by every authorization server.
 */
const clientMetadataDocumentValidator = vine.create(
  vine
    .object({
      client_id: vine.string(),
      client_name: vine.string().trim().minLength(1).maxLength(255),
      redirect_uris: vine.array(vine.string().use(redirectUriRule())).minLength(1),
      token_endpoint_auth_method: vine.string().optional(),
      grant_types: vine.array(vine.string()).optional(),
      response_types: vine.array(vine.string()).optional(),
      scope: vine.string().optional(),
      client_uri: httpsUri,
      logo_uri: httpsUri,
      tos_uri: httpsUri,
      policy_uri: httpsUri,
      software_id: vine.string().maxLength(255).optional(),
      software_version: vine.string().maxLength(255).optional(),
    })
    .allowUnknownProperties()
)

export type ClientMetadataDocument = Infer<typeof clientMetadataDocumentValidator>

/**
 * Symmetric secrets cannot exist for a client that was never registered.
 */
const FORBIDDEN_PROPERTIES = ['client_secret', 'client_secret_expires_at']

/**
 * Explain why `token_endpoint_auth_method` is rejected. A missing value
 * is treated as `none`.
 */
const UNSUPPORTED_AUTH_METHODS: Record<string, string> = {
  private_key_jwt: 'private_key_jwt client authentication is not supported',
}

function invalidDocument(description: string) {
  return new E_INVALID_CLIENT(`Invalid client metadata document: ${description}`)
}

/**
 * Checks done before the schema validation: identity and authentication
 * constraints from the specification.
 */
function assertDocumentIdentity(options: { body: Record<string, unknown>; clientId: string }) {
  if (options.body.client_id !== options.clientId) {
    throw invalidDocument('client_id does not match the document URL')
  }

  const forbidden = FORBIDDEN_PROPERTIES.find((property) => property in options.body)
  if (forbidden) throw invalidDocument(`${forbidden} must not be present`)

  const authMethod = options.body.token_endpoint_auth_method
  if (authMethod === undefined || authMethod === 'none') return

  const reason =
    typeof authMethod === 'string' && Object.hasOwn(UNSUPPORTED_AUTH_METHODS, authMethod)
      ? UNSUPPORTED_AUTH_METHODS[authMethod]
      : 'token_endpoint_auth_method must be "none"'

  throw invalidDocument(reason)
}

/**
 * Validate a fetched Client ID Metadata Document against the requested
 * client identifier. Throws `E_INVALID_CLIENT` describing the problem.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-4
 * @see https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-id-metadata-documents
 */
export async function validateClientMetadataDocument(options: {
  body: unknown
  clientId: string
}): Promise<ClientMetadataDocument> {
  const body = options.body
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw invalidDocument('document must be a JSON object')
  }

  assertDocumentIdentity({ body: body as Record<string, unknown>, clientId: options.clientId })

  const [error, document] = await clientMetadataDocumentValidator.tryValidate(body)
  if (error) throw invalidDocument(error.messages[0]?.message ?? 'invalid metadata')

  if (document.response_types && !document.response_types.includes('code')) {
    throw invalidDocument('response_types must include "code"')
  }

  return document
}
