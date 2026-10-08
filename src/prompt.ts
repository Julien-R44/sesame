/**
 * OIDC `prompt` values acted upon by Sésame and advertised in
 * `prompt_values_supported`. Other values (`login`, `select_account`,
 * `create`) are accepted but ignored.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */
export const SUPPORTED_PROMPT_VALUES = ['none', 'consent']

/**
 * Parse the space-delimited, case-sensitive `prompt` parameter.
 */
export function parsePrompt(prompt?: string): Set<string> {
  return new Set(prompt?.split(' ').filter(Boolean) ?? [])
}
