import type { DateTime } from 'luxon'
import type { GrantContext } from '../types.ts'

/**
 * Stored OAuth client. `clientSecret` is a hash and must never be exposed
 * in public responses.
 */
export interface OAuthClientRecord {
  id: string
  clientId: string
  clientSecret: string | null
  name: string
  redirectUris: string[]
  scopes: string[]
  grantTypes: string[]
  isPublic: boolean
  isDisabled: boolean
  requirePkce: boolean
  type: string | null
  metadata: Record<string, any> | null
  userId: string | null
  createdAt: DateTime
  updatedAt: DateTime
}

/**
 * One authorization given by a user to a client. Codes and tokens issued
 * from it reference it through `grantId`, so revoking the grant revokes
 * them all. `expiresAt` slides with the latest token issued.
 */
export interface OAuthGrantRecord {
  id: string
  clientId: string
  userId: string
  scopes: string[]
  context: GrantContext | null
  expiresAt: DateTime
  createdAt: DateTime
  updatedAt: DateTime
}

/**
 * `grantId` is null for client_credentials tokens and tokens issued before grants existed.
 */
export interface OAuthAccessTokenRecord {
  id: string
  tokenHash: string
  clientId: string
  userId: string | null
  grantId: string | null
  scopes: string[]
  expiresAt: DateTime
  revokedAt: DateTime | null
  createdAt: DateTime
  updatedAt: DateTime
}

export interface OAuthRefreshTokenRecord {
  id: string
  token: string
  accessTokenId: string
  clientId: string
  userId: string
  grantId: string | null
  scopes: string[]
  expiresAt: DateTime
  revokedAt: DateTime | null
  createdAt: DateTime
  updatedAt: DateTime
}

export interface OAuthAuthorizationCodeRecord {
  id: string
  code: string
  clientId: string
  userId: string
  grantId: string | null
  scopes: string[]
  redirectUri: string
  codeChallenge: string | null
  codeChallengeMethod: string | null
  nonce: string | null
  consumedAt: DateTime | null
  expiresAt: DateTime
  createdAt: DateTime
  updatedAt: DateTime
}

/**
 * Access token joined with its grant, so the guard reads both in one query.
 * `grant` is null when the token has no grant or its grant was revoked.
 */
export interface OAuthAccessTokenWithGrantRecord extends OAuthAccessTokenRecord {
  grant: OAuthGrantRecord | null
}

export interface OAuthPendingAuthorizationRequestRecord {
  id: string
  token: string
  userId: string
  clientId: string
  redirectUri: string
  scopes: string[]
  state: string | null
  codeChallenge: string | null
  codeChallengeMethod: string | null
  nonce: string | null
  expiresAt: DateTime
  createdAt: DateTime
}

type SesameOptionalCreateKeys<T> =
  | Extract<keyof T, 'createdAt' | 'updatedAt'>
  | { [K in keyof T]-?: null extends T[K] ? K : never }[keyof T]

/**
 * Nullable fields default to null; timestamps default to the current time.
 */
export type SesameCreateRecord<T> = Omit<T, SesameOptionalCreateKeys<T>> &
  Partial<Pick<T, SesameOptionalCreateKeys<T>>>

/**
 * Creation input for each persisted OAuth record.
 */
export type CreateClientRecord = SesameCreateRecord<OAuthClientRecord>
export type CreateGrantRecord = SesameCreateRecord<OAuthGrantRecord>
export type CreateAccessTokenRecord = SesameCreateRecord<OAuthAccessTokenRecord>
export type CreateRefreshTokenRecord = SesameCreateRecord<OAuthRefreshTokenRecord>
export type CreateAuthorizationCodeRecord = SesameCreateRecord<OAuthAuthorizationCodeRecord>
export type CreatePendingAuthorizationRequestRecord =
  SesameCreateRecord<OAuthPendingAuthorizationRequestRecord>

export type UpdateClientRecord = Partial<
  Pick<
    OAuthClientRecord,
    'name' | 'redirectUris' | 'scopes' | 'grantTypes' | 'isDisabled' | 'requirePkce' | 'metadata'
  >
>

export type UpdateGrantRecord = Partial<Pick<OAuthGrantRecord, 'context'>>

export interface SesamePurgeResult {
  accessTokens: number
  refreshTokens: number
  authorizationCodes: number
  pendingRequests: number
  grants: number
}

/**
 * Pre-grant credentials attached to a newly created grant, so a later
 * replay of them revokes that grant. Only rows whose grant_id is null change.
 */
export interface GrantAdoption {
  codeId?: string
  refreshTokenId?: string
  accessTokenId?: string
}

/**
 * Grant change applied in the same transaction as a token issuance.
 *
 * - `extend`: the grant must exist and be active, otherwise the whole
 *   issuance fails. Its expiry moves to `expiresAt` but never backwards.
 * - `create`: tokens issued before grants existed get a new grant, and
 *   the presented credentials are adopted into it.
 */
export type TokenGrantWrite =
  | { type: 'extend'; id: string; expiresAt: DateTime }
  | { type: 'create'; grant: CreateGrantRecord; adopt: GrantAdoption }

export interface IssueTokenPairOptions {
  accessToken: CreateAccessTokenRecord
  refreshToken: CreateRefreshTokenRecord
  grant?: TokenGrantWrite
}

/**
 * Mark a code consumed (it is kept to detect reuse) and issue its tokens.
 */
export interface ExchangeAuthorizationCodeOptions {
  codeId: string
  consumedAt: DateTime
  accessToken: CreateAccessTokenRecord
  refreshToken: CreateRefreshTokenRecord | null
  grant?: TokenGrantWrite
}

export interface RotateRefreshTokenOptions extends IssueTokenPairOptions {
  oldRefreshTokenId: string
  oldAccessTokenId: string
  revokedAt: DateTime
}

export interface PurgeTokensOptions {
  purgeRevoked: boolean
  purgeExpired: boolean
  cutoff: DateTime
  now: DateTime
}

/**
 * Select dynamically registered clients created before `createdBefore`
 * that have no token, authorization code, consent, or pending request.
 */
export interface PurgeUnusedClientsOptions {
  createdBefore: DateTime
}

/**
 * Look up an owner's unexpired pending request using its stored token hash.
 */
export interface PendingAuthorizationRequestLookupOptions {
  token: string
  userId: string
  now: DateTime
}

/**
 * List a user's grants, newest first. `activeAt` keeps only grants expiring after it.
 */
export interface ListStoredGrantsOptions {
  userId: string
  clientId?: string
  activeAt?: DateTime
}

/**
 * OAuth-specific persistence operations. Callers never build database predicates.
 * Conditional exchanges, rotations, and issuances return false when another
 * request won or when the grant they extend is no longer active.
 */
export interface SesameStore {
  findClient(clientId: string): Promise<OAuthClientRecord | null>
  listClients(options?: { userId?: string }): Promise<OAuthClientRecord[]>
  createClient(data: CreateClientRecord): Promise<OAuthClientRecord>
  updateClient(options: { id: string; data: UpdateClientRecord }): Promise<void>
  updateClientSecret(options: { id: string; secret: string }): Promise<void>
  deleteClient(clientId: string): Promise<boolean>

  findAccessToken(options: {
    hash: string
    clientId?: string
  }): Promise<OAuthAccessTokenWithGrantRecord | null>
  createAccessToken(data: CreateAccessTokenRecord): Promise<void>
  revokeAccessToken(options: { hash: string; clientId: string; now: DateTime }): Promise<boolean>

  findRefreshToken(options: {
    hash: string
    clientId: string
  }): Promise<OAuthRefreshTokenRecord | null>
  revokeRefreshToken(options: { hash: string; clientId: string; now: DateTime }): Promise<void>
  /**
   * Replay detection for tokens without a grant: delete the refresh tokens
   * and revoke the access tokens of the client and user whose grant_id is null.
   */
  revokeLegacyTokenFamily(options: {
    clientId: string
    userId: string
    now: DateTime
  }): Promise<void>

  findAuthorizationCode(options: {
    code: string
    clientId: string
  }): Promise<OAuthAuthorizationCodeRecord | null>
  createAuthorizationCode(data: CreateAuthorizationCodeRecord): Promise<void>
  deleteAuthorizationCode(id: string): Promise<void>
  exchangeAuthorizationCode(options: ExchangeAuthorizationCodeOptions): Promise<boolean>

  createGrant(data: CreateGrantRecord): Promise<void>
  findGrant(id: string): Promise<OAuthGrantRecord | null>
  listGrants(options: ListStoredGrantsOptions): Promise<OAuthGrantRecord[]>
  updateGrant(options: { id: string; data: UpdateGrantRecord }): Promise<void>
  /**
   * Delete the grant with its codes and refresh tokens, and revoke its
   * access tokens. Returns false when the grant did not exist.
   */
  revokeGrant(options: { id: string; now: DateTime }): Promise<boolean>
  /**
   * Revoke every grant of a user (optionally for one client) like `revokeGrant`.
   * Returns the number of revoked grants.
   */
  revokeGrants(options: { userId: string; clientId?: string; now: DateTime }): Promise<number>

  createPendingAuthorizationRequest(data: CreatePendingAuthorizationRequestRecord): Promise<void>
  findPendingAuthorizationRequest(
    options: PendingAuthorizationRequestLookupOptions
  ): Promise<OAuthPendingAuthorizationRequestRecord | null>
  consumePendingAuthorizationRequest(
    options: PendingAuthorizationRequestLookupOptions
  ): Promise<OAuthPendingAuthorizationRequestRecord | null>

  issueTokenPair(options: IssueTokenPairOptions): Promise<boolean>
  rotateRefreshToken(options: RotateRefreshTokenOptions): Promise<boolean>
  revokeAllForUser(options: { userId: string; now: DateTime }): Promise<void>
  purgeTokens(options: PurgeTokensOptions): Promise<SesamePurgeResult>
  purgeUnusedClients(options: PurgeUnusedClientsOptions): Promise<number>
}
