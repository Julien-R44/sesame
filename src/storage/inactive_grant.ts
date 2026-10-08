/**
 * Thrown inside a store transaction when the grant a token issuance
 * extends was revoked or expired meanwhile, to roll the issuance back.
 */
export class InactiveGrantError extends Error {
  constructor() {
    super('Grant has been revoked or has expired')
  }
}

/**
 * Run a transactional issuance and report an inactive grant as `false`
 * instead of an error, like any other lost conditional write.
 */
export async function falseOnInactiveGrant(operation: () => Promise<boolean>): Promise<boolean> {
  try {
    return await operation()
  } catch (error) {
    if (error instanceof InactiveGrantError) return false

    throw error
  }
}
