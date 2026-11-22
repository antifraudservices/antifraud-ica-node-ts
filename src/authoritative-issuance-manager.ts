import {createPublicKey, verify, type JsonWebKey} from 'node:crypto'

import {
  defineCredentialIssuanceRequest,
  type CredentialIssuanceRequest,
} from 'antifraud-data-utils-ts'

export interface IssuanceCommand extends CredentialIssuanceRequest {
  actorReference: string
}

export class OpenId4VciProofError extends Error {
  constructor(message: string, readonly code: 'invalid_proof' | 'invalid_nonce' = 'invalid_proof') {
    super(message)
  }
}

export class CredentialIssuanceDeniedError extends Error {}

export interface OpenId4VciOfferBinding {
  credentialIssuer: string
  /** Atomically consumes a valid nonce within the authorized offer and actor scope. */
  consumeNonce(nonce: string, command: IssuanceCommand): Promise<boolean>
}

export interface AuthorizationDecision {
  allowed: boolean
  reason?: string
}

export interface VerificationDecision {
  verified: boolean
  reason?: string
}

export interface AuthoritativeSubject {
  sourceId: string
  claims: Readonly<Record<string, unknown>>
}

export interface PolicyDecision {
  allowed: boolean
  reason?: string
}

export interface SignedCredentialResult {
  issuanceId: string
  credential: unknown
}

export type IssuanceAuditEvent =
  | { issuanceId: string; outcome: 'issued'; occurredAt: string }
  | { outcome: 'denied' | 'failed'; reason: string; occurredAt: string }

export interface AuthoritativeIssuancePorts {
  authorization: {
    authorize(input: IssuanceCommand): Promise<AuthorizationDecision>
  }
  verification: {
    assertVerified(transactionId: string): Promise<VerificationDecision>
  }
  index: {
    readAuthoritativeSubject(subjectReference: string): Promise<AuthoritativeSubject>
  }
  policy: {
    evaluate(input: {
      command: IssuanceCommand
      authoritativeSubject: AuthoritativeSubject
    }): Promise<PolicyDecision>
  }
  signer: {
    issue(input: {
      command: IssuanceCommand
      sourceId: string
      claims: Readonly<Record<string, unknown>>
      holderKey?: JsonWebKey
    }): Promise<SignedCredentialResult>
  }
  audit: {
    record(event: IssuanceAuditEvent): Promise<void>
  }
  clock: {
    now(): string
  }
}

function reasonOrFallback(reason: string | undefined, fallback: string): string {
  return reason && reason.length > 0 ? reason : fallback
}

export class AuthoritativeIssuanceManager {
  constructor(private readonly ports: AuthoritativeIssuancePorts) {}

  async issue(command: IssuanceCommand & Record<string, unknown>): Promise<SignedCredentialResult> {
    return this.issueCredential(command)
  }

  /** Applies the wallet proof to an offer that the server has already resolved. */
  async issueForWallet(
    command: IssuanceCommand & Record<string, unknown>,
    proof: string,
    offer: OpenId4VciOfferBinding,
  ): Promise<SignedCredentialResult> {
    return this.issueCredential(command, () => consumeWalletHolderProof(command, proof, offer, Date.parse(this.ports.clock.now())))
  }

  private async issueCredential(
    command: IssuanceCommand & Record<string, unknown>,
    resolveHolderKey?: () => Promise<JsonWebKey>,
  ): Promise<SignedCredentialResult> {
    if ('claims' in command) {
      throw new Error('Caller-supplied claims are not accepted; the provider must perform authoritative readback')
    }

    defineCredentialIssuanceRequest(command)

    const authorization = await this.ports.authorization.authorize(command)
    if (!authorization.allowed) {
      await this.deny(reasonOrFallback(authorization.reason, 'authorization-denied'))
    }

    const verification = await this.ports.verification.assertVerified(
      command.verificationTransactionId,
    )
    if (!verification.verified) {
      await this.deny(reasonOrFallback(verification.reason, 'verification-not-trusted'))
    }

    const authoritativeSubject = await this.ports.index.readAuthoritativeSubject(
      command.subjectReference,
    )
    const policy = await this.ports.policy.evaluate({ command, authoritativeSubject })
    if (!policy.allowed) {
      await this.deny(reasonOrFallback(policy.reason, 'issuance-policy-denied'))
    }

    const holderKey = await resolveHolderKey?.()
    const result = await this.ports.signer.issue({
      command,
      sourceId: authoritativeSubject.sourceId,
      claims: authoritativeSubject.claims,
      ...(holderKey ? {holderKey} : {}),
    })
    await this.ports.audit.record({
      issuanceId: result.issuanceId,
      outcome: 'issued',
      occurredAt: this.ports.clock.now(),
    })
    return result
  }

  private async deny(reason: string): Promise<never> {
    await this.ports.audit.record({
      outcome: 'denied',
      reason,
      occurredAt: this.ports.clock.now(),
    })
    throw new CredentialIssuanceDeniedError(reason)
  }
}

function decodeProofPart(part: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid wallet proof object')
  return parsed as Record<string, unknown>
}

function verifyWalletProof(proof: string, issuer: string, now: number): {holderKey: JsonWebKey; nonce: string} {
  if (typeof proof !== 'string' || proof.length > 8192 || !/^[\w-]+\.[\w-]+\.[\w-]+$/.test(proof)) {
    throw new Error('Invalid wallet proof JWT')
  }
  const [headerPart = '', payloadPart = '', signaturePart = ''] = proof.split('.')
  const header = decodeProofPart(headerPart)
  if (header.typ !== 'openid4vci-proof+jwt' || header.alg !== 'ES256'
    || 'crit' in header || 'kid' in header || 'x5c' in header || 'jku' in header || 'x5u' in header) {
    throw new Error('Unsupported wallet proof header')
  }
  const key = header.jwk as JsonWebKey | undefined
  if (!key || key.d !== undefined || key.kty !== 'EC' || key.crv !== 'P-256'
    || typeof key.x !== 'string' || typeof key.y !== 'string'
    || !/^[\w-]{43}$/.test(key.x) || !/^[\w-]{43}$/.test(key.y)) {
    throw new Error('Wallet proof requires a public P-256 JWK')
  }
  const holderKey = {kty: key.kty, crv: key.crv, x: key.x, y: key.y}
  const signature = Buffer.from(signaturePart, 'base64url')
  if (signature.length !== 64 || !verify('sha256', Buffer.from(`${headerPart}.${payloadPart}`), {
    key: createPublicKey({key: holderKey, format: 'jwk'}), dsaEncoding: 'ieee-p1363',
  }, signature)) throw new Error('Invalid wallet proof signature')
  const payload = decodeProofPart(payloadPart)
  if (payload.aud !== issuer) throw new Error('Invalid wallet proof audience')
  if (typeof payload.iat !== 'number' || !Number.isSafeInteger(payload.iat) || !Number.isFinite(now)
    || payload.iat < now / 1000 - 300 || payload.iat > now / 1000 + 30) throw new Error('Wallet proof is outside its validity window')
  if (typeof payload.nonce !== 'string' || !payload.nonce) throw new Error('Wallet proof nonce is required')
  return {holderKey, nonce: payload.nonce}
}

/** Verifies possession before atomically consuming the nonce and its offer. */
export async function consumeWalletHolderProof(
  command: IssuanceCommand,
  proof: string,
  offer: OpenId4VciOfferBinding,
  now: number,
): Promise<JsonWebKey> {
  let verified: ReturnType<typeof verifyWalletProof>
  try {
    verified = verifyWalletProof(proof, offer.credentialIssuer, now)
  } catch (error) {
    throw new OpenId4VciProofError(error instanceof Error ? error.message : 'Invalid wallet proof')
  }
  const {holderKey, nonce} = verified
  if (!await offer.consumeNonce(nonce, command)) {
    throw new OpenId4VciProofError('Invalid or already used wallet proof nonce', 'invalid_nonce')
  }
  return holderKey
}
