export interface IssuanceCommand {
  actorReference: string
  subjectReference: string
  capability: string
  verificationTransactionId: string
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

  async issue(
    command: IssuanceCommand & Record<string, unknown>,
  ): Promise<SignedCredentialResult> {
    if ('claims' in command) {
      throw new Error('Caller-supplied claims are not accepted; the provider must perform authoritative readback')
    }

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

    const result = await this.ports.signer.issue({
      command,
      sourceId: authoritativeSubject.sourceId,
      claims: authoritativeSubject.claims,
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
    throw new Error(reason)
  }
}

