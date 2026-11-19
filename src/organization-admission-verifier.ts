import type { IcaNetworkKind } from './portable/network-kind.js'

export interface OrganizationLegalIdentifier {
  scheme: string
  value: string
}

export interface OrganizationAdmissionScope {
  network: IcaNetworkKind
  jurisdiction: string
  sector: string
}

export interface OrganizationAdmissionCommand extends OrganizationAdmissionScope {
  actorReference: string
  identifier: OrganizationLegalIdentifier
  proofReference: string
}

interface RegistryObservation {
  identifier: OrganizationLegalIdentifier
  active: boolean
  /** Official publication URL that supports this observation. */
  sourceUrl: string
  /** Time when the adapter observed the status at the authoritative source. */
  checkedAt: string
}

interface VerifiedOrganizationProof {
  /** Organization bound by the proof, such as the entity represented by the signer. */
  identifier: OrganizationLegalIdentifier
  /** Reference to the provider's verified evidence, separate from the submitted reference. */
  reference: string
}

export interface OrganizationAdmissionProfile extends OrganizationAdmissionScope {
  method: 'pdf-certificate' | 'organization-controller-vp' | 'official-contact'
  normalizeIdentifier(identifier: OrganizationLegalIdentifier): OrganizationLegalIdentifier | undefined
  maxRegistryCacheAgeMs?: number
  /** Return unavailable only for a temporary source outage; undefined means an authoritative miss. */
  lookup(identifier: OrganizationLegalIdentifier): Promise<RegistryObservation | 'unavailable' | undefined>
  lookupCached?(identifier: OrganizationLegalIdentifier): Promise<RegistryObservation | undefined>
  /** Authenticate the proof and its actor binding before returning an organization. */
  verifyProof(input: OrganizationAdmissionCommand): Promise<VerifiedOrganizationProof | undefined>
}

export interface OrganizationAdmissionEvidence extends OrganizationAdmissionScope {
  actorReference: string
  identifier: OrganizationLegalIdentifier
  registry: { active: true; source: 'live' | 'cache'; sourceUrl: string; checkedAt: string }
  proof: { method: OrganizationAdmissionProfile['method']; reference: string }
}

export interface OrganizationAdmissionPorts {
  profiles: readonly OrganizationAdmissionProfile[]
  authorize(input: OrganizationAdmissionCommand): Promise<boolean>
  saveEvidence(evidence: OrganizationAdmissionEvidence): Promise<void>
  now?(): number
  warnRegistry?(event: RegistryFallbackWarning): void
}

export interface RegistryFallbackWarning extends OrganizationAdmissionScope {
  reason: 'cache-used' | 'cache-unusable' | 'unavailable'
  checkedAt?: string
  maxAgeMs: number
}

export function readRegistryCacheMaxAgeMs(environment: Readonly<Record<string, string | undefined>>): number {
  const value = environment.ANTIFRAUD_ICA_REGISTRY_CACHE_MAX_AGE_HOURS?.trim() ?? '72'
  const milliseconds = Number(value) * 60 * 60 * 1000
  if (!/^\d+$/u.test(value) || !Number.isSafeInteger(milliseconds)) {
    throw new Error('ANTIFRAUD_ICA_REGISTRY_CACHE_MAX_AGE_HOURS must be a nonnegative whole number of hours')
  }
  return milliseconds
}

function scopeKey({ network, jurisdiction, sector }: OrganizationAdmissionScope): string {
  return JSON.stringify([network, jurisdiction, sector])
}

function normalizedScope(scope: OrganizationAdmissionScope): OrganizationAdmissionScope {
  return {
    network: scope.network,
    jurisdiction: scope.jurisdiction.trim().toUpperCase(),
    sector: scope.sector.trim().toLowerCase(),
  }
}

function matches(expected: OrganizationLegalIdentifier, observed: OrganizationLegalIdentifier | undefined): boolean {
  return observed?.scheme === expected.scheme && observed.value === expected.value
}

function verifiedRegistrySource(
  observation: RegistryObservation, source: 'live' | 'cache',
): OrganizationAdmissionEvidence['registry'] {
  const url = URL.parse(observation.sourceUrl)
  const time = Date.parse(observation.checkedAt)
  if (!url || url.protocol !== 'https:' || url.username || url.password
    || !/^\d{4}-\d{2}-\d{2}T/u.test(observation.checkedAt) || !Number.isFinite(time)) {
    throw new Error('organization_registry_evidence_invalid')
  }
  return { active: true, source, sourceUrl: url.href, checkedAt: new Date(time).toISOString() }
}

/** Verifies admission evidence. The configured host policy still owns the decision to admit. */
export class OrganizationAdmissionVerifier {
  private readonly profiles = new Map<string, OrganizationAdmissionProfile>()
  private readonly maxRegistryCacheAgeMs: number

  constructor(
    private readonly ports: OrganizationAdmissionPorts,
    environment: Readonly<Record<string, string | undefined>> = process.env,
  ) {
    this.maxRegistryCacheAgeMs = readRegistryCacheMaxAgeMs(environment)
    for (const profile of ports.profiles) {
      const key = scopeKey(normalizedScope(profile))
      if (this.profiles.has(key)) throw new Error('organization_admission_scope_duplicate')
      if (profile.maxRegistryCacheAgeMs !== undefined && (
        !Number.isSafeInteger(profile.maxRegistryCacheAgeMs) || profile.maxRegistryCacheAgeMs < 0
      )) throw new Error('organization_registry_cache_age_invalid')
      this.profiles.set(key, profile)
    }
  }

  async verify(command: OrganizationAdmissionCommand): Promise<OrganizationAdmissionEvidence> {
    const scope = normalizedScope(command)
    const profile = this.profiles.get(scopeKey(scope))
    if (!profile) throw new Error('organization_admission_scope_unsupported')
    if (!command.actorReference.trim() || !command.proofReference.trim()) {
      throw new Error('organization_admission_request_invalid')
    }
    const identifier = profile.normalizeIdentifier(command.identifier)
    if (!identifier) throw new Error('organization_admission_identifier_invalid')
    const input = { ...scope, identifier, actorReference: command.actorReference, proofReference: command.proofReference }
    if (await this.ports.authorize(input) !== true) throw new Error('organization_admission_unauthorized')

    const source = await this.readRegistry(profile, scope, identifier)

    const proof = await profile.verifyProof(input)
    if (!proof?.reference.trim()) throw new Error('organization_proof_unverified')
    if (!matches(identifier, profile.normalizeIdentifier(proof.identifier))) {
      throw new Error('organization_proof_identifier_mismatch')
    }
    const evidence: OrganizationAdmissionEvidence = {
      ...scope, actorReference: command.actorReference, identifier, registry: source,
      proof: { method: profile.method, reference: proof.reference },
    }
    await this.ports.saveEvidence(evidence)
    return evidence
  }

  private async readRegistry(
    profile: OrganizationAdmissionProfile, scope: OrganizationAdmissionScope, identifier: OrganizationLegalIdentifier,
  ): Promise<OrganizationAdmissionEvidence['registry']> {
    const live = await profile.lookup(identifier)
    const source = live === 'unavailable' ? 'cache' : 'live'
    const maxAgeMs = Math.min(this.maxRegistryCacheAgeMs, profile.maxRegistryCacheAgeMs ?? this.maxRegistryCacheAgeMs)
    const registry = live === 'unavailable' && maxAgeMs > 0 ? await profile.lookupCached?.(identifier) : live
    if (source === 'cache' && (!registry || registry === 'unavailable')) {
      this.warn({ ...scope, reason: 'unavailable', maxAgeMs })
      throw new Error('organization_registry_unavailable')
    }
    if (!registry || registry === 'unavailable') throw new Error('organization_registry_not_found')
    const observed = verifiedRegistrySource(registry, source)
    if (source === 'cache') {
      const age = (this.ports.now?.() ?? Date.now()) - Date.parse(observed.checkedAt)
      if (!Number.isFinite(age) || age < 0 || age > maxAgeMs) {
        this.warn({ ...scope, reason: 'cache-unusable', checkedAt: observed.checkedAt, maxAgeMs })
        throw new Error('organization_registry_cache_unusable')
      }
      this.warn({ ...scope, reason: 'cache-used', checkedAt: observed.checkedAt, maxAgeMs })
    }
    if (registry.active !== true) throw new Error('organization_registry_inactive')
    if (!matches(identifier, profile.normalizeIdentifier(registry.identifier))) {
      throw new Error('organization_registry_identifier_mismatch')
    }
    return observed
  }

  private warn(event: RegistryFallbackWarning): void {
    if (this.ports.warnRegistry) this.ports.warnRegistry(event)
    else console.warn(JSON.stringify({ severity: 'WARNING', event: 'organization_registry_fallback', ...event }))
  }
}
