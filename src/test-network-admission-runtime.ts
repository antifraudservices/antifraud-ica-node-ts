import { createHash, timingSafeEqual } from 'node:crypto'
import { createIcaHttpServer, type WalletIssuanceOptions } from './credential-issuance-http.js'
import { OrganizationAdmissionError, OrganizationAdmissionVerifier, type OrganizationAdmissionCommand, type OrganizationAdmissionProfile } from './organization-admission-verifier.js'
import { normalizeSpanishOrganizationIdentifier } from './portable/spanish-organization-identifier.js'


type Environment = Readonly<Record<string, string | undefined>>
type ProviderProfile = Readonly<{
  jurisdiction: string
  sector: string
  method: OrganizationAdmissionProfile['method']
  acceptedTemplateVersion?: string
  signaturePolicyId?: string
}>

const methods: readonly string[] = ['pdf-certificate', 'organization-controller-vp', 'official-contact']
const digest = (value: string) => createHash('sha256').update(value).digest()
const unavailable = () => new OrganizationAdmissionError('organization_admission_provider_unavailable', 503)
const invalidResponse = () => new OrganizationAdmissionError('organization_admission_provider_invalid_response', 502)
const maximumAdmissionPdfBytes = 1024 * 1024

function readProfiles(value: string | undefined): ProviderProfile[] {
  const parsed: unknown = JSON.parse(value || '[]')
  if (!Array.isArray(parsed) || !parsed.length || !parsed.every(row =>
    row && typeof row.jurisdiction === 'string' && /^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/.test(row.jurisdiction)
    && typeof row.sector === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(row.sector)
    && methods.includes(row.method)
    && (row.method !== 'pdf-certificate' || (typeof row.signaturePolicyId === 'string' && row.signaturePolicyId.trim()))
    && (row.acceptedTemplateVersion === undefined
      || (row.method === 'pdf-certificate' && typeof row.acceptedTemplateVersion === 'string' && row.acceptedTemplateVersion.trim() === row.acceptedTemplateVersion && row.acceptedTemplateVersion)),
  )) throw new Error('Invalid ICA Test Network admission profiles')
  return parsed
}

function readIdentifier(value: unknown): { scheme: string; value: string } | undefined {
  if (!value || typeof value !== 'object') return undefined
  const record = value as Record<string, unknown>
  return typeof record.scheme === 'string' && typeof record.value === 'string'
    ? { scheme: record.scheme, value: record.value } : undefined
}

function readObservation(value: Record<string, unknown> | undefined) {
  if (!value) return undefined
  const identifier = readIdentifier(value.identifier)
  if (!identifier || typeof value.active !== 'boolean' || typeof value.sourceUrl !== 'string' || typeof value.checkedAt !== 'string') {
    throw invalidResponse()
  }
  return { identifier, active: value.active, sourceUrl: value.sourceUrl, checkedAt: value.checkedAt }
}

async function readAdmissionPdf(response: Response) {
  const reader = response.body?.getReader()
  if (!reader || response.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/pdf') throw invalidResponse()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    for (;;) {
      const next = await reader.read()
      if (next.done) return Buffer.concat(chunks, length)
      length += next.value.byteLength
      if (length > maximumAdmissionPdfBytes) {
        await reader.cancel()
        throw invalidResponse()
      }
      chunks.push(next.value)
    }
  } finally {
    reader.releaseLock()
  }
}

export function createIcaTestNetworkAdmissionServer(environment: Environment, transport: typeof fetch = fetch, walletIssuance?: WalletIssuanceOptions) {
  const hostDid = environment.ANTIFRAUD_ICA_ADMISSION_HOST_DID?.trim()
  const gatewayToken = environment.ANTIFRAUD_ICA_ADMISSION_GATEWAY_TOKEN?.trim()
  const providerToken = environment.ANTIFRAUD_ICA_ADMISSION_PROVIDER_TOKEN?.trim()
  const provider = URL.parse(environment.ANTIFRAUD_ICA_ADMISSION_PROVIDER_URL || '')
  const documentUrl = environment.ANTIFRAUD_ICA_ADMISSION_DOCUMENT_URL?.trim()
  const documentToken = environment.ANTIFRAUD_ICA_ADMISSION_DOCUMENT_TOKEN?.trim()
  const documentEndpoint = URL.parse(documentUrl || '')
  if (environment.ANTIFRAUD_DEPLOYMENT_STAGE !== 'test-network' || !hostDid || !/^did:web:[^\s]+$/.test(hostDid)
    || !gatewayToken || /\s/.test(gatewayToken) || !providerToken || /\s/.test(providerToken)
    || provider?.protocol !== 'https:' || provider.username || provider.password || provider.search || provider.hash) {
    throw new Error('Invalid ICA Test Network admission configuration')
  }
  if ((documentUrl || documentToken) && (!documentToken || /\s/.test(documentToken) || documentEndpoint?.protocol !== 'https:'
    || documentEndpoint.username || documentEndpoint.password || documentEndpoint.search || documentEndpoint.hash)) {
    throw new Error('Invalid ICA admission document source configuration')
  }
  provider.pathname = `${provider.pathname.replace(/\/+$/, '')}/`
  const gatewayDigest = digest(gatewayToken)
  const providerBase = provider.href

  async function call(operation: string, payload: unknown): Promise<Record<string, unknown> | undefined> {
    let response: Response
    try {
      response = await transport(new URL(operation, providerBase), {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
        headers: { authorization: `Bearer ${providerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      })
    } catch {
      throw unavailable()
    }
    if (operation !== 'evidence' && response.status === 404) return undefined
    if (operation === 'evidence' && [200, 201, 204].includes(response.status)) return undefined
    if (response.status === 429 || response.status >= 500) throw unavailable()
    if (response.status !== 200) throw invalidResponse()
    const data: unknown = await response.json().catch(() => undefined)
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw invalidResponse()
    return data as Record<string, unknown>
  }

  async function fetchApplicationPdf(input: OrganizationAdmissionCommand): Promise<Buffer | undefined> {
    const expectedHash = /^urn:sha256:([a-f0-9]{64})$/.exec(input.proofReference)?.[1]
    if (!documentEndpoint || !documentToken || !input.admissionBinding || !expectedHash) return undefined
    let response: Response
    try {
      response = await transport(documentEndpoint, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
        headers: { authorization: `Bearer ${documentToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          ...input.admissionBinding, actorReference: input.actorReference, network: input.network,
          jurisdiction: input.jurisdiction, sector: input.sector, proofReference: input.proofReference,
        }),
      })
    } catch {
      throw unavailable()
    }
    if (response.status === 404) return undefined
    if (response.status !== 200) throw unavailable()
    const pdf = await readAdmissionPdf(response)
    return createHash('sha256').update(pdf).digest('hex') === expectedHash ? pdf : undefined
  }

  const profiles: OrganizationAdmissionProfile[] = readProfiles(environment.ANTIFRAUD_ICA_ADMISSION_PROFILES_JSON).map(profile => {
    const scope = { network: 'test-network' as const, jurisdiction: profile.jurisdiction, sector: profile.sector }
    return {
      ...profile, ...scope,
      normalizeIdentifier: identifier => {
        if (scope.jurisdiction.split('-')[0] === 'ES') return normalizeSpanishOrganizationIdentifier(identifier)
        const scheme = identifier.scheme.trim().toUpperCase()
        const value = identifier.value.trim()
        return scheme && value ? { scheme, value } : undefined
      },
      async lookup(identifier) {
        try { return readObservation(await call('registry', { ...scope, identifier })) }
        catch (error) { if (error instanceof OrganizationAdmissionError && error.status === 503) return 'unavailable'; throw error }
      },
      async lookupCached(identifier) {
        try { return readObservation(await call('registry-cache', { ...scope, identifier })) }
        catch (error) { if (error instanceof OrganizationAdmissionError && error.status === 503) return undefined; throw error }
      },
      async verifyProof(input) {
        let pdf: Buffer | undefined
        if (documentEndpoint && profile.method === 'pdf-certificate') {
          pdf = await fetchApplicationPdf(input)
          if (!pdf) return undefined
        }
        const result = await call('proof', {
          ...input, method: profile.method, acceptedTemplateVersion: profile.acceptedTemplateVersion, signaturePolicyId: profile.signaturePolicyId,
          ...(pdf ? { pdfBase64: pdf.toString('base64') } : {}),
        })
        if (!result) return undefined
        const identifier = readIdentifier(result.identifier)
        if (result.proofReference !== input.proofReference || !identifier || typeof result.reference !== 'string' || !result.reference.trim()) return undefined
        const template = result.verifiedTemplate as Record<string, unknown> | undefined
        const verifiedTemplate = typeof template?.version === 'string' && template.requiredFieldsVerified === true
          && typeof template.documentSha256 === 'string'
          ? { version: template.version, requiredFieldsVerified: true as const, documentSha256: template.documentSha256 }
          : undefined
        return {
          identifier, reference: result.reference,
          ...(result.certificateValidation ? { certificateValidation: result.certificateValidation } : {}),
          ...(verifiedTemplate ? { verifiedTemplate } : {}),
        }
      },
      async lookupSectorDirectory(identifier) {
        let result: Record<string, unknown> | undefined
        try { result = await call('directory', { ...scope, identifier }) }
        catch (error) { if (error instanceof OrganizationAdmissionError && error.status === 503) return 'unavailable'; throw error }
        const observation = readObservation(result)
        if (!result || !observation || typeof result.jurisdiction !== 'string' || typeof result.sector !== 'string') return undefined
        return { ...observation, jurisdiction: result.jurisdiction, sector: result.sector }
      },
    }
  })

  return createIcaHttpServer({
    ...(walletIssuance ? {walletIssuance} : {}),
    organizationAdmissionVerifier: new OrganizationAdmissionVerifier({
      profiles,
      authorize: async command => command.admissionBinding?.hostDid === hostDid,
      saveEvidence: async evidence => { await call('evidence', evidence) },
    }, environment),
    async resolveActor(request) {
      const bearer = /^Bearer ([^\s]+)$/i.exec(request.headers.authorization || '')?.[1]
      const applicationId = request.headers['x-admission-application-id']
      const actorReference = request.headers['x-admission-actor']
      if (!bearer || !timingSafeEqual(digest(bearer), gatewayDigest)
        || typeof applicationId !== 'string' || !/^[a-zA-Z0-9._:-]{1,200}$/.test(applicationId)
        || typeof actorReference !== 'string' || !/^(?:did|urn):[^\s]{1,500}$/.test(actorReference)) return undefined
      return { actorReference, admissionBinding: { hostDid, applicationId } }
    },
  })
}
