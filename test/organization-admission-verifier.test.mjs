// Flow contract: an authorized applicant must match an active official registry record and a verified organization proof in the exact jurisdiction and sector before ICA stores evidence.
import assert from 'node:assert/strict'
import { once } from 'node:events'
import test from 'node:test'
import {
  OrganizationAdmissionVerifier,
  createIcaHttpServer,
  normalizeSpanishOrganizationIdentifier,
  readRegistryCacheMaxAgeMs,
} from '../dist/index.js'

const command = {
  actorReference: 'urn:example:verified-applicant',
  network: 'test-network',
  jurisdiction: 'ES',
  sector: 'animal-research',
  identifier: { scheme: 'NIF', value: 'B00000001' },
  proofReference: 'urn:example:document',
}
const checkedAt = '2026-01-01T12:00:00.000Z'

function setup({
  active = true, authorized = true, certificateValue = 'VATES-B00000001',
  source = 'live', maxRegistryCacheAgeMs, now = Date.parse(checkedAt), cacheHours = '72', useDefaultLogger = false,
} = {}) {
  const calls = []
  const evidence = []
  const warnings = []
  const observation = {
    identifier: command.identifier,
    active,
    sourceUrl: 'https://registry.example/organizations/01',
    checkedAt,
  }
  const verifier = new OrganizationAdmissionVerifier({
    profiles: [{
      network: command.network,
      jurisdiction: command.jurisdiction,
      sector: command.sector,
      method: 'pdf-certificate',
      maxRegistryCacheAgeMs,
      normalizeIdentifier: normalizeSpanishOrganizationIdentifier,
      async lookup(identifier) {
        calls.push('registry')
        assert.deepEqual(identifier, command.identifier)
        return source === 'live' ? observation : 'unavailable'
      },
      async lookupCached(identifier) {
        calls.push('cache')
        assert.deepEqual(identifier, command.identifier)
        return source === 'unavailable' ? undefined : observation
      },
      async verifyProof(input) {
        calls.push('proof')
        assert.equal(input.actorReference, command.actorReference)
        assert.equal(input.proofReference, command.proofReference)
        return {
          identifier: { scheme: 'VAT', value: certificateValue },
          reference: 'urn:example:verified-document',
        }
      },
    }],
    async authorize() { calls.push('authorization'); return authorized },
    async saveEvidence(value) { evidence.push(value) },
    now: () => now,
    ...(useDefaultLogger ? {} : { warnRegistry(event) { warnings.push(event) } }),
  }, { ANTIFRAUD_ICA_REGISTRY_CACHE_MAX_AGE_HOURS: cacheHours })
  return { verifier, calls, evidence, warnings }
}

test('stores official source and timestamp when the certificate and registry identify the same organization', async () => {
  const { verifier, calls, evidence } = setup()
  const result = await verifier.verify(command)
  assert.deepEqual(calls, ['authorization', 'registry', 'proof'])
  assert.deepEqual(evidence, [result])
  assert.deepEqual(result.identifier, command.identifier)
  assert.deepEqual(result.registry, {
    active: true, source: 'live', sourceUrl: 'https://registry.example/organizations/01', checkedAt,
  })
  assert.deepEqual(result.proof, { method: 'pdf-certificate', reference: 'urn:example:verified-document' })
})

test('accepts a current cache under the scope policy and records when the official source was checked', async () => {
  const { verifier, evidence, warnings } = setup({ source: 'cache', maxRegistryCacheAgeMs: 60_000, now: Date.parse(checkedAt) + 30_000 })
  const result = await verifier.verify(command)
  assert.deepEqual(result.registry, {
    active: true, source: 'cache', sourceUrl: 'https://registry.example/organizations/01', checkedAt,
  })
  assert.deepEqual(evidence, [result])
  assert.deepEqual(warnings, [{
    network: 'test-network', jurisdiction: 'ES', sector: 'animal-research',
    reason: 'cache-used', checkedAt, maxAgeMs: 60_000,
  }])
})

test('distinguishes an unreachable source from an inactive organization', async () => {
  const { verifier, calls, evidence } = setup({ source: 'unavailable' })
  await assert.rejects(verifier.verify(command), /organization_registry_unavailable/)
  assert.deepEqual(calls, ['authorization', 'registry', 'cache'])
  assert.deepEqual(evidence, [])
})

test('blocks an expired cache before verifying the submitted proof', async () => {
  const { verifier, calls, evidence, warnings } = setup({ source: 'cache', maxRegistryCacheAgeMs: 60_000, now: Date.parse(checkedAt) + 120_000 })
  await assert.rejects(verifier.verify(command), /organization_registry_cache_unusable/)
  assert.deepEqual(calls, ['authorization', 'registry', 'cache'])
  assert.deepEqual(evidence, [])
  assert.equal(warnings[0].reason, 'cache-unusable')
})

test('does not consult a cache when the pod disables registry fallback', async () => {
  const { verifier, calls, evidence } = setup({ source: 'cache', cacheHours: '0' })
  await assert.rejects(verifier.verify(command), /organization_registry_unavailable/)
  assert.deepEqual(calls, ['authorization', 'registry'])
  assert.deepEqual(evidence, [])
})

test('rejects an observed inactive organization without falling back to the cache', async () => {
  const { verifier, calls, evidence } = setup({ active: false, maxRegistryCacheAgeMs: 60_000 })
  await assert.rejects(verifier.verify(command), /organization_registry_inactive/)
  assert.deepEqual(calls, ['authorization', 'registry'])
  assert.deepEqual(evidence, [])
})

test('rejects a valid proof for another organization and saves no evidence', async () => {
  const { verifier, calls, evidence } = setup({ certificateValue: 'VATES-B00000002' })
  await assert.rejects(verifier.verify(command), /organization_proof_identifier_mismatch/)
  assert.deepEqual(calls, ['authorization', 'registry', 'proof'])
  assert.deepEqual(evidence, [])
})

test('rejects an unapproved sector and an unauthorized applicant before reading the registry', async () => {
  const { verifier, calls, evidence } = setup({ authorized: false })
  await assert.rejects(verifier.verify({ ...command, sector: 'animal-care' }), /organization_admission_scope_unsupported/)
  await assert.rejects(verifier.verify(command), /organization_admission_unauthorized/)
  assert.deepEqual(calls, ['authorization'])
  assert.deepEqual(evidence, [])
})

test('the Spanish comparison accepts a Spanish VAT prefix and rejects a foreign VAT identifier', () => {
  const vat = { scheme: 'VAT', value: ' VATES-B00000001 ' }
  assert.deepEqual(normalizeSpanishOrganizationIdentifier(vat), command.identifier)
  assert.equal(normalizeSpanishOrganizationIdentifier({ ...vat, value: 'VATFR-B00000001' }), undefined)
  assert.equal(normalizeSpanishOrganizationIdentifier({ ...vat, scheme: 'BN' }), undefined)
})

test('reads a 72-hour cache allowance by default and supports explicit overrides and disabling', () => {
  assert.equal(readRegistryCacheMaxAgeMs({}), 72 * 60 * 60 * 1000)
  assert.equal(readRegistryCacheMaxAgeMs({ ANTIFRAUD_ICA_REGISTRY_CACHE_MAX_AGE_HOURS: '24' }), 24 * 60 * 60 * 1000)
  assert.equal(readRegistryCacheMaxAgeMs({ ANTIFRAUD_ICA_REGISTRY_CACHE_MAX_AGE_HOURS: '0' }), 0)
  assert.throws(() => readRegistryCacheMaxAgeMs({ ANTIFRAUD_ICA_REGISTRY_CACHE_MAX_AGE_HOURS: '-1' }), /REGISTRY_CACHE_MAX_AGE_HOURS/)
})

test('HTTP admission verifies a server-authenticated actor and stores evidence', async t => {
  const { verifier, evidence, calls } = setup()
  const server = createIcaHttpServer({
    organizationAdmissionVerifier: verifier,
    async resolveActor(request) {
      return request.headers.authorization === 'Bearer local-test'
        ? { actorReference: command.actorReference }
        : undefined
    },
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => server.close())
  const url = `http://127.0.0.1:${server.address().port}/organization-verifications`
  const { actorReference, ...body } = command
  const post = (payload, headers = {}) => fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(payload),
  })
  const token = { authorization: 'Bearer local-test' }
  const unauthenticated = await post(body)
  assert.equal(unauthenticated.status, 401)
  const callerSuppliedActor = await post({ ...body, actorReference }, token)
  assert.equal(callerSuppliedActor.status, 400)
  assert.deepEqual(calls, [])
  const verified = await post(body, token)
  assert.equal(verified.status, 200)
  assert.deepEqual(await verified.json(), evidence[0])
  assert.deepEqual(calls, ['authorization', 'registry', 'proof'])
  const unsupported = await post({ ...body, sector: 'animal-care' }, token)
  assert.equal(unsupported.status, 422)
  assert.deepEqual(await unsupported.json(), { error: 'organization_admission_scope_unsupported' })
  assert.equal(evidence.length, 1)
})

test('logs the 72-hour cache decision without including the organization identifier or contact', async t => {
  const warn = t.mock.method(console, 'warn', () => {})
  const maxAgeMs = 72 * 60 * 60 * 1000
  const { verifier } = setup({ source: 'cache', now: Date.parse(checkedAt) + maxAgeMs, useDefaultLogger: true })
  await verifier.verify(command)
  assert.equal(warn.mock.callCount(), 1)
  assert.deepEqual(JSON.parse(warn.mock.calls[0].arguments[0]), {
    severity: 'WARNING', event: 'organization_registry_fallback',
    network: command.network, jurisdiction: command.jurisdiction, sector: command.sector,
    reason: 'cache-used', checkedAt, maxAgeMs,
  })
})
