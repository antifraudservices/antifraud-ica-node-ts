// Flow contract: the deployed Test Network ICA verifies only scoped requests from its designated Gateway, resolves evidence through its provider, and returns success only after saving it.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import test from 'node:test'
import { createIcaTestNetworkAdmissionServer } from '../dist/index.js'

const env = {
  ANTIFRAUD_DEPLOYMENT_STAGE: 'test-network',
  ANTIFRAUD_ICA_ADMISSION_HOST_DID: 'did:web:gateway.example',
  ANTIFRAUD_ICA_ADMISSION_GATEWAY_TOKEN: 'example-gateway-bearer',
  ANTIFRAUD_ICA_ADMISSION_PROVIDER_URL: 'https://provider.example/admission/',
  ANTIFRAUD_ICA_ADMISSION_PROVIDER_TOKEN: 'example-provider-bearer',
  ANTIFRAUD_ICA_ADMISSION_PROFILES_JSON: JSON.stringify([
    { jurisdiction: 'ES-MD', sector: 'health-tech', method: 'pdf-certificate', acceptedTemplateVersion: 'revision-2', signaturePolicyId: 'test-signature-policy' },
  ]),
}
const request = {
  network: 'test-network', jurisdiction: 'ES-MD', sector: 'health-tech',
  identifier: { scheme: 'NIF', value: 'B00000001' }, proofReference: `urn:sha256:${'a'.repeat(64)}`,
}
const auth = {
  authorization: 'Bearer example-gateway-bearer',
  'x-admission-application-id': 'example-application',
  'x-admission-actor': 'did:web:controller.example',
}

function certificateValidation(input, overrides = {}) {
  return {
    indication: 'TOTAL_PASSED', documentSha256: input.proofReference.slice('urn:sha256:'.length),
    policyId: input.signaturePolicyId, completeDocumentCovered: true, organizationAuthorityVerified: true,
    ...input.admissionBinding, actorReference: input.actorReference, network: input.network,
    jurisdiction: input.jurisdiction, sector: input.sector, reportReference: 'urn:example:report',
    ...overrides,
  }
}

async function listening(t, transport, settings = env) {
  const server = createIcaTestNetworkAdmissionServer(settings, transport)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => server.close())
  const base = `http://127.0.0.1:${server.address().port}`
  return {
    verify: (body, headers = auth) => fetch(`${base}/organization-verifications`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
    }),
    health: () => fetch(`${base}/healthz`),
  }
}

test('starts only with a complete Test Network profile and an HTTPS provider', () => {
  assert.throws(() => createIcaTestNetworkAdmissionServer({ ...env, ANTIFRAUD_DEPLOYMENT_STAGE: 'network' }))
  assert.throws(() => createIcaTestNetworkAdmissionServer({ ...env, ANTIFRAUD_ICA_ADMISSION_PROVIDER_URL: 'http://provider.example/' }))
  assert.throws(() => createIcaTestNetworkAdmissionServer({ ...env, ANTIFRAUD_ICA_ADMISSION_PROFILES_JSON: '[]' }))
  assert.throws(() => createIcaTestNetworkAdmissionServer({
    ...env,
    ANTIFRAUD_ICA_ADMISSION_PROFILES_JSON: JSON.stringify([{ jurisdiction: 'ES-MD', sector: 'health-tech', method: 'pdf-certificate' }]),
  }))
})

test('provides the exact private PDF to the verifier and does not persist a document with a different digest', async t => {
  const pdf = Buffer.from('%PDF-1.7\napplication bytes\n%%EOF')
  const actual = createHash('sha256').update(pdf).digest('hex')
  const documentUrl = 'https://portal.example/api/internal/admission-document'
  const settings = {
    ...env, ANTIFRAUD_ICA_ADMISSION_DOCUMENT_URL: documentUrl,
    ANTIFRAUD_ICA_ADMISSION_DOCUMENT_TOKEN: 'example-document-token',
  }
  assert.throws(() => createIcaTestNetworkAdmissionServer({ ...settings, ANTIFRAUD_ICA_ADMISSION_DOCUMENT_TOKEN: '' }))
  const actions = []
  const api = await listening(t, async (url, init) => {
    const body = JSON.parse(init.body)
    const method = new URL(url).pathname.split('/').at(-1)
    actions.push(method)
    if (method === 'registry') return Response.json({
      identifier: request.identifier, active: true, sourceUrl: 'https://registry.example/org', checkedAt: '2026-01-01T00:00:00Z',
    })
    if (method === 'admission-document') {
      assert.equal(String(url), documentUrl)
      assert.equal(init.headers.authorization, 'Bearer example-document-token')
      assert.equal(init.redirect, 'error')
      assert.equal(body.applicationId, auth['x-admission-application-id'])
      assert.equal(body.actorReference, auth['x-admission-actor'])
      assert.equal(body.hostDid, env.ANTIFRAUD_ICA_ADMISSION_HOST_DID)
      assert.equal(body.jurisdiction, request.jurisdiction)
      return new Response(pdf, { headers: { 'content-type': 'application/pdf' } })
    }
    if (method === 'proof') {
      assert.deepEqual(Buffer.from(body.pdfBase64, 'base64'), pdf)
      return Response.json({
        proofReference: body.proofReference, identifier: request.identifier, reference: 'urn:example:verified-upload',
        certificateValidation: certificateValidation(body),
      })
    }
    if (method === 'evidence') {
      assert.equal('pdfBase64' in body, false)
      return new Response(null, { status: 201 })
    }
    return new Response(null, { status: 404 })
  }, settings)
  assert.equal((await api.verify({ ...request, proofReference: `urn:sha256:${'b'.repeat(64)}` })).status, 422)
  assert.deepEqual(actions, ['registry', 'admission-document'])
  actions.length = 0
  assert.equal((await api.verify({ ...request, proofReference: `urn:sha256:${actual}` })).status, 200)
  assert.deepEqual(actions, ['registry', 'admission-document', 'proof', 'directory', 'evidence'])
})

test('authorizes, verifies and stores only a scoped application supplied through the Gateway', async t => {
  const calls = []
  const api = await listening(t, async (url, init) => {
    assert.equal(init.redirect, 'error')
    assert.equal(init.headers.authorization, 'Bearer example-provider-bearer')
    const method = new URL(url).pathname.split('/').at(-1)
    const body = JSON.parse(init.body)
    calls.push({ method, body })
    if (method === 'registry') return Response.json({
      identifier: request.identifier, active: true, sourceUrl: 'https://registry.example/org', checkedAt: '2026-01-01T00:00:00Z',
    })
    if (method === 'proof') return Response.json({
      proofReference: body.proofReference, identifier: { scheme: 'VAT', value: 'VATES-B00000001' },
      reference: 'urn:example:immutable-evidence',
      verifiedTemplate: { version: 'revision-2', requiredFieldsVerified: true, documentSha256: 'a'.repeat(64) },
      certificateValidation: certificateValidation(body),
    })
    if (method === 'evidence') return new Response(null, { status: 201 })
    if (method === 'directory') return new Response(null, { status: 503 })
    return new Response(null, { status: 404 })
  })
  assert.equal((await api.health()).status, 200)
  assert.equal((await api.verify(request, {})).status, 401)
  assert.equal((await api.verify({ ...request, network: 'network' })).status, 422)
  assert.equal((await api.verify({ ...request, admissionBinding: { hostDid: 'did:web:other.example' } })).status, 400)
  assert.deepEqual(calls, [])
  const response = await api.verify(request)
  assert.equal(response.status, 200)
  const evidence = await response.json()
  assert.deepEqual(evidence.admissionBinding, { hostDid: env.ANTIFRAUD_ICA_ADMISSION_HOST_DID, applicationId: 'example-application' })
  assert.deepEqual(evidence.checks, ['legal-identifier-match', 'official-registry-active', 'signed-application-template'])
  assert.deepEqual(evidence.proof.certificate, {
    reportReference: 'urn:example:report', documentSha256: 'a'.repeat(64), policyId: 'test-signature-policy',
  })
  assert.deepEqual(calls.map(call => call.method), ['registry', 'proof', 'directory', 'evidence'])
  assert.deepEqual(calls.at(-1).body, evidence)
})

test('withholds approval evidence when the provider has not saved the result', async t => {
  const api = await listening(t, async (url, init) => {
    const body = JSON.parse(init.body)
    switch (new URL(url).pathname.split('/').at(-1)) {
      case 'registry': return Response.json({ identifier: request.identifier, active: true, sourceUrl: 'https://registry.example/org', checkedAt: '2026-01-01T00:00:00Z' })
      case 'proof': return Response.json({
        proofReference: body.proofReference, identifier: request.identifier, reference: 'urn:example:proof',
        certificateValidation: certificateValidation(body),
      })
      case 'evidence': return new Response(null, { status: 503 })
      default: return new Response(null, { status: 404 })
    }
  })
  const response = await api.verify(request)
  assert.equal(response.status, 503)
  assert.deepEqual(await response.json(), { error: 'organization_admission_provider_unavailable' })
})

test('withholds PDF certificate verification when the provider returns only an identifier and reference', async t => {
  const stages = []
  const api = await listening(t, async (url, init) => {
    const body = JSON.parse(init.body)
    const stage = new URL(url).pathname.split('/').at(-1)
    stages.push(stage)
    if (stage === 'registry') return Response.json({
      identifier: request.identifier, active: true, sourceUrl: 'https://registry.example/org', checkedAt: '2026-01-01T00:00:00Z',
    })
    if (stage === 'proof') return Response.json({ proofReference: body.proofReference, identifier: request.identifier, reference: 'urn:example:proof' })
    if (stage === 'evidence') return new Response(null, { status: 201 })
    return new Response(null, { status: 404 })
  })
  const response = await api.verify({ ...request, proofReference: `urn:sha256:${'a'.repeat(64)}` })
  assert.equal(response.status, 422)
  assert.deepEqual(await response.json(), { error: 'organization_proof_unverified' })
  assert.deepEqual(stages, ['registry', 'proof'])
})

test('rejects failed, partial, unbound or differently scoped certificate reports', async t => {
  const variants = [
    { indication: 'INDETERMINATE' },
    { indication: 'TOTAL_FAILED' },
    { completeDocumentCovered: false },
    { organizationAuthorityVerified: false },
    { documentSha256: 'b'.repeat(64) },
    { policyId: 'another-policy' },
    { hostDid: 'did:web:other.example' },
    { applicationId: 'other-application' },
    { actorReference: 'did:web:other.example' },
    { network: 'network' },
    { jurisdiction: 'ES-CL' },
    { sector: 'animal-tech' },
  ]
  const stages = []
  const api = await listening(t, async (url, init) => {
    const body = JSON.parse(init.body)
    const stage = new URL(url).pathname.split('/').at(-1)
    stages.push(stage)
    if (stage === 'registry') return Response.json({
      identifier: request.identifier, active: true, sourceUrl: 'https://registry.example/org', checkedAt: '2026-01-01T00:00:00Z',
    })
    return Response.json({
      proofReference: body.proofReference, identifier: request.identifier, reference: 'urn:example:proof',
      certificateValidation: certificateValidation(body, variants.shift()),
    })
  })
  while (variants.length) assert.equal((await api.verify(request)).status, 422)
  assert.equal(stages.some(stage => stage === 'evidence' || stage === 'directory'), false)
})

test('verifies an official-contact profile without requesting a certificate or PDF', async t => {
  const regional = { ...request, jurisdiction: 'CA-BC', identifier: { scheme: 'BN', value: '123456789' }, proofReference: 'urn:example:registry-phone' }
  const settings = {
    ...env,
    ANTIFRAUD_ICA_ADMISSION_DOCUMENT_URL: 'https://portal.example/api/internal/admission-document',
    ANTIFRAUD_ICA_ADMISSION_DOCUMENT_TOKEN: 'example-document-token',
    ANTIFRAUD_ICA_ADMISSION_PROFILES_JSON: JSON.stringify([{ jurisdiction: regional.jurisdiction, sector: regional.sector, method: 'official-contact' }]),
  }
  const calls = []
  const api = await listening(t, async (url, init) => {
    const stage = new URL(url).pathname.split('/').at(-1)
    const payload = JSON.parse(init.body)
    calls.push(stage)
    if (stage === 'registry') return Response.json({
      identifier: regional.identifier, active: true, sourceUrl: 'https://registry.example/org', checkedAt: '2026-01-01T00:00:00Z',
    })
    if (stage === 'proof') {
      assert.equal(payload.method, 'official-contact')
      assert.equal(payload.pdfBase64, undefined)
      return Response.json({ proofReference: payload.proofReference, identifier: regional.identifier, reference: 'urn:example:confirmed-contact' })
    }
    if (stage === 'evidence') return new Response(null, { status: 201 })
    return new Response(null, { status: 404 })
  }, settings)
  const response = await api.verify(regional)
  assert.equal(response.status, 200)
  const result = await response.json()
  assert.deepEqual(result.checks, ['legal-identifier-match', 'official-registry-active'])
  assert.equal(result.proof.certificate, undefined)
  assert.deepEqual(calls, ['registry', 'proof', 'directory', 'evidence'])
})
