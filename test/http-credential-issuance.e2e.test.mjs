// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Journey: 1. Start the neutral ICA HTTP runtime. 2. Resolve the caller server-side. 3. Submit through the published Node SDK. 4. Authorize, verify, read authoritative claims, evaluate policy and sign. 5. Persist and reload the public receipt. Authorization invariant: caller claims and actor identity are never authoritative input. Persistence invariant: reload uses the issuance store and audit contains no subject claims.
import assert from 'node:assert/strict'
import {once} from 'node:events'
import test from 'node:test'

import {
  AuthoritativeCredentialProviderClient,
  createAuthoritativeCredentialIssuanceController,
} from 'antifraud-sdk-node-ts'

import {
  AuthoritativeIssuanceManager,
  InMemoryCredentialIssuanceStore,
  createIcaHttpServer,
  icaOpenApiDocument,
} from '../dist/index.js'

function createRuntime() {
  const calls = []
  const manager = new AuthoritativeIssuanceManager({
    authorization: {authorize: async () => (calls.push('authorize'), {allowed: true})},
    verification: {assertVerified: async () => (calls.push('verify'), {verified: true})},
    index: {
      readAuthoritativeSubject: async () => {
        calls.push('read')
        return {
          sourceId: 'opaque-source',
          claims: {'org.schema.Person.birthDate': '2000-01-01'},
        }
      },
    },
    policy: {evaluate: async () => (calls.push('policy'), {allowed: true})},
    signer: {
      issue: async ({claims}) => {
        calls.push('sign')
        return {
          issuanceId: 'issuance-synthetic-001',
          credential: {type: ['VerifiableCredential'], credentialSubject: claims},
        }
      },
    },
    audit: {record: async (event) => calls.push({audit: event})},
    clock: {now: () => '2026-10-17T00:00:00.000Z'},
  })
  const store = new InMemoryCredentialIssuanceStore()
  const server = createIcaHttpServer({
    manager,
    store,
    resolveActor: async request => request.headers.authorization === 'Bearer provider-bearer'
      ? {actorReference: 'urn:actor:server-resolved'}
      : undefined,
  })
  return {calls, server, store}
}

async function listen(server) {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  return `http://127.0.0.1:${address.port}`
}

test('published SDK completes issuance and reload through the real local HTTP boundary', async (t) => {
  const {calls, server} = createRuntime()
  t.after(() => server.close())
  const baseUrl = await listen(server)
  const bearerCredential = async () => 'provider-bearer'
  const controller = createAuthoritativeCredentialIssuanceController({baseUrl, bearerCredential})
  const client = new AuthoritativeCredentialProviderClient({baseUrl, bearerCredential})

  const issued = await controller.issue({
    subjectReference: 'urn:subject:synthetic',
    capability: 'identity.relationship.attest',
    verificationTransactionId: 'verification-synthetic-001',
  })
  assert.equal(issued.status, 'issued')
  assert.equal(issued.issuanceId, 'issuance-synthetic-001')

  const reloaded = await client.getIssuance(issued.issuanceId)
  assert.deepEqual(reloaded, issued)
  assert.deepEqual(calls.slice(0, 5), ['authorize', 'verify', 'read', 'policy', 'sign'])
  assert.equal(JSON.stringify(calls.at(-1)).includes('birthDate'), false)
})

test('HTTP boundary rejects unauthenticated issuance receipt lookup', async (t) => {
  const {server} = createRuntime()
  t.after(() => server.close())
  const baseUrl = await listen(server)

  const response = await fetch(`${baseUrl}/credential-issuances/issuance-synthetic-001`)

  assert.equal(response.status, 401)
  assert.deepEqual(await response.json(), {error: 'unauthorized'})
})

test('HTTP boundary rejects caller claims before invoking provider ports', async (t) => {
  const {calls, server} = createRuntime()
  t.after(() => server.close())
  const baseUrl = await listen(server)

  const response = await fetch(`${baseUrl}/credential-issuances`, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({
      subject_reference: 'urn:subject:synthetic',
      capability: 'identity.relationship.attest',
      verification_transaction_id: 'verification-synthetic-001',
      claims: {name: 'caller supplied'},
    }),
  })

  assert.equal(response.status, 400)
  assert.deepEqual(calls, [])
})

test('HTTP boundary returns health without exposing tenant or credential state', async (t) => {
  const {server} = createRuntime()
  t.after(() => server.close())
  const baseUrl = await listen(server)

  const response = await fetch(`${baseUrl}/healthz`)
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), {status: 'ok'})
})

test('documents every public HTTP route in OpenAPI', () => {
  assert.deepEqual(Object.keys(icaOpenApiDocument.paths).sort(), [
    '/credential-issuances',
    '/credential-issuances/{issuanceId}',
    '/healthz',
  ])
})
