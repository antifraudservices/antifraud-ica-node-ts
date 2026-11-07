// Flow contract: the current ICA serves the same issuance HTTP manager in an explicitly enabled all-local test profile; unknown actors and caller claims fail closed, while production cannot enable synthetic authority.
import assert from 'node:assert/strict'
import {once} from 'node:events'
import test from 'node:test'
import {createIcaLocalTestServer} from '../dist/index.js'

const environment = {
  ANTIFRAUD_DEPLOYMENT_STAGE: 'test', ANTIFRAUD_NETWORK_KIND: 'test',
  ANTIFRAUD_ICA_DEMO_ENABLED: 'true',
  ANTIFRAUD_ICA_DEMO_BEARER: 'synthetic-local-ica-bearer',
  ANTIFRAUD_ICA_DEMO_SIGNING_SECRET: 'synthetic-local-signing-secret-at-least-32-bytes',
  ANTIFRAUD_ICA_ISSUER_DID: 'did:web:localhost%3A3210',
}

test('starts the current authority locally, issues a synthetic credential and reloads its receipt', async t => {
  const server = createIcaLocalTestServer(environment)
  t.after(() => server.close())
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const baseUrl = `http://127.0.0.1:${server.address().port}`
  assert.equal((await fetch(`${baseUrl}/healthz`)).status, 200)
  const input = { subject_reference: 'urn:subject:synthetic-local-person', capability: 'identity.relationship.attest', verification_transaction_id: 'verification:synthetic-local-person' }
  const headers = { 'content-type': 'application/json', authorization: `Bearer ${environment.ANTIFRAUD_ICA_DEMO_BEARER}` }
  assert.equal((await fetch(`${baseUrl}/credential-issuances`, { method: 'POST', headers: { ...headers, authorization: 'Bearer wrong' }, body: JSON.stringify(input) })).status, 401)
  assert.equal((await fetch(`${baseUrl}/credential-issuances`, { method: 'POST', headers, body: JSON.stringify({ ...input, claims: { injected: true } }) })).status, 400)
  const response = await fetch(`${baseUrl}/credential-issuances`, { method: 'POST', headers, body: JSON.stringify(input) })
  assert.equal(response.status, 201)
  const receipt = await response.json()
  assert.equal(receipt.credential.issuer, environment.ANTIFRAUD_ICA_ISSUER_DID)
  assert.equal(receipt.credential.demo, true)
  const read = await fetch(`${baseUrl}/credential-issuances/${encodeURIComponent(receipt.issuance_id)}`, { headers })
  assert.deepEqual(await read.json(), receipt)
})

test('rejects production, mismatched networks and missing explicit enablement', () => {
  for (const override of [{ ANTIFRAUD_DEPLOYMENT_STAGE: 'production' }, { ANTIFRAUD_NETWORK_KIND: 'test-network' }, { NODE_ENV: 'production' }, { ANTIFRAUD_ICA_DEMO_ENABLED: 'false' }]) {
    assert.throws(() => createIcaLocalTestServer({ ...environment, ...override }))
  }
})
