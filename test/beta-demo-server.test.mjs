// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Journey: 1. Start the explicitly enabled Beta Demo ICA. 2. Reject an unknown bearer. 3. Resolve the synthetic actor server-side. 4. Read synthetic authoritative claims, apply policy and issue. 5. Reload the issuance receipt. Authorization invariant: callers supply neither claims nor actor authority. Persistence invariant: the process-owned store is authoritative only for the disposable Beta Demo lifetime.
import assert from 'node:assert/strict'
import {once} from 'node:events'
import test from 'node:test'

import {createIcaBetaDemoServer} from '../dist/index.js'

const environment = Object.freeze({
  ANTIFRAUD_DEPLOYMENT_STAGE: 'staging',
  ANTIFRAUD_NETWORK_KIND: 'demo',
  ANTIFRAUD_ICA_DEMO_ENABLED: 'true',
  ANTIFRAUD_ICA_DEMO_BEARER: 'synthetic-beta-ica-bearer',
  ANTIFRAUD_ICA_DEMO_SIGNING_SECRET: 'synthetic-beta-signing-secret-at-least-32-bytes',
})

async function listen(server) {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  return `http://127.0.0.1:${address.port}`
}

test('serves authenticated disposable Beta Demo issuance and authoritative reload', async t => {
  const server = createIcaBetaDemoServer(environment)
  t.after(() => server.close())
  const baseUrl = await listen(server)
  const input = {
    subject_reference: 'urn:subject:synthetic-beta-learner',
    capability: 'identity.relationship.attest',
    verification_transaction_id: 'verification:synthetic-beta-learner',
  }

  const denied = await fetch(`${baseUrl}/credential-issuances`, {
    method: 'POST',
    headers: {'content-type': 'application/json', authorization: 'Bearer wrong'},
    body: JSON.stringify(input),
  })
  assert.equal(denied.status, 401)

  const issued = await fetch(`${baseUrl}/credential-issuances`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${environment.ANTIFRAUD_ICA_DEMO_BEARER}`,
    },
    body: JSON.stringify(input),
  })
  assert.equal(issued.status, 201)
  const receipt = await issued.json()
  assert.equal(receipt.status, 'issued')
  assert.equal(receipt.credential.demo, true)
  assert.match(receipt.credential.proof.signature, /^[A-Za-z0-9_-]+$/u)

  const reloaded = await fetch(`${baseUrl}/credential-issuances/${encodeURIComponent(receipt.issuance_id)}`, {
    headers: {authorization: `Bearer ${environment.ANTIFRAUD_ICA_DEMO_BEARER}`},
  })
  assert.equal(reloaded.status, 200)
  assert.deepEqual(await reloaded.json(), receipt)
})

test('fails closed unless the staging Demo profile and secrets are explicit', () => {
  assert.throws(() => createIcaBetaDemoServer({...environment, ANTIFRAUD_ICA_DEMO_ENABLED: 'false'}), /explicitly enabled/i)
  assert.throws(() => createIcaBetaDemoServer({...environment, ANTIFRAUD_DEPLOYMENT_STAGE: 'production'}), /staging/i)
  assert.throws(() => createIcaBetaDemoServer({...environment, ANTIFRAUD_ICA_DEMO_BEARER: ''}), /bearer/i)
})
