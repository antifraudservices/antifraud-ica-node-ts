// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict'
import test from 'node:test'

import {AuthoritativeIssuanceManager} from '../dist/index.js'

function createPorts(overrides = {}) {
  const calls = []
  return {
    calls,
    ports: {
      authorization: {
        authorize: async () => {
          calls.push('authorize')
          return {allowed: true}
        },
      },
      verification: {
        assertVerified: async () => {
          calls.push('verify')
          return {verified: true}
        },
      },
      index: {
        readAuthoritativeSubject: async () => {
          calls.push('read')
          return {
            sourceId: 'opaque-source',
            claims: {'org.schema.Person.birthDate': '2000-01-01'},
          }
        },
      },
      policy: {
        evaluate: async () => {
          calls.push('policy')
          return {allowed: true}
        },
      },
      signer: {
        issue: async (input) => {
          calls.push('sign')
          return {
            issuanceId: 'opaque-issuance',
            credential: {proof: 'signed', credentialSubject: input.claims},
          }
        },
      },
      audit: {
        record: async (event) => calls.push({audit: event}),
      },
      clock: {
        now: () => '2026-10-17T00:00:00.000Z',
      },
      ...overrides,
    },
  }
}

const command = {
  actorReference: 'urn:actor:opaque',
  subjectReference: 'urn:subject:opaque',
  capability: 'identity.relationship.attest',
  verificationTransactionId: 'opaque-transaction',
}

test('rejects caller-supplied claims before invoking any provider port', async () => {
  const {calls, ports} = createPorts()
  const manager = new AuthoritativeIssuanceManager(ports)

  await assert.rejects(
    manager.issue({...command, claims: {name: 'caller supplied'}}),
    /Caller-supplied claims are not accepted/,
  )
  assert.deepEqual(calls, [])
})

test('signs only after authorization, trusted verification, readback and policy approval', async () => {
  const {calls, ports} = createPorts()
  const manager = new AuthoritativeIssuanceManager(ports)

  const result = await manager.issue(command)

  assert.equal(result.issuanceId, 'opaque-issuance')
  assert.deepEqual(calls.slice(0, 5), ['authorize', 'verify', 'read', 'policy', 'sign'])
  assert.deepEqual(result.credential.credentialSubject, {
    'org.schema.Person.birthDate': '2000-01-01',
  })
  const auditEvent = calls.at(-1).audit
  assert.deepEqual(auditEvent, {
    issuanceId: 'opaque-issuance',
    outcome: 'issued',
    occurredAt: '2026-10-17T00:00:00.000Z',
  })
  assert.equal(JSON.stringify(auditEvent).includes('birthDate'), false)
})

test('fails closed and never signs when authorization is denied', async () => {
  const calls = []
  const {ports} = createPorts({
    authorization: {
      authorize: async () => {
        calls.push('authorize')
        return {allowed: false, reason: 'capability-denied'}
      },
    },
    signer: {
      issue: async () => {
        calls.push('sign')
        throw new Error('must not sign')
      },
    },
  })
  const manager = new AuthoritativeIssuanceManager(ports)

  await assert.rejects(manager.issue(command), /capability-denied/)
  assert.deepEqual(calls, ['authorize'])
})
