// Flow contract: an issuer-approved command creates an opaque wallet offer; the code and transaction PIN authorize one grant, and one valid nonce authorizes one issuance.
import assert from 'node:assert/strict'
import {randomBytes} from 'node:crypto'
import test from 'node:test'
import {createPreAuthorizedWalletOffers, preAuthorizedCodeGrantType} from '../dist/index.js'

const origin = 'https://issuer.example'
const configuration = 'synthetic-professional'
const command = Object.freeze({actorReference: 'urn:actor:eligible', subjectReference: 'urn:subject:eligible',
  capability: 'identity.relationship.attest', verificationTransactionId: 'synthetic-verification'})

function fixture() {
  let now = Date.now()
  const entries = new Map()
  const usedNonces = new Set()
  const store = {
    create: async (reference, value) => { assert.equal(entries.has(reference), false); entries.set(reference, structuredClone(value)) },
    read: async reference => structuredClone(entries.get(reference)),
    compareAndSet: async (reference, revision, value) => {
      if (entries.get(reference)?.revision !== revision) return false
      entries.set(reference, structuredClone(value))
      return true
    },
    consumeForIssuance: async ({reference, revision, nonceDigest}) => {
      const entry = entries.get(reference)
      if (entry?.revision !== revision || usedNonces.has(nonceDigest)) return false
      usedNonces.add(nonceDigest)
      entries.set(reference, structuredClone({...entry, revision: revision + 1, state: 'used'}))
      return true
    },
  }
  return {entries, advance: ms => { now += ms }, authority: createPreAuthorizedWalletOffers({
    credentialIssuer: origin, secret: randomBytes(32), store, now: () => now,
  })}
}

test('a bound offer exposes the protocol grant and each redemption boundary is atomic', async () => {
  const {authority, entries} = fixture()
  const prepared = await authority.prepare(command, configuration)
  const reference = new URL(prepared.offerUri).pathname.split('/').at(-1)
  assert.ok(prepared.offerUri.startsWith(`${origin}/credential-offers/`))
  assert.match(prepared.transactionCode, /^\d{6}$/)
  const offer = await authority.readOffer(reference)
  assert.deepEqual(offer.credential_configuration_ids, [configuration])
  assert.equal(offer.credential_issuer, origin)
  const grant = offer.grants[preAuthorizedCodeGrantType]
  assert.deepEqual(grant.tx_code, {input_mode: 'numeric', length: 6})
  assert.ok(!JSON.stringify(offer).includes(command.subjectReference))
  assert.ok(!JSON.stringify([...entries.values()]).includes(grant['pre-authorized_code']))
  const incorrect = prepared.transactionCode === '000000' ? '000001' : '000000'
  assert.equal(await authority.exchange(grant['pre-authorized_code'], incorrect), undefined)
  const results = await Promise.all([1, 2].map(() => authority.exchange(grant['pre-authorized_code'], prepared.transactionCode)))
  const tokens = results.filter(Boolean)
  assert.equal(tokens.length, 1)
  assert.equal(await authority.readOffer(reference), undefined)
  const access = await authority.resolveGrant(tokens[0].access_token)
  assert.deepEqual(access.command, command)
  assert.equal(access.configurationId, configuration)
  assert.equal(await access.consumeNonce('invalid', command), false)
  const nonce = await authority.issueNonce()
  assert.equal(await access.consumeNonce(nonce, {...command, subjectReference: 'urn:subject:different'}), false)
  const redemptions = await Promise.all([1, 2].map(() => access.consumeNonce(nonce, command)))
  assert.equal(redemptions.filter(Boolean).length, 1)
  assert.equal(await authority.resolveGrant(tokens[0].access_token), undefined)
})

test('locks repeated bad PINs and expires unused offers', async () => {
  const {authority, advance} = fixture()
  const a = await authority.prepare(command, configuration)
  const reference = new URL(a.offerUri).pathname.split('/').at(-1)
  const offer = await authority.readOffer(reference)
  const code = offer.grants[preAuthorizedCodeGrantType]['pre-authorized_code']
  const wrong = a.transactionCode === '000000' ? '000001' : '000000'
  for (let i = 0; i < 5; i++) assert.equal(await authority.exchange(code, wrong), undefined)
  assert.equal(await authority.exchange(code, a.transactionCode), undefined)
  const b = await authority.prepare(command, configuration)
  advance(6 * 60 * 1000)
  assert.equal(await authority.readOffer(new URL(b.offerUri).pathname.split('/').at(-1)), undefined)
})


test('a proof nonce consumed in one offer cannot authorize a second offer', async () => {
  const {authority} = fixture()
  async function resolveAccess() {
    const prepared = await authority.prepare(command, configuration)
    const reference = new URL(prepared.offerUri).pathname.split('/').at(-1)
    const offer = await authority.readOffer(reference)
    const token = await authority.exchange(offer.grants[preAuthorizedCodeGrantType]['pre-authorized_code'], prepared.transactionCode)
    return authority.resolveGrant(token.access_token)
  }
  const [first, second] = await Promise.all([resolveAccess(), resolveAccess()])
  const nonce = await authority.issueNonce()
  assert.equal(await first.consumeNonce(nonce, command), true)
  assert.equal(await second.consumeNonce(nonce, command), false)
})
