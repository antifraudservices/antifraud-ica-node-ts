// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Journey: 1. Reject an untrusted offer caller. 2. Resolve one authorized reference through the gateway.
// 3. Exchange the offer. 4. Reject a proof for another issuer. 5. Validate the wallet signature and request
// a tenant signature over authoritative claims. 6. Reject replay. Only opaque references enter offer storage.
import assert from 'node:assert/strict'
import {generateKeyPairSync, randomBytes, sign, verify} from 'node:crypto'
import {once} from 'node:events'
import {createServer} from 'node:http'
import test from 'node:test'
import {credentialIssuanceRequestFixture} from 'antifraud-data-utils-ts'
import {createConfiguredWalletIssuance, createIcaHttpServer, preAuthorizedCodeGrantType} from '../dist/index.js'

async function listen(server, t) {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => server.close())
  return `http://127.0.0.1:${server.address().port}`
}

function compact(header, payload, privateKey) {
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url')
  const message = `${encode(header)}.${encode(payload)}`
  return `${message}.${sign('sha256', Buffer.from(message), {key: privateKey, dsaEncoding: 'ieee-p1363'}).toString('base64url')}`
}

test('only a redeemed offer and valid wallet proof can reach the configured tenant signer', async t => {
  const credentialIssuer = 'https://issuer.example/tenant'
  const configurationId = 'employee'
  const vct = 'https://issuer.example/types/employee'
  const requestFixture = {...credentialIssuanceRequestFixture,
    verificationTransactionId: randomBytes(32).toString('base64url')}
  const command = {...requestFixture, actorReference: 'urn:actor:synthetic'}
  const inboundBearer = randomBytes(32).toString('base64url')
  const outboundBearer = randomBytes(32).toString('base64url')
  const tenantKeys = generateKeyPairSync('ec', {namedCurve: 'P-256'})
  const walletKeys = generateKeyPairSync('ec', {namedCurve: 'P-256'})
  const holderKey = walletKeys.publicKey.export({format: 'jwk'})
  const calls = []
  const authorizations = new Set([requestFixture.verificationTransactionId])
  const gateway = await listen(createServer(async (request, response) => {
    let raw = ''
    for await (const chunk of request) raw += chunk
    calls.push({path: request.url, bearer: request.headers.authorization, body: JSON.parse(raw)})
    response.setHeader('content-type', 'application/json')
    if (request.url === '/authorize') {
      if (!authorizations.delete(calls.at(-1).body.authorization_reference)) {
        response.statusCode = 409
        return response.end('{}')
      }
      return response.end(JSON.stringify({command, configurationId}))
    }
    response.end(JSON.stringify({
      issuanceId: 'issuance-synthetic',
      credential: `${compact({typ: 'dc+sd-jwt', alg: 'ES256'}, {
        iss: credentialIssuer, vct, cnf: {jwk: holderKey},
      }, tenantKeys.privateKey)}~`,
    }))
  }), t)
  const store = new Map()
  const offerStore = {
    create: async (id, entry) => {store.set(id, entry)},
    read: async id => store.get(id),
    compareAndSet: async (id, revision, entry) => {
      if (store.get(id)?.revision !== revision) return false
      store.set(id, entry)
      return true
    },
    consumeForIssuance: async ({reference, revision}) => {
      if (store.get(reference)?.revision !== revision) return false
      store.delete(reference)
      return true
    },
  }
  const authorizationUrl = 'https://gateway.example/authorize'
  const signingUrl = 'https://gateway.example/sign'
  const walletIssuance = createConfiguredWalletIssuance({
    ANTIFRAUD_ICA_WALLET_ISSUER: credentialIssuer,
    ANTIFRAUD_ICA_WALLET_CONFIGURATION_ID: configurationId,
    ANTIFRAUD_ICA_WALLET_VCT: vct,
    ANTIFRAUD_ICA_WALLET_GATEWAY_AUTHORIZATION_URL: authorizationUrl,
    ANTIFRAUD_ICA_WALLET_GATEWAY_SIGNING_URL: signingUrl,
    ANTIFRAUD_ICA_WALLET_INBOUND_BEARER: inboundBearer,
    ANTIFRAUD_ICA_WALLET_OUTBOUND_BEARER: outboundBearer,
    ANTIFRAUD_ICA_WALLET_OFFER_SECRET: randomBytes(32).toString('base64url'),
    ANTIFRAUD_ICA_WALLET_FIRESTORE_PROJECT: 'demo-synthetic-issuer',
  }, {
    createStore: (project, namespace) => {
      assert.equal(project, 'demo-synthetic-issuer')
      assert.match(namespace, /^[a-f0-9]{64}$/u)
      return offerStore
    },
    fetch: async (url, init) => {
      assert.ok([authorizationUrl, signingUrl].includes(url))
      assert.equal(init.redirect, 'error')
      return fetch(`${gateway}${new URL(url).pathname}`, init)
    },
  })
  const ica = await listen(createIcaHttpServer({walletIssuance, resolveActor: async () => undefined}), t)
  const base = `${ica}/tenant`
  const postJson = (path, bearer, body) => fetch(base + path, {
    method: 'POST', headers: {authorization: `Bearer ${bearer}`, 'content-type': 'application/json'},
    body: JSON.stringify(body),
  })
  assert.equal((await postJson('/credential-offers', outboundBearer, {authorization_reference: requestFixture.verificationTransactionId})).status, 403)
  assert.equal(calls.length, 0)
  const prepared = await postJson('/credential-offers', inboundBearer, {authorization_reference: requestFixture.verificationTransactionId})
  assert.equal(prepared.status, 201)
  const {offerUri, transactionCode} = await prepared.json()
  const offer = await fetch(ica + new URL(offerUri).pathname).then(response => response.json())
  const exchange = await fetch(base + '/token', {method: 'POST', body: new URLSearchParams({
    grant_type: preAuthorizedCodeGrantType, tx_code: transactionCode,
    'pre-authorized_code': offer.grants[preAuthorizedCodeGrantType]['pre-authorized_code'],
  })})
  assert.equal(exchange.status, 200)
  const {access_token: accessToken} = await exchange.json()
  const {c_nonce: nonce} = await fetch(base + '/nonce', {method: 'POST'}).then(response => response.json())
  const makeRequest = audience => ({credential_configuration_id: configurationId, proofs: {jwt: [compact(
    {typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: holderKey},
    {aud: audience, nonce, iat: Math.floor(Date.now() / 1000)}, walletKeys.privateKey,
  )]}})
  assert.equal((await postJson('/credential', accessToken, makeRequest(signingUrl))).status, 400)
  assert.deepEqual(calls, [{path: '/authorize', bearer: `Bearer ${outboundBearer}`,
    body: {authorization_reference: requestFixture.verificationTransactionId}}])
  const issued = await postJson('/credential', accessToken, makeRequest(credentialIssuer))
  assert.equal(issued.status, 200)
  const {credentials: [{credential}]} = await issued.json()
  const [header, payload, signature] = credential.slice(0, -1).split('.')
  assert.ok(verify('sha256', Buffer.from(`${header}.${payload}`),
    {key: tenantKeys.publicKey, dsaEncoding: 'ieee-p1363'}, Buffer.from(signature, 'base64url')))
  assert.deepEqual(JSON.parse(Buffer.from(payload, 'base64url')).cnf.jwk, holderKey)
  assert.equal((await postJson('/credential', accessToken, makeRequest(credentialIssuer))).status, 401)
  assert.deepEqual(calls[1], {path: '/sign', bearer: `Bearer ${outboundBearer}`, body: {command, holderKey}})
  assert.equal(calls.length, 2)
  const duplicate = await postJson('/credential-offers', inboundBearer, {authorization_reference: requestFixture.verificationTransactionId})
  assert.equal(duplicate.status, 403)
})

test('wallet issuance stays disabled with an empty environment and rejects partial configuration', () => {
  assert.equal(createConfiguredWalletIssuance({}), undefined)
  assert.throws(() => createConfiguredWalletIssuance({ANTIFRAUD_ICA_WALLET_ISSUER: 'https://issuer.example/tenant'}),
    /ANTIFRAUD_ICA_WALLET_/u)
})
