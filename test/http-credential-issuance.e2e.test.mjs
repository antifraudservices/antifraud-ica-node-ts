// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// The wallet journey additionally resolves an offer from a server-trusted token, consumes its challenge and signs a key-bound credential.
// Journey: 1. Start the neutral ICA HTTP runtime. 2. Resolve the caller server-side. 3. Submit through the published Node SDK. 4. Authorize, verify, read authoritative claims, evaluate policy and sign. 5. Persist and reload the public receipt. Authorization invariant: caller claims and actor identity are never authoritative input. Persistence invariant: reload uses the issuance store and audit contains no subject claims.
import assert from 'node:assert/strict'
import {generateKeyPairSync, randomBytes, sign, verify} from 'node:crypto'
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
  createPreAuthorizedWalletOffers,
  preAuthorizedCodeGrantType,
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

  const cloudRunResponse = await fetch(`${baseUrl}/health`)
  assert.equal(cloudRunResponse.status, 200)
  assert.deepEqual(await cloudRunResponse.json(), {status: 'ok'})
})

test('documents every public HTTP route in OpenAPI', () => {
  assert.deepEqual(Object.keys(icaOpenApiDocument.paths).sort(), [
    '/.well-known/oauth-authorization-server',
    '/.well-known/openid-credential-issuer',
    '/credential',
    '/credential-issuances',
    '/credential-issuances/{issuanceId}',
    '/credential-offers',
    '/credential-offers/{reference}',
    '/health',
    '/healthz',
    '/nonce',
    '/organization-verifications',
    '/token',
  ])
})


test('OpenID4VCI credential endpoint verifies the wallet proof and returns an issuer-signed holder-bound credential', async t => {
  const issuerPath = '/synthetic-tenant/identity';
  const issuer = `https://issuer.example${issuerPath}`;
  const configurationId = 'synthetic-organization-relationship';
  const command = {actorReference: 'urn:actor:server-resolved', subjectReference: 'urn:subject:synthetic',
    capability: 'identity.relationship.attest', verificationTransactionId: 'verification-synthetic-001'};
  const clock = '2026-10-17T00:00:00.000Z';
  const issuerKeys = generateKeyPairSync('ec', {namedCurve: 'P-256'});
  const walletKeys = generateKeyPairSync('ec', {namedCurve: 'P-256'});
  const walletKey = walletKeys.publicKey.export({format: 'jwk'});
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const makeJwt = (header, body, key) => {
    const message = `${encode(header)}.${encode(body)}`;
    return `${message}.${sign('sha256', Buffer.from(message), {key, dsaEncoding: 'ieee-p1363'}).toString('base64url')}`;
  };
  const records = new Map();
  const usedNonces = new Set();
  const walletOffers = createPreAuthorizedWalletOffers({credentialIssuer: issuer, secret: randomBytes(32), store: {
    create: async (reference, entry) => { records.set(reference, entry); },
    read: async reference => records.get(reference),
    compareAndSet: async (reference, revision, entry) => {
      if (records.get(reference)?.revision !== revision) return false;
      records.set(reference, entry);
      return true;
    },
    consumeForIssuance: async ({reference, revision, nonceDigest}) => {
      const record = records.get(reference);
      if (record?.revision !== revision || usedNonces.has(nonceDigest)) return false;
      usedNonces.add(nonceDigest);
      records.set(reference, {...record, revision: revision + 1, state: 'used'});
      return true;
    },
  }});

  const manager = new AuthoritativeIssuanceManager({
    authorization: {authorize: async issued => ({allowed: issued.actorReference === command.actorReference})},
    verification: {assertVerified: async id => ({verified: id === command.verificationTransactionId})},
    index: {readAuthoritativeSubject: async reference => ({sourceId: reference, claims: {sub: reference}})},
    policy: {evaluate: async () => ({allowed: true})},
    signer: {issue: async ({holderKey, claims}) => ({issuanceId: 'issuance-synthetic-001', credential: `${makeJwt({alg: 'ES256', typ: 'dc+sd-jwt'}, {
      ...claims, iss: issuer, vct: configurationId, cnf: {jwk: holderKey},
    }, issuerKeys.privateKey)}~`})},
    audit: {record: async () => {}}, clock: {now: () => clock},
  });
  const server = createIcaHttpServer({manager, resolveActor: async () => undefined, walletIssuance: {
    credentialIssuer: issuer, authorizationServer: issuer, credentialConfigurations: {[configurationId]: {format: 'dc+sd-jwt', vct: configurationId}},
    issueNonce: walletOffers.issueNonce, resolveGrant: walletOffers.resolveGrant, preAuthorizedOffers: walletOffers,
    offerAuthorization: async (request, reference) => request.headers.authorization === 'Bearer provider-bearer'
      && reference === command.verificationTransactionId ? {command, configurationId} : undefined,
  }});
  t.after(() => server.close());
  const url = await listen(server);
  const metadata = await fetch(`${url}/.well-known/openid-credential-issuer${issuerPath}`);
  assert.equal(metadata.status, 200);
  assert.equal((await fetch(`${url}/.well-known/openid-credential-issuer`)).status, 404);
  assert.equal((await fetch(`${url}/.well-known/openid-credential-issuer/other${issuerPath}`)).status, 404);
  assert.equal((await metadata.json()).credential_endpoint, `${issuer}/credential`);
  const oauth = await fetch(`${url}/.well-known/oauth-authorization-server${issuerPath}`);
  assert.equal(oauth.status, 200);
  assert.equal((await oauth.json()).token_endpoint, `${issuer}/token`);
  const prepareOffer = (token, body) => fetch(`${url}${issuerPath}/credential-offers`, {method: 'POST',
    headers: {authorization: `Bearer ${token}`, 'content-type': 'application/json'}, body: JSON.stringify(body)});
  const authorization = {authorization_reference: command.verificationTransactionId};
  assert.equal((await prepareOffer('other-bearer', authorization)).status, 403);
  assert.equal((await prepareOffer('provider-bearer', {...authorization, claims: {sub: 'untrusted'}})).status, 400);
  const responseOffer = await prepareOffer('provider-bearer', authorization);
  assert.equal(responseOffer.status, 201);
  assert.equal(responseOffer.headers.get('cache-control'), 'no-store');
  const prepared = await responseOffer.json();
  assert.match(prepared.transactionCode, /^\d{6}$/);
  const offerResponse = await fetch(`${url}${new URL(prepared.offerUri).pathname}`);
  assert.equal(offerResponse.status, 200);
  assert.equal(offerResponse.headers.get('cache-control'), 'no-store');
  const offer = await offerResponse.json();
  assert.equal(offer.credential_issuer, issuer);
  const params = new URLSearchParams({grant_type: preAuthorizedCodeGrantType,
    'pre-authorized_code': offer.grants[preAuthorizedCodeGrantType]['pre-authorized_code'], tx_code: prepared.transactionCode});
  const exchange = () => fetch(`${url}${issuerPath}/token`, {method: 'POST', body: params});
  const tokenResponse = await exchange();
  assert.equal(tokenResponse.status, 200);
  const {access_token: token} = await tokenResponse.json();
  assert.equal((await exchange()).status, 400);
  const challenge = await fetch(`${url}${issuerPath}/nonce`, {method: 'POST'});
  const {c_nonce: nonce} = await challenge.json();
  assert.equal(typeof nonce, 'string');
  const proof = makeJwt({alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: walletKey}, {aud: issuer, iat: Date.parse(clock) / 1000, nonce}, walletKeys.privateKey);
  const request = (bearer, body) => fetch(`${url}${issuerPath}/credential`, {method: 'POST', headers: {authorization: `Bearer ${bearer}`, 'content-type': 'application/json'}, body: JSON.stringify(body)});
  const body = {credential_configuration_id: configurationId, proofs: {jwt: [proof]}};
  assert.equal((await request('other-bearer', body)).status, 401);
  assert.equal((await request(token, {...body, claims: {sub: 'untrusted'}})).status, 400);
  const response = await request(token, body);
  assert.equal(response.status, 200);
  const {credentials: [{credential}]} = await response.json();
  const [credentialHeader, credentialClaims, credentialSignature] = credential.split('~')[0].split('.');
  assert.equal(verify('sha256', Buffer.from(`${credentialHeader}.${credentialClaims}`), {
    key: issuerKeys.publicKey, dsaEncoding: 'ieee-p1363',
  }, Buffer.from(credentialSignature, 'base64url')), true);
  const claims = JSON.parse(Buffer.from(credentialClaims, 'base64url'));
  assert.deepEqual(claims.cnf.jwk, walletKey);
  assert.equal(claims.sub, command.subjectReference);
  const replay = await request(token, body);
  assert.equal(replay.status, 401);
});
