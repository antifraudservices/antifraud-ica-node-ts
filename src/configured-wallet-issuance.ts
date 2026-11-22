import {createHash} from 'node:crypto'
import {Firestore} from '@google-cloud/firestore'
import type {WalletIssuanceOptions} from './credential-issuance-http.js'
import {createDelegatedWalletIssuance} from './delegated-wallet-issuance.js'
import {createFirestoreWalletOfferStore} from './firestore-wallet-offer-store.js'
import {createPreAuthorizedWalletOffers, type WalletOfferStore} from './preauthorized-wallet-offers.js'

type Environment = Readonly<Record<string, string | undefined>>

export function createConfiguredWalletIssuance(
  environment: Environment,
  dependencies: {
    createStore?: (projectId: string, namespace: string) => WalletOfferStore
    fetch?: typeof globalThis.fetch
  } = {},
): WalletIssuanceOptions | undefined {
  const prefix = 'ANTIFRAUD_ICA_WALLET_'
  if (!Object.entries(environment).some(([key, value]) => key.startsWith(prefix) && value)) return undefined
  const read = (key: string) => {
    const name = prefix + key
    const value = environment[name]
    if (!value || value.trim() !== value) throw new TypeError(`${name} is required`)
    return value
  }
  const credentialIssuer = read('ISSUER')
  const configurationId = read('CONFIGURATION_ID')
  const vct = read('VCT')
  const authorizationUrl = read('GATEWAY_AUTHORIZATION_URL')
  const signingUrl = read('GATEWAY_SIGNING_URL')
  const inboundBearer = read('INBOUND_BEARER')
  const outboundBearer = read('OUTBOUND_BEARER')
  const projectId = read('FIRESTORE_PROJECT')
  const encodedSecret = read('OFFER_SECRET')
  const secret = Buffer.from(encodedSecret, 'base64url')
  if (secret.length !== 32 || secret.toString('base64url') !== encodedSecret) {
    throw new TypeError('ANTIFRAUD_ICA_WALLET_OFFER_SECRET must contain 32 base64url-encoded bytes')
  }
  const namespace = createHash('sha256').update(credentialIssuer).digest('hex')
  const store = dependencies.createStore?.(projectId, namespace)
    ?? createFirestoreWalletOfferStore(new Firestore({projectId}), namespace)
  const signingIssuer = environment.ANTIFRAUD_ICA_WALLET_SIGNING_ISSUER
  return createDelegatedWalletIssuance({
    credentialIssuer, ...(signingIssuer ? {signingIssuer} : {}),
    configurationId, vct, authorizationUrl, signingUrl, inboundBearer, outboundBearer,
    offers: createPreAuthorizedWalletOffers({credentialIssuer, secret, store}),
    ...(dependencies.fetch ? {fetch: dependencies.fetch} : {}),
  })
}
