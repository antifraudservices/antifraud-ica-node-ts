import {createHash, timingSafeEqual, type JsonWebKey} from 'node:crypto'
import {defineCredentialIssuanceRequest} from 'antifraud-data-utils-ts'
import {
  consumeWalletHolderProof, CredentialIssuanceDeniedError,
  type IssuanceCommand, type SignedCredentialResult,
} from './authoritative-issuance-manager.js'
import type {WalletIssuanceOptions} from './credential-issuance-http.js'
import {parseOpenIdIssuerUrl} from './openid-issuer-url.js'
import type {createPreAuthorizedWalletOffers} from './preauthorized-wallet-offers.js'

export interface DelegatedWalletIssuanceOptions {
  credentialIssuer: string
  /** Trusted identifier used in the signed credential if different from the OpenID issuer URL. */
  signingIssuer?: string
  configurationId: string
  vct: string
  authorizationUrl: string
  signingUrl: string
  inboundBearer: string
  outboundBearer: string
  offers: ReturnType<typeof createPreAuthorizedWalletOffers>
  fetch?: typeof globalThis.fetch
}

const bearerSecret = /^[A-Za-z0-9_-]{43,128}$/u
const digest = (value: string) => createHash('sha256').update(value).digest()

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined
}

function parseAuthorizedCommand(value: unknown, reference: string): IssuanceCommand | undefined {
  const command = asObject(value)
  if (!command || typeof command.actorReference !== 'string' || typeof command.subjectReference !== 'string'
    || command.verificationTransactionId !== reference || typeof command.capability !== 'string'
    || Object.keys(command).length !== 4) return undefined
  const opaqueUrn = /^urn:[A-Za-z0-9:_-]{1,180}$/u
  if (!opaqueUrn.test(command.actorReference) || !opaqueUrn.test(command.subjectReference)) return undefined
  const validated = defineCredentialIssuanceRequest(command as IssuanceCommand & Record<string, unknown>)
  return {...validated, actorReference: command.actorReference}
}

function readSignedCredential(
  value: Record<string, unknown> | undefined,
  issuer: string,
  vct: string,
  holder: JsonWebKey,
): SignedCredentialResult {
  const credential = value?.credential
  const issuanceId = value?.issuanceId
  if (typeof issuanceId !== 'string' || !issuanceId || issuanceId.length > 256
    || typeof credential !== 'string' || !credential.endsWith('~')
    || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~(?:[A-Za-z0-9_-]+~)*$/u.test(credential)) {
    throw new Error('The signing provider did not return an SD-JWT credential')
  }
  const [headerPart, claimsPart] = credential.split('~', 1)[0]!.split('.')
  const header = asObject(JSON.parse(Buffer.from(headerPart!, 'base64url').toString('utf8')))
  const claims = asObject(JSON.parse(Buffer.from(claimsPart!, 'base64url').toString('utf8')))
  const key = asObject(asObject(claims?.cnf)?.jwk)
  if (header?.typ !== 'dc+sd-jwt' || header.alg !== 'ES256' || claims?.iss !== issuer || claims.vct !== vct
    || !key || key.d !== undefined || key.kty !== holder.kty || key.crv !== holder.crv || key.x !== holder.x || key.y !== holder.y) {
    throw new Error('The returned credential does not match the negotiated issuer, format or holder key')
  }
  return {issuanceId, credential}
}

/** Uses an explicitly trusted gateway for current authorization, readback and tenant signing. */
export function createDelegatedWalletIssuance(options: DelegatedWalletIssuanceOptions): WalletIssuanceOptions {
  const {credentialIssuer, configurationId, vct, offers, inboundBearer, outboundBearer} = options
  const transport = options.fetch ?? fetch
  const {authorizationUrl, signingUrl} = options
  const authorizationEndpoint = parseOpenIdIssuerUrl(authorizationUrl)
  const signingEndpoint = parseOpenIdIssuerUrl(signingUrl)
  parseOpenIdIssuerUrl(credentialIssuer)
  if (!bearerSecret.test(inboundBearer) || !bearerSecret.test(outboundBearer) || inboundBearer === outboundBearer
    || !/^[A-Za-z0-9_-]{1,100}$/u.test(configurationId) || !vct || authorizationUrl === signingUrl
    || authorizationEndpoint.origin !== signingEndpoint.origin) {
    throw new TypeError('Invalid delegated wallet issuance settings')
  }

  const expectedBearer = digest(inboundBearer)
  async function requestGateway(url: string, body: unknown) {
    const response = await transport(url, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(7000),
      headers: {authorization: `Bearer ${outboundBearer}`, accept: 'application/json', 'content-type': 'application/json'},
      body: JSON.stringify(body),
    })
    if ([403, 404, 409, 410].includes(response.status)) return undefined
    if (response.status !== 200) throw new Error('Wallet credential gateway request failed')
    const payload = asObject(await response.json().catch(() => undefined))
    if (!payload) throw new Error('Invalid wallet credential gateway response')
    return payload
  }

  return {
    credentialIssuer,
    authorizationServer: credentialIssuer,
    credentialConfigurations: {[configurationId]: {format: 'dc+sd-jwt', vct}},
    preAuthorizedOffers: offers,
    issueNonce: offers.issueNonce,
    resolveGrant: offers.resolveGrant,
    async offerAuthorization(request, reference) {
      const bearer = /^Bearer ([^\s]+)$/iu.exec(request.headers.authorization ?? '')?.[1]
      if (!bearer || !timingSafeEqual(digest(bearer), expectedBearer)
        || !/^[A-Za-z0-9_-]{43}$/u.test(reference)) return undefined
      const approved = await requestGateway(authorizationUrl, {authorization_reference: reference})
      if (approved?.configurationId !== configurationId) return undefined
      const command = parseAuthorizedCommand(approved.command, reference)
      return command ? {command, configurationId} : undefined
    },
    async issueForWallet(command, proof, binding) {
      const holderKey = await consumeWalletHolderProof(command, proof, binding, Date.now())
      const result = await requestGateway(signingUrl, {command, holderKey})
      if (!result) throw new CredentialIssuanceDeniedError('Authoritative issuance was denied')
      return readSignedCredential(result, options.signingIssuer ?? credentialIssuer, vct, holderKey)
    },
  }
}
