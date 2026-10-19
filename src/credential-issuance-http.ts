import {createServer, type IncomingMessage, type Server, type ServerResponse} from 'node:http'

import {
  CredentialIssuanceStatus,
  defineCredentialIssuanceRequest,
  type CredentialIssuanceReceipt,
  type CredentialIssuanceRequest,
  type IdentityAttestationCapabilityValue,
} from 'antifraud-data-utils-ts'

import {AuthoritativeIssuanceManager} from './authoritative-issuance-manager.js'

export interface CredentialIssuanceStore {
  put(receipt: CredentialIssuanceReceipt): Promise<void>
  get(issuanceId: string): Promise<CredentialIssuanceReceipt | undefined>
}

export class InMemoryCredentialIssuanceStore implements CredentialIssuanceStore {
  private readonly receipts = new Map<string, CredentialIssuanceReceipt>()

  async put(receipt: CredentialIssuanceReceipt): Promise<void> {
    this.receipts.set(receipt.issuanceId, structuredClone(receipt))
  }

  async get(issuanceId: string): Promise<CredentialIssuanceReceipt | undefined> {
    const receipt = this.receipts.get(issuanceId)
    return receipt ? structuredClone(receipt) : undefined
  }
}

export interface ResolvedIssuanceActor {
  actorReference: string
}

export interface IcaHttpServerOptions {
  manager: AuthoritativeIssuanceManager
  store: CredentialIssuanceStore
  resolveActor(request: IncomingMessage): Promise<ResolvedIssuanceActor | undefined>
}

type JsonObject = Record<string, unknown>

function sendJson(response: ServerResponse, statusCode: number, body: JsonObject): void {
  response.writeHead(statusCode, {'content-type': 'application/json'})
  response.end(JSON.stringify(body))
}

async function readJson(request: IncomingMessage): Promise<JsonObject> {
  const chunks: Buffer[] = []
  for await (const chunk of request) chunks.push(Buffer.from(chunk))
  if (chunks.length === 0) throw new TypeError('Request body is required')
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new TypeError('Request body must be a JSON object')
  }
  return parsed as JsonObject
}

function parseRequest(body: JsonObject): CredentialIssuanceRequest {
  if ('claims' in body || 'actor' in body || 'actor_reference' in body) {
    throw new TypeError('Caller-supplied claims and actor authority are not accepted')
  }
  return defineCredentialIssuanceRequest({
    subjectReference: body.subject_reference,
    capability: body.capability as IdentityAttestationCapabilityValue,
    verificationTransactionId: body.verification_transaction_id,
  } as CredentialIssuanceRequest)
}

function toWire(receipt: CredentialIssuanceReceipt): JsonObject {
  return {
    issuance_id: receipt.issuanceId,
    status: receipt.status,
    ...('credential' in receipt ? {credential: receipt.credential} : {}),
    ...(receipt.credentialReference
      ? {credential_reference: receipt.credentialReference}
      : {}),
    ...(receipt.reason ? {reason: receipt.reason} : {}),
  }
}

function issuanceIdFromPath(pathname: string): string | undefined {
  const prefix = '/credential-issuances/'
  if (!pathname.startsWith(prefix)) return undefined
  const encoded = pathname.slice(prefix.length)
  if (!encoded || encoded.includes('/')) return undefined
  return decodeURIComponent(encoded)
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: IcaHttpServerOptions,
): Promise<void> {
  const pathname = new URL(request.url ?? '/', 'http://localhost').pathname
  if (request.method === 'GET' && pathname === '/healthz') {
    sendJson(response, 200, {status: 'ok'})
    return
  }

  if (request.method === 'POST' && pathname === '/credential-issuances') {
    const body = await readJson(request)
    const canonicalRequest = parseRequest(body)
    const actor = await options.resolveActor(request)
    if (!actor?.actorReference) {
      sendJson(response, 401, {error: 'unauthorized'})
      return
    }
    const result = await options.manager.issue({...canonicalRequest, actorReference: actor.actorReference})
    const receipt: CredentialIssuanceReceipt = {
      issuanceId: result.issuanceId,
      status: CredentialIssuanceStatus.Issued,
      credential: result.credential,
    }
    await options.store.put(receipt)
    sendJson(response, 201, toWire(receipt))
    return
  }

  if (request.method === 'GET') {
    const issuanceId = issuanceIdFromPath(pathname)
    if (issuanceId) {
      const actor = await options.resolveActor(request)
      if (!actor?.actorReference) {
        sendJson(response, 401, {error: 'unauthorized'})
        return
      }
      const receipt = await options.store.get(issuanceId)
      if (!receipt) {
        sendJson(response, 404, {error: 'issuance-not-found'})
        return
      }
      sendJson(response, 200, toWire(receipt))
      return
    }
  }
  sendJson(response, 404, {error: 'not-found'})
}

export function createIcaHttpServer(options: IcaHttpServerOptions): Server {
  return createServer((request, response) => {
    void handleRequest(request, response, options).catch(error => {
      const isClientError = error instanceof TypeError || error instanceof SyntaxError
      sendJson(response, isClientError ? 400 : 500, {
        error: isClientError ? 'invalid-request' : 'credential-issuance-failed',
      })
    })
  })
}

export const icaOpenApiDocument = Object.freeze({
  openapi: '3.1.0',
  info: {title: 'Neutral Identity Credential Authority', version: '0.1.0'},
  paths: {
    '/healthz': {get: {operationId: 'getHealth'}},
    '/credential-issuances': {post: {operationId: 'createCredentialIssuance'}},
    '/credential-issuances/{issuanceId}': {get: {operationId: 'getCredentialIssuance'}},
  },
})
