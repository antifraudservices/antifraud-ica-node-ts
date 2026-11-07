import {createHmac, randomUUID} from 'node:crypto'
import type {Server} from 'node:http'

import {AuthoritativeIssuanceManager} from './authoritative-issuance-manager.js'
import {
  InMemoryCredentialIssuanceStore,
  createIcaHttpServer,
} from './credential-issuance-http.js'

type Environment = Readonly<Record<string, string | undefined>>

function required(environment: Environment, name: string, minimumLength: number): string {
  const value = environment[name]?.trim() ?? ''
  if (value.length < minimumLength) throw new Error(`${name} is required and must contain at least ${minimumLength} characters.`)
  return value
}

function bearerCredential(authorization: string | undefined): string | undefined {
  return authorization?.match(/^Bearer\s+(.+)$/iu)?.[1]?.trim()
}

export function createIcaBetaDemoServer(environment: Environment): Server {
  if (environment.ANTIFRAUD_DEPLOYMENT_STAGE !== 'staging' || environment.ANTIFRAUD_NETWORK_KIND !== 'demo') {
    throw new Error('The disposable ICA Demo runtime is allowed only in the staging Demo profile.')
  }
  return createSyntheticIcaServer(environment, 'beta', 'did:web:host-beta.antifraud.services:ica')
}

/** Explicit all-local authority composition; it never enables deployed authority. */
export function createIcaLocalTestServer(environment: Environment): Server {
  if (environment.ANTIFRAUD_DEPLOYMENT_STAGE !== 'test' || environment.ANTIFRAUD_NETWORK_KIND !== 'test'
    || environment.NODE_ENV === 'production') throw new Error('The local ICA requires the test deployment and test network.')
  const issuer = required(environment, 'ANTIFRAUD_ICA_ISSUER_DID', 8)
  if (!issuer.startsWith('did:web:')) throw new Error('The local ICA issuer must be a configured did:web authority.')
  return createSyntheticIcaServer(environment, 'local', issuer)
}

function createSyntheticIcaServer(environment: Environment, profile: 'beta' | 'local', issuer: string): Server {
  if (environment.NODE_ENV === 'production') throw new Error('Synthetic ICA authority is unavailable in production.')
  if (environment.ANTIFRAUD_ICA_DEMO_ENABLED !== 'true') {
    throw new Error('The disposable ICA Demo runtime must be explicitly enabled.')
  }
  const bearer = required(environment, 'ANTIFRAUD_ICA_DEMO_BEARER', 16)
  const signingSecret = required(environment, 'ANTIFRAUD_ICA_DEMO_SIGNING_SECRET', 32)
  const actorReference = `urn:actor:antifraud-${profile}-professional`
  const subjectPrefix = `urn:subject:synthetic-${profile}-`
  const verificationPrefix = `verification:synthetic-${profile}-`
  const syntheticType = profile === 'beta' ? 'synthetic-beta-learner' : 'synthetic-local-subject'
  const store = new InMemoryCredentialIssuanceStore()
  const manager = new AuthoritativeIssuanceManager({
    authorization: {
      authorize: async command => ({
        allowed: command.actorReference === actorReference
          && command.capability === 'identity.relationship.attest',
      }),
    },
    verification: {
      assertVerified: async transactionId => ({
        verified: transactionId.startsWith(verificationPrefix),
      }),
    },
    index: {
      readAuthoritativeSubject: async subjectReference => {
        if (!subjectReference.startsWith(subjectPrefix)) {
          throw new Error('The Beta Demo ICA accepts only governed synthetic subjects.')
        }
        return {
          sourceId: `source:${subjectReference}`,
          claims: Object.freeze({
            'org.schema.Person.identifier.value': subjectReference,
            'org.schema.Person.additionalType': syntheticType,
          }),
        }
      },
    },
    policy: {
      evaluate: async ({authoritativeSubject}) => ({
        allowed: authoritativeSubject.claims['org.schema.Person.additionalType'] === syntheticType,
      }),
    },
    signer: {
      issue: async ({command, sourceId, claims}) => {
        const issuanceId = `urn:uuid:${randomUUID()}`
        const credentialBody = {
          id: issuanceId,
          type: ['VerifiableCredential', 'IdentityAttestationCredential'],
          issuer,
          credentialSubject: {id: sourceId, claims},
          capability: command.capability,
          demo: true,
        }
        const signature = createHmac('sha256', signingSecret)
          .update(JSON.stringify(credentialBody))
          .digest('base64url')
        return {
          issuanceId,
          credential: Object.freeze({
            ...credentialBody,
            proof: Object.freeze({
              type: profile === 'beta' ? 'AntifraudBetaDemoHmacProof2026' : 'AntifraudLocalTestHmacProof2026',
              verificationMethod: `${issuer}#demo-signing`,
              signature,
            }),
          }),
        }
      },
    },
    audit: {record: async () => undefined},
    clock: {now: () => new Date().toISOString()},
  })
  return createIcaHttpServer({
    manager,
    store,
    resolveActor: async request => bearerCredential(request.headers.authorization) === bearer
      ? {actorReference}
      : {actorReference: ''},
  })
}
