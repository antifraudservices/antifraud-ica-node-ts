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
  if (environment.ANTIFRAUD_ICA_DEMO_ENABLED !== 'true') {
    throw new Error('The disposable ICA Demo runtime must be explicitly enabled.')
  }
  const bearer = required(environment, 'ANTIFRAUD_ICA_DEMO_BEARER', 16)
  const signingSecret = required(environment, 'ANTIFRAUD_ICA_DEMO_SIGNING_SECRET', 32)
  const store = new InMemoryCredentialIssuanceStore()
  const manager = new AuthoritativeIssuanceManager({
    authorization: {
      authorize: async command => ({
        allowed: command.actorReference === 'urn:actor:antifraud-beta-professional'
          && command.capability === 'identity.relationship.attest',
      }),
    },
    verification: {
      assertVerified: async transactionId => ({
        verified: transactionId.startsWith('verification:synthetic-beta-'),
      }),
    },
    index: {
      readAuthoritativeSubject: async subjectReference => {
        if (!subjectReference.startsWith('urn:subject:synthetic-beta-')) {
          throw new Error('The Beta Demo ICA accepts only governed synthetic subjects.')
        }
        return {
          sourceId: `source:${subjectReference}`,
          claims: Object.freeze({
            'org.schema.Person.identifier.value': subjectReference,
            'org.schema.Person.additionalType': 'synthetic-beta-learner',
          }),
        }
      },
    },
    policy: {
      evaluate: async ({authoritativeSubject}) => ({
        allowed: authoritativeSubject.claims['org.schema.Person.additionalType'] === 'synthetic-beta-learner',
      }),
    },
    signer: {
      issue: async ({command, sourceId, claims}) => {
        const issuanceId = `urn:uuid:${randomUUID()}`
        const credentialBody = {
          id: issuanceId,
          type: ['VerifiableCredential', 'IdentityAttestationCredential'],
          issuer: 'did:web:host-beta.antifraud.services:ica',
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
              type: 'AntifraudBetaDemoHmacProof2026',
              verificationMethod: 'did:web:host-beta.antifraud.services:ica#demo-signing',
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
      ? {actorReference: 'urn:actor:antifraud-beta-professional'}
      : {actorReference: ''},
  })
}
