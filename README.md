# Antifraud Identity Credential Authority

Product-neutral Node.js service for authoritative verification and signed credential issuance.

## Status

Public implementation foundation. No service image has been built or deployed and no production readiness is claimed yet.

## Authority boundary

This service is the provider-side authority. It may issue a credential only when all of the following are true:

1. the caller and requested capability are authorized;
2. the relevant identity presentation or evidence has been verified by a configured trusted verifier;
3. the subject or relationship has been read again from the configured authoritative index;
4. the returned data satisfies the canonical schema and conflict rules;
5. the issuer policy permits the requested credential and disclosure;
6. signing succeeds using service-controlled key custody;
7. an auditable issuance result is recorded without logging personal data.

A user interface, wallet, generic backend for frontend, or SDK must never supply authoritative claims as if they were provider readback and must never receive the signing key.

## Protocol boundary

OpenID for Verifiable Presentations and the High Assurance Interoperability Profile are used to request and verify wallet presentations. They do not issue the resulting provider credential.

Credential issuance is a separate endpoint and state machine. It may expose OpenID for Verifiable Credential Issuance or another documented protocol. Presentation, readback, decision, issuance, status, and revocation remain distinct audit events.

## Planned service modules

- trusted-verifier integration;
- authoritative-index provider adapters;
- policy and capability evaluation;
- canonical claim validation;
- credential construction and signing;
- credential status and revocation;
- audit-event emission;
- optional distributed-ledger anchoring through an adapter.

A ledger may record issuer authority, credential status, licence status, or a non-personal integrity commitment. Raw identity evidence, disclosed personal claims, credentials, and signing keys must not be written to a ledger.

## Public repository boundary

This repository contains neutral source, tests, examples, and deployment templates without live values. Secrets, private trust material, personal data, tenant manifests, live endpoints, and operational evidence remain outside Git.

The existing private legacy gateway repository is not the source of truth for this service and will not be made public or copied wholesale. Any reused behavior requires a file-by-file contract and security audit.

## Dependency direction

```text
antifraud-data-utils-ts
          ↓
antifraud-sdk-core-ts
          ↓
antifraud-sdk-node-ts
          ↓
antifraud-ica-node-ts
```

Service-side implementation may use lower-level packages directly where appropriate, but must not duplicate their canonical literals or schemas.

## Implementation gate

The first implementation increment must prove, with executable tests, that issuance fails before authoritative readback, rejects conflicting claims, never exports signing authority, and records a non-personal audit result. Real deployment, key custody, trust, status, and revocation require separate integration and end-to-end evidence.

## License

Apache-2.0.

