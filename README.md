# Antifraud Identity Credential Authority

Product-neutral Node.js service for authoritative verification and signed credential issuance.

Its core trust invariant is that evidence never substitutes authority. An
employer, university, licensing body, verifier, and subject may support related
facts, but each retains a separate issuer identity, jurisdiction, signature,
and status.

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

## Implemented neutral core

- authoritative issuance orchestration with injected authorization, verification, readback, policy, signer and audit ports;
- deterministic canonical JSON serialization;
- SHA3-256 and SHA3-384 multihash and raw-content CID helpers;
- OpenID Identity Assurance evidence validation;
- Schema.org credential-subject validation;
- explicit `test`, `local-network`, `test-network` and `network` context handling;
- production startup rejection for demo security mode.
- a minimal local HTTP runtime for credential issuance, receipt lookup and
  health, with every route represented in the exported OpenAPI document;
- server-side actor resolution, canonical request validation and durable-store
  port separation; the included in-memory store is for local tests only.

## Remaining service modules

- trusted-verifier integration;
- authoritative-index provider adapters;
- policy and capability evaluation;
- canonical claim validation;
- credential construction and signing;
- credential status and revocation;
- audit-event emission;
- optional distributed-ledger anchoring through an adapter.
- production HTTP authentication, persistent receipt storage and service-image
  deployment.

A ledger may record issuer authority, credential status, licence status, or a non-personal integrity commitment. Raw identity evidence, disclosed personal claims, credentials, and signing keys must not be written to a ledger.

## Workforce authorization at the provider

Before accepting evidence or issuing a credential on behalf of an
organization, the service must verify the employee's active assignment, active
membership in the exact group, and the controller-managed authorization for
that same group and requested capability. The employee does not have a
separate Consent merely because they are a member.

If the operation also requires permission from the subject or lawful
representative, that authorization is an additional and independent gate. A
group authorization never substitutes for it. Assignment notifications sent
as Communication records are auditable notices, not proof of authority.

Provider readback, schema validation, policy evaluation, signing, and
non-personal audit remain mandatory after these authorization gates.

For an employee qualification, the provider resolves an awarding organization
by legal identifier and jurisdiction. An employer may issue its own signed
attestation when it has reviewed evidence, but may not impersonate the
university or licensing body. If a source-issued credential later exists, its
proof is retained alongside the employer proof with each issuer clearly
identified.

In health use cases, qualification proof remains separate from current licence
status, active employment, group authorization, and any required subject
authorization. The provider evaluates all required gates and fails closed; it
does not manufacture professional authority from an employer attestation.

## Public repository boundary

This repository contains neutral source, tests, examples, and deployment templates without live values. Secrets, private trust material, personal data, tenant manifests, live endpoints, and operational evidence remain outside Git.

The existing private ICA repository is not published and is not copied wholesale. Neutral behavior is migrated file by file with a public contract, provenance record and security review. Sector directories, jurisdiction-specific admission rules, tenant configurations, live endpoints, certificates and deployment evidence remain outside this repository.

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
