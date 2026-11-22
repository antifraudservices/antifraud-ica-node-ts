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

`AuthoritativeIssuanceManager.issueForWallet` is the issuance boundary for an
already-authorized OpenID4VCI offer. It verifies an ES256 wallet proof against
the offer's credential issuer, validates its timestamp, and consumes a scoped
nonce before handing the public holder key to the issuer's signer. The signer
binds the issued credential to that key. The offer adapter owns atomic nonce
storage and associates the offer with the authenticated actor, capability and
subject. The existing authorization, verification, readback and policy checks
apply to the wallet flow.

Configure `walletIssuance` on `createIcaHttpServer` to enable issuer metadata,
`POST /nonce`, and the bearer-protected `POST /credential` endpoint. The OAuth
authorization server must validate and bind the access grant to a specific
credential configuration and authoritative subject. Configure an SD-JWT VC
signer that emits `cnf.jwk` and an atomic, short-lived nonce store. This
adapter is exercised against the real local HTTP routes. Wallet onboarding,
issuer trust registration and presentation validation are separate integration
acceptance steps.



For the pre-authorized code flow, call `createPreAuthorizedWalletOffers` with
an issuer-scoped secret and a durable `WalletOfferStore`. Prepare the offer
only after resolving the authorized actor, organization and subject from
trusted records. Give the holder the offer URL and deliver the transaction
code separately. Connect `preAuthorizedOffers`, `issueNonce` and
`resolveGrant` to the same offer service instance in `walletIssuance`.
A backend with an authorized issuance reference can request an offer with
`POST /credential-offers` when `offerAuthorization` is configured. The adapter
must authenticate the backend, resolve the current authorization and reserve
that reference once. The request contains the opaque `authorization_reference`.
The response contains the wallet offer URL and a transaction code for separate
delivery to the authenticated holder.

The wallet can then fetch the offer, exchange the code at `/token` and obtain
the credential at `/credential`. The store must atomically mark the grant
used and reserve the nonce across concurrent requests and offers. Retain the
nonce reservation until its supplied expiry.

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

## Local test runtime

`npm test` builds the service and exercises its real HTTP boundary. An
all-local launcher may run `npm run build` and `npm start` with
`ANTIFRAUD_DEPLOYMENT_STAGE=test`, `ANTIFRAUD_NETWORK_KIND=test`,
`ANTIFRAUD_ICA_DEMO_ENABLED=true`, a configured `ANTIFRAUD_ICA_ISSUER_DID`
(`did:web:`), and disposable `ANTIFRAUD_ICA_DEMO_BEARER` (at least 16
characters) and `ANTIFRAUD_ICA_DEMO_SIGNING_SECRET` (at least 32 characters).
This mode binds to `127.0.0.1` and rejects `NODE_ENV=production`.

It reuses the issuance manager, rejects caller-supplied claims, accepts only
the local synthetic subject and verification prefixes, and keeps receipts in
memory. Credentials contain `demo: true` and an explicitly local HMAC proof;
they are not production credentials or the reviewed admission credentials
used by a gateway. No legacy verification endpoint is added by this runtime.

## Remaining service modules

### Organization admission and registry fallback

The admission verifier selects a profile by network, jurisdiction and sector.
A profile supplies the authoritative registry lookup and the verifier for
the required proof. ICA compares the legal identifier from the registry with
the organization identifier established by the proof before storing evidence.

The verifier reads the official source first. A temporary outage permits a
cached observation when the profile has a cache adapter and the observation
is within the configured age. A live inactive status or a live result with
no matching organization takes precedence. Cache evidence retains the
official source URL, the original observation timestamp and its cache origin.

Set `ANTIFRAUD_ICA_REGISTRY_CACHE_MAX_AGE_HOURS` in the pod environment,
for example via its ConfigMap. The default is `72`. A value of `0` disables
fallback. A profile may apply a shorter limit. The cache adapter must
preserve the time when it actually observed the record at the source.

The structured `organization_registry_fallback` warning identifies the
network, jurisdiction, sector and reason. When a cache observation is
available, it includes the observation timestamp and the effective age limit.
Route a log alert for this event to the designated ICA controller's email
through the deployment's monitoring system. No alert includes legal
identifiers, registry URLs, contact details or proof references.

The HTTP runtime accepts evidence verification at
`POST /organization-verifications` when configured with the verifier module.
The request supplies `network`, `jurisdiction`, `sector`, `identifier`
with `scheme` and `value`, and a `proofReference`. The runtime resolves the
actor from the authenticated request. Evidence verification requires the
registry, proof, authorization and evidence-storage adapters, and precedes
the separate decision to admit the organization. The decision caller checks
the authenticated actor and `proof.submittedReference` against its request
before using the checks. The provider's immutable verified reference remains
available separately in `proof.reference`.

The admission-only Test Network runtime starts with
`ANTIFRAUD_DEPLOYMENT_STAGE=test-network`. Configure the exact host DID and
Gateway secret with `ANTIFRAUD_ICA_ADMISSION_HOST_DID` and
`ANTIFRAUD_ICA_ADMISSION_GATEWAY_TOKEN`. The authenticated Gateway supplies
the actor and application ID in `X-Admission-Actor` and
`X-Admission-Application-Id`. The default Demo runtime does not use this
configuration.

Set `ANTIFRAUD_ICA_ADMISSION_PROFILES_JSON` to the enabled jurisdiction and
sector pairs. Each entry includes `jurisdiction`, `sector` and `method`.
PDF certificate profiles require a `signaturePolicyId` and can pin an
`acceptedTemplateVersion`. Configure the trusted
provider through `ANTIFRAUD_ICA_ADMISSION_PROVIDER_URL` and
`ANTIFRAUD_ICA_ADMISSION_PROVIDER_TOKEN`. ICA posts to these paths under the
configured HTTPS base URL:

| Path | Provider responsibility |
| --- | --- |
| `registry` | Resolve the exact legal identifier in the official registry and return its status, source URL and observation timestamp. |
| `registry-cache` | Return the previously observed registry record if available. ICA enforces its age limit. |
| `proof` | Resolve the submitted reference for the authorized application and actor, verify the proof and return the matching identifier, the original submitted reference, an immutable verified reference and the template validation result when available. A PDF digest refers to stored bytes that the provider must retrieve and verify. |
| `directory` | Return an active regional sector record with its jurisdiction, sector, legal identifier, source URL and observation timestamp. An unavailable directory leaves this check unconfirmed. |
| `evidence` | Persist the full verification result before acknowledging the request with HTTP 200, 201 or 204. |

For a PDF certificate profile, `proof` also returns a
`certificateValidation` record with:

- `indication` equal to `TOTAL_PASSED` under the configured `policyId`;
- `documentSha256` and `reportReference` for the exact verified document and
  its provider-held report;
- `completeDocumentCovered` and `organizationAuthorityVerified` both set to
  true after checking the signed document and the signer's authority;
- the matching `hostDid`, `applicationId`, `actorReference`, `network`,
  `jurisdiction` and `sector`.

Return `verifiedTemplate` with `version`, `documentSha256` and
`requiredFieldsVerified: true` after validating all mandatory fields of the
configured application template. The template digest must match the digest
in the successful certificate report. The ICA includes
`signed-application-template` in the evidence when both validations match
the configured version and the submitted document.

The provider owns cryptographic validation and normalizes its report into
this record. The ICA compares the record with the current request and stores
the matching report reference with the evidence. A validation indication
describes the result under the provider's validation policy.
[DSS validation reporting](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html#_signature_validation_and_reports)

Keep configured secrets and evidence stores private. The runtime can use the
provider only once these adapters and its scoped proof records are available.

To retrieve PDF bytes from the application owner, configure
`ANTIFRAUD_ICA_ADMISSION_DOCUMENT_URL` and
`ANTIFRAUD_ICA_ADMISSION_DOCUMENT_TOKEN`. For a PDF certificate profile,
ICA reads the authorized application by scope, verifies the document digest
and sends its bytes to the configured proof provider as `pdfBase64`. The
evidence store receives the resulting proof reference and checks. A generated
application draft can be resolved by digest. Only the proof provider can
establish that the document has a valid certificate signature.

### Provider integrations

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
