# Changelog

## Unreleased

- Persist wallet offers and issuer-wide nonce reservations in atomic Firestore
  transactions so that an ICA restart or a second instance cannot replay them.

- Allow an authenticated backend to prepare a wallet offer using a
  server-resolved authorization reference.

- Add by-reference OpenID4VCI offers with a transaction code, one-time OAuth
  grant exchange and issuer-wide proof nonce replay protection.

- Add OpenID4VCI issuer metadata, nonce and credential endpoints. Verify the wallet holder proof and consume an offer-bound nonce before issuing a holder-bound credential.

- Include the exact submitted proof reference next to its verified provider
  reference in persisted organization admission evidence.

- Bind the required application field checks to the same PDF as the verified
  certificate signature before reporting the signed-template check.

- Require a successful certificate validation report for the pinned policy,
  exact document digest, organization authority and admission scope.

- Retrieve a scoped PDF from the configured private application source,
  verify the SHA-256 digest and forward the bytes to the proof verifier.

- Add a Test Network admission runtime with scoped Gateway authentication,
  configured HTTPS evidence adapters and durable-provider acknowledgement.

- Add a scoped organization admission evidence verifier with authoritative
  registry matching, Spanish NIF/VAT correlation and bounded registry cache
  fallback. Record the observation time and emit a structured warning on outage.
- Expose organization evidence verification over authenticated HTTP when the
  provider configures the verifier and its adapters.
- Report verified admission checks for the configured signed template and for
  a matching active organization in the exact regional sector directory.

- Add an explicitly enabled, loopback-only local test runtime alongside the
  staging Demo runtime. Reuse issuance, authorization, readback and receipt
  ports with synthetic local fixtures; reject production and mismatched
  network configuration. No legacy verification endpoint is introduced.
- Verify local HTTP issuance, receipt reload and fail-closed startup as part
  of the 17-test service suite.

- Add the documented `/health` alias used for public Cloud Run verification
  while retaining `/healthz` for local and container probes.

- Add a fail-closed, explicitly staging-only Beta Demo runtime, service entry
  point and non-root Cloud Run image. It resolves the synthetic actor and
  authoritative claims server-side, issues an explicitly Demo credential and
  retains receipts only for the disposable process lifetime. Both issuance and
  receipt reload require the BFF-owned bearer credential.

- Pin `antifraud-data-utils-ts@0.1.4` and the test-only
  `antifraud-sdk-node-ts@0.2.6` chain, including its bearer-authenticated
  provider client, and verify
  that the canonical confidential-document and DIDComm attachment exports are
  available without introducing an ICA-local copy.

- Port audited product-neutral canonical JSON, SHA3 multihash/CID, network-kind, security-mode, OpenID Identity Assurance and Schema.org validation primitives from the existing private ICA.
- Add an executable public-source boundary that rejects the excluded veterinary and regional-health profiles.
- Document source provenance and the remaining adapter migration boundary.

- Add the authoritative credential-issuance manager and provider ports.
- Document provider enforcement of exact active group membership, reusable
  controller-managed group authorization, and separate optional subject
  authorization.
- Distinguish employer-signed qualification attestations from credentials
  issued by the referenced university or licensing body.
- Add the credential-issuance HTTP runtime, server-owned actor resolution,
  receipt-store port, local in-memory adapter and route-complete OpenAPI
  document.
- Prove the local Core -> Node SDK -> HTTP service -> authoritative issuance
  journey without accepting caller-owned claims or actor authority.
