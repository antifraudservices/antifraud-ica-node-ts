# Changelog

## Unreleased

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
