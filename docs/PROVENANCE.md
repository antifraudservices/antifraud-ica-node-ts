# Source provenance

This service core is a product-neutral extraction of the provider boundary already documented in the existing private ICA and identity-application repositories.

The first audited migration imports only these implementation-neutral primitives from the existing private ICA:

- deterministic canonical JSON serialization;
- SHA3-256 and SHA3-384 multihash and raw CID helpers;
- explicit network-kind parsing;
- production security-mode guardrails;
- OpenID Identity Assurance evidence validation;
- Schema.org credential-subject validation.

The imported files were detached from product dependencies and are covered by a public portability contract. The private source repository was not modified.

No sector directory, organization-admission policy, clinic workflow, regional-health workflow, deployment manifest, tenant configuration, endpoint, certificate, key material or operational evidence was copied. `node_modules` and generated `dist` content are ignored and are never source artifacts.

Additional adapters may be migrated file by file only after their endpoint, authentication, storage, ledger and key-custody contracts have been audited against this service boundary. Each migration must identify its source behavior, remove deployment-specific policy and add a failing public contract test before implementation.
