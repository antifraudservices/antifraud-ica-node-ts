# AGENTS.md

## Scope

This repository owns the product-neutral provider service that authorizes requests, confirms trusted verification, performs authoritative index readback, evaluates issuance policy, signs credentials through injected key custody and emits non-personal audit events.

## Development contract

- Use red-green-refactor test-driven development.
- Begin every test file with the required flow-contract comment.
- Reject caller-supplied claims before authorization, readback or signing.
- Signing requires authorization, trusted verification, authoritative readback and policy approval.
- Signing keys remain behind an injected signer and never enter requests or responses.
- Audit events contain no personal claims, presentation, credential or key material.
- Ledger integration is optional and adapter-owned.
- Documentation and code are written in English.

