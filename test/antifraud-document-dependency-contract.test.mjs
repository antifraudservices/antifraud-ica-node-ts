// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Journey: (1) install the exact released data and Node SDK chain; (2) resolve the canonical confidential document;
// (3) resolve both DIDComm attachment builders and the trusted Node delivery controller from registry artifacts.
// Authorization invariant: this dependency smoke grants no tenant, issuer, wallet or delivery authority.
// Persistence invariant: ICA keeps its authoritative issuance state separate from document-transport continuity.
import assert from 'node:assert/strict'
import test from 'node:test'

import {
  SyntheticConfidentialDocumentFixture,
  buildDidCommInlineBinaryAttachment,
  buildDidCommLinkedBinaryAttachment,
  buildSchemaOrgConfidentialDocumentGraph,
} from 'antifraud-data-utils-ts'
import {createTrustedDocumentDeliveryController} from 'antifraud-sdk-node-ts'

test('loads the exact released confidential-document and DIDComm attachment surface', () => {
  assert.equal(typeof buildSchemaOrgConfidentialDocumentGraph, 'function')
  assert.equal(typeof buildDidCommInlineBinaryAttachment, 'function')
  assert.equal(typeof buildDidCommLinkedBinaryAttachment, 'function')
  assert.equal(typeof createTrustedDocumentDeliveryController, 'function')
  assert.equal(SyntheticConfidentialDocumentFixture.attachment.mediaType, 'application/pdf')
})
