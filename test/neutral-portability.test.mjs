// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict'
import {readFile, readdir} from 'node:fs/promises'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import test from 'node:test'

import {
  assertIcaSecurityStartupGuardrails,
  assertSchemaOrgCredential,
  assertValidOidc4idaEvidenceObject,
  multibase58MultihashSha3_384Hex,
  parseIcaNetworkKind,
  stableStringifyJson,
} from '../dist/index.js'

test('exports the audited neutral primitives migrated from the existing ICA', () => {
  assert.equal(stableStringifyJson({z: 1, a: 2}), '{"a":2,"z":1}')
  assert.equal(parseIcaNetworkKind('terms'), 'test')
  assert.match(
    multibase58MultihashSha3_384Hex('00'.repeat(48)),
    /^z[1-9A-HJ-NP-Za-km-z]+$/,
  )

  assert.doesNotThrow(() => assertSchemaOrgCredential({
    credentialSubject: {'@type': 'Person'},
  }))
  assert.doesNotThrow(() => assertValidOidc4idaEvidenceObject({
    type: 'electronic_signature',
    signature_type: 'qualified_electronic_signature',
    issuer: 'urn:issuer:synthetic',
    serial_number: 'synthetic-001',
    created_at: '2026-10-17T00:00:00.000Z',
  }))
})

test('fails closed when a production process selects demo security mode', () => {
  const original = process.env.NODE_ENV
  process.env.NODE_ENV = 'production'
  try {
    assert.throws(
      () => assertIcaSecurityStartupGuardrails({
        securityMode: 'demo',
        jsonLegacy: true,
        demoAllowInsecureBearer: true,
        allowLegacyDidcommPlaintextMediaType: true,
      }),
      /not allowed/,
    )
  } finally {
    if (original === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = original
  }
})

async function sourceFiles(directory) {
  const entries = await readdir(directory, {withFileTypes: true})
  const files = []
  for (const entry of entries) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await sourceFiles(path))
    else if (entry.isFile()) files.push(path)
  }
  return files
}

test('public runtime excludes the veterinary and regional-health source profiles', async () => {
  const files = await sourceFiles(fileURLToPath(new URL('../src/', import.meta.url)))
  const content = (await Promise.all(files.map((file) => readFile(file, 'utf8')))).join('\n')

  // These literals are intentionally asserted because their presence is the prohibited behavior.
  for (const forbidden of [
    'British Columbia',
    'Castilla y León',
    'veterinary-clinic',
    'health-care',
  ]) {
    assert.equal(content.toLowerCase().includes(forbidden.toLowerCase()), false, forbidden)
  }
})
