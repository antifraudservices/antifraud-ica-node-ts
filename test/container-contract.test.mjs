// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import test from 'node:test'

test('defines a reproducible non-root Cloud Run service image and documented Beta environment', async () => {
  const [dockerfile, packageJson, environment] = await Promise.all([
    readFile(new URL('../Dockerfile', import.meta.url), 'utf8'),
    readFile(new URL('../package.json', import.meta.url), 'utf8').then(JSON.parse),
    readFile(new URL('../.env.example', import.meta.url), 'utf8'),
  ])
  assert.match(dockerfile, /FROM node:24\.15\.0-alpine AS build/u)
  assert.match(dockerfile, /USER node/u)
  assert.match(dockerfile, /CMD \["node", "dist\/server\.js"\]/u)
  assert.equal(packageJson.scripts.start, 'node dist/server.js')
  for (const name of [
    'ANTIFRAUD_DEPLOYMENT_STAGE',
    'ANTIFRAUD_NETWORK_KIND',
    'ANTIFRAUD_ICA_DEMO_ENABLED',
    'ANTIFRAUD_ICA_DEMO_BEARER',
    'ANTIFRAUD_ICA_DEMO_SIGNING_SECRET',
  ]) assert.match(environment, new RegExp(`^${name}=`, 'mu'))
})
