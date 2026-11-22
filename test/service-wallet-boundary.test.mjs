// Flow contract: start the organization admission service even when obsolete professional
// wallet settings exist. Offers and wallet issuer metadata belong to the tenant.
import {strict as assert} from 'node:assert'
import {spawn} from 'node:child_process'
import {randomBytes} from 'node:crypto'
import {once} from 'node:events'
import test from 'node:test'
import {fileURLToPath} from 'node:url'

test('the admission service starts independently of professional wallet configuration', {timeout: 10_000}, async t => {
  const tenantIssuer = 'https://issuer.example/tenant'
  const child = spawn(process.execPath, [fileURLToPath(new URL('../dist/server.js', import.meta.url))], {
    env: {
      ...process.env,
      PORT: '0',
      NODE_ENV: 'test',
      ANTIFRAUD_DEPLOYMENT_STAGE: 'test',
      ANTIFRAUD_NETWORK_KIND: 'test',
      ANTIFRAUD_ICA_ISSUER_DID: 'did:web:issuer.example',
      ANTIFRAUD_ICA_DEMO_ENABLED: 'true',
      ANTIFRAUD_ICA_DEMO_BEARER: randomBytes(32).toString('base64url'),
      ANTIFRAUD_ICA_DEMO_SIGNING_SECRET: randomBytes(32).toString('base64url'),
      ANTIFRAUD_ICA_WALLET_ISSUER: tenantIssuer,
    },
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  t.after(() => child.kill())
  const started = await Promise.race([
    once(child.stdout, 'data').then(([output]) => output.toString()),
    once(child, 'exit').then(([code]) => `exit ${code}`),
  ])
  assert.match(started, /ICA listening/u)
})
