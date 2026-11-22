import {createConfiguredWalletIssuance} from './configured-wallet-issuance.js'
import {createIcaBetaDemoServer, createIcaLocalTestServer} from './beta-demo-server.js'
import {createIcaTestNetworkAdmissionServer} from './test-network-admission-runtime.js'

const port = Number.parseInt(process.env.PORT ?? '8080', 10)
const localTest = process.env.ANTIFRAUD_DEPLOYMENT_STAGE === 'test'
const walletIssuance = createConfiguredWalletIssuance(process.env)
const server = localTest ? createIcaLocalTestServer(process.env, walletIssuance)
  : process.env.ANTIFRAUD_DEPLOYMENT_STAGE === 'test-network'
    ? createIcaTestNetworkAdmissionServer(process.env, fetch, walletIssuance)
    : createIcaBetaDemoServer(process.env, walletIssuance)
server.listen(port, localTest ? '127.0.0.1' : '0.0.0.0', () => process.stdout.write(`Antifraud ICA listening on ${port}\n`))
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => server.close(() => process.exit(0)))
