import {createIcaBetaDemoServer, createIcaLocalTestServer} from './beta-demo-server.js'

const port = Number.parseInt(process.env.PORT ?? '8080', 10)
const localTest = process.env.ANTIFRAUD_DEPLOYMENT_STAGE === 'test'
const server = localTest ? createIcaLocalTestServer(process.env) : createIcaBetaDemoServer(process.env)
server.listen(port, localTest ? '127.0.0.1' : '0.0.0.0', () => process.stdout.write(`Antifraud ICA listening on ${port}\n`))
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => server.close(() => process.exit(0)))
