import {createIcaBetaDemoServer} from './beta-demo-server.js'

const port = Number.parseInt(process.env.PORT ?? '8080', 10)
const server = createIcaBetaDemoServer(process.env)
server.listen(port, '0.0.0.0', () => process.stdout.write(`Antifraud ICA Beta Demo listening on ${port}\n`))
