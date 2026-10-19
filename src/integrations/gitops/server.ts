import { readFile } from 'node:fs/promises';
import { createGitOpsWebhookHttpsServer } from './webhook.js';

const port = Number(process.env.PORT ?? 8443);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535');
}

const keyPath = process.env.TLS_KEY_FILE ?? '/var/run/webhook-tls/tls.key';
const certPath = process.env.TLS_CERT_FILE ?? '/var/run/webhook-tls/tls.crt';
const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
const server = createGitOpsWebhookHttpsServer({ key, cert });
server.listen(port, '0.0.0.0');

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => server.close(() => process.exit(0)));
}
