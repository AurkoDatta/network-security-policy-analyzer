import http from 'http';
import { createApp } from './app';
import { connectDb } from './config/db';
import { env } from './config/env';
import { attachSocketIO } from './websocket/server';

async function main(): Promise<void> {
  await connectDb();

  const app = createApp();
  const server = http.createServer(app);
  attachSocketIO(server);

  server.listen(env.apiPort, () => {
    console.log(`API listening on port ${env.apiPort}`);
  });
}

main().catch((err) => {
  console.error('Failed to start API server', err);
  process.exit(1);
});
