import { createApp } from './app';
import { connectDb } from './config/db';
import { env } from './config/env';

async function main(): Promise<void> {
  await connectDb();

  const app = createApp();
  app.listen(env.apiPort, () => {
    console.log(`API listening on port ${env.apiPort}`);
  });
}

main().catch((err) => {
  console.error('Failed to start API server', err);
  process.exit(1);
});
