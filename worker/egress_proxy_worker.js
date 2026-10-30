import fs from 'node:fs';
import { ControlledEgressProxy } from '../core/investigators/egress_proxy.js';

function argsFromCli() {
  const values = {};
  for (const arg of process.argv.slice(2)) {
    if (!arg.startsWith('--')) continue;
    const split = arg.indexOf('=');
    if (split > 2) values[arg.slice(2, split)] = arg.slice(split + 1);
  }
  return values;
}

const args = argsFromCli();
if (!args.username || !args.password || !args.output) {
  console.error('Egress proxy requires username, password and output path.');
  process.exit(2);
}

const correlationId = args.correlationId || 'UNAVAILABLE';

const proxy = new ControlledEgressProxy({
  host: '0.0.0.0',
  port: 3128,
  requireAuth: true,
  username: args.username,
  password: args.password
});

try {
  await proxy.start();
  console.log('TRUST_LAYER_EGRESS_READY');
} catch (error) {
  console.error(`Egress proxy failed to start: ${error.message}`);
  process.exit(1);
}

let stopping = false;
function persistObservations() {
  try {
    const snapshot = JSON.stringify({
      correlationId,
      allowedRequests: proxy.allowedRequests.map(item => ({ ...item, correlationId })),
      blockedRequests: proxy.blockedRequests.map(item => ({ ...item, correlationId }))
    }, null, 2);
    const temporaryPath = `${args.output}.tmp`;
    fs.writeFileSync(temporaryPath, snapshot);
    fs.renameSync(temporaryPath, args.output);
  } catch (error) {
    console.error(`Failed to persist egress observations: ${error.message}`);
  }
}
const observationFlush = setInterval(persistObservations, 200);
async function stop() {
  if (stopping) return;
  stopping = true;
  clearInterval(observationFlush);
  persistObservations();
  await proxy.stop();
  process.exit(0);
}

process.on('SIGTERM', stop);
process.on('SIGINT', stop);
