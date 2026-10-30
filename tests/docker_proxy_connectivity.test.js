import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';

const enabled = process.env.TRUSTLAYER_DOCKER_INTEGRATION === '1';

test('internal worker network reaches only the authenticated dual-homed egress proxy', { skip: !enabled }, async () => {
  const name = `trustlayer-egress-test-${process.pid}-${Date.now()}`;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustlayer-proxy-test-'));
  const username = randomUUID();
  const password = randomUUID();
  const docker = args => execFileSync('docker', args, { encoding: 'utf8', timeout: 20000 });
  try {
    docker([
      'run', '-d', '--rm', '--name', name,
      '--network=trustlayer-isolated-net', '--network-alias=trustlayer-egress',
      '--user=pwuser', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
      '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=128m', '--cpus=0.25',
      '-v', `${tempDir}:/output`, '--entrypoint', 'node', 'trustlayer-worker:latest',
      'worker/egress_proxy_worker.js', `--username=${username}`, `--password=${password}`,
      '--output=/output/egress.json'
    ]);
    docker(['network', 'connect', 'trustlayer-egress-net', name]);
    await new Promise(resolve => setTimeout(resolve, 500));

    const checkProxy = `
      const http = require('node:http');
      const request = http.get({
        hostname: 'trustlayer-egress',
        port: 3128,
        path: 'http://127.0.0.1/',
        headers: { 'proxy-authorization': 'Basic ${Buffer.from(`${username}:${password}`).toString('base64')}' }
      }, response => {
        console.log('PROXY_HTTP_STATUS=' + response.statusCode);
        response.resume();
      });
      request.on('error', error => { console.error(error.message); process.exitCode = 2; });
      const direct = require('node:net').connect(443, '1.1.1.1');
      direct.setTimeout(1500);
      direct.on('connect', () => { console.error('DIRECT_EGRESS_ALLOWED'); direct.destroy(); process.exitCode = 3; });
      direct.on('timeout', () => { console.log('DIRECT_EGRESS_BLOCKED'); direct.destroy(); });
      direct.on('error', () => { console.log('DIRECT_EGRESS_BLOCKED'); });
    `;
    const output = docker([
      'run', '--rm', '--network=trustlayer-isolated-net',
      '--entrypoint', 'node', 'trustlayer-worker:latest', '-e', checkProxy
    ]);

    // The proxy must be reachable on the private network; it must then reject
    // the private loopback destination under the SSRF policy.
    assert.match(output, /PROXY_HTTP_STATUS=403/);
    assert.match(output, /DIRECT_EGRESS_BLOCKED/);
    assert.doesNotMatch(output, /DIRECT_EGRESS_ALLOWED/);
  } finally {
    try { docker(['stop', '--time', '2', name]); } catch {}
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
