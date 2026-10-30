import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LiveJobController } from '../core/investigators/live_job_controller.js';

test('Mode C refuses to run a browser in an uncontained host process', async (t) => {
  const controller = new LiveJobController();
  if (controller.dockerAvailable) {
    t.skip('Docker is available; real container screenshot coverage is provided by tests/mode_c_api_smoke.test.js');
    return;
  }

  const result = await controller.submitJob('http://127.0.0.1/', 'case-host-refusal', {
    skipDns: true,
    _testBypassSsrf: true
  });

  assert.equal(result.status, 'FAILED');
  assert.match(result.error, /container runtime unavailable/i);
  assert.equal(result.result.isolationReport.runtimeMode, 'REFUSED_INSECURE_RUNTIME');
});
