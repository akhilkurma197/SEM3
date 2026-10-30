import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('Mode C screenshot countdown ticks before and after the worker publishes its deadline', () => {
  const html = fs.readFileSync(path.join(root, 'investigation.html'), 'utf8');
  const start = html.indexOf('function updateScreenshotCountdown(schema) {');
  const end = html.indexOf('\nfunction setHdrModeButtons', start);
  assert.ok(start >= 0 && end > start, 'countdown renderer must remain present in Investigation Console');
  const countdownSource = html.slice(start, end);

  let now = 1000;
  let tick = null;
  const elements = new Map();
  for (const id of ['web-screenshot-countdown', 'web-screenshot-countdown-seconds', 'web-screenshot-countdown-message']) {
    elements.set(id, { style: {}, textContent: '' });
  }
  const clockDate = class extends Date { static now() { return now; } };
  const schema = {
    id: 'case-countdown-test', status: 'RUNNING', inspectionMode: 'ISOLATED_LIVE',
    pageAnalysis: { screenshotAvailable: false }, liveInspection: { screenshotCaptured: false },
    screenshotCapture: { status: 'STARTING', captureDelayMs: 10000 }
  };
  const context = {
    Date: clockDate,
    document: { getElementById: id => elements.get(id) || null },
    window: { activeCase: { id: schema.id, schema } },
    setInterval: callback => { tick = callback; return 1; },
    clearInterval: () => {},
    describeInspectionStatus: () => ({ reason: 'test fixture' })
  };
  vm.createContext(context);
  vm.runInContext(`let screenshotCountdownCaseId = null; let screenshotCountdownStartedAt = null; let screenshotCountdownTimer = null;\n${countdownSource}`, context);
  const update = vm.runInContext('updateScreenshotCountdown', context);

  update(schema);
  assert.equal(elements.get('web-screenshot-countdown-seconds').textContent, '10');
  now = 2500;
  tick();
  assert.equal(elements.get('web-screenshot-countdown-seconds').textContent, '9', 'local countdown must decrease while the worker starts');

  schema.screenshotCapture = { status: 'COUNTDOWN', captureDelayMs: 10000, countdownStartedAt: 3000, countdownEndsAt: 13000 };
  now = 3000;
  tick();
  now = 6000;
  tick();
  assert.equal(elements.get('web-screenshot-countdown-seconds').textContent, '7', 'worker deadline must drive the post-render countdown');

  schema.pageAnalysis.screenshotAvailable = true;
  schema.initialScreenshotUrl = '/api/cases/case-countdown-test/screenshot?type=initial';
  update(schema);
  assert.equal(elements.get('web-screenshot-countdown').style.display, 'flex', 'initial screenshot can display while final capture counts down');
  schema.liveInspection.screenshotCaptured = true;
  update(schema);
  assert.equal(elements.get('web-screenshot-countdown').style.display, 'none', 'final screenshot stops the countdown');
});
