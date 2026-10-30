/**
 * Trust Layer — Backend Investigation Server v2.5
 * REST & SSE APIs serving structured case schema telemetry.
 * Control Plane only: Does not perform arbitrary fetches or run browsers in-process.
 */

import express from 'express';
import fs from 'node:fs';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { InvestigationEngine, INSPECTION_MODE } from '../core/investigation_engine.js';
import { CASE_STATE } from '../core/case_schema.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// In-memory case repository
const cases = new Map();

// 1. Landing page / main pre-investigation dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(rootDir, 'index.html'));
});

// 2. Investigation console routes
app.get('/investigate', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

app.get('/console', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

app.get('/investigation', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

app.get('/investigation.html', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

// Serve static frontend assets
app.use(express.static(rootDir));

// ── Case Management REST API ──────────────────────────────────────────────

/**
 * POST /api/cases
 * Create and execute a new forensic investigation case
 */
app.post('/api/cases', async (req, res) => {
  const { target, targetType, expectedContext, inspectionMode, consentConfirmed, captureDelayMs } = req.body || {};
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'Field "target" is required.' });
  }

  const cleanTarget = target.trim();
  const selectedMode = inspectionMode || INSPECTION_MODE.URL_ONLY;
  if (selectedMode === INSPECTION_MODE.ISOLATED_LIVE && captureDelayMs !== undefined && ![0, 5000, 10000].includes(captureDelayMs)) {
    return res.status(400).json({ error: 'captureDelayMs must be 0, 5000, or 10000.' });
  }
  if ([INSPECTION_MODE.MODE_B, INSPECTION_MODE.ISOLATED_LIVE].includes(selectedMode) && consentConfirmed !== true) {
    return res.status(400).json({ error: 'Explicit consent is required before active HTTP tracing or isolated live inspection.' });
  }
  const icase = InvestigationEngine.createCase(cleanTarget, targetType || 'URL', selectedMode);
  icase.schema.captureDelayMs = selectedMode === INSPECTION_MODE.ISOLATED_LIVE ? (captureDelayMs ?? 10000) : 10000;
  icase.schema.screenshotCapture.captureDelayMs = icase.schema.captureDelayMs;
  if (selectedMode === INSPECTION_MODE.MODE_B) icase.schema.modeBConsentAt = Date.now();
  if (selectedMode === INSPECTION_MODE.ISOLATED_LIVE) icase.schema.modeCConsentAt = Date.now();
  if (expectedContext) {
    icase.schema.expectedContext = expectedContext;
  }
  cases.set(icase.id, icase);

  // SSE client set
  icase._sseClients = new Set();

  // Broadcast events to SSE subscribers
  icase.on('*', (msg) => {
    const payload = `data: ${JSON.stringify(msg)}\n\n`;
    for (const client of icase._sseClients) {
      try { client.write(payload); } catch {}
    }
  });

  // Execute pipeline in background
  InvestigationEngine.investigate(icase).catch((err) => {
    icase.log(`PIPELINE EXCEPTION: ${err.message}`, 'error');
  });

  res.status(201).json({
    caseId: icase.id,
    target: icase.target,
    status: icase.status,
    currentStage: icase.currentStage,
    inspectionMode: icase.schema.inspectionMode,
    createdAt: icase.schema.createdAt
  });
});

/**
 * POST /api/cases/:id/live-inspect
 * Explicitly trigger Mode C (Isolated Live Inspection) with user consent
 */
app.post('/api/cases/:id/live-inspect', async (req, res) => {
  const icase = cases.get(req.params.id);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }

  const { consentConfirmed, captureDelayMs } = req.body || {};
  if (!consentConfirmed) {
    return res.status(400).json({ error: 'Explicit user consent is required to execute live inspection.' });
  }
  if (captureDelayMs !== undefined && ![0, 5000, 10000].includes(captureDelayMs)) {
    return res.status(400).json({ error: 'captureDelayMs must be 0, 5000, or 10000.' });
  }

  icase.schema.inspectionMode = INSPECTION_MODE.ISOLATED_LIVE;
  icase.schema.captureDelayMs = captureDelayMs ?? icase.schema.captureDelayMs ?? 10000;
  icase.schema.screenshotCapture = { status: 'STARTING', captureDelayMs: icase.schema.captureDelayMs,
    countdownStartedAt: null, countdownEndsAt: null, capturedAt: null };
  // A reinspection must leave the previous terminal state immediately so SSE/UI
  // consumers can show live progress instead of retaining stale INCOMPLETE.
  icase.schema.status = CASE_STATE.NORMALIZING;
  icase.schema.completedAt = null;
  icase._abortController = new AbortController();
  icase._abortSignal = icase._abortController.signal;
  icase.log('OPERATOR AUTHORIZED: Upgrading case to Mode C (Isolated Live Inspection)');
  icase.emit('stage', { stage: 'ISOLATED_LIVE_AUTHORIZED' });

  // Re-run pipeline with Mode C active
  InvestigationEngine.investigate(icase).catch((err) => {
    icase.log(`LIVE INSPECTION EXCEPTION: ${err.message}`, 'error');
  });

  res.json({
    caseId: icase.id,
    mode: INSPECTION_MODE.ISOLATED_LIVE,
    status: icase.status,
    message: 'Isolated Live Inspection started in background worker.'
  });
});

/**
 * POST /api/cases/:id/cancel-live
 * Abort active live inspection
 */
app.post('/api/cases/:id/cancel-live', (req, res) => {
  const icase = cases.get(req.params.id);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }

  if (icase._abortController) {
    icase._abortController.abort();
  }
  const wasCompleted = icase.schema.status === CASE_STATE.COMPLETED;
  if (icase.schema.liveInspection) {
    icase.schema.liveInspection.runtimeSessionActive = false;
    icase.schema.liveInspection.runtimeSessionEndedAt = Date.now();
  }
  if (!wasCompleted) icase.schema.status = CASE_STATE.INCOMPLETE;
  icase.log(wasCompleted ? 'LIVE BROWSER SESSION STOPPED BY OPERATOR' : 'LIVE INSPECTION CANCELLED BY OPERATOR', 'warn');
  icase.emit('complete', icase.schema);

  res.json({ message: 'Live inspection cancelled', caseId: icase.id });
});

/**
 * GET /api/cases
 * List recent investigation cases
 */
app.get('/api/cases', (req, res) => {
  const list = [];
  for (const [id, icase] of cases.entries()) {
    list.push({
      id,
      target: icase.target,
      status: icase.status,
      currentStage: icase.currentStage,
      inspectionMode: icase.schema.inspectionMode || 'URL_ONLY',
      assessment: icase.assessment,
      evidenceCount: icase.evidence.length,
      createdAt: icase.schema.createdAt,
      completedAt: icase.schema.completedAt,
      isDemo: icase.isDemo
    });
  }
  res.json({ cases: list.reverse() });
});

/**
 * GET /api/cases/:id
 * Retrieve complete structured case schema
 */
app.get('/api/cases/:id', (req, res) => {
  const icase = cases.get(req.params.id);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }
  res.json(icase.schema);
});

/**
 * GET /api/cases/:id/events
 * SSE stream for real-time investigation telemetry
 */
app.get('/api/cases/:id/events', (req, res) => {
  const icase = cases.get(req.params.id);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });

  if (!icase._sseClients) icase._sseClients = new Set();
  icase._sseClients.add(res);

  // Send current schema snapshot immediately
  res.write(`data: ${JSON.stringify({ event: 'snapshot', schema: icase.schema })}\n\n`);

  req.on('close', () => {
    icase._sseClients.delete(res);
  });
});

/**
 * POST /api/cases/:id/cancel
 */
app.post('/api/cases/:id/cancel', (req, res) => {
  const icase = cases.get(req.params.id);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }

  if (icase._abortController) {
    icase._abortController.abort();
  }
  icase.schema.status = CASE_STATE.INCOMPLETE;
  icase.schema.completedAt = Date.now();
  icase.log('INVESTIGATION HALTED BY OPERATOR', 'warn');
  icase.emit('complete', icase.schema);

  res.json({ message: 'Investigation cancelled', caseId: icase.id });
});

// /console is an alias for the unified SPA — keeps legacy bookmarks working

/**
 * GET /api/cases/:id/screenshot
 * Stream validated webpage screenshot artifact
 */
app.get('/api/cases/:id/screenshot', (req, res) => {
  const caseId = req.params.id;

  // 1. Validate Case ID format to block path traversal attempts
  if (!caseId || !/^[a-zA-Z0-9_-]+$/.test(caseId)) {
    return res.status(400).json({ error: 'Invalid case identifier format' });
  }

  // 2. Enforce case access / existence check
  if (!cases.has(caseId) && !InvestigationEngine.CASE_HISTORY?.has(caseId)) {
    return res.status(404).json({ error: 'Case not found' });
  }

  // 3. Resolve path strictly within approved storage root
  const storageRoot = path.resolve(rootDir, 'data', 'screenshots');
  const shotFileName = req.query.type === 'initial' ? `${caseId}-initial.png` : `${caseId}.png`;
  let shotPath = path.resolve(storageRoot, shotFileName);
  if (!shotPath.startsWith(storageRoot + path.sep)) {
    return res.status(403).json({ error: 'Access denied: Path traversal detected' });
  }

  // Fallback to primary screenshot if initial checkpoint doesn't exist
  if (!fs.existsSync(shotPath) && req.query.type === 'initial') {
    shotPath = path.resolve(storageRoot, `${caseId}.png`);
  }

  if (!fs.existsSync(shotPath)) {
    return res.status(404).json({
      error: 'Screenshot unavailable',
      reason: 'No screenshot artifact exists for this case (e.g. Mode A URL-only or failed navigation).'
    });
  }

  try {
    const fd = fs.openSync(shotPath, 'r');
    const header = Buffer.alloc(8);
    fs.readSync(fd, header, 0, 8, 0);
    fs.closeSync(fd);

    const isPng = header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4e && header[3] === 0x47 &&
                  header[4] === 0x0d && header[5] === 0x0a && header[6] === 0x1a && header[7] === 0x0a;

    if (!isPng) {
      return res.status(415).json({ error: 'Invalid or corrupt screenshot artifact' });
    }

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    fs.createReadStream(shotPath).pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Failed to stream screenshot artifact' });
  }
});

app.get('/console', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🛡️  Trust Layer — Unified Forensic Investigation Platform`);
  console.log(`   Server listening at http://localhost:${PORT}`);
  console.log(`   Unified SPA:     http://localhost:${PORT}/`);
  console.log(`   (alias)          http://localhost:${PORT}/console`);
});
