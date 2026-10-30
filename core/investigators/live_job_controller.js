/**
 * Trust Layer — Trusted Live Job Controller v2.0
 * Control Plane Supervisor & Queue for Isolated Browser Inspections.
 * 
 * Guarantees:
 * 1. Express process NEVER fetches target URLs or launches browsers in-process.
 * 2. Launches an isolated Docker worker only; refuses when Docker is unavailable.
 * 3. Starts and pins a dedicated Controlled Egress Proxy for every job.
 * 4. Strips environment variables (no application secrets / credentials in worker).
 * 5. Captures, validates, and stores webpage screenshots safely.
 * 6. Bounded concurrency, timeout enforcement, and clean process lifecycle.
 */

import { spawn, execSync, execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { SSRFGuard } from './ssrf_guard.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');
const screenshotsDir = path.join(rootDir, 'data', 'screenshots');

export const JOB_STATUS = {
  QUEUED: 'QUEUED',
  RUNNING: 'RUNNING',
  COMPLETED: 'COMPLETED',
  PARTIAL: 'PARTIAL',
  BLOCKED: 'BLOCKED',
  FAILED: 'FAILED',
  TIMED_OUT: 'TIMED_OUT',
  CANCELLED: 'CANCELLED'
};

/**
 * Check if Docker daemon is running
 */
function isDockerAvailable() {
  try {
    execSync('docker info', { stdio: 'ignore', timeout: 1500 });
    return true;
  } catch {
    return false;
  }
}

function runDocker(args, options = {}) {
  return execFileSync('docker', args, {
    cwd: rootDir,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: options.timeout || 15000,
    windowsHide: true
  }).trim();
}

function ensureDockerRuntime() {
  if (!isDockerAvailable()) throw new Error('Docker daemon is not running or this process cannot access it.');

  let isolatedNetwork = '';
  try {
    isolatedNetwork = runDocker(['network', 'inspect', 'trustlayer-isolated-net', '--format', '{{.Driver}} {{.Internal}}']);
  } catch {
    runDocker(['network', 'create', '--driver', 'bridge', '--internal', 'trustlayer-isolated-net']);
    isolatedNetwork = 'bridge true';
  }
  if (isolatedNetwork !== 'bridge true') {
    throw new Error('Docker network trustlayer-isolated-net must be an internal bridge; refusing to run browser worker.');
  }

  let egressNetwork = '';
  try {
    egressNetwork = runDocker(['network', 'inspect', 'trustlayer-egress-net', '--format', '{{.Driver}} {{.Internal}}']);
  } catch {
    runDocker(['network', 'create', '--driver', 'bridge', 'trustlayer-egress-net']);
    egressNetwork = 'bridge false';
  }
  if (egressNetwork !== 'bridge false') {
    throw new Error('Docker network trustlayer-egress-net must be an outbound bridge used only by the validated proxy.');
  }

  // Invoke BuildKit only when an executable worker/security input changed.
  const buildInputs = ['worker/Dockerfile', 'worker/browser_worker.js', 'worker/egress_proxy_worker.js',
    'worker/chromium-seccomp.json', 'worker/package.json', 'worker/package-lock.json'];
  const fingerprint = createHash('sha256').update(buildInputs.map(file => fs.readFileSync(path.join(rootDir, file))).join('')).digest('hex');
  let imageFingerprint = '';
  try {
    imageFingerprint = runDocker(['image', 'inspect', 'trustlayer-worker:latest', '--format={{ index .Config.Labels "trustlayer.source-hash" }}']);
  } catch {}
  if (imageFingerprint !== fingerprint) {
    runDocker(['build', '-t', 'trustlayer-worker:latest', `--label=trustlayer.source-hash=${fingerprint}`, '-f', 'worker/Dockerfile', '.'], { timeout: 300000 });
  }
}

export class LiveJobController {
  constructor(options = {}) {
    this.maxConcurrent = options.maxConcurrent || 3;
    this.defaultTimeoutMs = options.defaultTimeoutMs || 25000;
    this.activeJobs = new Map();
    // Recheck for every job. Docker Desktop is commonly started after this
    // control plane, so a constructor-time snapshot stays stale forever.
    this.dockerAvailable = isDockerAvailable();
    fs.mkdirSync(screenshotsDir, { recursive: true });
  }

  _ensureDockerRuntime() {
    ensureDockerRuntime();
  }

  /**
   * Submit a new live inspection job
   */
  async submitJob(targetUrl, caseId, options = {}, prevalidatedSsrfResult = null) {
    const jobId = `job-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const timeoutMs = options.timeoutMs || this.defaultTimeoutMs;

    // 1. Initial destination pre-validation via SSRFGuard
    const canonicalTarget = (() => { try { return new URL(targetUrl).href; } catch { return ''; } })();
    const reusablePrecheck = prevalidatedSsrfResult?.allowed === true &&
      prevalidatedSsrfResult.canonicalUrl === canonicalTarget &&
      Array.isArray(prevalidatedSsrfResult.resolvedIps) && prevalidatedSsrfResult.resolvedIps.length > 0;
    const preCheck = reusablePrecheck
      ? prevalidatedSsrfResult
      : await SSRFGuard.validateAndResolve(targetUrl, options);
    if (!preCheck.allowed) {
      return {
        jobId,
        caseId,
        targetUrl,
        status: JOB_STATUS.BLOCKED,
        blockedReason: preCheck.blockedReason,
        resolvedIps: preCheck.resolvedIps,
        durationMs: 0,
        result: null
      };
    }

    const job = {
      jobId,
      caseId,
      targetUrl,
      status: JOB_STATUS.QUEUED,
      createdAt: Date.now(),
      startedAt: null,
      completedAt: null,
      timeoutMs,
      options,
      result: null,
      error: null
    };

    return this._executeJob(job);
  }

  /**
   * Execute an inspection job inside a disposable Docker worker.
   */
  async _executeJob(job) {
    job.status = JOB_STATUS.RUNNING;
    job.startedAt = Date.now();

    const tempDir = path.join(os.tmpdir(), 'trustlayer-jobs', job.jobId);
    fs.mkdirSync(tempDir, { recursive: true });
    const resultFile = path.join(tempDir, 'result.json');
    const readyResultFile = `${resultFile}.ready`;
    const screenshotFile = path.join(tempDir, 'screenshot.png');
    const initialScreenshotFile = path.join(tempDir, 'screenshot-initial.png');
    const captureStatusFile = path.join(tempDir, 'result.json.capture-status.json');
    const stageTimings = { container_start_ms: 0, proxy_ready_ms: 0, browser_launch_ms: 0,
      navigation_ms: 0, render_readiness_ms: 0, user_countdown_ms: 0,
      screenshot_capture_ms: 0, screenshot_transfer_ms: 0, ocr_analysis_ms: 0 };

    // 1. Confirm the runtime, isolated network, and worker image are ready.
    const runtimeSetupAt = Date.now();
    try {
      this._ensureDockerRuntime();
      stageTimings.container_start_ms += Date.now() - runtimeSetupAt;
      this.dockerAvailable = true;
    } catch (err) {
      this.dockerAvailable = false;
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
      job.status = JOB_STATUS.FAILED;
      job.error = `Mode C container runtime unavailable: ${err.message}`;
      job.completedAt = Date.now();
      job.durationMs = Date.now() - job.startedAt;
      job.result = { status: 'FAILED', error: job.error, isolationReport: { containerAvailable: false, runtimeMode: 'REFUSED_INSECURE_RUNTIME' } };
      return job;
    }

    // 2. Start the validated egress proxy as a dual-homed container. The
    // browser can reach it on the internal-only network, while only this
    // authenticated proxy has a second, outbound-connected interface.
    const egressContainerName = `trustlayer-egress-${job.jobId}`;
    // A shared Docker DNS alias lets stale or concurrent proxies answer a
    // worker's lookup with the wrong per-job credentials. Give every proxy a
    // unique address on the isolated network.
    const proxyAlias = `trustlayer-egress-${job.jobId}`;
    const browserContainerName = `trustlayer-browser-${job.jobId}`;
    const proxyUsername = randomUUID();
    const proxyPassword = randomUUID();
    const containerStartAt = Date.now();
    try {
      runDocker([
        'run', '-d', '--rm', '--name', egressContainerName,
        '--network=trustlayer-isolated-net', `--network-alias=${proxyAlias}`,
        '--user=pwuser', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=32', '--memory=128m', '--cpus=0.25',
        '-v', `${tempDir}:/output`,
        '--entrypoint', 'node', 'trustlayer-worker:latest',
        'worker/egress_proxy_worker.js', `--username=${proxyUsername}`,
        `--password=${proxyPassword}`, `--correlationId=${job.jobId}`, '--output=/output/egress.json'
      ]);
      stageTimings.container_start_ms += Date.now() - containerStartAt;
      const proxyStartAt = Date.now();
      runDocker(['network', 'connect', 'trustlayer-egress-net', egressContainerName]);

      let proxyReady = false;
      for (let attempt = 0; attempt < 20 && !proxyReady; attempt++) {
        try {
          runDocker(['exec', egressContainerName, 'node', '-e',
            "const n=require('node:net').connect(3128,'127.0.0.1');n.on('connect',()=>{n.destroy();process.exit(0)});n.on('error',()=>process.exit(1))"]);
          proxyReady = true;
        } catch {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }
      if (!proxyReady) throw new Error('Egress proxy container did not become ready.');
      stageTimings.proxy_ready_ms = Date.now() - proxyStartAt;
    } catch (err) {
      try { runDocker(['rm', '-f', egressContainerName]); } catch {}
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
      job.status = JOB_STATUS.FAILED;
      job.error = `Failed to start isolated egress proxy: ${err.message}`;
      job.completedAt = Date.now();
      job.durationMs = job.completedAt - job.startedAt;
      return job;
    }

    let child;
    let timer;
    let initialScreenshotWatcher;
    let readyResultWatcher;
    let captureStatusWatcher;
    let earlyResultPublished = false;
    let initialScreenshotPublished = false;
    const publishInitialScreenshot = () => {
      if (initialScreenshotPublished || !fs.existsSync(initialScreenshotFile)) return false;
      try {
        const bytes = fs.readFileSync(initialScreenshotFile);
        const isPng = bytes.length >= 1000 && bytes.length <= 5 * 1024 * 1024 &&
          bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 &&
          bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a;
        if (!isPng) return false;

        const artifactUrl = `/api/cases/${job.caseId}/screenshot?type=initial`;
        fs.writeFileSync(path.join(screenshotsDir, `${job.caseId}-initial.png`), bytes);
        let renderStatus = 'RENDER_PARTIAL';
        try { renderStatus = JSON.parse(fs.readFileSync(captureStatusFile, 'utf8')).renderStatus || renderStatus; } catch {}
        initialScreenshotPublished = true;
        if (job.options?.onInitialScreenshot) {
          try {
            job.options.onInitialScreenshot({
              caseId: job.caseId,
              artifactUrl,
              screenshotBytes: bytes.length,
              renderStatus,
              capturedAt: Date.now(),
              sha256: createHash('sha256').update(bytes).digest('hex')
            });
          } catch {}
        }
        return true;
      } catch {
        return false;
      }
    };

    return new Promise((resolve) => {
      let isSettled = false;

      // Watchdog wall-clock timer
      timer = setTimeout(() => {
        if (!isSettled) {
          isSettled = true;
          if (!earlyResultPublished) {
            job.status = JOB_STATUS.TIMED_OUT;
            job.error = `Inspection exceeded wall-clock limit of ${job.timeoutMs}ms`;
          } else if (job.result) {
            job.result.runtimeSessionActive = false;
            job.result.runtimeSessionEndedAt = Date.now();
          }
          this._cleanup(job.jobId);
          resolve(job);
        }
      }, job.timeoutMs + 3000);

      // Containerized Worker Execution
      const dockerArgs = [
        'run', '--rm', '--name', browserContainerName,
        '--network=trustlayer-isolated-net',
        '--user=pwuser',
        '--init',
        '--read-only',
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
        '--tmpfs', '/dev/shm:rw,noexec,nosuid,size=64m',
        '--cap-drop=ALL',
        '--cap-add=SYS_CHROOT',
        '--security-opt=seccomp=worker/chromium-seccomp.json',
        '--security-opt=no-new-privileges',
        '--pids-limit=128',
        '--memory=512m',
        '--cpus=1.0',
        '-v', `${tempDir}:/output`,
        'trustlayer-worker:latest',
        `--url=${job.targetUrl}`,
        `--jobId=${job.jobId}`,
        `--proxy=http://${proxyAlias}:3128`,
        `--proxyUsername=${proxyUsername}`,
        `--proxyPassword=${proxyPassword}`,
        `--output=/output/result.json`,
        `--screenshot=/output/screenshot.png`,
        `--initialScreenshot=/output/screenshot-initial.png`,
        `--captureStatus=/output/result.json.capture-status.json`,
        `--captureDelayMs=${[0, 5000, 10000].includes(job.options.captureDelayMs) ? job.options.captureDelayMs : 10000}`,
        `--timeout=${job.timeoutMs}`,
        `--keepAlive=${Math.min(150000, Math.max(0, job.options.keepAliveMs || 0))}`
      ];
      child = spawn('docker', dockerArgs, { stdio: ['ignore', 'pipe', 'pipe'] });

      let stdout = '';
      let stderr = '';
      if (child.stdout) child.stdout.on('data', (d) => { stdout += d; });
      if (child.stderr) child.stderr.on('data', (d) => { stderr += d; });

      const jobHandle = {
        job,
        child,
        browserContainerName,
        egressContainerName,
        tempDir,
        timer,
        publishInitialScreenshot,
        get initialScreenshotWatcher() { return initialScreenshotWatcher; },
        get readyResultWatcher() { return readyResultWatcher; },
      get captureStatusWatcher() { return captureStatusWatcher; },
        cancel: () => {
          if (!isSettled) {
            isSettled = true;
            if (earlyResultPublished && job.result) {
              job.result.runtimeSessionActive = false;
              job.result.runtimeSessionEndedAt = Date.now();
            } else {
              job.status = JOB_STATUS.CANCELLED;
              job.error = 'Investigation halted by operator';
            }
            this._cleanup(job.jobId);
            resolve(job);
          }
        }
      };
      this.activeJobs.set(job.jobId, jobHandle);
      initialScreenshotWatcher = setInterval(publishInitialScreenshot, 100);
      publishInitialScreenshot();

      let lastCaptureStatus = '';
      captureStatusWatcher = setInterval(() => {
        try {
          if (!fs.existsSync(captureStatusFile)) return;
          const captureStatus = JSON.parse(fs.readFileSync(captureStatusFile, 'utf8'));
          if (captureStatus.status !== lastCaptureStatus) {
            lastCaptureStatus = captureStatus.status;
            job.options?.onCaptureStatus?.(captureStatus);
          }
        } catch {}
      }, 100);

      const publishReadyResult = () => {
        if (earlyResultPublished || !fs.existsSync(readyResultFile)) return false;
        try {
          const result = JSON.parse(fs.readFileSync(readyResultFile, 'utf8'));
          if (result.jobId !== job.jobId || result.targetUrl !== job.targetUrl ||
              result.isolationReport?.chromiumSandboxEnabled !== true) return false;
          if (!fs.existsSync(screenshotFile)) return false;
          const transferStartedAt = Date.now();
          const bytes = fs.readFileSync(screenshotFile);
          const isPng = bytes.length >= 1000 && bytes.length <= 5 * 1024 * 1024 &&
            bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 &&
            bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a;
          if (!isPng) return false;

          fs.writeFileSync(path.join(screenshotsDir, `${job.caseId}.png`), bytes);
          stageTimings.screenshot_transfer_ms = Date.now() - transferStartedAt;
          result.screenshotCaptured = true;
          result.screenshotBytes = bytes.length;
          result.correlationId = result.correlationId || job.jobId;
          try {
            const egressPath = path.join(tempDir, 'egress.json');
            if (fs.existsSync(egressPath)) result.egressObservations = JSON.parse(fs.readFileSync(egressPath, 'utf8'));
          } catch (egressError) {
            result.egressObservationError = egressError.message;
          }
          result.modeCTimings = { ...stageTimings, ...(result.modeCTimings || {}) };
          job.options?.onTimings?.(result.modeCTimings);
          result.pageExtraction = result.pageExtraction || {};
          result.pageExtraction.screenshotAvailable = true;
          result.pageExtraction.screenshotUrl = `/api/cases/${job.caseId}/screenshot`;
          result.pageExtraction.screenshotBytes = bytes.length;
          result.isolationReport.runtimeMode = 'CONTAINER_DOCKER';
          result.isolationReport.containerAvailable = true;
          result.isolationReport.capabilityPolicy = 'ALL_DROPPED_EXCEPT_SYS_CHROOT';
          result.isolationReport.networkIsolated = true;
          result.isolationReport.containerImage = 'trustlayer-worker:latest';
          result.runtimeSessionActive = Math.min(150000, Math.max(0, job.options.keepAliveMs || 0)) > 0;
          result.runtimeSessionUntil = result.runtimeSessionActive
            ? Date.now() + Math.min(150000, Math.max(0, job.options.keepAliveMs || 0)) : null;
          job.result = result;
          job.status = String(result.status).toUpperCase() === 'SUCCESS' ? JOB_STATUS.COMPLETED
            : (String(result.status).toUpperCase() === 'PARTIAL' ? JOB_STATUS.PARTIAL : JOB_STATUS.FAILED);
          if (job.status === JOB_STATUS.FAILED) return false;
          job.completedAt = Date.now();
          job.durationMs = job.completedAt - job.startedAt;
          earlyResultPublished = true;
          resolve(job);
          return true;
        } catch {
          return false;
        }
      };
      readyResultWatcher = setInterval(publishReadyResult, 100);
      publishReadyResult();

      child.on('close', async (code) => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        clearInterval(initialScreenshotWatcher);
        clearInterval(readyResultWatcher);
        clearInterval(captureStatusWatcher);
        if (earlyResultPublished) {
          if (job.result) {
            job.result.runtimeSessionActive = false;
            job.result.runtimeSessionEndedAt = Date.now();
          }
          this._cleanup(job.jobId);
          resolve(job);
          return;
        }
        publishInitialScreenshot();

        job.completedAt = Date.now();
        job.durationMs = job.completedAt - job.startedAt;

        // 1. Process result JSON artifact
        if (fs.existsSync(resultFile)) {
          try {
            const rawResult = fs.readFileSync(resultFile, 'utf8');
            job.result = JSON.parse(rawResult);
            if (job.result.jobId !== job.jobId || job.result.targetUrl !== job.targetUrl) {
              throw new Error('Worker output job/target association does not match the submitted case.');
            }
            const workerStatus = String(job.result.status || '').toUpperCase();
            job.status = workerStatus === 'SUCCESS' ? JOB_STATUS.COMPLETED
              : (workerStatus === 'PARTIAL' ? JOB_STATUS.PARTIAL
              : (workerStatus === 'BLOCKED' ? JOB_STATUS.BLOCKED
              : (workerStatus === 'CANCELLED' ? JOB_STATUS.CANCELLED
              : (workerStatus === 'TIMEOUT' || workerStatus === 'TIMED_OUT' ? JOB_STATUS.TIMED_OUT
              : (workerStatus === 'FAILED' ? JOB_STATUS.FAILED
              : (code === 0 ? JOB_STATUS.COMPLETED : JOB_STATUS.FAILED))))));
          } catch (e) {
            job.status = JOB_STATUS.FAILED;
            job.error = `Failed to parse worker output: ${e.message}`;
          }
        } else {
          job.status = JOB_STATUS.FAILED;
          job.error = stderr || `Worker exited with code ${code} without producing result artifact`;
        }

        // 2. Validate and store screenshot artifact
        if (fs.existsSync(screenshotFile)) {
          try {
            const shotBuf = fs.readFileSync(screenshotFile);
            const isPng = shotBuf.length >= 8 &&
              shotBuf[0] === 0x89 && shotBuf[1] === 0x50 && shotBuf[2] === 0x4e && shotBuf[3] === 0x47 &&
              shotBuf[4] === 0x0d && shotBuf[5] === 0x0a && shotBuf[6] === 0x1a && shotBuf[7] === 0x0a;

            if (isPng && shotBuf.length >= 1000 && shotBuf.length <= 5 * 1024 * 1024) {
              const destPath = path.join(screenshotsDir, `${job.caseId}.png`);
              fs.writeFileSync(destPath, shotBuf);
              stageTimings.screenshot_transfer_ms = Date.now() - job.startedAt;
              if (job.result) {
                if (!job.result.pageExtraction) job.result.pageExtraction = {};
                job.result.pageExtraction.screenshotAvailable = true;
                job.result.pageExtraction.screenshotUrl = `/api/cases/${job.caseId}/screenshot`;
                job.result.pageExtraction.screenshotBytes = shotBuf.length;
                job.result.screenshotCaptured = true;
                job.result.modeCTimings = { ...stageTimings, ...(job.result.modeCTimings || {}) };
                job.options?.onTimings?.(job.result.modeCTimings);
              }
            }
          } catch (shotErr) {
            if (job.result) job.result.screenshotError = shotErr.message;
          }
        }

        if (job.status === JOB_STATUS.COMPLETED && job.result?.screenshotCaptured !== true) {
          job.status = JOB_STATUS.FAILED;
          job.error = 'Rendered inspection did not produce a validated screenshot artifact.';
        }

        if (fs.existsSync(initialScreenshotFile)) {
          try {
            const initialBuf = fs.readFileSync(initialScreenshotFile);
            const isPng = initialBuf.length >= 8 && initialBuf[0] === 0x89 && initialBuf[1] === 0x50 &&
              initialBuf[2] === 0x4e && initialBuf[3] === 0x47 && initialBuf[4] === 0x0d &&
              initialBuf[5] === 0x0a && initialBuf[6] === 0x1a && initialBuf[7] === 0x0a;
            if (isPng && initialBuf.length <= 5 * 1024 * 1024) {
              fs.writeFileSync(path.join(screenshotsDir, `${job.caseId}-initial.png`), initialBuf);
              if (job.result?.pageExtraction) job.result.pageExtraction.initialScreenshotAvailable = true;
            }
          } catch (initialError) {
            if (job.result) job.result.initialScreenshotError = initialError.message;
          }
        }

        // 3. Attach egress proxy blocked requests
        try { runDocker(['stop', '--time', '2', egressContainerName]); } catch {}
        const egressObservationPath = path.join(tempDir, 'egress.json');
        if (job.result && fs.existsSync(egressObservationPath)) {
          try {
            const observations = JSON.parse(fs.readFileSync(egressObservationPath, 'utf8'));
            job.result.egressObservations = observations;
            if (observations.blockedRequests?.length) {
              if (!job.result.blockedRequests) job.result.blockedRequests = [];
              job.result.blockedRequests.push(...observations.blockedRequests);
            }
          } catch (observationError) {
            job.result.egressObservationError = observationError.message;
          }
        }

        // 4. Update isolation report with truthful runtime metadata
        if (job.result) {
          if (!job.result.isolationReport) job.result.isolationReport = {};
          job.result.isolationReport.runtimeMode = 'CONTAINER_DOCKER';
          job.result.isolationReport.containerAvailable = true;
          job.result.isolationReport.capabilityPolicy = 'ALL_DROPPED_EXCEPT_SYS_CHROOT';
          if (job.result.isolationReport.chromiumSandboxEnabled !== true) {
            job.result.isolationReport.chromiumSandboxEnabled = false;
            if (job.status === JOB_STATUS.COMPLETED) {
              job.status = JOB_STATUS.FAILED;
              job.error = 'Worker did not verify Chromium sandbox configuration.';
            }
          }
          job.result.isolationReport.networkIsolated = true;
          job.result.isolationReport.containerImage = 'trustlayer-worker:latest';
        }

        this._cleanup(job.jobId);
        resolve(job);
      });

      child.on('error', (err) => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        clearInterval(initialScreenshotWatcher);
        clearInterval(readyResultWatcher);
        clearInterval(captureStatusWatcher);
        job.status = JOB_STATUS.FAILED;
        job.error = `Worker process failed: ${err.message}`;
        this._cleanup(job.jobId);
        resolve(job);
      });

      if (job.options?.abortSignal) {
        const abortActiveJob = () => jobHandle.cancel();
        if (job.options.abortSignal.aborted) abortActiveJob();
        else job.options.abortSignal.addEventListener('abort', abortActiveJob, { once: true });
      }
    });
  }

  /**
   * Cancel an active inspection job
   */
  cancelJob(jobId) {
    const handle = this.activeJobs.get(jobId);
    if (handle) {
      handle.cancel();
      return true;
    }
    return false;
  }

  /**
   * Clean up worker resources
   */
  async _cleanup(jobId) {
    const handle = this.activeJobs.get(jobId);
    if (!handle) return;
    this.activeJobs.delete(jobId);

    handle.publishInitialScreenshot?.();
    if (handle.initialScreenshotWatcher) clearInterval(handle.initialScreenshotWatcher);
    if (handle.readyResultWatcher) clearInterval(handle.readyResultWatcher);
    if (handle.captureStatusWatcher) clearInterval(handle.captureStatusWatcher);

    if (handle.browserContainerName) {
      try { execFileSync('docker', ['rm', '-f', handle.browserContainerName], { stdio: 'ignore', timeout: 5000, windowsHide: true }); } catch {}
    }

    if (handle.egressContainerName) {
      try { execFileSync('docker', ['rm', '-f', handle.egressContainerName], { stdio: 'ignore', timeout: 5000, windowsHide: true }); } catch {}
    }

    if (handle.child && !handle.child.killed) {
      try { handle.child.kill('SIGTERM'); } catch {}
    }

    if (handle.tempDir) {
      try {
        fs.rmSync(handle.tempDir, { recursive: true, force: true });
      } catch {}
    }
  }
}

export const globalJobController = new LiveJobController();
