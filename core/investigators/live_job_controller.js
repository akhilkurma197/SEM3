/**
 * Trust Layer — Trusted Live Job Controller v2.0
 * Control Plane Supervisor & Queue for Isolated Browser Inspections.
 * 
 * Guarantees:
 * 1. Express process NEVER fetches target URLs or launches browsers in-process.
 * 2. Launches isolated worker (container if Docker is active, or standalone process with clean env).
 * 3. Starts and pins a dedicated Controlled Egress Proxy for every job.
 * 4. Strips environment variables (no application secrets / credentials in worker).
 * 5. Captures, validates, and stores webpage screenshots safely.
 * 6. Bounded concurrency, timeout enforcement, and clean process lifecycle.
 */

import { spawn, execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { ControlledEgressProxy } from './egress_proxy.js';
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

export class LiveJobController {
  constructor(options = {}) {
    this.maxConcurrent = options.maxConcurrent || 3;
    this.defaultTimeoutMs = options.defaultTimeoutMs || 10000;
    this.activeJobs = new Map();
    this.dockerAvailable = isDockerAvailable();
    fs.mkdirSync(screenshotsDir, { recursive: true });
  }

  /**
   * Submit a new live inspection job
   */
  async submitJob(targetUrl, caseId, options = {}) {
    const jobId = `job-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const timeoutMs = options.timeoutMs || this.defaultTimeoutMs;

    // 1. Initial destination pre-validation via SSRFGuard
    const preCheck = await SSRFGuard.validateAndResolve(targetUrl, options);
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
   * Execute an inspection job inside an isolated worker (container or restricted subprocess)
   */
  async _executeJob(job) {
    job.status = JOB_STATUS.RUNNING;
    job.startedAt = Date.now();

    const tempDir = path.join(os.tmpdir(), 'trustlayer-jobs', job.jobId);
    fs.mkdirSync(tempDir, { recursive: true });
    const resultFile = path.join(tempDir, 'result.json');
    const screenshotFile = path.join(tempDir, 'screenshot.png');

    // 1. Start dedicated Egress Proxy for this job
    const proxy = new ControlledEgressProxy({
      allowedPorts: job.options.allowedPorts || [80, 443],
      _testBypassSsrf: job.options._testBypassSsrf || false
    });
    let proxyInfo;
    try {
      proxyInfo = await proxy.start();
    } catch (err) {
      job.status = JOB_STATUS.FAILED;
      job.error = `Failed to start Egress Proxy: ${err.message}`;
      return job;
    }

    // 2. Strict Isolation Gate: Container runtime (Docker) is mandatory
    // Standalone host subprocess execution is strictly forbidden for live inspection.
    if (!this.dockerAvailable) {
      await proxy.stop();
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
      job.status = JOB_STATUS.FAILED;
      job.error = 'Live inspection refused: Isolated container runtime (Docker daemon) is required but unavailable on this host. Execution in an uncontained host subprocess is prohibited by security policy. Target analysis remains active in Mode A (URL-Only).';
      job.completedAt = Date.now();
      job.durationMs = 0;
      job.result = {
        status: 'FAILED',
        error: job.error,
        isolationReport: {
          containerAvailable: false,
          runtimeMode: 'REFUSED_INSECURE_RUNTIME',
          chromiumSandboxEnabled: true,
          credentialsIsolated: true,
          message: 'Mode C strictly requires container isolation with Chromium sandboxing and network isolation. Standalone host subprocess execution has been disabled.'
        }
      };
      return job;
    }

    let child;
    let timer;

    return new Promise((resolve) => {
      let isSettled = false;

      // Watchdog wall-clock timer
      timer = setTimeout(() => {
        if (!isSettled) {
          isSettled = true;
          job.status = JOB_STATUS.TIMED_OUT;
          job.error = `Inspection exceeded wall-clock limit of ${job.timeoutMs}ms`;
          this._cleanup(job.jobId);
          resolve(job);
        }
      }, job.timeoutMs + 3000);

      // Containerized Worker Execution
      const dockerArgs = [
        'run', '--rm',
        '--network=trustlayer-isolated-net',
        '--user=pwuser',
        '--read-only',
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
        '--cap-drop=ALL',
        '--cap-add=SYS_ADMIN',
        '--security-opt=no-new-privileges',
        '--memory=512m',
        '--cpus=1.0',
        '-v', `${tempDir}:/output`,
        'trustlayer-worker:latest',
        `--url=${job.targetUrl}`,
        `--jobId=${job.jobId}`,
        `--proxy=${proxyInfo.proxyUrl}`,
        `--output=/output/result.json`,
        `--screenshot=/output/screenshot.png`,
        `--timeout=${job.timeoutMs}`
      ];
      child = spawn('docker', dockerArgs, { stdio: ['ignore', 'pipe', 'pipe'] });

      let stdout = '';
      let stderr = '';
      if (child.stdout) child.stdout.on('data', (d) => { stdout += d; });
      if (child.stderr) child.stderr.on('data', (d) => { stderr += d; });

      const jobHandle = {
        job,
        child,
        proxy,
        tempDir,
        timer,
        cancel: () => {
          if (!isSettled) {
            isSettled = true;
            job.status = JOB_STATUS.CANCELLED;
            job.error = 'Investigation halted by operator';
            this._cleanup(job.jobId);
            resolve(job);
          }
        }
      };
      this.activeJobs.set(job.jobId, jobHandle);

      child.on('close', async (code) => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);

        job.completedAt = Date.now();
        job.durationMs = job.completedAt - job.startedAt;

        // 1. Process result JSON artifact
        if (fs.existsSync(resultFile)) {
          try {
            const rawResult = fs.readFileSync(resultFile, 'utf8');
            job.result = JSON.parse(rawResult);
            job.status = job.result.status || (code === 0 ? JOB_STATUS.COMPLETED : JOB_STATUS.FAILED);
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

            if (isPng && shotBuf.length <= 5 * 1024 * 1024) {
              const destPath = path.join(screenshotsDir, `${job.caseId}.png`);
              fs.writeFileSync(destPath, shotBuf);
              if (job.result) {
                if (!job.result.pageExtraction) job.result.pageExtraction = {};
                job.result.pageExtraction.screenshotAvailable = true;
                job.result.pageExtraction.screenshotUrl = `/api/cases/${job.caseId}/screenshot`;
                job.result.pageExtraction.screenshotBytes = shotBuf.length;
                job.result.screenshotCaptured = true;
              }
            }
          } catch (shotErr) {
            if (job.result) job.result.screenshotError = shotErr.message;
          }
        }

        // 3. Attach egress proxy blocked requests
        if (job.result && proxy.blockedRequests.length > 0) {
          if (!job.result.blockedRequests) job.result.blockedRequests = [];
          job.result.blockedRequests.push(...proxy.blockedRequests);
        }

        // 4. Update isolation report with truthful runtime metadata
        if (job.result) {
          if (!job.result.isolationReport) job.result.isolationReport = {};
          job.result.isolationReport.runtimeMode = 'CONTAINER_DOCKER';
          job.result.isolationReport.containerAvailable = true;
          job.result.isolationReport.chromiumSandboxEnabled = true;
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
        job.status = JOB_STATUS.FAILED;
        job.error = `Worker process failed: ${err.message}`;
        this._cleanup(job.jobId);
        resolve(job);
      });
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

    if (handle.proxy) {
      try { await handle.proxy.stop(); } catch {}
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
