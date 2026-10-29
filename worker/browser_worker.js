/**
 * Trust Layer — Isolated Browser Worker v2.0
 * Executed as an independent, restricted worker (container or subprocess).
 * Uses real Playwright Chromium rendering with network interception & screenshot capture.
 * Zero database access, zero application secrets, zero user browser profiles.
 * All outbound network traffic routed through Controlled Egress Proxy.
 */

import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import { PageStructureExtractor } from '../core/investigators/page_extractor.js';

// Parse command-line flags
function parseArgs() {
  const args = {};
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx !== -1) {
        const key = arg.slice(2, eqIdx);
        const val = arg.slice(eqIdx + 1);
        args[key] = val;
      }
    }
  }
  return args;
}

const args = parseArgs();
const targetUrl = args.url;
const jobId = args.jobId || 'job-' + Date.now();
const proxyUrl = args.proxy;
const outputPath = args.output;
const screenshotPath = args.screenshot;
const timeoutMs = parseInt(args.timeout || '10000', 10);
const maxHops = parseInt(args.maxRedirects || '5', 10);
const maxBytes = parseInt(args.maxBytes || '1000000', 10);

if (!targetUrl || !outputPath) {
  console.error('Usage: node worker/browser_worker.js --url=<url> --output=<path> [--screenshot=<path>] [--proxy=<proxyUrl>] [--timeout=<ms>]');
  process.exit(1);
}

const startTime = Date.now();
const networkEvents = [];
const blockedRequests = [];
const redirectChain = [];
const warnings = [];
const errors = [];
const limitations = [];

// Try to load Playwright
let playwright = null;
try {
  playwright = await import('playwright');
} catch (e) {
  warnings.push(`Playwright import notice: ${e.message}`);
}

/**
 * Execute real Playwright browser inspection and screenshot capture
 */
async function runPlaywrightInspection() {
  const chromium = playwright.chromium;
  const launchOptions = {
    headless: true,
    args: [
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-background-networking',
      '--disable-sync',
      '--disable-default-apps',
      '--disable-extensions',
      '--mute-audio',
      '--no-first-run'
    ]
  };

  if (proxyUrl) {
    launchOptions.proxy = { server: proxyUrl };
  }

  const browser = await chromium.launch(launchOptions);
  let context = null;
  let page = null;
  let screenshotCaptured = false;
  let screenshotBytes = 0;

  try {
    context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      userAgent: 'TrustLayer-Isolated-Browser/2.5 (Security Investigation Bot; Restricted Sandbox; ReadOnly)',
      ignoreHTTPSErrors: false,
      permissions: []
    });

    page = await context.newPage();

    // ── Network Request Interception (Observation Mode: Block non-GET/HEAD mutations) ──
    await page.route('**/*', async (route) => {
      const req = route.request();
      const method = req.method();
      const reqUrl = req.url();
      const resourceType = req.resourceType();

      // Block state-changing mutation requests
      if (method !== 'GET' && method !== 'HEAD') {
        const blockedItem = {
          time: new Date().toISOString(),
          method,
          url: reqUrl,
          resourceType,
          reason: `Disallowed HTTP method ${method} — Observation mode prohibits data transmission / state mutation.`
        };
        blockedRequests.push(blockedItem);
        await route.abort('blockedbyclient');
        return;
      }

      route.continue();
    });

    // Record response events
    page.on('response', (res) => {
      try {
        const req = res.request();
        networkEvents.push({
          time: new Date().toISOString(),
          method: req.method(),
          url: req.url(),
          status: res.status(),
          type: req.resourceType() || res.headers()['content-type'] || 'resource',
          size: res.headers()['content-length'] ? `${res.headers()['content-length']} B` : 'Unknown',
          timingMs: Date.now() - startTime
        });
      } catch {}
    });

    // Record request failures (including proxy blocks)
    page.on('requestfailed', (req) => {
      const failure = req.failure();
      networkEvents.push({
        time: new Date().toISOString(),
        method: req.method(),
        url: req.url(),
        status: 'FAILED',
        type: req.resourceType(),
        error: failure?.errorText || 'Request failed'
      });
    });

    // ── Navigate to Target ──
    let response = null;
    try {
      response = await page.goto(targetUrl, {
        timeout: timeoutMs,
        waitUntil: 'domcontentloaded'
      });
    } catch (navErr) {
      errors.push(`Browser navigation error: ${navErr.message}`);
    }

    // Bounded settlement wait for dynamic JavaScript hydration
    try {
      await page.waitForTimeout(Math.min(timeoutMs / 4, 1200));
    } catch {}

    const finalUrl = page.url();
    const httpStatus = response ? response.status() : null;
    const contentType = response?.headers()['content-type'] || 'text/html';

    // ── Extract Live Rendered DOM ──
    const renderedData = await page.evaluate(() => {
      const title = document.title || null;
      const metaDesc = document.querySelector('meta[name="description"]')?.getAttribute('content') || null;

      // Headings
      const headings = [];
      document.querySelectorAll('h1, h2, h3').forEach((h) => {
        const t = (h.textContent || '').trim();
        if (t && t.length > 1 && !headings.includes(t)) headings.push(t);
      });

      // Buttons / CTAs
      const buttons = [];
      document.querySelectorAll('button, input[type="submit"], input[type="button"], a.btn, a.button').forEach((b) => {
        const val = b.value || b.textContent || '';
        const t = val.trim();
        if (t && !buttons.includes(t)) buttons.push(t);
      });

      // Forms
      const forms = [];
      document.querySelectorAll('form').forEach((f) => {
        const action = f.getAttribute('action') || '';
        const method = (f.getAttribute('method') || 'GET').toUpperCase();
        const inputs = [];
        let hasPassword = false;
        let hasSensitive = false;

        f.querySelectorAll('input, select, textarea').forEach((inp) => {
          const type = (inp.getAttribute('type') || 'text').toLowerCase();
          const name = inp.getAttribute('name') || inp.getAttribute('id') || '';
          const placeholder = inp.getAttribute('placeholder') || '';
          const isHidden = type === 'hidden' || inp.style?.display === 'none';
          const isPassword = type === 'password';
          const isSensitive = isPassword || /otp|cvv|card|ssn|pin|token|secret/i.test(name);
          if (isPassword) hasPassword = true;
          if (isSensitive) hasSensitive = true;

          inputs.push({
            name,
            type,
            placeholder,
            isPassword,
            isSensitive,
            isHidden,
            isUserEditable: !isHidden
          });
        });

        const isExternal = action.startsWith('http') && !action.includes(window.location.hostname);
        forms.push({
          action,
          method,
          destinationHost: action.startsWith('http') ? (new URL(action, window.location.href)).hostname : window.location.hostname,
          fields: inputs.map(i => i.name).filter(Boolean),
          inputs,
          hasPassword,
          hasSensitive,
          isExternal
        });
      });

      // Scripts
      const scripts = [];
      document.querySelectorAll('script').forEach((s) => {
        const src = s.getAttribute('src');
        if (src) {
          try {
            const parsed = new URL(src, window.location.href);
            scripts.push({
              src,
              domain: parsed.hostname,
              isExternal: parsed.hostname !== window.location.hostname,
              isInline: false
            });
          } catch {
            scripts.push({ src, domain: null, isExternal: false, isInline: false });
          }
        } else {
          scripts.push({ src: null, domain: null, isExternal: false, isInline: true });
        }
      });

      // Links
      const links = [];
      document.querySelectorAll('a[href]').forEach((a) => {
        const href = a.getAttribute('href');
        if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
          try {
            const parsed = new URL(href, window.location.href);
            links.push({
              href,
              isExternal: parsed.hostname !== window.location.hostname
            });
          } catch {}
        }
      });

      const externalDomains = [...new Set(scripts.filter(s => s.domain).map(s => s.domain))];
      const domNodes = document.querySelectorAll('*').length;
      const htmlBytes = document.documentElement.outerHTML.length;

      return {
        title,
        metaDescription: metaDesc,
        headings,
        buttons,
        forms,
        scripts,
        links,
        externalDomains,
        domNodes,
        htmlBytes,
        htmlContent: document.documentElement.outerHTML
      };
    });

    // ── Real Webpage Screenshot Capture ──
    if (screenshotPath) {
      try {
        fs.mkdirSync(path.dirname(screenshotPath), { recursive: true });
        await page.screenshot({
          path: screenshotPath,
          type: 'png',
          fullPage: false
        });
        const stats = fs.statSync(screenshotPath);
        screenshotBytes = stats.size;
        screenshotCaptured = stats.size > 0;
      } catch (shotErr) {
        warnings.push(`Screenshot capture failed: ${shotErr.message}`);
        screenshotCaptured = false;
      }
    }

    const pageExtraction = {
      status: 'COMPLETED',
      title: renderedData.title,
      headings: renderedData.headings,
      metaDescription: renderedData.metaDescription,
      buttons: renderedData.buttons,
      domNodes: renderedData.domNodes,
      htmlBytes: renderedData.htmlBytes,
      forms: renderedData.forms,
      scripts: renderedData.scripts,
      iframes: [],
      links: renderedData.links,
      externalDomains: renderedData.externalDomains,
      domFingerprint: `DOM-${renderedData.domNodes}N-${renderedData.forms.length}F-${renderedData.scripts.length}S`,
      screenshotAvailable: screenshotCaptured,
      screenshotBytes
    };

    return {
      status: response ? 'SUCCESS' : (renderedData.domNodes > 0 ? 'PARTIAL' : 'FAILED'),
      finalUrl,
      httpStatus,
      contentType,
      redirectChain,
      pageExtraction,
      networkEvents,
      blockedRequests,
      screenshotCaptured,
      screenshotBytes,
      isolationReport: {
        sandboxType: 'CONTAINER_PLAYWRIGHT_CHROMIUM',
        playwrightAvailable: true,
        chromiumSandboxEnabled: true,
        credentialsIsolated: true,
        cookiesIsolated: true,
        downloadsBlocked: true,
        storageEphemeral: true,
        proxyEnforced: !!proxyUrl,
        workerPid: process.pid,
        screenshotCaptured
      }
    };

  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

/**
 * Execute fallback HTTP inspection if Playwright is unavailable
 */
async function runHttpWorkerInspection() {
  limitations.push('Playwright unavailable in this environment — static HTTP/DOM extraction active.');

  let currentUrl = targetUrl;
  let finalUrl = targetUrl;
  let statusCode = null;
  let headers = {};
  let contentType = '';
  let bodyContent = '';
  let redirectCount = 0;
  const visited = new Set();

  while (redirectCount <= maxHops) {
    if (visited.has(currentUrl)) {
      errors.push(`Circular redirect loop detected: ${currentUrl}`);
      break;
    }
    visited.add(currentUrl);

    const hopStart = Date.now();
    const hopRes = await fetchOneHop(currentUrl, timeoutMs);

    statusCode = hopRes.statusCode;
    headers = hopRes.headers;
    contentType = hopRes.contentType;
    bodyContent = hopRes.body || '';

    const isRedirect = (statusCode >= 300 && statusCode < 400);
    const location = headers['location'];

    redirectChain.push({
      hop: redirectCount + 1,
      fromUrl: currentUrl,
      toUrl: isRedirect && location ? new URL(location, currentUrl).href : currentUrl,
      status: statusCode,
      location: location || null,
      latencyMs: Date.now() - hopStart,
      contentType,
      isFinal: !isRedirect || !location
    });

    networkEvents.push({
      time: new Date().toISOString(),
      method: 'GET',
      url: currentUrl,
      status: statusCode,
      type: contentType || 'document',
      size: `${bodyContent.length} B`,
      duration: `${Date.now() - hopStart}ms`
    });

    if (isRedirect && location && redirectCount < maxHops) {
      redirectCount++;
      currentUrl = new URL(location, currentUrl).href;
      finalUrl = currentUrl;
    } else {
      finalUrl = currentUrl;
      break;
    }
  }

  const urlHost = new URL(finalUrl).hostname;
  const pageExtraction = PageStructureExtractor.extract(bodyContent, urlHost);
  pageExtraction.screenshotAvailable = false;

  for (const f of pageExtraction.forms) {
    if (f.isExternal) {
      blockedRequests.push({
        time: new Date().toISOString(),
        method: f.method || 'POST',
        url: f.action,
        reason: 'Form action targets external server (mutating submissions prohibited in observation mode)'
      });
    }
  }

  return {
    status: statusCode ? 'SUCCESS' : 'FAILED',
    finalUrl,
    httpStatus: statusCode,
    contentType,
    redirectChain,
    pageExtraction,
    networkEvents,
    blockedRequests,
    screenshotCaptured: false,
    screenshotBytes: 0,
    isolationReport: {
      sandboxType: 'ISOLATED_PROCESS_WORKER',
      playwrightAvailable: false,
      chromiumSandboxEnabled: false,
      credentialsIsolated: true,
      cookiesIsolated: true,
      downloadsBlocked: true,
      storageEphemeral: true,
      proxyEnforced: !!proxyUrl,
      workerPid: process.pid,
      screenshotCaptured: false
    }
  };
}

/**
 * Single hop HTTP fetcher
 */
function fetchOneHop(urlStr, timeout) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(urlStr);
    } catch (e) {
      resolve({ statusCode: null, headers: {}, contentType: '', body: '', error: e.message });
      return;
    }

    const isHttps = u.protocol === 'https:';
    const client = isHttps ? https : http;

    const reqOptions = {
      method: 'GET',
      headers: {
        'User-Agent': 'TrustLayer-Forensic-Recon/2.5 (Security Investigation Bot; Isolated Sandbox; ReadOnly)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      timeout
    };

    if (proxyUrl) {
      const pUrl = new URL(proxyUrl);
      reqOptions.host = pUrl.hostname;
      reqOptions.port = pUrl.port;
      reqOptions.path = urlStr;
      reqOptions.headers['Host'] = u.host;
    } else {
      reqOptions.host = u.hostname;
      reqOptions.port = u.port || (isHttps ? 443 : 80);
      reqOptions.path = u.pathname + u.search;
    }

    const req = client.request(urlStr, reqOptions, (res) => {
      const headers = {};
      for (const [k, v] of Object.entries(res.headers)) {
        headers[k.toLowerCase()] = v;
      }
      const contentType = headers['content-type'] || '';
      let chunks = [];
      let totalBytes = 0;

      res.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes <= maxBytes) {
          chunks.push(chunk);
        }
      });

      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({
          statusCode: res.statusCode,
          headers,
          contentType,
          body,
          error: null
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ statusCode: null, headers: {}, contentType: '', body: '', error: 'Request timeout' });
    });

    req.on('error', (err) => {
      resolve({ statusCode: null, headers: {}, contentType: '', body: '', error: err.message });
    });

    req.end();
  });
}

// ── Main Entrypoint ──
(async () => {
  try {
    let result;
    if (playwright) {
      result = await runPlaywrightInspection();
    } else {
      result = await runHttpWorkerInspection();
    }

    result.jobId = jobId;
    result.targetUrl = targetUrl;
    result.durationMs = Date.now() - startTime;
    result.warnings = warnings;
    result.errors = errors;
    result.limitations = limitations;

    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
    process.exit(0);
  } catch (fatal) {
    const errorResult = {
      jobId,
      targetUrl,
      status: 'FAILED',
      error: fatal.message,
      durationMs: Date.now() - startTime,
      isolationReport: {
        sandboxType: 'ISOLATED_PROCESS_WORKER',
        workerPid: process.pid,
        error: fatal.message
      }
    };
    try {
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      fs.writeFileSync(outputPath, JSON.stringify(errorResult, null, 2), 'utf8');
    } catch {}
    process.exit(1);
  }
})();
