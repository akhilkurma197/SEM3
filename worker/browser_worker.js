/**
 * Trust Layer — Isolated Browser Worker v2.0
 * Executed only by the disposable Docker worker runtime supervised by LiveJobController.
 * Uses real Playwright Chromium rendering with network interception & screenshot capture.
 * Zero database access, zero application secrets, zero user browser profiles.
 * All outbound network traffic routed through Controlled Egress Proxy.
 */

import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';

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
const proxyUsername = args.proxyUsername;
const proxyPassword = args.proxyPassword;
const outputPath = args.output;
const screenshotPath = args.screenshot;
const initialScreenshotPath = args.initialScreenshot;
const timeoutMs = parseInt(args.timeout || '25000', 10);
const keepAliveMs = Math.min(150000, Math.max(0, parseInt(args.keepAlive || '120000', 10)));
const requestedCaptureDelayMs = Number.parseInt(args.captureDelayMs || '10000', 10);
const captureDelayMs = [0, 5000, 10000].includes(requestedCaptureDelayMs) ? requestedCaptureDelayMs : 10000;
const captureStatusPath = args.captureStatus || (outputPath ? `${outputPath}.capture-status.json` : null);
const maxHops = parseInt(args.maxRedirects || '5', 10);
const maxBytes = parseInt(args.maxBytes || '1000000', 10);

if (!targetUrl || !outputPath) {
  console.error('Usage: node worker/browser_worker.js --url=<url> --output=<path> [--screenshot=<path>] [--proxy=<proxyUrl>] [--timeout=<ms>]');
  process.exit(1);
}

const startTime = Date.now();
const stageTimings = { browser_launch_ms: 0, navigation_ms: 0, render_readiness_ms: 0, user_countdown_ms: 0, screenshot_capture_ms: 0 };
const networkEvents = [];
const pendingRenderRequests = new Map();
let lastRenderNetworkActivityAt = Date.now();
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
  errors.push(`Playwright is unavailable; refusing Mode C without rendered browser inspection: ${e.message}`);
}

/**
 * Execute real Playwright browser inspection and screenshot capture
 */
async function runPlaywrightInspection() {
  const chromium = playwright.chromium;
  const launchOptions = {
    headless: true,
    chromiumSandbox: true,
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
    launchOptions.proxy = {
      server: proxyUrl,
      ...(proxyUsername && proxyPassword ? { username: proxyUsername, password: proxyPassword } : {})
    };
  }

  const launchStartedAt = Date.now();
  const browser = await chromium.launch(launchOptions);
  stageTimings.browser_launch_ms = Date.now() - launchStartedAt;
  let context = null;
  let page = null;
  let screenshotCaptured = false;
  let screenshotBytes = 0;
  let finalScreenshotCapturedAt = null;
  let initialScreenshotCaptured = false;

function safeResponseHeaders(headers = {}) {
  const safeNames = ['content-type', 'content-length', 'server', 'via', 'location', 'date',
    'x-cache', 'x-request-id', 'cf-ray', 'x-trustlayer-egress-policy'];
  return Object.fromEntries(safeNames.filter(name => headers[name] !== undefined)
    .map(name => [name, String(headers[name]).slice(0, 512)]));
}

function safeRequestHeaders(headers = {}) {
  const safeNames = ['user-agent', 'accept', 'accept-language', 'sec-fetch-site',
    'sec-fetch-mode', 'sec-fetch-dest', 'upgrade-insecure-requests'];
  return Object.fromEntries(safeNames.filter(name => headers[name] !== undefined)
    .map(name => [name, String(headers[name]).slice(0, 512)]));
}

async function extractRedirectChain(finalResponse) {
  if (!finalResponse) return [];
  const reversed = [];
  let request = finalResponse.request();
  while (request && reversed.length < 10) {
    const response = await request.response().catch(() => null);
    const observed = response && networkEvents.findLast(event => event.url === request.url() && event.status === response.status());
    reversed.push({
      url: request.url(),
      status: response?.status() ?? null,
      location: response?.headers()?.location || null,
      timingMs: observed?.timingMs ?? null,
      correlationId: jobId,
      final: request === finalResponse.request()
    });
    request = request.redirectedFrom();
  }
  return reversed.reverse();
}

async function safeResponseExcerpt(response) {
  if (!response) return '';
  const headers = response.headers();
  const type = String(headers['content-type'] || '').toLowerCase();
  const length = Number(headers['content-length'] || 0);
  if (!(type.includes('text/') || type.includes('html') || type.includes('json')) || length > 1024 * 1024) return '';
  const body = await Promise.race([
    response.text().catch(() => ''),
    new Promise(resolve => setTimeout(() => resolve(''), 600))
  ]);
  return String(body).replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ').replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ').trim().slice(0, 500);
}

  try {
    context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      userAgent: 'TrustLayer-Isolated-Browser/2.5 (Security Investigation Bot; Restricted Sandbox; ReadOnly)',
      ignoreHTTPSErrors: false,
      permissions: []
    });

    page = await context.newPage();

    // Observe meaningful page mutations from document start. InnerHTML snapshots
    // are expensive and miss quiet periods between hydration bursts.
    await page.addInitScript(() => {
      window.__trustLayerRenderSignals = { lastMutationAt: Date.now(), mutations: 0 };
      const observe = () => {
        if (!document.documentElement || window.__trustLayerRenderSignals.observer) return;
        const observer = new MutationObserver((records) => {
          if (records.some(record => record.type === 'childList' || record.type === 'characterData' ||
              (record.type === 'attributes' && ['src', 'srcset', 'href', 'class', 'style'].includes(record.attributeName)))) {
            window.__trustLayerRenderSignals.lastMutationAt = Date.now();
            window.__trustLayerRenderSignals.mutations += records.length;
          }
        });
        observer.observe(document.documentElement, { subtree: true, childList: true, characterData: true,
          attributes: true, attributeFilter: ['src', 'srcset', 'href', 'class', 'style'] });
        window.__trustLayerRenderSignals.observer = observer;
      };
      observe();
      document.addEventListener('DOMContentLoaded', observe, { once: true });
    });

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
    const renderResourceTypes = new Set(['document', 'stylesheet', 'script', 'image', 'font']);
    page.on('request', (req) => {
      if (!renderResourceTypes.has(req.resourceType())) return;
      pendingRenderRequests.set(req, { type: req.resourceType(), url: req.url(), startedAt: Date.now() });
      lastRenderNetworkActivityAt = Date.now();
    });
    const finishRenderRequest = (req) => {
      if (pendingRenderRequests.delete(req)) lastRenderNetworkActivityAt = Date.now();
    };
    page.on('requestfinished', finishRenderRequest);
    page.on('requestfailed', finishRenderRequest);

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
    let observedMainDocumentResponse = null;
    page.on('response', (candidate) => {
      try {
        if (candidate.request().isNavigationRequest() && candidate.request().frame() === page.mainFrame()) {
          observedMainDocumentResponse = candidate;
        }
      } catch {}
    });
    const navigationStartedAt = Date.now();
    let navigationError = null;
    try {
      response = await page.goto(targetUrl, {
        // Reserve time for readiness checks and screenshot capture instead of
        // letting slow document navigation consume the full job budget.
        // Capture a useful initial viewport early; later readiness checks can
        // continue while that first screenshot is already being published.
        timeout: Math.min(7000, Math.max(5000, Math.floor(timeoutMs * 0.28))),
        // Commit is sufficient for the first (explicitly partial) viewport.
        // DOMContentLoaded is handled by the separate bounded readiness phase
        // so a slow document does not delay the first screenshot.
        waitUntil: 'commit'
      });
    } catch (navErr) {
      navigationError = navErr;
      errors.push(`Browser navigation error: ${navErr.message}`);
    }
    stageTimings.navigation_ms = Date.now() - navigationStartedAt;
    if (!response && observedMainDocumentResponse) response = observedMainDocumentResponse;

    // Publish an explicitly partial first viewport as soon as navigation
    // settles. Waiting for image/font/DOM stability before this point can push
    // otherwise useful evidence past the UI's ten-second first-image target.
    if (initialScreenshotPath) {
      try {
        if (response || observedMainDocumentResponse) await page.waitForTimeout(300);
        fs.mkdirSync(path.dirname(initialScreenshotPath), { recursive: true });
        await page.screenshot({ path: initialScreenshotPath, type: 'png', fullPage: false });
        const initialStats = fs.statSync(initialScreenshotPath);
        initialScreenshotCaptured = initialStats.size >= 1000 && initialStats.size <= 5 * 1024 * 1024;
        if (!initialScreenshotCaptured) warnings.push('Initial viewport screenshot was outside the accepted artifact size bounds.');
      } catch (initialShotError) {
        warnings.push(`Initial viewport screenshot failed: ${initialShotError.message}`);
      }
    }

    // Bounded render readiness. Background polling/websockets never hold the
    // capture open; the wait is driven by document lifecycle, visible resources,
    // meaningful content, and a short mutation quiet window.
    let renderStatus = 'RENDER_PARTIAL';
    let readinessDiagnostics = {};
    const renderStartedAt = Date.now();
    try {
      const readinessDeadline = Date.now() + Math.min(7000, Math.max(2500, Math.floor(timeoutMs * 0.35)));
      const remaining = () => Math.max(1, readinessDeadline - Date.now());
      const domContentLoaded = await page.waitForFunction(
        () => document.readyState === 'interactive' || document.readyState === 'complete', null,
        { timeout: Math.min(2500, remaining()) }
      ).then(() => true).catch(() => false);
      let state = null;
      let stableAt = 0;
      while (Date.now() < readinessDeadline) {
        state = await page.evaluate(() => {
          const visible = (el) => {
            const rect = el.getBoundingClientRect();
            const style = getComputedStyle(el);
            return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
          };
          const images = [...(document.images || [])].filter(img => {
            const r = img.getBoundingClientRect();
            return r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth;
          });
          const pendingImages = images.filter(img => !img.complete || (img.currentSrc && img.naturalWidth === 0)).length;
          const visibleText = (document.body?.innerText || '').replace(/\\s+/g, ' ').trim().slice(0, 120);
          const hasRenderedContent = Boolean(visibleText || [...document.querySelectorAll('img,svg,canvas,video')].some(visible));
          const pendingStylesheets = [...document.querySelectorAll('link[rel="stylesheet"]')]
            .filter(link => !link.sheet).length;
          const signals = window.__trustLayerRenderSignals || {};
          return { readyState: document.readyState, hasRenderedContent, visibleTextLength: visibleText.length,
            visibleImageCount: images.length, pendingImages, pendingStylesheets,
            lastMutationAt: signals.lastMutationAt || Date.now(), mutationCount: signals.mutations || 0,
            fontStatus: document.fonts?.status || 'unsupported' };
        }).catch(() => null);
        if (!state) break;
        const pendingCriticalRequests = pendingRenderRequests.size;
        const networkQuiet = Date.now() - lastRenderNetworkActivityAt >= 350;
        const resourcesReady = state.pendingImages === 0 && state.pendingStylesheets === 0 &&
          pendingCriticalRequests === 0 && networkQuiet;
        const mutationQuiet = Date.now() - state.lastMutationAt >= 700;
        if (state.hasRenderedContent && resourcesReady && mutationQuiet) { stableAt = Date.now(); break; }
        await page.waitForTimeout(Math.min(200, remaining())).catch(() => {});
      }
      // Decode viewport images after their network loads; decode is separately
      // bounded and never allows a broken image to hold the worker open.
      const imageDecodesReady = await page.evaluate(async () => {
        const images = [...(document.images || [])].filter(img => {
          const r = img.getBoundingClientRect();
          return r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth &&
            img.complete && img.naturalWidth > 0 && typeof img.decode === 'function';
        });
        return Promise.race([
          Promise.allSettled(images.map(img => img.decode())).then(results => results.every(result => result.status === 'fulfilled')),
          new Promise(resolve => setTimeout(() => resolve(false), 700))
        ]);
      }).catch(() => false);
      // Font loading is useful but non-critical: bound it separately so late
      // third-party fonts cannot starve the screenshot.
      const fontsReady = await page.evaluate(() => !document.fonts?.ready ? true :
        Promise.race([document.fonts.ready.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 500))])
      ).catch(() => false);
      readinessDiagnostics = { domContentLoaded, readyState: state?.readyState || 'unavailable',
        hasRenderedContent: state?.hasRenderedContent || false, visibleTextLength: state?.visibleTextLength || 0,
        visibleImageCount: state?.visibleImageCount || 0, pendingImages: state?.pendingImages ?? null,
        pendingStylesheets: state?.pendingStylesheets ?? null,
        pendingCriticalRequests: pendingRenderRequests.size,
        networkQuietMs: Date.now() - lastRenderNetworkActivityAt,
        imageDecodesReady, mutationCount: state?.mutationCount || 0,
        stableAt: stableAt || null, fontsReady, waitMs: Date.now() - renderStartedAt,
        timedOut: Date.now() >= readinessDeadline && !stableAt };
      const isAccessDenied = response && [401, 403].includes(response.status());
      renderStatus = isAccessDenied ? 'ACCESS_DENIED'
        : (domContentLoaded && stableAt && imageDecodesReady ? 'RENDER_COMPLETE'
          : (readinessDiagnostics.timedOut ? 'RENDER_TIMEOUT' : 'RENDER_PARTIAL'));
    } catch {
      renderStatus = 'RENDER_PARTIAL';
    }
    stageTimings.render_readiness_ms = Date.now() - renderStartedAt;

    // Countdown begins only after the bounded DOM/readiness milestone. A
    // status file is the backend-authoritative clock consumed by the UI.
    const countdownStartedAt = Date.now();
    const countdownEndsAt = countdownStartedAt + captureDelayMs;
    const writeCaptureStatus = (status, extra = {}) => {
      if (!captureStatusPath) return;
      try {
        fs.writeFileSync(captureStatusPath, JSON.stringify({ status, captureDelayMs,
          countdownStartedAt, countdownEndsAt, updatedAt: Date.now(), renderStatus, ...extra }));
      } catch {}
    };
    writeCaptureStatus(captureDelayMs ? 'COUNTDOWN' : 'CAPTURING', { readinessDiagnostics });
    if (captureDelayMs > 0) {
      while (Date.now() < countdownEndsAt) {
        await page.waitForTimeout(Math.min(250, countdownEndsAt - Date.now())).catch(() => {});
        writeCaptureStatus(Date.now() >= countdownEndsAt ? 'CAPTURING' : 'COUNTDOWN', { readinessDiagnostics });
      }
    }
    stageTimings.user_countdown_ms = Date.now() - countdownStartedAt;

    // The user-configured deadline is the screenshot capture point. Capture
    // before DOM extraction, OCR preparation, or any post-render analysis.
    if (screenshotPath) {
      try {
        fs.mkdirSync(path.dirname(screenshotPath), { recursive: true });
        const screenshotStartedAt = Date.now();
        await page.screenshot({ path: screenshotPath, type: 'png', fullPage: false });
        const stats = fs.statSync(screenshotPath);
        screenshotBytes = stats.size;
        screenshotCaptured = stats.size > 0;
        finalScreenshotCapturedAt = Date.now();
        stageTimings.screenshot_capture_ms = Date.now() - screenshotStartedAt;
        writeCaptureStatus(screenshotCaptured ? 'READY' : 'FAILED', { capturedAt: finalScreenshotCapturedAt, screenshotBytes, readinessDiagnostics });
      } catch (shotErr) {
        warnings.push(`Screenshot capture failed: ${shotErr.message}`);
        writeCaptureStatus('FAILED', { error: shotErr.message });
      }
    }

    if (observedMainDocumentResponse) response = observedMainDocumentResponse;
    const finalUrl = page.url();
    const httpStatus = response ? response.status() : null;
    const contentType = response?.headers()['content-type'] || 'text/html';
    const responseHeaders = safeResponseHeaders(response?.headers() || {});
    const responseBodyExcerpt = await safeResponseExcerpt(response);
    const tlsDetails = response ? await response.securityDetails().catch(() => null) : null;
    const browserPeerAddress = response ? await response.serverAddr().catch(() => null) : null;
    redirectChain.push(...await extractRedirectChain(response));

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
      const bodyTextLength = (document.body?.innerText || '').trim().length;

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
        bodyTextLength,
        htmlContent: document.documentElement.outerHTML
      };
    });
    if (!renderedData.domNodes) {
      renderStatus = navigationError && /timeout/i.test(navigationError.message) ? 'RENDER_TIMEOUT' : 'RENDER_FAILED';
    } else if (response && [401, 403].includes(response.status())) {
      renderStatus = 'ACCESS_DENIED';
    } else if (navigationError && renderStatus !== 'RENDER_COMPLETE') {
      renderStatus = /timeout/i.test(navigationError.message) ? 'RENDER_TIMEOUT' : 'RENDER_PARTIAL';
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
      screenshotBytes,
      initialScreenshotAvailable: initialScreenshotCaptured,
      renderStatus,
      screenshotMetadata: screenshotCaptured ? { checkpoint: 'FINAL', capturedAt: finalScreenshotCapturedAt, finalUrl,
        renderStatus, readinessDiagnostics } : null
    };

    const inspectionResult = {
      jobId,
      targetUrl,
      browserDiagnostics: {
        browser: 'Chromium',
        browserVersion: browser.version(),
        playwrightVersion: '1.64.1',
        headless: launchOptions.headless,
        chromiumSandbox: launchOptions.chromiumSandbox,
        launchArguments: launchOptions.args,
        userAgent: 'TrustLayer-Isolated-Browser/2.5 (Security Investigation Bot; Restricted Sandbox; ReadOnly)',
        proxyConfigured: Boolean(proxyUrl),
        navigationWaitUntil: 'commit',
        navigationTimeoutMs: Math.min(7000, Math.max(5000, Math.floor(timeoutMs * 0.28)))
      },
      durationMs: Date.now() - startTime,
      warnings,
      errors,
      limitations,
      status: response ? 'SUCCESS' : (renderedData.domNodes > 0 ? 'PARTIAL' : 'FAILED'),
      finalUrl,
      httpStatus,
      responseHeaders,
      responseDiagnostics: {
        statusCode: httpStatus,
        statusText: response?.statusText() || null,
        finalResponseUrl: response?.url() || finalUrl,
        origin: responseHeaders['x-trustlayer-egress-policy'] ? 'EGRESS_PROXY_POLICY' : (response ? 'TARGET_TLS_TUNNEL' : 'NO_HTTP_RESPONSE'),
        tls: tlsDetails,
        browserPeerAddress,
        browserPeerRole: proxyUrl ? 'CONFIGURED_EGRESS_PROXY_SOCKET' : 'DIRECT_SOCKET_NOT_PERMITTED_BY_MODE_C_POLICY'
      },
      requestHeaders: safeRequestHeaders(response?.request().headers() || {}),
      responseBodyExcerpt,
      correlationId: jobId,
      contentType,
      redirectChain,
      pageExtraction,
      networkEvents,
      blockedRequests,
      screenshotCaptured,
      screenshotBytes,
      modeCTimings: { ...stageTimings },
      renderStatus,
      readinessDiagnostics,
      screenshotCapture: { status: screenshotCaptured ? 'READY' : 'FAILED', captureDelayMs,
        countdownStartedAt, countdownEndsAt, capturedAt: finalScreenshotCapturedAt, screenshotBytes },
      isolationReport: {
        sandboxType: 'PLAYWRIGHT_WORKER_IN_CONTAINER',
        playwrightAvailable: true,
        chromiumSandboxEnabled: true,
        credentialsIsolated: true,
        cookiesIsolated: true,
        downloadsBlocked: true,
        storageEphemeral: true,
        proxyEnforced: !!proxyUrl,
        networkIsolated: null,
        runtimeMode: 'WORKER_RUNTIME_PENDING_SUPERVISOR_VALIDATION',
        workerPid: process.pid,
        screenshotCaptured
      }
    };

    // Publish real page data as soon as capture and extraction finish. The
    // supervisor can complete the case while this isolated browser remains
    // available for the requested short live session.
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(`${outputPath}.ready`, JSON.stringify(inspectionResult, null, 2), 'utf8');
    if (keepAliveMs > 0) await page.waitForTimeout(keepAliveMs).catch(() => {});
    return inspectionResult;

  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

// ── Main Entrypoint ──
(async () => {
  try {
    if (!playwright) throw new Error('Playwright is required for Mode C; HTTP-only fallback is disabled.');
    const result = await runPlaywrightInspection();

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
        sandboxType: 'WORKER_RUNTIME_UNVERIFIED',
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
