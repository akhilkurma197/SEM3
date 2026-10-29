/**
 * Trust Layer — Real HTTP Reconnaissance Investigator v2.4
 * Performs live network probing with exact timing, hop-by-hop redirect tracing,
 * SSRF safeguards (pre-connection DNS validation via SSRFGuard), and zero synthetic fallbacks.
 */

import { SSRFGuard } from './ssrf_guard.js';

export class HTTPReconInvestigator {
  /**
   * Probes target URL and inspects navigation / redirects hop-by-hop
   * @param {string} targetUrl 
   * @param {object} options
   * @returns {Promise<{
   *   status: string,
   *   statusCode: number|null,
   *   statusText: string|null,
   *   initialUrl: string,
   *   finalUrl: string,
   *   redirectCount: number,
   *   redirectChain: Array<object>,
   *   latencyMs: number,
   *   headers: object,
   *   contentType: string,
   *   bodySnippet: string|null,
   *   error: string|null
   * }>}
   */
  static async probe(targetUrl, options = {}) {
    const timeoutMs = options.timeoutMs || 4000;
    const maxHops = options.maxHops || 10;
    const startTime = Date.now();
    const chain = [];

    // ── Pre-connection SSRF guard for initial URL ──
    const initialGuard = await SSRFGuard.validateAndResolve(targetUrl);
    if (!initialGuard.allowed) {
      return {
        status: 'BLOCKED',
        statusCode: null,
        statusText: null,
        initialUrl: targetUrl,
        finalUrl: targetUrl,
        redirectCount: 0,
        redirectChain: [],
        latencyMs: 0,
        headers: {},
        contentType: '',
        bodySnippet: null,
        error: `SSRF blocked: ${initialGuard.blockedReason}`
      };
    }

    let currentUrl = targetUrl;
    let finalUrl = targetUrl;
    let statusCode = null;
    let statusText = null;
    let headers = {};
    let contentType = '';
    let bodySnippet = null;
    let redirectCount = 0;

    try {
      const visitedUrls = new Set();

      while (redirectCount < maxHops) {
        if (visitedUrls.has(currentUrl)) {
          throw new Error(`Circular redirect loop detected on: ${currentUrl}`);
        }
        visitedUrls.add(currentUrl);

        // ── Per-hop SSRF guard ──
        if (redirectCount > 0) {
          const hopGuard = await SSRFGuard.validateAndResolve(currentUrl);
          if (!hopGuard.allowed) {
            throw new Error(`Redirect destination blocked by SSRF guard: ${hopGuard.blockedReason}`);
          }
        }

        const hopStart = Date.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        const res = await fetch(currentUrl, {
          method: 'GET',
          signal: controller.signal,
          redirect: 'manual',
          headers: {
            'User-Agent': 'TrustLayer-Forensic-Recon/2.4 (Security Investigation Bot; Isolated Sandbox)'
          }
        });

        clearTimeout(timeoutId);
        const hopLatency = Date.now() - hopStart;
        statusCode = res.status;
        statusText = res.statusText;

        // Check for 3xx redirect status
        const isRedirect = (statusCode >= 300 && statusCode < 400);
        const locationHeader = res.headers.get('location');

        if (isRedirect && locationHeader) {
          const nextUrl = new URL(locationHeader, currentUrl).href;

          // Guard the redirect target before following
          const redirectGuard = await SSRFGuard.validateAndResolve(nextUrl);

          redirectCount++;
          chain.push({
            hop: redirectCount,
            fromUrl: currentUrl,
            toUrl: nextUrl,
            method: 'GET',
            status: statusCode,
            statusText,
            location: locationHeader,
            latencyMs: hopLatency,
            contentType: res.headers.get('content-type') || '',
            timestamp: Date.now(),
            isFinal: false,
            resolvedIps: redirectGuard.resolvedIps || []
          });

          if (!redirectGuard.allowed) {
            throw new Error(`Redirect to ${nextUrl} blocked: ${redirectGuard.blockedReason}`);
          }

          currentUrl = nextUrl;
          finalUrl = nextUrl;
        } else {
          // Final landing page reached (200, 404, etc.)
          res.headers.forEach((val, key) => {
            headers[key.toLowerCase()] = val;
          });
          contentType = headers['content-type'] || '';

          if (contentType.includes('text') || contentType.includes('json') || contentType.includes('html') || !contentType) {
            try {
              const text = await res.text();
              bodySnippet = text.substring(0, 250000);
            } catch {}
          }

          finalUrl = currentUrl;

          // Get resolved IPs for the final hop (already validated earlier)
          const finalGuard = redirectCount === 0 ? initialGuard : await SSRFGuard.validateAndResolve(currentUrl);

          chain.push({
            hop: redirectCount + 1,
            fromUrl: currentUrl,
            toUrl: currentUrl,
            method: 'GET',
            status: statusCode,
            statusText,
            location: null,
            latencyMs: hopLatency,
            contentType,
            timestamp: Date.now(),
            isFinal: true,
            resolvedIps: finalGuard.resolvedIps || []
          });
          break;
        }
      }

      return {
        status: 'SUCCESS',
        statusCode,
        statusText,
        initialUrl: targetUrl,
        finalUrl,
        redirectCount,
        redirectChain: chain,
        latencyMs: Date.now() - startTime,
        headers,
        contentType,
        bodySnippet,
        error: null
      };

    } catch (err) {
      const latencyMs = Date.now() - startTime;
      const isTimeout = err.name === 'AbortError' || err.message?.includes('timeout');

      return {
        status: 'FAILED',
        statusCode,
        statusText,
        initialUrl: targetUrl,
        finalUrl: currentUrl || targetUrl,
        redirectCount: chain.length,
        redirectChain: chain,
        latencyMs,
        headers,
        contentType,
        bodySnippet,
        error: isTimeout ? `Connection timed out after ${timeoutMs}ms` : `Network request failed: ${err.message}`
      };
    }
  }
}
