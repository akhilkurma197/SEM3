/**
 * Trust Layer — Mode B: Active Redirect & HTTP Header Tracer v1.0
 * Performs bounded, non-browser HTTP network-only examination of actual HTTP redirects
 * and response headers without launching Playwright, executing JavaScript, or fetching secondary assets.
 * Enforces pre-connection and per-hop SSRF validation, DNS pinning, and safe header extraction.
 */

import { HTTPReconInvestigator } from './http_recon.js';
import { URLParser } from '../ml/url_parser.js';

export class RedirectTracer {
  /**
   * Executes Mode B redirect chain and safe header inspection.
   * @param {string} targetUrl 
   * @param {object} [options]
   * @returns {Promise<{
   *   status: string,
   *   riskLevel: 'SAFE' | 'UNDER_REVIEW' | 'PHISHING',
   *   riskScore: number,
   *   hopsCount: number,
   *   initialUrl: string,
   *   finalUrl: string,
   *   crossDomainJumps: number,
   *   redirectChain: Array<object>,
   *   inferredJsRedirects: Array<object>,
   *   metaRefresh: object|null,
   *   headers: object,
   *   securityHeadersPresent: string[],
   *   securityHeadersMissing: string[],
   *   summary: string,
   *   error: string|null
   * }>}
   */
  static async trace(targetUrl, options = {}) {
    const probeRes = await HTTPReconInvestigator.probe(targetUrl, {
      timeoutMs: options.timeoutMs || 5000,
      maxTotalMs: options.maxTotalMs || 15000,
      maxHops: options.maxHops || 10,
      maxBytes: options.maxBytes,
      allowedPorts: options.allowedPorts,
      _testBypassSsrf: options._testBypassSsrf === true
    });

    if (probeRes.status === 'BLOCKED') {
      return {
        status: 'BLOCKED',
        // Egress/SSRF policy blocks are not evidence that the destination is phishing.
        riskLevel: 'UNKNOWN',
        riskScore: 0,
        hopsCount: probeRes.redirectCount || 0,
        initialUrl: targetUrl,
        finalUrl: probeRes.finalUrl || null,
        crossDomainJumps: 0,
        redirectChain: probeRes.redirectChain || [],
        inferredJsRedirects: [],
        metaRefresh: null,
        headers: {},
        securityHeadersPresent: [],
        securityHeadersMissing: [],
        initialResolvedIps: probeRes.initialResolvedIps || [],
        finalResolvedIps: probeRes.finalResolvedIps || [],
        latencyMs: probeRes.latencyMs || 0,
        limitations: ['The full rendered webpage was not inspected.'],
        summary: `Mode B trace blocked by network boundary policy; no risk conclusion was made: ${probeRes.error}`,
        error: probeRes.error
      };
    }

    if (probeRes.status === 'FAILED') {
      return {
        status: 'FAILED',
        riskLevel: 'UNKNOWN',
        riskScore: 0,
        hopsCount: probeRes.redirectCount || 0,
        initialUrl: targetUrl,
        finalUrl: probeRes.finalUrl || null,
        crossDomainJumps: 0,
        redirectChain: probeRes.redirectChain || [],
        inferredJsRedirects: [],
        metaRefresh: null,
        headers: probeRes.headers || {},
        securityHeadersPresent: [],
        securityHeadersMissing: [],
        initialResolvedIps: probeRes.initialResolvedIps || [],
        finalResolvedIps: probeRes.finalResolvedIps || [],
        latencyMs: probeRes.latencyMs || 0,
        limitations: ['The full rendered webpage was not inspected.'],
        summary: `Mode B trace incomplete; no risk conclusion was made: ${probeRes.error}`,
        error: probeRes.error
      };
    }

    const chain = probeRes.redirectChain || [];
    const hopsCount = probeRes.redirectCount || 0;
    const finalUrl = probeRes.finalUrl || targetUrl;
    const initialParsed = URLParser.parse(targetUrl);
    const finalParsed = URLParser.parse(finalUrl);

    // 1. Calculate Cross-Domain Jumps
    let crossDomainJumps = 0;
    const domainsSeen = [initialParsed.domain || initialParsed.hostname];

    for (const hop of chain) {
      if (hop.toUrl && hop.toUrl !== hop.fromUrl) {
        const toP = URLParser.parse(hop.toUrl);
        const toDomain = toP.domain || toP.hostname;
        const lastDomain = domainsSeen[domainsSeen.length - 1];
        if (toDomain && lastDomain && toDomain.toLowerCase() !== lastDomain.toLowerCase()) {
          crossDomainJumps++;
          domainsSeen.push(toDomain);
        }
      }
    }

    // 2. Static HTML Analysis of Response (Meta-Refresh & JS Redirect Candidates)
    let metaRefresh = null;
    const inferredJsRedirects = [];
    const htmlSnippet = probeRes.bodySnippet || '';

    if (htmlSnippet) {
      // Check for <meta http-equiv="refresh" content="...;url=...">
      const metaMatch = htmlSnippet.match(/<meta[^>]*http-equiv=["']refresh["'][^>]*content=["']([^"']*)["'][^>]*>/i) ||
                        htmlSnippet.match(/<meta[^>]*content=["']([^"']*)["'][^>]*http-equiv=["']refresh["'][^>]*>/i);
      if (metaMatch) {
        const contentStr = metaMatch[1] || '';
        const urlPart = contentStr.match(/url\s*=\s*([^;,\s]+)/i);
        const delayPart = contentStr.match(/^\s*(\d+)/);
        const destination = urlPart ? urlPart[1].replace(/['"]/g, '').trim() : '';
        const delaySec = delayPart ? parseInt(delayPart[1], 10) : 0;
        if (destination) {
          metaRefresh = {
            destination,
            delaySec,
            rawDeclaration: metaMatch[0]
          };
        }
      }

      // Check for static JS redirect candidates (e.g. window.location = "...", location.href = "...", location.replace("..."))
      const jsPatterns = [
        /(?:window\.)?location\s*=\s*['"]([^'"]+)['"]/gi,
        /(?:window\.)?location\.href\s*=\s*['"]([^'"]+)['"]/gi,
        /(?:window\.)?location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)/gi
      ];

      for (const pattern of jsPatterns) {
        let m;
        while ((m = pattern.exec(htmlSnippet)) !== null) {
          const dest = m[1];
          if (dest && !dest.startsWith('#') && !dest.startsWith('javascript:')) {
            if (!inferredJsRedirects.some(r => r.candidateUrl === dest)) {
              inferredJsRedirects.push({
                type: 'STATIC_JS_REDIRECT_CANDIDATE',
                candidateUrl: dest,
                snippet: m[0],
                status: 'INFERRED' // Strictly marked as INFERRED, not executed
              });
            }
          }
        }
      }
    }

    // 3. Security Headers Evaluation
    const headers = probeRes.headers || {};
    const keySecurityHeaders = [
      'strict-transport-security',
      'content-security-policy',
      'x-content-type-options',
      'x-frame-options'
    ];
    const securityHeadersPresent = [];
    const securityHeadersMissing = [];

    for (const h of keySecurityHeaders) {
      if (headers[h]) {
        securityHeadersPresent.push(h);
      } else {
        securityHeadersMissing.push(h);
      }
    }

    // 4. Deterministic Mode B Risk Scoring
    let riskScore = 0;
    let riskLevel = 'SAFE';
    const reasons = [];

    // Protocol upgrade (HTTP -> HTTPS on same domain) is benign
    const isBenignHttpsUpgrade = hopsCount === 1 &&
      initialParsed.hostname === finalParsed.hostname &&
      initialParsed.protocol === 'http:' && finalParsed.protocol === 'https:';

    if (hopsCount > 0 && !isBenignHttpsUpgrade) {
      // Multiple hops
      if (hopsCount >= 3) {
        riskScore += 25;
        reasons.push(`Extended redirect chain (${hopsCount} hops).`);
      } else {
        riskScore += 10;
        reasons.push(`Redirect chain observed (${hopsCount} hop).`);
      }

      // Cross-domain transitions
      if (crossDomainJumps >= 2) {
        riskScore += 35;
        reasons.push(`Multiple cross-domain hops (${crossDomainJumps} apex transitions).`);
      } else if (crossDomainJumps === 1) {
        riskScore += 15;
        reasons.push(`Cross-domain redirection to: ${finalParsed.hostname}.`);
      }
    }

    // Check if landing domain has suspicious traits (IP host or suspicious TLD)
    if (finalParsed.isIp) {
      riskScore += 40;
      reasons.push('Redirect chain terminates on raw IP address.');
    }
    if (finalParsed.isPunycode) {
      riskScore += 30;
      reasons.push('Redirect chain terminates on Punycode domain.');
    }

    // Check meta-refresh to external domain
    if (metaRefresh && metaRefresh.destination.startsWith('http')) {
      const metaP = URLParser.parse(metaRefresh.destination);
      if (metaP.domain && metaP.domain !== finalParsed.domain) {
        riskScore += 25;
        reasons.push(`Static meta-refresh targets external domain: ${metaP.hostname}.`);
      }
    }

    // Check static JS redirects to external domains
    if (inferredJsRedirects.length > 0) {
      reasons.push(`Found ${inferredJsRedirects.length} static client-side JavaScript redirect candidate(s).`);
    }

    // Classification
    riskScore = Math.min(riskScore, 59);
    // Redirect traits are investigative signals; this layer has no reputation feed
    // or content evidence capable of issuing a definitive phishing verdict.
    if (riskScore >= 25) {
      riskLevel = 'UNDER_REVIEW';
    } else {
      riskLevel = 'SAFE';
    }

    // Summary
    let summary = '';
    if (isBenignHttpsUpgrade) {
      summary = `Standard secure protocol upgrade from HTTP to HTTPS (${finalParsed.hostname}). Zero cross-domain jumps.`;
    } else if (hopsCount === 0) {
      summary = `Direct destination response without HTTP redirects (HTTP ${probeRes.statusCode || 200}).`;
    } else {
      summary = `Traced ${hopsCount} HTTP redirect hop(s) with ${crossDomainJumps} cross-domain transition(s) to ${finalParsed.hostname}.`;
    }

    return {
      status: 'SUCCESS',
      riskLevel,
      riskScore,
      hopsCount,
      initialUrl: targetUrl,
      finalUrl,
      crossDomainJumps,
      redirectChain: chain,
      inferredJsRedirects,
      metaRefresh,
      headers,
      initialResolvedIps: probeRes.initialResolvedIps || [],
      finalResolvedIps: probeRes.finalResolvedIps || [],
      latencyMs: probeRes.latencyMs || 0,
        limitations: ['The full rendered webpage was not inspected: Mode B does not launch Chromium, execute JavaScript, or load secondary resources.'],
      securityHeadersPresent,
      securityHeadersMissing,
      summary,
      reasons,
      error: null
    };
  }
}
