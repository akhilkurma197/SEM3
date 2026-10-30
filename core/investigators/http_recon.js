/**
 * Trust Layer — Bounded HTTP reconnaissance through the controlled egress proxy.
 * Redirects are followed manually, with preflight and connection-time destination
 * validation on each hop. No browser or secondary resource loading is performed.
 */

import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { SSRFGuard } from './ssrf_guard.js';
import { ControlledEgressProxy } from './egress_proxy.js';

const MAX_RESPONSE_BYTES = 250000;
const SAFE_HOP_HEADERS = [
  'cache-control', 'content-length', 'content-security-policy', 'content-type', 'date',
  'location', 'last-modified', 'server', 'strict-transport-security', 'via',
  'x-content-type-options', 'x-frame-options', 'x-redirect-by'
];

function selectedHeaders(headers = {}) {
  const result = {};
  for (const name of SAFE_HOP_HEADERS) {
    if (headers[name] !== undefined) result[name] = headers[name];
  }
  return result;
}

function requestViaProxy(targetUrl, proxyAddress, timeoutMs, maxBytes) {
  const target = new URL(targetUrl);
  const proxy = new URL(proxyAddress);
  return new Promise((resolve, reject) => {
    let timer;
    let settled = false;
    const fail = error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };
    const finishResponse = (request, response) => {
      clearTimeout(timer);
      let bytes = 0;
      let truncated = false;
      const chunks = [];
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({
          status: response.statusCode,
          statusText: response.statusMessage,
          headers: response.headers,
          body: Buffer.concat(chunks).toString('utf8'),
          truncated
        });
      };
      timer = setTimeout(() => request.destroy(new Error(`Connection timed out after ${timeoutMs}ms`)), timeoutMs);
      response.on('data', chunk => {
        if (settled) return;
        const buffer = Buffer.from(chunk);
        const remaining = maxBytes - bytes;
        if (buffer.length > remaining) {
          if (remaining > 0) chunks.push(buffer.subarray(0, remaining));
          bytes = maxBytes;
          truncated = true;
          finish();
          response.destroy();
          request.destroy();
          return;
        }
        chunks.push(buffer);
        bytes += buffer.length;
      });
      response.on('end', finish);
      response.on('close', finish);
      response.on('error', error => truncated ? finish() : fail(error));
      request.on('error', error => truncated ? finish() : fail(error));
    };

    if (target.protocol === 'http:') {
      const request = http.request({
        hostname: proxy.hostname,
        port: proxy.port,
        method: 'GET',
        path: target.href,
        headers: {
          host: target.host,
          'user-agent': 'TrustLayer-Redirect-Tracer/1.0 (read-only; controlled egress)',
          connection: 'close'
        }
      }, response => finishResponse(request, response));
      request.on('error', fail);
      timer = setTimeout(() => request.destroy(new Error(`Connection timed out after ${timeoutMs}ms`)), timeoutMs);
      request.end();
      return;
    }

    if (target.protocol !== 'https:') {
      fail(new Error(`Unsupported URL scheme: ${target.protocol}`));
      return;
    }

    const port = Number(target.port || 443);
    const connectRequest = http.request({
      hostname: proxy.hostname,
      port: proxy.port,
      method: 'CONNECT',
      path: `${target.hostname}:${port}`,
      headers: { host: `${target.hostname}:${port}` }
    });
    timer = setTimeout(() => connectRequest.destroy(new Error(`Connection timed out after ${timeoutMs}ms`)), timeoutMs);
    connectRequest.on('connect', (connectResponse, socket, head) => {
      if (connectResponse.statusCode !== 200) {
        socket.destroy();
        const error = new Error(`Controlled egress proxy refused HTTPS tunnel (HTTP ${connectResponse.statusCode})`);
        error.blocked = connectResponse.statusCode === 403;
        fail(error);
        return;
      }
      if (head?.length) socket.unshift(head);
      const secureSocket = tls.connect({
        socket,
        servername: target.hostname,
        rejectUnauthorized: true,
        ALPNProtocols: ['http/1.1']
      });
      secureSocket.once('secureConnect', () => {
        const request = https.request({
          hostname: target.hostname,
          port,
          path: `${target.pathname}${target.search}`,
          method: 'GET',
          agent: false,
          createConnection: () => secureSocket,
          headers: {
            host: target.host,
            'user-agent': 'TrustLayer-Redirect-Tracer/1.0 (read-only; controlled egress)',
            connection: 'close'
          }
        }, response => finishResponse(request, response));
        request.on('error', fail);
        request.end();
      });
      secureSocket.once('error', fail);
    });
    connectRequest.on('error', fail);
    connectRequest.end();
  });
}

function makeResult(overrides) {
  return {
    status: 'FAILED',
    statusCode: null,
    statusText: null,
    initialUrl: null,
    finalUrl: null,
    redirectCount: 0,
    redirectChain: [],
    latencyMs: 0,
    headers: {},
    contentType: '',
    bodySnippet: null,
    initialResolvedIps: [],
    finalResolvedIps: [],
    error: null,
    ...overrides
  };
}

export class HTTPReconInvestigator {
  /**
   * Performs a bounded read-only GET trace. Every connection passes through the
   * controlled egress proxy; redirects are manually validated before following.
   */
  static async probe(targetUrl, options = {}) {
    const timeoutMs = options.timeoutMs || 4000;
    const maxHops = options.maxHops || 10;
    const maxBytes = Math.min(options.maxBytes || MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES);
    const maxTotalMs = options.maxTotalMs || 15000;
    const startTime = Date.now();
    const deadline = startTime + maxTotalMs;
    const chain = [];
    const initialResult = makeResult({ initialUrl: targetUrl, finalUrl: targetUrl });
    let currentUrl = targetUrl;
    let lastReachableUrl = null;
    let currentGuard;
    let proxy;

    try {
      currentGuard = await SSRFGuard.validateAndResolve(currentUrl, { _testBypassSsrf: options._testBypassSsrf });
      if (!currentGuard.allowed) {
        return makeResult({
          ...initialResult,
          status: 'BLOCKED',
          finalUrl: null,
          error: `SSRF blocked: ${currentGuard.blockedReason}`,
          initialResolvedIps: currentGuard.resolvedIps || [],
          finalResolvedIps: currentGuard.resolvedIps || []
        });
      }

      proxy = new ControlledEgressProxy({
        allowedPorts: options.allowedPorts || [80, 443],
        _testBypassSsrf: options._testBypassSsrf === true
      });
      const proxyInfo = await proxy.start();
      const visited = new Set();
      let finalResponse = null;
      let redirectCount = 0;
      let blockedReason = null;
      let failure = null;
      const initialResolvedIps = currentGuard.resolvedIps || [];

      while (chain.length < maxHops) {
        const remainingMs = deadline - Date.now();
        if (remainingMs <= 0) {
          failure = `Total HTTP trace time budget exceeded (${maxTotalMs}ms)`;
          break;
        }
        if (visited.has(currentUrl)) {
          failure = `Circular redirect loop detected on ${currentUrl}`;
          break;
        }
        visited.add(currentUrl);

        const hopStart = Date.now();
        let response;
        try {
          response = await requestViaProxy(currentUrl, proxyInfo.proxyUrl, Math.min(timeoutMs, remainingMs), maxBytes);
        } catch (error) {
          failure = error.message;
          if (error.blocked) blockedReason = error.message;
          chain.push({
            hop: chain.length + 1, fromUrl: currentUrl, toUrl: currentUrl, method: 'GET',
            status: null, location: null, latencyMs: Date.now() - hopStart,
            timestamp: Date.now(), headers: {}, resolvedIps: currentGuard.resolvedIps || [],
            blocked: Boolean(error.blocked), blockedReason: error.blocked ? error.message : null,
            error: error.blocked ? null : error.message, isFinal: false
          });
          break;
        }
        const hopLatency = Date.now() - hopStart;
        const connectedTarget = new URL(currentUrl);
        const egressRequestKey = connectedTarget.protocol === 'https:'
          ? `${connectedTarget.hostname}:${connectedTarget.port || 443}`
          : connectedTarget.href;
        const egressObservation = [...proxy.allowedRequests].reverse().find(entry => entry.url === egressRequestKey) || null;
        const connectedIp = egressObservation?.targetIp || null;
        const policyHeader = response.headers['x-trustlayer-egress-policy'] || '';
        const proxyPolicy = policyHeader.startsWith(`${proxy._policyToken}:`) ? policyHeader.slice(proxy._policyToken.length + 1) : null;
        if (response.status === 403 && proxyPolicy && proxyPolicy !== 'METHOD_BLOCKED') {
          blockedReason = (response.body.match(/Egress Proxy Blocked:[^"}]*/i) || [])[0] || 'Connection-time egress policy rejected this hop.';
          chain.push({
            hop: chain.length + 1, fromUrl: currentUrl, toUrl: currentUrl, method: 'GET',
            status: null, policyStatus: 403, location: null, latencyMs: hopLatency,
            timestamp: Date.now(), headers: {}, resolvedIps: currentGuard.resolvedIps || [],
            blocked: true, blockedReason, isFinal: false
          });
          break;
        }
        if (response.status === 502 && proxyPolicy === 'UPSTREAM_FAILED') {
          failure = (response.body.match(/Upstream connection failed:[^"}]*/i) || [])[0] || 'The egress proxy could not connect to the validated destination.';
          chain.push({
            hop: chain.length + 1, fromUrl: currentUrl, toUrl: currentUrl, method: 'GET',
            status: null, policyStatus: 502, location: null, latencyMs: hopLatency,
            timestamp: Date.now(), headers: {}, resolvedIps: currentGuard.resolvedIps || [],
            blocked: false, blockedReason: failure, isFinal: false
          });
          break;
        }
        const headers = Object.fromEntries(Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v]));
        lastReachableUrl = currentUrl;
        const location = headers.location || null;
        const isRedirect = response.status >= 300 && response.status < 400 && Boolean(location);

        if (isRedirect) {
          redirectCount++;
          let destination;
          try {
            destination = new URL(location, currentUrl).href;
          } catch {
            chain.push({
              hop: chain.length + 1,
              fromUrl: currentUrl,
              toUrl: location,
              method: 'GET',
              status: response.status,
              statusText: response.statusText,
              location,
              latencyMs: hopLatency,
              timestamp: Date.now(),
              headers: selectedHeaders(headers),
              resolvedIps: currentGuard.resolvedIps || [],
              blocked: true,
              blockedReason: 'Invalid redirect destination URL',
              isFinal: false
            });
            blockedReason = 'Invalid redirect destination URL';
            break;
          }

          const destinationGuard = await SSRFGuard.validateAndResolve(destination, {
            _testBypassSsrf: options._testBypassSsrf
          });
          const hop = {
            hop: chain.length + 1,
            fromUrl: currentUrl,
            toUrl: destination,
            method: 'GET',
            status: response.status,
            statusText: response.statusText,
            location,
            latencyMs: hopLatency,
            timestamp: Date.now(),
            headers: selectedHeaders(headers),
            resolvedIps: currentGuard.resolvedIps || [],
            connectedIp,
            destinationResolvedIps: destinationGuard.resolvedIps || [],
            blocked: !destinationGuard.allowed,
            blockedReason: destinationGuard.allowed ? null : destinationGuard.blockedReason,
            isFinal: false
          };
          chain.push(hop);
          if (!destinationGuard.allowed) {
            blockedReason = `Redirect destination blocked by SSRF policy: ${destinationGuard.blockedReason}`;
            break;
          }

          currentUrl = destination;
          currentGuard = destinationGuard;
          continue;
        }

        finalResponse = response;
        chain.push({
          hop: chain.length + 1,
          fromUrl: currentUrl,
          toUrl: currentUrl,
          method: 'GET',
          status: response.status,
          statusText: response.statusText,
          location: null,
          latencyMs: hopLatency,
          timestamp: Date.now(),
          headers: selectedHeaders(headers),
          resolvedIps: currentGuard.resolvedIps || [],
          connectedIp,
          blocked: false,
          blockedReason: null,
          isFinal: true
        });
        break;
      }

      if (!finalResponse && !failure && !blockedReason && chain.length >= maxHops) {
        failure = `Redirect limit reached (${maxHops} hops)`;
      }

      const totalMs = Date.now() - startTime;
      if (blockedReason) {
        return makeResult({
          ...initialResult,
          status: 'BLOCKED',
          finalUrl: lastReachableUrl,
          redirectCount,
          redirectChain: chain,
          latencyMs: totalMs,
          initialResolvedIps,
          finalResolvedIps: lastReachableUrl === currentUrl ? (currentGuard?.resolvedIps || []) : [],
          error: blockedReason
        });
      }
      if (failure || !finalResponse) {
        return makeResult({
          ...initialResult,
          status: 'FAILED',
          statusCode: chain.at(-1)?.status || null,
          statusText: chain.at(-1)?.statusText || null,
          finalUrl: lastReachableUrl,
          redirectCount,
          redirectChain: chain,
          latencyMs: totalMs,
          initialResolvedIps,
          finalResolvedIps: lastReachableUrl === currentUrl ? (currentGuard?.resolvedIps || []) : [],
          error: failure || 'No final HTTP response was received.'
        });
      }

      const finalHeaders = Object.fromEntries(Object.entries(finalResponse.headers).map(([k, v]) => [k.toLowerCase(), v]));
      const contentType = finalHeaders['content-type'] || '';
      const bodySnippet = /text|json|html|xml/i.test(contentType) || !contentType ? finalResponse.body : null;
      return makeResult({
        ...initialResult,
        status: 'SUCCESS',
        statusCode: finalResponse.status,
        statusText: finalResponse.statusText,
        finalUrl: lastReachableUrl,
        redirectCount,
        redirectChain: chain,
        latencyMs: totalMs,
        headers: selectedHeaders(finalHeaders),
        contentType,
        bodySnippet,
        responseTruncated: finalResponse.truncated,
        initialResolvedIps,
        finalResolvedIps: currentGuard?.resolvedIps || [],
        error: null
      });
    } catch (error) {
      return makeResult({
        ...initialResult,
        status: 'FAILED',
        finalUrl: lastReachableUrl,
        redirectChain: chain,
        latencyMs: Date.now() - startTime,
        error: error.message
      });
    } finally {
      if (proxy) await proxy.stop().catch(() => {});
    }
  }
}
