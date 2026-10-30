/**
 * Trust Layer — Controlled Egress Proxy v1.0
 * Enforces strict network boundaries on worker outbound traffic:
 * 1. Blocks all non-public, loopback, private, link-local, and metadata destinations.
 * 2. Pinning: Connects directly to pre-validated IP addresses to prevent DNS rebinding.
 * 3. Default-deny ports: Permits only approved web destination ports (80, 443).
 * 4. Method restriction: Intercepts and blocks state-mutating requests (POST, PUT, DELETE, PATCH).
 * 5. Transparent HTTPS CONNECT tunneling with destination address validation.
 */

import http from 'node:http';
import net from 'node:net';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { URL } from 'node:url';
import { SSRFGuard } from './ssrf_guard.js';

export class ControlledEgressProxy {
  constructor(options = {}) {
    this.allowedPorts = new Set(options.allowedPorts || [80, 443]);
    this._testBypassSsrf = options._testBypassSsrf || false;
    this._policyToken = randomUUID();
    this.requireAuth = options.requireAuth === true;
    this.username = this.requireAuth ? (options.username || randomUUID()) : null;
    this.password = this.requireAuth ? (options.password || randomUUID()) : null;
    this._authorization = this.requireAuth
      ? `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`
      : null;
    this.blockedRequests = [];
    this.allowedRequests = [];
    this.server = null;
    this.port = Number.isInteger(options.port) ? options.port : null;
    this.host = options.host || '127.0.0.1';
  }

  /**
   * Start the proxy server on an ephemeral loopback port.
   * @returns {Promise<{ host: string, port: number, proxyUrl: string }>}
   */
  async start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => this._handleHttpRequest(req, res));
      this.server.on('connect', (req, clientSocket, head) => this._handleHttpsConnect(req, clientSocket, head));

      this.server.on('error', (err) => {
        reject(err);
      });

      this.server.listen(this.port || 0, this.host, () => {
        const addr = this.server.address();
        this.port = addr.port;
        resolve({
          host: this.host,
          port: this.port,
          proxyUrl: `http://${this.host}:${this.port}`,
          username: this.username,
          password: this.password
        });
      });
    });
  }

  /**
   * Handle cleartext HTTP proxy requests
   */
  async _handleHttpRequest(req, res) {
    const startTime = Date.now();

    if (!this._isAuthorized(req.headers['proxy-authorization'])) {
      res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="TrustLayer Egress"' });
      res.end('Proxy authentication required');
      return;
    }

    // 1. Method restriction (Observation Mode Only — no state-changing operations)
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const blockedItem = {
        time: new Date().toISOString(),
        method: req.method,
        url: req.url,
        reason: `Disallowed HTTP method ${req.method} — Inspection is read-only (GET/HEAD permitted).`,
        type: 'MUTATING_REQUEST_BLOCKED'
      };
      this.blockedRequests.push(blockedItem);
      res.writeHead(405, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:METHOD_BLOCKED` });
      res.end(JSON.stringify({ error: blockedItem.reason }));
      return;
    }

    let targetUrl;
    try {
      targetUrl = new URL(req.url);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Malformed proxy request URL' }));
      return;
    }

    // 2. Port check
    const port = targetUrl.port ? parseInt(targetUrl.port, 10) : (targetUrl.protocol === 'https:' ? 443 : 80);
    if (!this.allowedPorts.has(port)) {
      const blockedItem = {
        time: new Date().toISOString(),
        method: req.method,
        url: req.url,
        reason: `Port ${port} blocked by egress policy (allowed: ${Array.from(this.allowedPorts).join(', ')})`,
        type: 'PORT_DISALLOWED'
      };
      this.blockedRequests.push(blockedItem);
      res.writeHead(403, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:PORT_BLOCKED` });
      res.end(JSON.stringify({ error: blockedItem.reason }));
      return;
    }

    // 3. Pre-connection destination validation with SSRFGuard
    const validation = await SSRFGuard.validateAndResolve(targetUrl.href, { _testBypassSsrf: this._testBypassSsrf });
    if (!validation.allowed) {
      const blockedItem = {
        time: new Date().toISOString(),
        method: req.method,
        url: req.url,
        reason: validation.blockedReason,
        type: 'SSRF_BLOCKED'
      };
      this.blockedRequests.push(blockedItem);
      res.writeHead(403, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:DESTINATION_BLOCKED` });
      res.end(JSON.stringify({ error: `Egress Proxy Blocked: ${validation.blockedReason}` }));
      return;
    }

    const targetIp = validation.connectAddress || validation.resolvedIps[0] || targetUrl.hostname;

    // 4. Forward request to pinned IP
    const forwardOptions = {
      host: targetIp,
      port,
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers: {
        ...req.headers,
        host: targetUrl.host
      }
    };

    const upstreamReq = http.request(forwardOptions, (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
      upstreamRes.pipe(res);
      this.allowedRequests.push({
        time: new Date().toISOString(),
        method: req.method,
        url: targetUrl.href,
        status: upstreamRes.statusCode,
        targetIp,
        resolvedIps: validation.resolvedIps,
        destinationHost: targetUrl.hostname,
        durationMs: Date.now() - startTime
      });
    });

    upstreamReq.on('error', (err) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:UPSTREAM_FAILED` });
        res.end(JSON.stringify({ error: `Upstream connection failed: ${err.message}` }));
      }
    });

    req.pipe(upstreamReq);
  }

  /**
   * Handle HTTPS CONNECT tunneling
   */
  async _handleHttpsConnect(req, clientSocket, head) {
    const startTime = Date.now();
    if (!this._isAuthorized(req.headers['proxy-authorization'])) {
      clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="TrustLayer Egress"\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    const [rawHost, portStr] = req.url.split(':');
    const port = parseInt(portStr, 10) || 443;

    // 1. Destination port check
    if (!this.allowedPorts.has(port)) {
      this.blockedRequests.push({
        time: new Date().toISOString(),
        method: 'CONNECT',
        url: req.url,
        reason: `Port ${port} blocked by egress policy`,
        type: 'PORT_DISALLOWED'
      });
      clientSocket.write('HTTP/1.1 403 Forbidden (Non-Approved Egress Port)\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    // 2. Pre-connection IP validation via SSRFGuard
    const validation = await SSRFGuard.validateAndResolve(`https://${rawHost}:${port}/`, { _testBypassSsrf: this._testBypassSsrf });
    if (!validation.allowed) {
      this.blockedRequests.push({
        time: new Date().toISOString(),
        method: 'CONNECT',
        url: req.url,
        reason: validation.blockedReason,
        type: 'SSRF_BLOCKED'
      });
      clientSocket.write(`HTTP/1.1 403 Forbidden (SSRF Blocked: ${validation.blockedReason})\r\n\r\n`);
      clientSocket.destroy();
      return;
    }

    // 3. Connect to validated IP to enforce connection-time DNS pinning
    const targetIp = validation.connectAddress || validation.resolvedIps[0] || rawHost;
    const upstreamSocket = net.connect(port, targetIp, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length > 0) {
        upstreamSocket.write(head);
      }
      upstreamSocket.pipe(clientSocket);
      clientSocket.pipe(upstreamSocket);

      this.allowedRequests.push({
        time: new Date().toISOString(),
        method: 'CONNECT',
        url: req.url,
        targetIp,
        destinationHost: rawHost,
        resolvedIps: validation.resolvedIps,
        durationMs: Date.now() - startTime,
        status: 200
      });
    });

    upstreamSocket.on('error', () => {
      clientSocket.destroy();
    });

    clientSocket.on('error', () => {
      upstreamSocket.destroy();
    });
  }

  _isAuthorized(value) {
    if (!this.requireAuth) return true;
    if (typeof value !== 'string' || !this._authorization || value.length !== this._authorization.length) return false;
    return timingSafeEqual(Buffer.from(value), Buffer.from(this._authorization));
  }

  /**
   * Stop the proxy server.
   */
  async stop() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}
