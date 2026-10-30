import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { RedirectTracer } from '../core/investigators/redirect_tracer.js';

describe('Mode B redirect trace', () => {
  it('reports real HTTP redirect and final response observations from a controlled fixture server', async () => {
    const server = http.createServer((req, res) => {
      if (req.url === '/begin') {
        res.writeHead(302, { Location: '/landing', 'X-Redirect-Source': 'controlled-fixture' });
        res.end();
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Frame-Options': 'DENY',
        Server: 'trust-layer-controlled-fixture'
      });
      res.end('<!doctype html><title>Observed Landing</title><h1>Fixture destination</h1>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    try {
      const initialUrl = `http://127.0.0.1:${address.port}/begin`;
      const result = await RedirectTracer.trace(initialUrl, {
        _testBypassSsrf: true,
        timeoutMs: 1500,
        maxTotalMs: 5000,
        maxHops: 4,
        allowedPorts: [address.port]
      });
      if (process.env.TRUSTLAYER_PRINT_MODE_B_RESULT === '1') {
        console.log(JSON.stringify({
          status: result.status,
          initialUrl: result.initialUrl,
          finalUrl: result.finalUrl,
          hops: result.redirectChain.map(hop => ({
            hop: hop.hop,
            status: hop.status,
            location: hop.location,
            connectedIp: hop.connectedIp || null,
            destinationResolvedIps: hop.destinationResolvedIps || [],
            latencyMs: hop.latencyMs,
            headers: hop.headers,
            outcome: hop.isFinal ? 'FINAL_RESPONSE' : (hop.blocked ? 'BLOCKED' : 'REDIRECT_FOLLOWED')
          })),
          responseHeaders: result.headers,
          limitations: result.limitations
        }, null, 2));
      }

      assert.equal(result.status, 'SUCCESS');
      assert.equal(result.initialUrl, initialUrl);
      assert.equal(result.finalUrl, `http://127.0.0.1:${address.port}/landing`);
      assert.equal(result.hopsCount, 1);
      assert.equal(result.redirectChain.length, 2);
      assert.equal(result.redirectChain[0].status, 302);
      assert.equal(result.redirectChain[0].location, '/landing');
      assert.equal(result.redirectChain[0].toUrl, result.finalUrl);
      assert.equal(result.redirectChain[1].status, 200);
      assert.equal(result.redirectChain[1].isFinal, true);
      assert.equal(result.headers['x-frame-options'], 'DENY');
      assert.ok(result.latencyMs >= 0);
      assert.match(result.limitations.join(' '), /full rendered webpage was not inspected/i);
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
  });

  it('does not classify policy blocks as phishing or as a clean result', async () => {
    const result = await RedirectTracer.trace('http://127.0.0.1/private');
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.riskLevel, 'UNKNOWN');
    assert.equal(result.riskScore, 0);
    assert.match(result.error, /loopback|blocked/i);
  });
});
