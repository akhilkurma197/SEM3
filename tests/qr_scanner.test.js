/**
 * Trust Layer — QR Scanner & Routing Regression Suite
 * Verifies QR decoding, payload extraction, and URL routing logic.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { QREngine } from '../core/investigators/qr_engine.js';
import { QRGuardian } from '../core/qr_guardian.js';

describe('QR Scanner & Intent Routing Suite', () => {

  it('correctly classifies web URL payloads and extracts target URL', () => {
    const res = QREngine.analyzePayload('https://secure-login.bank-update.xyz/auth');
    assert.equal(res.type, 'URL');
    assert.equal(res.target, 'https://secure-login.bank-update.xyz/auth');
    assert.equal(res.claimedIdentity, 'secure-login.bank-update.xyz');
  });

  it('correctly handles URLs missing http prefix and normalizes them', () => {
    const res = QREngine.analyzePayload('www.google.com/search?q=test');
    assert.equal(res.type, 'URL');
    assert.ok(res.target.includes('google.com'));
  });

  it('correctly identifies UPI payment traps with reverse debit notes', () => {
    const res = QREngine.analyzePayload('upi://pay?pa=scammer.refund@okaxis&pn=Refund%20Dept&am=25000&tn=Claim%20Cashback');
    assert.equal(res.type, 'UPI');
    assert.equal(res.isSuspicious, true);
    assert.ok(res.anomalies.some(a => a.toLowerCase().includes('reverse debit')));
  });

  it('correctly extracts embedded URLs from vCard contact cards', async () => {
    const vcard = 'BEGIN:VCARD\nVERSION:3.0\nFN:Support Desk\nTEL:+919876543210\nURL:http://hdfc-netbanking-verify.xyz/login.php\nEND:VCARD';
    const parsed = await QRGuardian.parseVCard(vcard);
    assert.equal(parsed.embeddedUrl, 'http://hdfc-netbanking-verify.xyz/login.php');
    assert.equal(parsed.name, 'Support Desk');
  });

  it('identifies unencrypted open Wi-Fi traps', () => {
    const res = QREngine.analyzePayload('WIFI:S:Free_Airport_WiFi;T:nopass;;');
    assert.equal(res.type, 'WIFI');
    assert.equal(res.isSuspicious, true);
    assert.ok(res.anomalies.some(a => a.toLowerCase().includes('unencrypted')));
  });

  it('decodes controlled QR sample vectors without throwing', async () => {
    const phish = await QRGuardian.scanAndAnalyzeQR('sample-phishing-qr');
    assert.equal(phish.success, true);
    assert.equal(phish.payloadType, 'URL');
    assert.ok(phish.linkAnalysis);

    const upi = await QRGuardian.scanAndAnalyzeQR('sample-upi-qr');
    assert.equal(upi.success, true);
    assert.equal(upi.payloadType, 'UPI_PAYMENT');
    assert.equal(upi.upiData.isSuspicious, true);
  });
});
