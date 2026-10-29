/**
 * Trust Layer — Investigation Engine Unit Test Suite v2.1
 * Tests the refactored, single-source-of-truth case schema and intelligence pipeline.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { InvestigationEngine, CASE_STATE, EVIDENCE_PROVENANCE } from './investigation_engine.js';
import { URLFeatureExtractor } from './ml/url_features.js';

describe('Investigation Engine Core Tests', () => {

  it('generates well-formatted case IDs', () => {
    const caseId = InvestigationEngine.generateCaseId();
    assert.match(caseId, /^TL-\d{4}-\d{4}-\d{4}-[A-Z0-9]{3}$/);
  });

  it('creates an investigation case with correct initial state', () => {
    const icase = InvestigationEngine.createCase('https://example.com');
    assert.equal(icase.status, CASE_STATE.CREATED);
    assert.equal(icase.evidence.length, 0);
  });

  it('blocks private IP SSRF attempt (192.168.1.1)', async () => {
    const icase = InvestigationEngine.createCase('http://192.168.1.1/banking/login');
    await InvestigationEngine.investigate(icase);

    assert.equal(icase.status, CASE_STATE.BLOCKED);
    assert.ok(icase.evidence.some(e => e.title.includes('SSRF')));
  });

  it('investigates HDFC impersonation vector with full evidence & breakpoints', async () => {
    const icase = InvestigationEngine.createCase('http://hdfc-netbanking-verify.xyz/login.php?verify=1');
    await InvestigationEngine.investigate(icase);

    assert.equal(icase.status, CASE_STATE.COMPLETED);
    assert.equal(icase.isDemo, true);
    assert.equal(icase.riskLevel, 'CRITICAL');
    assert.ok(icase.evidence.length >= 4, `Expected >= 4 evidence items, got ${icase.evidence.length}`);
    
    // Check Evidence IDs
    const e1 = icase.evidence[0];
    assert.equal(e1.id, 'E-001');

    // Check Trust Breakpoints
    assert.ok(icase.trustBreakpoint.length >= 1, 'Should detect trust breakpoints');
    assert.ok(icase.trustBreakpoint.some(bp => bp.type === 'IDENTITY_DISCONTINUITY' || bp.type === 'EXTERNAL_CREDENTIAL_EXFILTRATION'));

    // Check Attack Story
    assert.ok(icase.attackStory.length >= 2, 'Attack story should have multi-step breakdown');

    // Check Deception Path
    assert.ok(icase.deceptionPath.perceived.length > 0);
    assert.ok(icase.deceptionPath.actual.length > 0);
  });

  it('correctly validates official trusted domains (google.com)', async () => {
    const icase = InvestigationEngine.createCase('https://www.google.com');
    await InvestigationEngine.investigate(icase);

    assert.equal(icase.status, CASE_STATE.COMPLETED);
    assert.equal(icase.riskLevel, 'LOW');
    assert.equal(icase.schema.assessment.verificationState, 'EVIDENCE_SUFFICIENT');
  });

  it('detects homoglyph spoofing characters via feature extractor', () => {
    const ext = URLFeatureExtractor.extract('http://pаypal-security-update.top/account/verify');
    assert.equal(ext.extractionStatus, 'SUCCESS');
    assert.equal(ext.features.has_homoglyphs, 1);
  });

});
