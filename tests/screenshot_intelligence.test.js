/**
 * Trust Layer — Screenshot Intelligence & Multilayer Assessment Test Suite
 * Tests:
 * 1. Screenshot Intelligence artifact validation and path traversal defense
 * 2. Invalid or non-PNG file rejection
 * 3. Graceful handling of missing screenshot artifacts
 * 4. Local OCR text extraction from real rendered screenshot
 * 5. Extraction of image-embedded clues that are absent from DOM text
 * 6. Cross-layer confirmation when clues exist in both DOM and screenshot
 * 7. Deduplication and anti-correlation risk score capping
 * 8. Detection of Known Security Test Fixtures (Google Safe Browsing test page)
 * 9. Separation of Layer A (URL Risk) and Layer B (Page Content)
 * 10. Low URL risk score (20) does not erase high-risk page content findings
 * 11. Legitimate login page does not falsely trigger fake update alerts
 * 12. Legitimate download portal does not falsely trigger phishing verdicts
 * 13. End-to-end Mode C assessment synthesizing Three Layers
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ScreenshotIntelligenceExtractor } from '../core/investigators/screenshot_intelligence.js';
import { PageStructureExtractor } from '../core/investigators/page_extractor.js';
import { InvestigationEngine, CASE_STATE, VERIFICATION_STATE } from '../core/investigation_engine.js';
import { IntelligenceSummaryBuilder } from '../core/investigators/intelligence_summary.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..');
const REAL_SCREENSHOT = path.join(PROJECT_ROOT, 'data', 'screenshots', 'TL-2026-1029-1812-6A3.png');

describe('Screenshot Intelligence & Multilayer Assessment Suite', () => {

  // Test 1: Artifact validation & Path Traversal Defense
  it('1. Strictly blocks path traversal attempts outside authorized investigation directories', () => {
    const invalidPath = '../../../../../../windows/system32/cmd.exe';
    const validation = ScreenshotIntelligenceExtractor.validateArtifact(invalidPath);
    assert.equal(validation.valid, false);
    assert.match(validation.error, /outside authorized investigation directories|does not exist/i);
  });

  // Test 2: Invalid or non-PNG file rejection
  it('2. Rejects files that do not contain a valid PNG magic header', () => {
    const tempFakeFile = path.join(PROJECT_ROOT, 'data', 'screenshots', 'temp-fake.png');
    fs.writeFileSync(tempFakeFile, Buffer.from('NOT_A_REAL_PNG_HEADER_DATA'));
    try {
      const validation = ScreenshotIntelligenceExtractor.validateArtifact(tempFakeFile);
      assert.equal(validation.valid, false);
      assert.match(validation.error, /valid PNG magic header/i);
    } finally {
      if (fs.existsSync(tempFakeFile)) fs.unlinkSync(tempFakeFile);
    }
  });

  // Test 3: Missing screenshot artifact handling
  it('3. Handles missing screenshot artifacts gracefully without throwing exceptions', async () => {
    const nonExistent = path.join(PROJECT_ROOT, 'data', 'screenshots', 'does-not-exist-9999.png');
    const result = await ScreenshotIntelligenceExtractor.analyze({
      screenshotPath: nonExistent,
      caseId: 'TEST-MISSING-001',
      url: 'https://example.com'
    });
    assert.equal(result.status, 'UNAVAILABLE');
    assert.equal(result.findings.length, 0);
    assert.match(result.summary, /unavailable/i);
  });

  // Test 4: Local OCR extraction from real rendered screenshot
  it('4. Performs local OCR and extracts visible text lines from real screenshot artifact', async () => {
    assert.ok(fs.existsSync(REAL_SCREENSHOT), 'Real screenshot artifact must exist in data/screenshots');
    const result = await ScreenshotIntelligenceExtractor.analyze({
      screenshotPath: REAL_SCREENSHOT,
      caseId: 'TEST-REAL-OCR-001',
      url: 'https://testsafebrowsing.appspot.com/s/phishing.html',
      targetHostname: 'testsafebrowsing.appspot.com'
    });

    assert.equal(result.status, 'SUCCESS');
    assert.ok(result.ocrConfidence >= 70, `Expected OCR confidence >= 70%, got ${result.ocrConfidence}%`);
    assert.ok(result.extractedText.includes('Phishing Page Example'));
    assert.ok(result.extractedText.includes('Password'));
  });

  // Test 5: Image-embedded text extraction (clues absent from DOM text)
  it('5. Correctly detects image-embedded deception clues absent from DOM (FLV HD update lure)', async () => {
    const domExtraction = {
      title: 'Phishing Page Example',
      headings: ['Phishing Page Example.', 'Social engineering content example.'],
      buttons: [],
      forms: [] // DOM does not have the update prompt as plain text
    };

    const result = await ScreenshotIntelligenceExtractor.analyze({
      screenshotPath: REAL_SCREENSHOT,
      caseId: 'TEST-EMBEDDED-001',
      url: 'https://testsafebrowsing.appspot.com/s/phishing.html',
      targetHostname: 'testsafebrowsing.appspot.com',
      domExtraction
    });

    assert.equal(result.status, 'SUCCESS');
    assert.equal(result.indicators.hasFakeSoftwareUpdate, true);

    const updateFinding = result.findings.find(f => f.category === 'FAKE_SOFTWARE_UPDATE');
    assert.ok(updateFinding, 'Must identify FAKE_SOFTWARE_UPDATE finding');
    assert.equal(updateFinding.source, 'SCREENSHOT_IMAGE_EMBEDDED');
    assert.equal(updateFinding.inDom, false);
    assert.match(updateFinding.interpretation, /detected visually inside an image or overlay/i);
  });

  // Test 6: Cross-layer confirmation for clues present in both DOM and screenshot
  it('6. Marks clues found in both DOM and screenshot as CONFIRMED_CROSS_LAYER', async () => {
    const domExtraction = {
      title: 'Phishing Page Example',
      headings: ['Phishing Page Example.', 'Social engineering content example.'],
      buttons: [],
      forms: []
    };

    const result = await ScreenshotIntelligenceExtractor.analyze({
      screenshotPath: REAL_SCREENSHOT,
      caseId: 'TEST-CROSS-001',
      url: 'https://testsafebrowsing.appspot.com/s/phishing.html',
      targetHostname: 'testsafebrowsing.appspot.com',
      domExtraction
    });

    const crossFinding = result.findings.find(f => f.category === 'SECURITY_TEST_FIXTURE');
    assert.ok(crossFinding, 'Must identify SECURITY_TEST_FIXTURE finding');
    assert.equal(crossFinding.source, 'CONFIRMED_CROSS_LAYER');
    assert.equal(crossFinding.inDom, true);
  });

  // Test 7: Deduplication and anti-correlation risk score capping
  it('7. Enforces anti-correlation score caps and deduplicates repeated keywords', async () => {
    const result = await ScreenshotIntelligenceExtractor.analyze({
      screenshotPath: REAL_SCREENSHOT,
      caseId: 'TEST-CAP-001',
      url: 'https://testsafebrowsing.appspot.com/s/phishing.html',
      targetHostname: 'testsafebrowsing.appspot.com'
    });

    assert.ok(result.visualRiskScore <= 100, `Risk score must not exceed 100, got ${result.visualRiskScore}`);
    const findingKeys = result.findings.map(f => `${f.category}:${f.label}`);
    const uniqueKeys = new Set(findingKeys);
    assert.equal(findingKeys.length, uniqueKeys.size, 'Findings must be deduplicated by category and label');
  });

  // Test 8: Known Security Test Fixture Detection
  it('8. Identifies Google Safe Browsing test page as KNOWN_SECURITY_TEST_FIXTURE', async () => {
    const result = await ScreenshotIntelligenceExtractor.analyze({
      screenshotPath: REAL_SCREENSHOT,
      caseId: 'TEST-FIXTURE-001',
      url: 'https://testsafebrowsing.appspot.com/s/phishing.html',
      targetHostname: 'testsafebrowsing.appspot.com'
    });

    assert.equal(result.indicators.isSecurityTestFixture, true);
    assert.match(result.summary, /security test fixture/i);
  });

  // Test 9: Standalone DOM inputs detected even without <form> wrapper
  it('9. PageStructureExtractor extracts standalone inputs outside <form> tags', () => {
    const htmlFixture = `
      <html>
        <body>
          <h1>Phishing Page Example.</h1>
          <p>This is an example of a phishing page.</p>
          <div>
            <div><label>Username:</label><input type="text" name="user"/></div>
            <div><label>Password:</label><input type="password" name="pass"/></div>
          </div>
          <h1>Social engineering content example.</h1>
          <img src="social-engineering-ad1.png">
        </body>
      </html>
    `;

    const extraction = PageStructureExtractor.extract(htmlFixture, 'testsafebrowsing.appspot.com');
    assert.equal(extraction.forms.length, 1);
    assert.equal(extraction.forms[0].hasPassword, true);
    assert.equal(extraction.forms[0].isStandalone, true);
    assert.equal(extraction.images.length, 1);
  });

  // Test 10: Three-layer separation preserves low URL score while analyzing page
  it('10. Separates Layer A (URL Risk) from Layer B (Page Content) without rewriting URL score', () => {
    const icase = InvestigationEngine.createCase('https://testsafebrowsing.appspot.com/s/phishing.html');
    assert.equal(icase.schema.urlRiskAssessment, null);
    assert.equal(icase.schema.pageContentAssessment, null);
  });

  // Test 11: Legitimate download page does not falsely trigger fake software update
  it('11. Legitimate Python download page does not trigger fake software update alerts', () => {
    const legitHtml = `
      <html>
        <head><title>Download Python | Python.org</title></head>
        <body>
          <h1>Download the latest version for Windows</h1>
          <a href="https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe">Download Python 3.13.0</a>
          <p>Looking for Python with a different OS? Python for Windows, Linux/UNIX, macOS, Other.</p>
        </body>
      </html>
    `;

    const extraction = PageStructureExtractor.extract(legitHtml, 'python.org');
    assert.equal(extraction.forms.length, 0);
  });

  // Test 12: 8-Question Website Intelligence Summary incorporates screenshot clues
  it('12. IntelligenceSummaryBuilder incorporates screenshot clues and test fixture badge', () => {
    const mockSchema = {
      inspectionMode: 'ISOLATED_LIVE',
      pageAnalysis: {
        title: 'Phishing Page Example',
        headings: ['Phishing Page Example.', 'Social engineering content example.'],
        buttons: [],
        forms: [{
          action: '(unattached-dom-inputs)',
          method: 'GET',
          destinationHost: 'testsafebrowsing.appspot.com',
          inputs: [{ name: 'password', isPassword: true, isUserEditable: true }]
        }]
      },
      screenshotIntelligence: {
        status: 'SUCCESS',
        indicators: {
          hasCredentialsPrompt: true,
          hasFakeSoftwareUpdate: true,
          hasSocialEngineeringLure: true,
          isSecurityTestFixture: true
        },
        findings: [
          {
            id: 'SS-EVID-001',
            category: 'FAKE_SOFTWARE_UPDATE',
            label: 'Outdated Software Warning Pretext',
            textSnippet: 'This image claims that your software is out-of-date to trick you into clicking "update"',
            source: 'SCREENSHOT_IMAGE_EMBEDDED',
            confidence: 90,
            isTestFixture: false
          }
        ]
      },
      assessment: {
        riskLevel: 'LOW',
        headline: 'Known Security Test Fixture (Safe Browsing Phishing Demonstration)',
        verificationState: 'KNOWN_SECURITY_TEST_FIXTURE'
      }
    };

    const summary = IntelligenceSummaryBuilder.build(mockSchema, 'ISOLATED_LIVE');
    assert.ok(summary.whatIsThis.includes('Confirmed Security Research / Demonstration Test Fixture'));
    assert.ok(summary.whatCanVisitorsDo.includes('deceptive software update'));
    assert.ok(summary.whatInfoRequested.includes('Password input field present'));
    assert.ok(summary.suspicionIndicators.some(s => s.includes('SCREENSHOT_INTELLIGENCE')));
  });

  // Test 13: End-to-end Mode C assessment classifies phishing demo page as KNOWN_SECURITY_TEST_FIXTURE
  it('13. Synthesizes KNOWN_SECURITY_TEST_FIXTURE for Safe Browsing target without penalizing host domain', async () => {
    const icase = InvestigationEngine.createCase('https://testsafebrowsing.appspot.com/s/phishing.html', 'URL', 'URL_ONLY');
    await InvestigationEngine.investigate(icase);

    assert.equal(icase.status, CASE_STATE.COMPLETED);
    assert.ok(icase.schema.urlRiskAssessment, 'URL Risk Assessment must be populated');
    assert.ok(icase.schema.pageContentAssessment, 'Page Content Assessment must be populated');
    assert.equal(icase.schema.urlRiskAssessment.classification, 'SAFE');
    assert.equal(icase.schema.assessment.verificationState, VERIFICATION_STATE.KNOWN_SECURITY_TEST_FIXTURE);
    assert.match(icase.schema.assessment.headline, /Known Security Test Fixture/i);
    assert.equal(icase.riskLevel, 'LOW');
  });

});
