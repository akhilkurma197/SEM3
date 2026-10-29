/**
 * Trust Layer — Page Intent ML Accuracy Regression Test Suite
 * Validates the 5 target homepages to verify that:
 * 1. Google is classified as SEARCH (not ACCOUNT_CREATION).
 * 2. Wikipedia is classified as CONTENT_READING / SEARCH (no false alarms).
 * 3. Python.org is classified as HOMEPAGE_PORTAL (available download links do not make it DOWNLOAD).
 * 4. MDN Web Docs is classified as DOCUMENTATION (not DOWNLOAD at 98.8%).
 * 5. GitHub is classified as DEVELOPER_PLATFORM (not DOWNLOAD at 58.5%).
 * 6. Analytics/tracking parameters (utm_*, fbclid) are isolated without distorting analysis.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PageStructureExtractor } from '../core/investigators/page_extractor.js';
import { PageIntentEngine, PAGE_INTENT } from '../core/ml/page_intent_engine.js';
import { PageIntentClassifier } from '../core/ml/page_intent_classifier.js';
import { URLParser } from '../core/ml/url_parser.js';

describe('Page Intent ML Accuracy — 5 Target Homepage Regressions', () => {

  it('1. Google Homepage: classified as SEARCH (NOT ACCOUNT_CREATION) with system params filtered', () => {
    // Realistic representation of Google Search homepage with search input + hidden tracking/system inputs
    const googleHtml = `
      <!doctype html>
      <html>
        <head>
          <title>Google</title>
          <meta name="description" content="Search the world's information, including webpages, images, videos and more.">
        </head>
        <body>
          <header>
            <a href="https://accounts.google.com/ServiceLogin">Sign in</a>
          </header>
          <main>
            <form action="/search" method="GET" role="search">
              <input type="hidden" name="ie" value="ISO-8859-1">
              <input type="hidden" name="hl" value="en">
              <input type="hidden" name="source" value="hp">
              <input type="hidden" name="biw" value="1440">
              <input type="hidden" name="bih" value="789">
              <input type="hidden" name="iflsig" value="AL9hW_gAAAAAZ">
              <input type="hidden" name="gbv" value="1">
              <input name="q" type="search" placeholder="Search Google or type a URL" autocomplete="off">
              <input type="submit" value="Google Search">
              <input type="submit" value="I'm Feeling Lucky">
            </form>
          </main>
        </body>
      </html>
    `;

    const parsed = URLParser.parse('https://www.google.com/');
    const pageExt = PageStructureExtractor.extract(googleHtml, 'www.google.com');

    // Verify PageStructureExtractor properly categorized inputs
    const form = pageExt.forms[0];
    assert.ok(form, 'Form should be extracted');
    assert.equal(form.inputs.find(i => i.name === 'q').isUserEditable, true);
    assert.equal(form.inputs.find(i => i.name === 'ie').isSystemParam, true);
    assert.equal(form.inputs.find(i => i.name === 'hl').isSystemParam, true);
    assert.equal(form.inputs.find(i => i.name === 'iflsig').isSystemParam, true);

    const intent = PageIntentEngine.analyze(pageExt, parsed);

    // Primary role MUST be SEARCH, NOT ACCOUNT_CREATION
    assert.equal(intent.primaryPageRole, PAGE_INTENT.SEARCH);
    assert.equal(intent.primary, PAGE_INTENT.SEARCH);
    assert.notEqual(intent.primary, PAGE_INTENT.ACCOUNT_CREATION);

    // System parameters must NOT be listed in requested user data
    assert.ok(!intent.requestedData.includes('ie'), 'System param "ie" must not be in requestedData');
    assert.ok(!intent.requestedData.includes('iflsig'), 'System param "iflsig" must not be in requestedData');
    assert.ok(intent.requestedData.includes('SEARCH_QUERY'), 'Search query must be recognized in requestedData');

    // Available actions must include search
    assert.ok(intent.availableActions.includes('SUBMIT_SEARCH'));
    assert.equal(intent.purposeMismatch, false);
  });

  it('2. Wikipedia Homepage: classified as CONTENT_READING / SEARCH (no false alarms)', () => {
    const wikiHtml = `
      <!doctype html>
      <html>
        <head>
          <title>Wikipedia, the free encyclopedia</title>
          <meta name="description" content="Wikipedia is a free online encyclopedia, created and edited by volunteers around the world and hosted by the Wikimedia Foundation.">
        </head>
        <body>
          <h1>Wikipedia</h1>
          <h2>The Free Encyclopedia</h2>
          <form action="/w/index.php" method="GET">
            <input type="hidden" name="title" value="Special:Search">
            <input name="search" type="search" placeholder="Search Wikipedia">
            <button type="submit">Search</button>
          </form>
          <div class="content">
            <h3>From today's featured article</h3>
            <p>The history of astronomy covers the development of humanity understanding of the cosmos...</p>
          </div>
        </body>
      </html>
    `;

    const parsed = URLParser.parse('https://www.wikipedia.org/');
    const pageExt = PageStructureExtractor.extract(wikiHtml, 'www.wikipedia.org');
    const intent = PageIntentEngine.analyze(pageExt, parsed);

    assert.ok(
      intent.primaryPageRole === PAGE_INTENT.SEARCH || intent.primaryPageRole === PAGE_INTENT.CONTENT_READING,
      `Expected SEARCH or CONTENT_READING, got ${intent.primaryPageRole}`
    );
    assert.notEqual(intent.primaryPageRole, PAGE_INTENT.LOGIN);
    assert.notEqual(intent.primaryPageRole, PAGE_INTENT.ACCOUNT_CREATION);
    assert.equal(intent.purposeMismatch, false);
    assert.ok(!intent.requestedData.includes('PASSWORD'));
  });

  it('3. Python.org Homepage: classified as HOMEPAGE_PORTAL / CONTENT_READING (NOT DOWNLOAD)', () => {
    const pythonHtml = `
      <!doctype html>
      <html>
        <head>
          <title>Welcome to Python.org</title>
          <meta name="description" content="The official home of the Python Programming Language. Python is a programming language that lets you work quickly.">
        </head>
        <body>
          <header>
            <h1>Welcome to Python.org</h1>
            <nav>
              <a href="/about/">About</a>
              <a href="/downloads/">Downloads</a>
              <a href="/doc/">Documentation</a>
              <a href="/community/">Community</a>
              <a href="/downloads/release/python-3120/">Download Python 3.12</a>
            </nav>
          </header>
          <main>
            <h2>Python is powerful... and fast</h2>
            <p>Python is an interpreted, interactive, object-oriented programming language used by millions.</p>
            <h3>Latest News</h3>
            <p>Python Software Foundation announces new grants for open source developers.</p>
          </main>
        </body>
      </html>
    `;

    const parsed = URLParser.parse('https://www.python.org/');
    const pageExt = PageStructureExtractor.extract(pythonHtml, 'www.python.org');
    const intent = PageIntentEngine.analyze(pageExt, parsed);

    // Primary role must NOT be DOWNLOAD merely because a download link exists
    assert.notEqual(intent.primaryPageRole, PAGE_INTENT.DOWNLOAD, 'Python.org homepage must not be classified as DOWNLOAD');
    assert.ok(
      intent.primaryPageRole === PAGE_INTENT.HOMEPAGE_PORTAL || intent.primaryPageRole === PAGE_INTENT.CONTENT_READING,
      `Expected HOMEPAGE_PORTAL or CONTENT_READING, got ${intent.primaryPageRole}`
    );

    // Available actions must capture the download option separately
    assert.ok(intent.availableActions.includes('DOWNLOAD_FILE'), 'Download should be listed as an available action');
    assert.ok(!intent.requiredActions.includes('DOWNLOAD_FILE'), 'Download must NOT be a required action');
    assert.equal(intent.purposeMismatch, false);
  });

  it('4. MDN Web Docs: classified as DOCUMENTATION (NOT DOWNLOAD at 98.8%)', () => {
    const mdnHtml = `
      <!doctype html>
      <html>
        <head>
          <title>MDN Web Docs — Resources for developers, by developers</title>
          <meta name="description" content="The MDN Web Docs site provides information about Open Web technologies including HTML, CSS, and APIs for both Web sites and progressive web apps.">
        </head>
        <body>
          <header>
            <h1>MDN Web Docs</h1>
            <nav>
              <a href="/en-US/docs/Web/HTML">HTML</a>
              <a href="/en-US/docs/Web/CSS">CSS</a>
              <a href="/en-US/docs/Web/JavaScript">JavaScript</a>
              <a href="/en-US/docs/Web/API">Web APIs</a>
              <a href="/offline-download">Download offline docs</a>
            </nav>
          </header>
          <main>
            <h2>Documenting web technologies since 2005</h2>
            <p>Explore comprehensive guides, code examples, and API references for web development.</p>
          </main>
        </body>
      </html>
    `;

    const parsed = URLParser.parse('https://developer.mozilla.org/en-US/');
    const pageExt = PageStructureExtractor.extract(mdnHtml, 'developer.mozilla.org');
    const intent = PageIntentEngine.analyze(pageExt, parsed);

    // Must be DOCUMENTATION or CONTENT_READING, definitely NOT DOWNLOAD
    assert.notEqual(intent.primaryPageRole, PAGE_INTENT.DOWNLOAD, 'MDN must NOT be classified as DOWNLOAD');
    assert.ok(
      intent.primaryPageRole === PAGE_INTENT.DOCUMENTATION || intent.primaryPageRole === PAGE_INTENT.CONTENT_READING,
      `Expected DOCUMENTATION or CONTENT_READING, got ${intent.primaryPageRole}`
    );

    // Available actions captures documentation browsing and download option
    assert.ok(intent.availableActions.includes('BROWSE_DOCUMENTATION'));
    assert.ok(intent.availableActions.includes('DOWNLOAD_FILE'));
    assert.equal(intent.purposeMismatch, false);
  });

  it('5. GitHub Homepage: classified as DEVELOPER_PLATFORM (NOT DOWNLOAD at 58.5%)', () => {
    const githubHtml = `
      <!doctype html>
      <html>
        <head>
          <title>GitHub: Let's build from here · GitHub</title>
          <meta name="description" content="GitHub is where over 100 million developers shape the future of software, together. Contribute to open source, build libraries, and automate workflows.">
        </head>
        <body>
          <header>
            <h1>GitHub</h1>
            <nav>
              <a href="/login">Sign in</a>
              <a href="/signup">Sign up</a>
              <a href="https://desktop.github.com">Download GitHub Desktop</a>
            </nav>
          </header>
          <main>
            <h2>Where the world builds software</h2>
            <p>Millions of developers and companies build, ship, and maintain their software on GitHub.</p>
            <form action="/signup" method="POST">
              <input name="email" type="email" placeholder="Enter your email">
              <button type="submit">Sign up for GitHub</button>
            </form>
          </main>
        </body>
      </html>
    `;

    const parsed = URLParser.parse('https://github.com/');
    const pageExt = PageStructureExtractor.extract(githubHtml, 'github.com');
    const intent = PageIntentEngine.analyze(pageExt, parsed);

    // Must be DEVELOPER_PLATFORM or HOMEPAGE_PORTAL, NOT DOWNLOAD
    assert.notEqual(intent.primaryPageRole, PAGE_INTENT.DOWNLOAD, 'GitHub must NOT be classified as DOWNLOAD');
    assert.ok(
      intent.primaryPageRole === PAGE_INTENT.DEVELOPER_PLATFORM || intent.primaryPageRole === PAGE_INTENT.HOMEPAGE_PORTAL,
      `Expected DEVELOPER_PLATFORM or HOMEPAGE_PORTAL, got ${intent.primaryPageRole}`
    );

    // Available actions distinguish options
    assert.ok(intent.availableActions.includes('DOWNLOAD_FILE'));
    assert.ok(intent.availableActions.includes('CREATE_ACCOUNT') || intent.availableActions.includes('SIGN_IN'));
    assert.equal(intent.purposeMismatch, false);
  });

  it('6. Analytics parameter isolation: isolates tracking tokens from security-sensitive query params', () => {
    const raw = 'https://portal.example.com/login?redirect=%2Fdashboard&target=home&utm_source=twitter&utm_medium=social&utm_campaign=spring2026&fbclid=AQD123456';
    const parsed = URLParser.parse(raw);

    assert.equal(parsed.isValid, true);
    assert.equal(parsed.hasTrackingParams, true);

    // Tracking parameters isolated
    assert.equal(parsed.trackingParameters['utm_source'], 'twitter');
    assert.equal(parsed.trackingParameters['utm_campaign'], 'spring2026');
    assert.equal(parsed.trackingParameters['fbclid'], 'AQD123456');

    // Functional & security parameters preserved!
    assert.equal(parsed.functionalParameters['redirect'], '/dashboard');
    assert.equal(parsed.functionalParameters['target'], 'home');

    // Secondary clean normalized URL strips only tracking, preserves functional
    assert.ok(parsed.cleanNormalizedUrl.includes('redirect=%2Fdashboard'));
    assert.ok(parsed.cleanNormalizedUrl.includes('target=home'));
    assert.ok(!parsed.cleanNormalizedUrl.includes('utm_source'));
    assert.ok(!parsed.cleanNormalizedUrl.includes('fbclid'));
  });

});
