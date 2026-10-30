/**
 * Trust Layer — Website Intelligence Summary Builder v1.0
 * Synthesizes structured 8-question intelligence summaries from case schema data.
 * Works for both URL_ONLY and ISOLATED_LIVE inspection modes.
 * Never fabricates evidence — only reports what is actually present in the schema.
 */

const MODE_LABELS = {
  URL_ONLY: 'URL Analysis Only',
  SNAPSHOT: 'HTML Snapshot Analysis',
  ISOLATED_LIVE: 'Isolated Live Inspection'
};

const MODE_LIMITATIONS = {
  URL_ONLY: [
    'No live network connection was made to the target',
    'Page content, forms, and scripts were NOT observed — URL structure only',
    'DNS resolution was performed but no HTTP request was sent',
    'Cannot confirm whether the site is currently active or offline',
    'All page-level intelligence is derived from URL lexical signals only'
  ],
  SNAPSHOT: [
    'Analysis based on a provided HTML snapshot, not a live connection',
    'Network requests from JavaScript are not observable',
    'The snapshot may not reflect the current live state of the site'
  ],
  ISOLATED_LIVE: [
    'Observation mode blocks mutating POST/PUT/DELETE requests to prevent credential transmission',
    'Cookie-based session state was not maintained'
  ]
};

export class IntelligenceSummaryBuilder {
  /**
   * Build a structured 8-question intelligence summary from a case schema.
   * @param {object} schema  — The InvestigationCase schema object
   * @param {string} mode    — 'URL_ONLY' | 'SNAPSHOT' | 'ISOLATED_LIVE'
   * @returns {object}
   */
  static build(schema, mode = 'URL_ONLY') {
    const modeLabel = MODE_LABELS[mode] || mode;
    const modeLimitations = MODE_LIMITATIONS[mode] || [];

    const page = schema?.pageAnalysis || null;
    const identity = schema?.identityAnalysis || {};
    const network = schema?.networkAnalysis || {};
    const trust = schema?.trustBreakpoints || [];
    const assessment = schema?.assessment || {};
    const urlAnalysis = schema?.urlAnalysis || {};
    const live = schema?.liveInspection || null;
    const accessDenied = schema?.accessStatus === 'BLOCKED_HTTP_403' || live?.accessStatus === 'BLOCKED_HTTP_403' ||
      Number(schema?.httpAnalysis?.statusCode || live?.httpStatus) === 403;
    const ssIntel = schema?.screenshotIntelligence || page?.screenshotIntelligence || live?.screenshotIntelligence || null;
    const isLive = mode === 'ISOLATED_LIVE';

    // ── Q1: Identity & Purpose ──
    let whatIsThis = '';
    {
      const title = page?.title || null;
      const claimed = identity?.claimedEntity || null;
      const observed = identity?.observedEntity || urlAnalysis?.hostname || 'unknown';
      const intent = page?.intent?.primary || 'UNKNOWN';
      const continuity = identity?.identityContinuity || 'UNKNOWN';

      if (title) {
        whatIsThis += `Page title: "${title}". `;
      }
      if (claimed && claimed !== 'UNKNOWN') {
        whatIsThis += `Claims to represent: ${claimed}. `;
      }
      whatIsThis += `Operating from domain: ${observed}. `;
      if (intent && intent !== 'UNKNOWN') {
        whatIsThis += `Primary detected function: ${intent}. `;
      }
      if (continuity === 'MISMATCH') {
        whatIsThis += `⚠️ Identity continuity check FAILED — claimed entity does not match registered domain. `;
      } else if (continuity === 'MATCH') {
        whatIsThis += `✅ Domain identity verified as matching claimed entity. `;
      } else {
        whatIsThis += `Identity could not be independently verified. `;
      }
      if (ssIntel?.indicators?.isSecurityTestFixture) {
        whatIsThis += `🛡️ Confirmed Security Research / Demonstration Test Fixture (Google Safe Browsing). `;
      }
      if (!isLive && !page?.title) {
        whatIsThis += `(No live page was fetched — identity based on URL analysis only.)`;
      }
    }

    // ── Q2: What can visitors do ──
    let whatCanVisitorsDo = '';
    {
      const buttons = page?.buttons || [];
      const actions = page?.intent?.requestedActions || [];
      const intent = page?.intent?.primary;

      if (!isLive && !page?.forms?.length && !buttons.length) {
        whatCanVisitorsDo = 'No live page was inspected — available actions could not be determined from URL analysis alone.';
      } else if (buttons.length || actions.length) {
        const allActions = [...new Set([...buttons.slice(0, 5), ...actions.slice(0, 5)])];
        whatCanVisitorsDo = `Detected interactive elements: ${allActions.join(', ')}. `;
        if (intent) whatCanVisitorsDo += `Primary functional intent: ${intent}.`;
      } else if (intent && intent !== 'UNKNOWN') {
        whatCanVisitorsDo = `Inferred purpose from page structure: ${intent}. No explicit call-to-action buttons detected.`;
      } else {
        whatCanVisitorsDo = 'No interactive actions detected on this page.';
      }

      if (ssIntel?.indicators?.hasFakeSoftwareUpdate) {
        whatCanVisitorsDo += ` ⚠️ Screenshot intelligence observed deceptive software update / installation action triggers embedded in viewport graphics.`;
      }
    }

    // ── Q3: What information is requested ──
    let whatInfoRequested = '';
    {
      const forms = page?.forms || [];
      if (!isLive && !forms.length) {
        whatInfoRequested = 'No page was fetched — form fields could not be observed.';
      } else if (forms.length === 0) {
        whatInfoRequested = 'No forms detected on this page.';
      } else {
        const userFields = [];
        const hiddenFields = [];
        let hasPassword = false;
        let hasSensitive = false;

        for (const form of forms) {
          for (const input of (form.inputs || [])) {
            const isHidden = input.isHidden || input.type === 'hidden';
            const isUserEditable = input.isUserEditable !== undefined ? input.isUserEditable : !isHidden;

            if (isUserEditable) {
              userFields.push(input.name + (input.isPassword ? ' [PASSWORD]' : input.isSensitive ? ' [SENSITIVE]' : ''));
              if (input.isPassword) hasPassword = true;
              if (input.isSensitive) hasSensitive = true;
            } else if (isHidden && !input.isSystemParam) {
              hiddenFields.push(input.name + ' [hidden]');
            }
          }
        }

        if (userFields.length) {
          whatInfoRequested = `Visible user-input fields: ${userFields.join(', ')}. `;
        } else {
          whatInfoRequested = 'No visible user-input fields detected. ';
        }
        if (hiddenFields.length) {
          whatInfoRequested += `Hidden (non-system) fields: ${hiddenFields.join(', ')}. `;
        }
        if (hasPassword) {
          whatInfoRequested += `⚠️ Password input field present. `;
        }
        if (hasSensitive) {
          whatInfoRequested += `⚠️ Sensitive data fields detected (OTP, card, PIN, etc.). `;
        }
      }

      if (ssIntel?.indicators?.hasCredentialsPrompt) {
        whatInfoRequested += `⚠️ Viewport screenshot OCR confirmed credential prompts visible to users.`;
      }
    }

    // ── Q4: Where could data go ──
    let whereCouldItGo = '';
    {
      const forms = page?.forms || [];
      const submissions = network?.formSubmissions || [];

      if (!isLive && !forms.length) {
        whereCouldItGo = 'No live page was fetched — form destinations could not be observed.';
      } else if (forms.length === 0) {
        whereCouldItGo = 'No form submission endpoints detected.';
      } else {
        const destinations = [];
        for (const form of forms) {
          const dest = form.action || '(same-origin)';
          const external = form.isExternal ? ' ⚠️ EXTERNAL HOST' : ' (same-origin)';
          destinations.push(`${dest}${external} [${form.method || 'GET'}]`);
        }
        whereCouldItGo = `Form destinations: ${destinations.join(' | ')}. `;
        if (submissions.length) {
          whereCouldItGo += `External form submissions: ${submissions.join(', ')}.`;
        }
      }
    }

    // ── Q5: Network activity ──
    let networkActivity = '';
    {
      const requests = network?.requests || [];
      const liveEvents = live?.networkEvents || [];

      if (isLive) {
        const docRequests = liveEvents.filter(e => e.type === 'document');
        const scriptRequests = liveEvents.filter(e => e.type === 'script');
        const iframeRequests = liveEvents.filter(e => e.type === 'iframe');
        const externalScripts = scriptRequests.filter(e => e.isExternal);

        networkActivity = `Live inspection contacted the target server directly. `;
        if (docRequests.length) {
          networkActivity += `Document fetched: ${docRequests[0].url} (HTTP ${docRequests[0].status}). `;
        }
        if (scriptRequests.length) {
          networkActivity += `${scriptRequests.length} script source(s) detected in HTML (not fetched — JS execution disabled). `;
        }
        if (externalScripts.length) {
          networkActivity += `External scripts from: ${[...new Set(externalScripts.map(s => s.domain))].join(', ')}. `;
        }
        if (iframeRequests.length) {
          networkActivity += `${iframeRequests.length} iframe(s) detected. `;
        }
        networkActivity += `Note: Mutating requests blocked under observation policy.`;
      } else {
        if (requests.length) {
          networkActivity = `${requests.length} HTTP request(s) recorded during investigation. `;
          networkActivity += `Note: This was URL-only analysis — no live network connection was made to the target site.`;
        } else {
          networkActivity = 'No network requests were made to the target (URL-only analysis mode). DNS resolution only.';
        }
      }
    }

    // ── Q6: Claimed vs observed behaviour ──
    let behaviourMatch = '';
    {
      const intent = page?.intent || {};
      const purposeConsistency = intent.purposeConsistency || 'INCOMPLETE';
      const claimedPurpose = intent.claimedPurpose || identity?.claimedEntity || 'Not determined';
      const observedPurpose = intent.observedPurpose || 'Not determined';
      const mismatch = intent.purposeMismatch || false;
      const mismatchReason = intent.mismatchReason || null;

      if (!isLive && purposeConsistency === 'INCOMPLETE') {
        behaviourMatch = 'Behaviour could not be assessed — no live page was loaded. Claimed identity vs page behaviour comparison requires HTTP inspection.';
      } else {
        behaviourMatch = `Claimed purpose: ${claimedPurpose}. Observed purpose: ${observedPurpose}. Consistency: ${purposeConsistency}. `;
        if (mismatch) {
          behaviourMatch += `⚠️ PURPOSE MISMATCH DETECTED: ${mismatchReason || 'The page behaviour does not match its claimed identity.'}`;
        } else if (purposeConsistency === 'MATCH') {
          behaviourMatch += `✅ Claimed and observed purposes are consistent.`;
        }
      }

      if (ssIntel?.indicators?.isSecurityTestFixture) {
        behaviourMatch += ` 🛡️ Security demonstration fixture: Phishing indicators are part of an intentional Google Safe Browsing test page.`;
      } else if (ssIntel?.indicators?.hasFakeSoftwareUpdate) {
        behaviourMatch += ` ⚠️ Deceptive software update dialogs detected in screenshot.`;
      }
    }

    // ── Q7: Suspicion indicators ──
    const suspicionIndicators = [];
    {
      for (const bp of trust) {
        const evId = schema?.evidence?.find(e => e.data && JSON.stringify(e.data).includes(bp.type))?.id || null;
        let indicator = `[${bp.type}] ${bp.description || bp.observed || ''}`;
        if (evId) indicator += ` (Evidence: ${evId})`;
        suspicionIndicators.push(indicator);
      }

      // Additional signals from model
      if (schema?.modelResult?.prediction === 'PHISHING' && schema?.modelResult?.probabilityPhishing > 0.7) {
        suspicionIndicators.push(`[MODEL_PHISHING_SIGNAL] ML model predicts phishing with ${(schema.modelResult.probabilityPhishing * 100).toFixed(1)}% probability`);
      }
      if (schema?.ruleEngineResult?.classification === 'PHISHING') {
        suspicionIndicators.push(`[RULE_ENGINE_PHISHING] Deterministic rule engine scored ${schema.ruleEngineResult.ruleScore}/100 — classified as PHISHING`);
      }
      if (schema?.conflictDetected) {
        suspicionIndicators.push(`[MODEL_EVIDENCE_CONFLICT] ${schema.conflictReason}`);
      }

      // Screenshot intelligence findings
      if (ssIntel?.findings?.length) {
        for (const f of ssIntel.findings) {
          if (!f.isTestFixture) {
            suspicionIndicators.push(`[SCREENSHOT_INTELLIGENCE] ${f.label}: "${f.textSnippet}" (${f.source}, Confidence: ${f.confidence}%) (Evidence: ${f.id})`);
          } else {
            suspicionIndicators.push(`[SECURITY_TEST_FIXTURE] ${f.label}: "${f.textSnippet}" (Evidence: ${f.id})`);
          }
        }
      }
    }

    // ── Q8: Not inspected ──
    const notInspected = [...(assessment?.limitations || []), ...modeLimitations];
    if (accessDenied) {
      whatIsThis = `The endpoint returned HTTP 403. A screenshot of the access-denial response was captured, but the target website's identity and purpose could not be assessed.`;
      whatCanVisitorsDo = 'Target website functionality could not be observed because the endpoint returned an access-denial response.';
      whatInfoRequested = 'Not assessed: the captured 403 response does not establish what information the target website requests.';
      whereCouldItGo = 'Not assessed: the target website and its form destinations were unavailable behind the HTTP 403 response.';
      networkActivity = `The isolated browser received HTTP 403 at ${live?.finalUrl || schema?.httpAnalysis?.finalUrl || 'the requested URL'}. The screenshot documents the response page, not the target website content.`;
      behaviourMatch = 'Not assessed: the target website purpose could not be compared with observed page behavior.';
      for (let index = suspicionIndicators.length - 1; index >= 0; index--) {
        if (/^\[(SCREENSHOT_INTELLIGENCE|SECURITY_TEST_FIXTURE)\]/.test(suspicionIndicators[index])) {
          suspicionIndicators.splice(index, 1);
        }
      }
      notInspected.push('Target page content, forms, and functional intent could not be assessed because HTTP 403 was returned.');
    }
    // Deduplicate
    const notInspectedUniq = [...new Set(notInspected)];

    // ── Full formatted summary ──
    const lines = [
      '═══════════════════════════════════════════════════════════════',
      `TRUST LAYER — WEBSITE INTELLIGENCE SUMMARY`,
      `Mode: ${modeLabel}`,
      '═══════════════════════════════════════════════════════════════',
      '',
      '❶  WHAT IS THIS? (Identity & Purpose)',
      whatIsThis,
      '',
      '❷  WHAT CAN VISITORS DO? (Available Actions)',
      whatCanVisitorsDo,
      '',
      '❸  WHAT INFORMATION IS REQUESTED? (Form Fields)',
      whatInfoRequested,
      '',
      '❹  WHERE COULD DATA GO? (Form Destinations)',
      whereCouldItGo,
      '',
      '❺  NETWORK ACTIVITY (Observed Connections)',
      networkActivity,
      '',
      '❻  CLAIMED vs OBSERVED BEHAVIOUR',
      behaviourMatch,
      '',
      '❼  SUSPICION INDICATORS',
      suspicionIndicators.length
        ? suspicionIndicators.map(s => `  • ${s}`).join('\n')
        : '  • No specific suspicion indicators triggered.',
      '',
      '❽  NOT INSPECTED / LIMITATIONS',
      notInspectedUniq.length
        ? notInspectedUniq.map(l => `  • ${l}`).join('\n')
        : '  • No significant limitations.',
      '',
      '═══════════════════════════════════════════════════════════════',
      `Overall Risk: ${assessment?.riskLevel || 'UNKNOWN'} — ${assessment?.headline || 'Pending'}`,
      '═══════════════════════════════════════════════════════════════'
    ];

    const overallText = lines.join('\n');

    return {
      mode,
      modeLabel,
      modeLimitations,
      whatIsThis,
      whatCanVisitorsDo,
      whatInfoRequested,
      whereCouldItGo,
      networkActivity,
      behaviourMatch,
      suspicionIndicators,
      notInspected: notInspectedUniq,
      overallText
    };
  }
}
