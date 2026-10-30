/**
 * Trust Layer — Deterministic URL Risk Aggregator
 * Combines triggered rule contributions, applies anti-correlation category caps,
 * and produces reproducible risk scores [0 - 100] with explicit categorization.
 */

export class RiskAggregator {
  /**
   * Aggregates evaluated rules into a bounded, calibrated score.
   * @param {Array<object>} evaluatedRules List of evaluated rule records
   * @param {object} config Rule configuration containing categoryCaps and thresholds
   * @returns {{
   *   score: number,
   *   classification: 'SAFE' | 'UNDER_REVIEW' | 'PHISHING',
   *   categoryBreakdown: object,
   *   triggeredRules: Array<object>,
   *   totalUncappedContribution: number,
   *   configVersion: string
   * }}
   */
  static aggregate(evaluatedRules, config) {
    const categoryCaps = config.categoryCaps || {};
    const thresholds = config.thresholds || { safeMax: 24, reviewMax: 59, phishingMin: 60 };
    const triggeredRules = evaluatedRules.filter(r => r.triggered);

    // Group contributions by category to apply anti-correlation caps
    const categoryTotals = {};
    const categoryCapped = {};
    let totalUncapped = 0;

    for (const rule of triggeredRules) {
      const cat = rule.category || 'OTHER';
      categoryTotals[cat] = (categoryTotals[cat] || 0) + rule.contribution;
      totalUncapped += rule.contribution;
    }

    let aggregatedScore = 0;
    const categoryBreakdown = {};

    for (const [cat, rawTotal] of Object.entries(categoryTotals)) {
      const cap = categoryCaps[cat] !== undefined ? categoryCaps[cat] : 50;
      const effective = Math.min(rawTotal, cap);
      categoryCapped[cat] = effective;
      aggregatedScore += effective;

      categoryBreakdown[cat] = {
        rawScore: rawTotal,
        cappedScore: effective,
        categoryCap: cap,
        rulesTriggeredCount: triggeredRules.filter(r => r.category === cat).length
      };
    }

    // Clamp total score between 0 and 100
    const finalScore = Math.min(Math.max(Math.round(aggregatedScore), 0), 100);

    // 3-way transparent classification
    let classification = 'SAFE';
    if (finalScore >= thresholds.phishingMin) {
      classification = 'PHISHING';
    } else if (finalScore > thresholds.safeMax) {
      classification = 'UNDER_REVIEW';
    }

    return {
      score: finalScore,
      classification,
      categoryBreakdown,
      triggeredRules,
      totalUncappedContribution: totalUncapped,
      configVersion: config.version || '1.0.0'
    };
  }
}

export class OverallRiskAggregator {
  /**
   * Cross-mode multi-layer risk synthesizer enforcing mandatory phishing precedence.
   * If ANY executed and applicable security-assessment layer returns a definitive PHISHING verdict,
   * the final investigation verdict MUST be PHISHING.
   * A low URL score or SAFE score from another mode can NEVER override this finding.
   */
  static aggregate({
    urlAssessment = null,
    redirectAssessment = null,
    pageContentAssessment = null,
    isTestFixture = false,
    hasIdentityMismatch = false,
    hasExfiltration = false,
    inspectionMode = 'URL_ONLY'
  }) {
    const urlScore = urlAssessment?.ruleScore ?? 0;
    const urlVerdict = urlAssessment?.classification || 'SAFE';

    const redirectScore = redirectAssessment?.riskScore ?? 0;
    const redirectVerdict = redirectAssessment?.riskLevel || null;

    const pageRisk = pageContentAssessment?.riskLevel || 'NOT_RUN';
    const pageVerdict = pageContentAssessment?.verdict || pageContentAssessment?.classification || null;
    const fullPageInspected = pageContentAssessment?.fullRenderedInspection === true &&
      pageContentAssessment?.status === 'COMPLETED';

    // Check if any executed mode returned PHISHING
    const isUrlPhishing = urlVerdict === 'PHISHING';
    const isRedirectPhishing = redirectVerdict === 'PHISHING';
    // Only an explicit verdict from an assessment layer is definitive. Individual clues remain evidence.
    const isPagePhishing = !isTestFixture && pageVerdict === 'PHISHING';

    let finalVerdict = 'SAFE';
    let finalRiskLevel = 'LOW';
    let determiningComponent = 'Mode A: URL-Only Assessment';
    let headline = 'Authentic Infrastructure Verified';
    let summary = 'Normal webpage and URL structure without detected credential traps or deceptive lures.';
    let reasons = [];
    let phishingPrecedenceApplied = false;

    // 1. Explicit Test Fixture Designation (Google Safe Browsing Test Harness)
    if (isUrlPhishing || isRedirectPhishing || isPagePhishing) {
      finalVerdict = 'PHISHING';
      finalRiskLevel = 'CRITICAL';
      phishingPrecedenceApplied = true;

      if (isPagePhishing) {
        determiningComponent = 'Mode C: Page Content & Screenshot Intelligence';
        headline = hasExfiltration
          ? 'High-Risk Impersonation & Credential Exfiltration Confirmed'
          : 'Confirmed Malicious Page Behaviour';
        summary = pageContentAssessment?.summary || 'An applicable page assessment issued a definitive PHISHING verdict.';
      } else if (isUrlPhishing) {
        determiningComponent = 'Mode A: URL Rule Engine';
        headline = 'High-Probability Phishing Infrastructure (URL Heuristics)';
        summary = urlAssessment?.summary || 'Deterministic URL rule engine scored target as high-risk phishing.';
      } else {
        determiningComponent = 'Mode B: Active Redirect Tracer';
        headline = 'Malicious Redirection Chain Detected';
        summary = redirectAssessment?.summary || 'Active HTTP redirect assessment issued a definitive PHISHING verdict.';
      }
      reasons.push(`Phishing precedence enforced: ${determiningComponent} issued a definitive PHISHING verdict.`, summary);
    }
    // A known demonstration page does not label its hosting operator as malicious.
    else if (isTestFixture) {
      finalVerdict = 'KNOWN_SECURITY_TEST_FIXTURE';
      finalRiskLevel = 'LOW';
      determiningComponent = 'Security Test Fixture Policy';
      headline = 'Known Security Test Fixture (Safe Browsing Phishing Demonstration)';
      summary = 'Target presents phishing credential capture inputs and deceptive software-update dialogs embedded within images, but is identified as an official Google Safe Browsing demonstration test fixture. The hosting domain is not accused of hosting an active malicious campaign.';
      reasons = [
        'Target verified as an official Google Safe Browsing security demonstration test fixture.',
        'Observed phishing inputs and deceptive update graphics are present as intentional test demonstration vectors.',
        'Hosting domain continuity verified; no malicious exfiltration penalty applied.'
      ];
    }
    // 3. Under Review: If any executed mode returned UNDER_REVIEW
    else if (urlVerdict === 'UNDER_REVIEW' || redirectVerdict === 'UNDER_REVIEW' || pageRisk === 'MODERATE' || pageRisk === 'HIGH') {
      finalVerdict = 'UNDER_REVIEW';
      finalRiskLevel = (pageRisk === 'HIGH') ? 'HIGH' : 'MODERATE';
      determiningComponent = (redirectVerdict === 'UNDER_REVIEW')
        ? 'Mode B: Active Redirect Tracer'
        : ((pageRisk === 'HIGH' || pageRisk === 'MODERATE') ? 'Mode C: Page Content Assessment' : 'Mode A: URL Rule Engine');
      const liveInspectionIncomplete = inspectionMode === 'ISOLATED_LIVE' && !fullPageInspected;
      headline = liveInspectionIncomplete ? 'Live Inspection Incomplete — Under Review' : 'Inconclusive Signals — Under Review';
      summary = liveInspectionIncomplete
        ? (pageContentAssessment?.summary || 'The isolated browser did not produce rendered page evidence. No final website safety conclusion is available.')
        : 'Available signals exhibit anomalies or unverified domain ownership requiring manual security verification.';
      reasons.push(liveInspectionIncomplete
        ? summary
        : 'Investigation completed with mixed/uncertain risk signals.');
    }
    // URL analysis and redirect tracing do not establish that rendered page content is safe.
    else if (!fullPageInspected) {
      finalVerdict = 'UNDER_REVIEW';
      finalRiskLevel = 'LOW';
      determiningComponent = inspectionMode === 'MODE_B'
        ? 'Mode B: HTTP Redirect Trace (Rendered Page Not Inspected)'
        : (inspectionMode === 'ISOLATED_LIVE'
          ? 'Mode C: Isolated Live Inspection (Incomplete)'
          : 'Mode A: Preliminary URL Assessment (Page Not Fetched)');
      headline = inspectionMode === 'MODE_B'
        ? 'Redirect Trace Complete — Rendered Page Not Inspected'
        : (inspectionMode === 'ISOLATED_LIVE'
          ? 'Live Inspection Incomplete — Under Review'
          : 'Initial URL Assessment — Webpage Not Fetched');
      summary = inspectionMode === 'MODE_B'
        ? 'The read-only redirect/header trace completed. It did not render the webpage, execute JavaScript, or inspect secondary resources; page safety remains unverified.'
        : (inspectionMode === 'ISOLATED_LIVE'
          ? (pageContentAssessment?.summary || 'The isolated browser did not produce rendered page evidence. No final website safety conclusion is available.')
          : 'URL structure and deterministic rules were assessed. Redirects and page content were not inspected, so this is not a final website safety verdict.');
      reasons.push(summary);
    }
    // 4. Clean Safe
    else {
      finalVerdict = 'SAFE';
      finalRiskLevel = 'LOW';
      determiningComponent = 'Consolidated Multi-Mode Verification';
      headline = 'Authentic Infrastructure Verified';
      summary = 'No credential traps, exfiltration endpoints, or deceptive lures observed across executed inspection modes.';
      reasons.push('All executed inspection stages completed cleanly.');
    }

    // Conservative combined numeric score = maximum of comparable executed scores
    const modeScores = {
      modeA: urlScore,
      modeB: redirectAssessment?.status === 'SUCCESS' ? redirectScore : null,
      modeC: fullPageInspected ? (pageRisk === 'CRITICAL' ? 95 : (pageRisk === 'HIGH' ? 70 : (pageRisk === 'MODERATE' ? 45 : 10))) : null
    };

    const validScores = [urlScore];
    if (modeScores.modeB !== null) validScores.push(modeScores.modeB);
    if (modeScores.modeC !== null) validScores.push(modeScores.modeC);

    const combinedScore = isTestFixture && !phishingPrecedenceApplied ? 0 : Math.max(...validScores);

    return {
      finalVerdict,
      finalRiskLevel,
      combinedScore,
      determiningComponent,
      headline,
      summary,
      reasons,
      modeScores,
      modeStatuses: {
        modeA: urlAssessment ? 'COMPLETED' : 'NOT_RUN',
        modeB: redirectAssessment?.status || 'NOT_RUN',
        modeC: fullPageInspected ? 'COMPLETED' : (pageContentAssessment?.status || 'NOT_RUN')
      },
      phishingPrecedenceApplied
    };
  }
}
