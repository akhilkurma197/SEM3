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
