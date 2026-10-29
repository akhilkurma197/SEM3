/**
 * Trust Layer - Plain-Language Explainability Synthesizer
 * Formats complex forensic signals into user-friendly explanations.
 */

export class ExplainabilityEngine {
  /**
   * Format Link Analysis into rich HTML/Markdown structure
   */
  static formatLinkReport(report) {
    const isHighRisk = report.riskLevel === 'CRITICAL' || report.riskLevel === 'HIGH';
    
    let html = `
      <div class="trust-report ${report.riskLevel.toLowerCase()}">
        <div class="report-header">
          <span class="badge ${report.riskLevel.toLowerCase()}">${report.riskLevel} RISK</span>
          <span class="score">Threat Index: ${(report.riskScore * 100).toFixed(0)}%</span>
        </div>
        
        <h4 class="report-title">${isHighRisk ? '⚠️ Phishing & Fraud Threat Detected' : '✅ Verified Safe Web Link'}</h4>
        <p class="summary-text">${report.explanation}</p>

        ${report.brandImpersonation ? `
          <div class="alert-box impersonation">
            <strong>🚨 Brand Impersonation Alert:</strong>
            <p>This web page attempts to fake <strong>${report.brandImpersonation.targetBrand}</strong>, but is actually hosted on unverified domain <code>${report.brandImpersonation.actualDomain}</code>.</p>
          </div>
        ` : ''}

        ${report.featuresTriggered.length > 0 ? `
          <div class="features-list">
            <h5>Key Security Findings:</h5>
            <ul>
              ${report.featuresTriggered.map(f => `
                <li>
                  <span class="impact ${f.impact.toLowerCase()}">[${f.impact}]</span>
                  <strong>${f.name}:</strong> ${f.desc}
                </li>
              `).join('')}
            </ul>
          </div>
        ` : ''}

        <div class="recommendation">
          <strong>Actionable Advice:</strong>
          <p>${report.recommendation}</p>
        </div>
      </div>
    `;

    return html;
  }

  /**
   * Format Payment Forensic Report
   */
  static formatPaymentReport(report) {
    const isTampered = report.riskLevel === 'FAKED / TAMPERED';

    let html = `
      <div class="trust-report ${isTampered ? 'critical' : 'low'}">
        <div class="report-header">
          <span class="badge ${isTampered ? 'critical' : 'low'}">${report.riskLevel}</span>
          <span class="score">Tamper Index: ${(report.tamperScore * 100).toFixed(0)}%</span>
        </div>

        <h4 class="report-title">${isTampered ? '🚨 Fake / Altered Payment Screenshot' : '✅ Verified Genuine Payment Receipt'}</h4>
        <p class="summary-text">${report.explanation}</p>

        ${report.anomalies.length > 0 ? `
          <div class="features-list">
            <h5>Forensic Anomalies Found:</h5>
            <ul>
              ${report.anomalies.map(a => `
                <li>
                  <span class="impact ${a.severity.toLowerCase()}">[${a.severity}]</span>
                  <strong>${a.type}:</strong> ${a.description}
                </li>
              `).join('')}
            </ul>
          </div>
        ` : ''}

        <div class="recommendation">
          <strong>Actionable Advice:</strong>
          <p>${report.recommendation}</p>
        </div>
      </div>
    `;

    return html;
  }
}
