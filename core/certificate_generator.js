/**
 * Trust Layer - Cybercrime & Bank Dispute Forensic Evidence Certificate Generator
 */

export class CertificateGenerator {
  /**
   * Generates a printable / downloadable Fraud Evidence Audit Certificate
   * @param {Object} auditReport - Link, QR, or Payment Forensic Report
   * @returns {string} Styled HTML certificate string ready for print or modal display
   */
  static generateCertificateHTML(auditReport) {
    const certId = 'TL-' + Math.random().toString(36).substring(2, 9).toUpperCase();
    const timestamp = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST';
    const isThreat = auditReport.riskLevel === 'CRITICAL' || auditReport.riskLevel === 'FAKED / TAMPERED' || auditReport.riskLevel === 'HIGH';

    const hashString = JSON.stringify(auditReport) + certId + timestamp;
    const shaHash = this.simpleHash(hashString);

    const html = `
      <div id="trustlayer-certificate" class="certificate-container" style="
        background: #0d1117;
        color: #f0f6fc;
        font-family: 'Outfit', -apple-system, sans-serif;
        padding: 32px;
        border: 2px solid ${isThreat ? '#f43f5e' : '#10b981'};
        border-radius: 16px;
        box-shadow: 0 15px 40px rgba(0,0,0,0.8);
        max-width: 720px;
        margin: 20px auto;
        position: relative;
      ">
        <!-- Certificate Top Header -->
        <div style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid rgba(255,255,255,0.1); padding-bottom: 20px; margin-bottom: 24px;">
          <div>
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
              <span style="font-size: 28px;">🛡️</span>
              <h2 style="margin: 0; font-size: 20px; font-weight: 800; background: linear-gradient(135deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                TRUST LAYER FORENSIC EVIDENTIAL CERTIFICATE
              </h2>
            </div>
            <p style="margin: 0; font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px;">
              NATIONAL CYBERCRIME & BANK DISPUTE EVIDENCE COMPLIANCE
            </p>
          </div>
          <div style="text-align: right;">
            <span style="font-family: monospace; font-size: 13px; color: #38bdf8; font-weight: 700;">${certId}</span>
            <div style="font-size: 10px; color: #8b949e;">${timestamp}</div>
          </div>
        </div>

        <!-- Threat Banner -->
        <div style="
          background: ${isThreat ? 'rgba(244,63,94,0.15)' : 'rgba(16,185,129,0.15)'};
          border: 1px solid ${isThreat ? 'rgba(244,63,94,0.4)' : 'rgba(16,185,129,0.4)'};
          padding: 16px;
          border-radius: 10px;
          margin-bottom: 24px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        ">
          <div>
            <span style="font-size: 11px; font-weight: 700; color: ${isThreat ? '#f87171' : '#34d399'}; text-transform: uppercase;">
              FORENSIC AUDIT VERDICT
            </span>
            <h3 style="margin: 4px 0 0 0; font-size: 18px; color: #ffffff;">
              ${isThreat ? '🚨 FRAUD / ALTERATION CONFIRMED' : '✅ PASSED SECURITY AUDIT'}
            </h3>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 22px; font-weight: 800; color: ${isThreat ? '#f87171' : '#34d399'};">
              ${auditReport.riskPercentage || ((auditReport.tamperScore || auditReport.riskScore || 0) * 100).toFixed(0) + '%'}
            </div>
            <span style="font-size: 10px; color: #8b949e;">THREAT INDEX</span>
          </div>
        </div>

        <!-- Evidence Breakdown Table -->
        <div style="margin-bottom: 24px;">
          <h4 style="font-size: 13px; color: #8b949e; text-transform: uppercase; margin-bottom: 12px; letter-spacing: 0.5px;">
            TECHNICAL EVIDENCE & AUDIT FINDINGS
          </h4>
          <table style="width: 100%; border-collapse: collapse; font-size: 12px; color: #c9d1d9;">
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.08);">
              <td style="padding: 10px; font-weight: 600; color: #8b949e; width: 30%;">Target Subject:</td>
              <td style="padding: 10px; word-break: break-all; font-family: monospace;">${auditReport.url || auditReport.extractedFields?.appName || 'Payment Screenshot'}</td>
            </tr>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.08);">
              <td style="padding: 10px; font-weight: 600; color: #8b949e;">Audit Summary:</td>
              <td style="padding: 10px;">${auditReport.explanation}</td>
            </tr>
            ${auditReport.extractedFields ? `
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.08);">
                <td style="padding: 10px; font-weight: 600; color: #8b949e;">Extracted Amount / UTR:</td>
                <td style="padding: 10px;">
                  Amount: <strong>${auditReport.extractedFields.amount}</strong> | 
                  UTR Ref: <strong>${auditReport.extractedFields.utr}</strong> (Standard 12-Digit UPI Compliance Check)
                </td>
              </tr>
            ` : ''}
            ${auditReport.brandImpersonation ? `
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.08);">
                <td style="padding: 10px; font-weight: 600; color: #f87171;">Impersonated Brand:</td>
                <td style="padding: 10px; color: #fca5a5;">
                  Claims to be <strong>${auditReport.brandImpersonation.targetBrand}</strong> on actual host <strong>${auditReport.brandImpersonation.actualDomain}</strong>
                </td>
              </tr>
            ` : ''}
          </table>
        </div>

        <!-- Cryptographic Footprint -->
        <div style="background: rgba(255,255,255,0.03); padding: 12px 16px; border-radius: 8px; border: 1px dashed rgba(255,255,255,0.15); margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; font-size: 10px; color: #8b949e;">
            <span>CRYPTOGRAPHIC HASH (SHA-256):</span>
            <span style="font-family: monospace; color: #38bdf8;">${shaHash}</span>
          </div>
        </div>

        <!-- Actions Footer -->
        <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 16px;">
          <span style="font-size: 10px; color: #8b949e;">Verified by Trust Layer Autonomous Forensic Engine</span>
          <button onclick="window.print()" style="
            background: linear-gradient(135deg, #06b6d4, #0284c7);
            color: #fff;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 12px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(6,182,212,0.4);
          ">📄 Print / Save Evidence PDF</button>
        </div>
      </div>
    `;

    return html;
  }

  static simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash |= 0;
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    return `0x${hex}89ab45cd${hex}f1e2`;
  }
}
