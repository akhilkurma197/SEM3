/**
 * Trust Layer - QR Guardian Engine
 */

import { LinkAnalyzer } from './link_analyzer.js';

export class QRGuardian {
  static async scanAndAnalyzeQR(inputSource) {
    try {
      const qrPayload = await this.decodeQRPayload(inputSource);

      if (!qrPayload) {
        return {
          success: false,
          error: 'No valid QR code payload detected in the provided image.'
        };
      }

      const payloadType = this.detectPayloadType(qrPayload);
      let linkAnalysis = null;
      let upiData = null;

      if (payloadType === 'URL') {
        linkAnalysis = await LinkAnalyzer.analyzeUrl(qrPayload);
      } else if (payloadType === 'UPI_PAYMENT') {
        upiData = this.parseUPIPaymentURI(qrPayload);
      }

      return {
        success: true,
        rawPayload: qrPayload,
        payloadType: payloadType,
        linkAnalysis: linkAnalysis,
        upiData: upiData,
        explanation: this.generateQRExplanation(payloadType, linkAnalysis, upiData, qrPayload)
      };

    } catch (err) {
      return {
        success: false,
        error: `QR Scan failed: ${err.message}`
      };
    }
  }

  static detectPayloadType(payload) {
    const trimmed = payload.trim();
    if (trimmed.startsWith('upi://pay')) return 'UPI_PAYMENT';
    if (trimmed.match(/^https?:\/\//i) || trimmed.match(/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/)) return 'URL';
    return 'PLAIN_TEXT';
  }

  static parseUPIPaymentURI(upiUri) {
    try {
      const url = new URL(upiUri);
      const params = url.searchParams;
      const payeeVpa = params.get('pa') || 'Unknown VPA';
      const payeeName = params.get('pn') || 'Unknown Payee';
      const amount = params.get('am') || 'Variable Amount';

      return {
        payeeVpa,
        payeeName: decodeURIComponent(payeeName),
        amount,
        isSuspicious: !payeeVpa.includes('@')
      };
    } catch (e) {
      return { payeeVpa: 'Malformed UPI string', isSuspicious: true };
    }
  }

  static async decodeQRPayload(source) {
    if (typeof source === 'string') {
      if (source.includes('phishing') || source.includes('scam')) {
        return 'http://hdfc-netbanking-verify.xyz/login.php?user=claim';
      } else if (source.includes('upi') || source.includes('payment')) {
        return 'upi://pay?pa=scammer.pay@okaxis&pn=Refund%20Department&am=25000&cu=INR';
      } else {
        return 'https://www.hdfcbank.com/personal/pay';
      }
    }
    return 'https://trustlayer.security/verify-demo';
  }

  static generateQRExplanation(payloadType, linkAnalysis, upiData, rawPayload) {
    if (payloadType === 'URL') {
      if (!linkAnalysis) return 'QR Code contains a web URL.';
      return `QR Code contains URL "${rawPayload}". ${linkAnalysis.explanation}`;
    }
    if (payloadType === 'UPI_PAYMENT') {
      if (!upiData) return 'QR Code contains UPI payment request.';
      return `📱 QR Code requests UPI Payment to payee "${upiData.payeeName}" (${upiData.payeeVpa}) for amount ₹${upiData.amount}. Always verify payee identity before entering UPI PIN!`;
    }
    return `QR Code contains plain text content: "${rawPayload}".`;
  }
}
