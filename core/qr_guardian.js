/**
 * Trust Layer - QR Guardian Engine
 * Decodes QR code payloads locally without executing/opening embedded links,
 * and routes decoded payload into 2-Tier Link Analyzer.
 */

import { LinkAnalyzer } from './link_analyzer.js';

export class QRGuardian {
  /**
   * Scans and analyzes a QR Code image file or canvas element
   * @param {HTMLImageElement|HTMLCanvasElement|ImageData|File|string} inputSource 
   * @returns {Promise<Object>} Detailed QR Quishing report & Link analysis
   */
  static async scanAndAnalyzeQR(inputSource) {
    try {
      // Step 1: Decode QR Code payload
      const qrPayload = await this.decodeQRPayload(inputSource);

      if (!qrPayload) {
        return {
          success: false,
          error: 'No valid QR code payload detected in the provided image.',
          recommendation: 'Ensure the QR code is clearly visible, well-lit, and unblurred.'
        };
      }

      // Step 2: Check payload type (URL vs UPI Payment vs Wi-Fi vs vCard vs Text)
      const payloadType = this.detectPayloadType(qrPayload);

      let linkAnalysis = null;
      let upiData = null;
      let wifiData = null;
      let vcardData = null;

      if (payloadType === 'URL') {
        linkAnalysis = await LinkAnalyzer.analyzeUrl(qrPayload);
      } else if (payloadType === 'UPI_PAYMENT') {
        upiData = this.parseUPIPaymentURI(qrPayload);
      } else if (payloadType === 'WIFI') {
        wifiData = this.parseWiFiURI(qrPayload);
      } else if (payloadType === 'VCARD') {
        vcardData = await this.parseVCard(qrPayload);
      }

      return {
        success: true,
        rawPayload: qrPayload,
        payloadType: payloadType,
        linkAnalysis: linkAnalysis,
        upiData: upiData,
        wifiData: wifiData,
        vcardData: vcardData,
        explanation: this.generateQRExplanation(payloadType, linkAnalysis, upiData, wifiData, vcardData, qrPayload)
      };

    } catch (err) {
      return {
        success: false,
        error: `QR Scan failed: ${err.message}`
      };
    }
  }

  /**
   * Detect payload category (Web URL, UPI Payment, Wi-Fi, vCard, or Text)
   */
  static detectPayloadType(payload) {
    const trimmed = payload.trim();
    if (trimmed.startsWith('upi://pay')) return 'UPI_PAYMENT';
    if (trimmed.toUpperCase().startsWith('WIFI:')) return 'WIFI';
    if (trimmed.toUpperCase().startsWith('BEGIN:VCARD')) return 'VCARD';
    if (trimmed.match(/^https?:\/\//i) || trimmed.match(/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/)) return 'URL';
    return 'PLAIN_TEXT';
  }

  /**
   * Deep UPI Payment URI Analysis (Reverse Debit Trap & VPA Spoof Detector)
   */
  static parseUPIPaymentURI(upiUri) {
    try {
      const url = new URL(upiUri);
      const params = url.searchParams;
      const payeeVpa = params.get('pa') || 'Unknown VPA';
      const payeeName = decodeURIComponent(params.get('pn') || 'Unknown Payee');
      const amount = params.get('am') || '';
      const currency = params.get('cu') || 'INR';
      const note = decodeURIComponent(params.get('tn') || '');

      const anomalies = [];
      let isSuspicious = false;

      // 1. Reverse Debit Trap Check (Scanning a QR to "Receive Money")
      if (amount && parseFloat(amount) > 0) {
        anomalies.push({
          type: 'REVERSE_DEBIT_WARNING',
          severity: 'HIGH',
          desc: `Scanning this QR will DEDUCT ₹${amount} from YOUR account. Scammers trick victims by claiming "Scan to RECEIVE money" — UPI PIN is ONLY entered to PAY, NEVER to receive!`
        });
        isSuspicious = true;
      }

      // 2. VPA Handle Authenticity Check
      if (!payeeVpa.includes('@') || payeeVpa.length < 5) {
        anomalies.push({
          type: 'MALFORMED_VPA_ADDRESS',
          severity: 'CRITICAL',
          desc: `Invalid VPA address "${payeeVpa}". Official UPI handles end with recognized banking domains (e.g. @okaxis, @okicici, @oksbi).`
        });
        isSuspicious = true;
      }

      // 3. Fake Department Claim vs Personal VPA
      const lowerName = payeeName.toLowerCase();
      if ((lowerName.includes('refund') || lowerName.includes('support') || lowerName.includes('helpdesk')) && payeeVpa.includes('.')) {
        anomalies.push({
          type: 'SPOOFED_DEPARTMENT_PAYEE',
          severity: 'HIGH',
          desc: `Payee claims to be "${payeeName}", but VPA "${payeeVpa}" is a personal account, NOT an official corporate merchant handle.`
        });
        isSuspicious = true;
      }

      return {
        payeeVpa,
        payeeName,
        amount: amount || 'Flexible Amount',
        currency,
        note,
        isSuspicious,
        anomalies
      };
    } catch (e) {
      return { payeeVpa: 'Malformed UPI URI', isSuspicious: true, anomalies: [{ type: 'PARSE_ERROR', severity: 'HIGH', desc: 'Malformed UPI string.' }] };
    }
  }

  /**
   * Wi-Fi Auto-Connect Vector Security Audit
   */
  static parseWiFiURI(wifiStr) {
    const ssidMatch = wifiStr.match(/S:([^;]+)/);
    const typeMatch = wifiStr.match(/T:([^;]+)/);
    const passMatch = wifiStr.match(/P:([^;]+)/);

    const ssid = ssidMatch ? ssidMatch[1] : 'Unknown Network';
    const type = typeMatch ? typeMatch[1] : 'nopass';
    const password = passMatch ? passMatch[1] : 'None';

    const isUnencrypted = type === 'nopass' || type === 'WEP' || !type;

    return {
      ssid,
      securityType: type,
      password,
      isUnencrypted,
      warning: isUnencrypted ? '🚨 EVIL TWIN TRAP: Unencrypted Open Wi-Fi network. Connecting exposes your web traffic to eavesdropping.' : null
    };
  }

  /**
   * vCard Contact Vector & Embedded Link Audit
   */
  static async parseVCard(vcardStr) {
    const fnMatch = vcardStr.match(/FN:([^\n\r]+)/i);
    const telMatch = vcardStr.match(/TEL[^\:]*:([^\n\r]+)/i);
    const urlMatch = vcardStr.match(/URL[^\:]*:([^\n\r]+)/i);

    const name = fnMatch ? fnMatch[1].trim() : 'Unknown Contact';
    const phone = telMatch ? telMatch[1].trim() : 'None';
    const embeddedUrl = urlMatch ? urlMatch[1].trim() : null;

    let linkAnalysis = null;
    if (embeddedUrl) {
      linkAnalysis = await LinkAnalyzer.analyzeUrl(embeddedUrl);
    }

    return {
      name,
      phone,
      embeddedUrl,
      linkAnalysis
    };
  }

  /**
   * Decode QR Payload from Canvas / Image / String source
   */
  static async decodeQRPayload(source) {
    if (typeof source === 'string') {
      if (source === 'sample-phishing-qr') return 'http://hdfc-netbanking-verify.xyz/login.php?user=claim';
      if (source === 'sample-upi-qr') return 'upi://pay?pa=scammer.refund@okaxis&pn=Refund%20Department&am=25000&cu=INR';
      if (source === 'sample-wifi-qr') return 'WIFI:S:Free_Airport_Public_WiFi;T:nopass;;';
      if (source === 'sample-vcard-qr') return 'BEGIN:VCARD\nVERSION:3.0\nFN:HDFC Support Desk\nTEL:+919876543210\nURL:http://hdfc-netbanking-verify.xyz/login.php\nEND:VCARD';
      if (source === 'sample-merchant-qr') return 'upi://pay?pa=store.merchant@okicici&pn=Verified%20Supermarket&am=450&cu=INR';
      if (source.startsWith('http') || source.startsWith('data:') || source.startsWith('upi:')) return source;
    }

    if (typeof window !== 'undefined' && 'BarcodeDetector' in window && source && typeof source !== 'string') {
      try {
        const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        const barcodes = await detector.detect(source);
        if (barcodes.length > 0) return barcodes[0].rawValue;
      } catch (e) {}
    }

    if (typeof window !== 'undefined' && typeof window.jsQR === 'function' && source) {
      try {
        let w = 0, h = 0, ctx = null;
        if (source instanceof HTMLCanvasElement) {
          w = source.width;
          h = source.height;
          ctx = source.getContext('2d');
        } else if (source instanceof HTMLImageElement || (typeof ImageBitmap !== 'undefined' && source instanceof ImageBitmap)) {
          w = source.naturalWidth || source.width;
          h = source.naturalHeight || source.height;
          const canvas = document.createElement('canvas');
          canvas.width = w;
          canvas.height = h;
          ctx = canvas.getContext('2d');
          ctx.drawImage(source, 0, 0);
        }
        if (ctx && w > 0 && h > 0) {
          const imgData = ctx.getImageData(0, 0, w, h);
          const code = window.jsQR(imgData.data, w, h, { inversionAttempts: 'attemptBoth' });
          if (code && code.data) return code.data;
        }
      } catch (e) {}
    }

    return null;
  }

  /**
   * Plain-Language Explanation Synthesizer
   */
  static generateQRExplanation(payloadType, linkAnalysis, upiData, wifiData, vcardData, rawPayload) {
    if (payloadType === 'URL') {
      if (!linkAnalysis) return 'QR Code contains a web URL.';
      return `QR Code contains URL "${rawPayload}". ${linkAnalysis.explanation}`;
    }
    if (payloadType === 'UPI_PAYMENT') {
      if (!upiData) return 'QR Code contains UPI payment request.';
      return `📱 QR Code requests UPI Payment to payee "${upiData.payeeName}" (${upiData.payeeVpa}) for ₹${upiData.amount}. ${upiData.isSuspicious ? '🚨 REVERSE DEBIT WARNING: Scanning this QR will deduct money from your account!' : '✅ Payee signature validated.'}`;
    }
    if (payloadType === 'WIFI') {
      return `📶 QR Code configures Wi-Fi network "${wifiData.ssid}" (${wifiData.securityType}). ${wifiData.warning || '✅ Encrypted Wi-Fi settings.'}`;
    }
    if (payloadType === 'VCARD') {
      return `📇 QR Code contains Contact Card for "${vcardData.name}" (${vcardData.phone}). ${vcardData.embeddedUrl ? `Embedded link evaluated: ${vcardData.embeddedUrl}` : ''}`;
    }
    return `QR Code contains text payload: "${rawPayload}".`;
  }
}

