/**
 * Trust Layer — Unified QR Code Guardian & Payload Investigator
 * Parses QR payloads (UPI, URL, Wi-Fi, vCard, Email, Tel, SMS, Text)
 * and evaluates expected context consistency and payment payload integrity.
 */

import { URLParser } from '../ml/url_parser.js';

export class QREngine {
  /**
   * Decodes and parses raw QR code payload
   * @param {string} rawPayload 
   * @returns {{
   *   type: 'URL' | 'UPI' | 'WIFI' | 'VCARD' | 'EMAIL' | 'TEL' | 'SMS' | 'TEXT',
   *   target: string,
   *   parsedData: object,
   *   isSuspicious: boolean,
   *   claimedIdentity: string|null,
   *   anomalies: string[],
   *   actionPreview: object
   * }}
   */
  static analyzePayload(rawPayload) {
    if (!rawPayload || typeof rawPayload !== 'string') {
      return {
        type: 'TEXT',
        target: '',
        parsedData: {},
        isSuspicious: false,
        claimedIdentity: null,
        anomalies: ['Empty or invalid QR payload'],
        actionPreview: { action: 'NONE', description: 'Empty or invalid payload' }
      };
    }

    const clean = rawPayload.trim();

    // 1. UPI Payment URI
    if (clean.startsWith('upi://pay')) {
      const anomalies = [];
      let payeeName = null;
      let payeeVpa = null;
      let amount = null;
      let note = null;
      let currency = 'INR';

      try {
        const url = new URL(clean);
        payeeVpa = url.searchParams.get('pa') || '';
        payeeName = decodeURIComponent(url.searchParams.get('pn') || '');
        amount = url.searchParams.get('am') || null;
        note = decodeURIComponent(url.searchParams.get('tn') || '');
        currency = url.searchParams.get('cu') || 'INR';

        // Check for reverse payment scams (e.g. note claiming "Receive Refund" when initiating a debit)
        const isReverseDebitLure = Boolean(note && ['refund', 'cashback', 'reward', 'receive', 'winner', 'claim', 'bonus', 'credit'].some(w => note.toLowerCase().includes(w)));
        const isMalformedVpa = !payeeVpa || !payeeVpa.includes('@');

        if (isReverseDebitLure) {
          anomalies.push(`Reverse Debit Scam Lure: Note claims "${note}" while initiating a debit request`);
        }
        if (isMalformedVpa) {
          anomalies.push('Malformed or missing Payee VPA address');
        }
      } catch {}

      const isSuspicious = anomalies.length > 0;

      return {
        type: 'UPI',
        target: clean,
        parsedData: { payeeVpa, payeeName, amount, note, currency },
        isSuspicious,
        claimedIdentity: payeeName || payeeVpa,
        anomalies,
        actionPreview: {
          action: 'PAYMENT_DEBIT',
          recipient: payeeVpa,
          merchantName: payeeName || 'Unspecified Payee',
          amount: amount ? `₹${amount} ${currency}` : 'User-entered amount',
          note: note || 'None',
          warning: isSuspicious ? anomalies.join('; ') : null
        }
      };
    }

    // 2. Wi-Fi Configuration URI
    if (clean.startsWith('WIFI:') || clean.startsWith('wifi:')) {
      const ssidMatch = clean.match(/S:([^;]+)/i);
      const typeMatch = clean.match(/T:([^;]+)/i);
      const passMatch = clean.match(/P:([^;]+)/i);

      const ssid = ssidMatch ? ssidMatch[1] : 'Unknown';
      const securityType = typeMatch ? typeMatch[1].toUpperCase() : 'OPEN';
      const password = passMatch ? passMatch[1] : '';

      const isUnencrypted = securityType === 'NOPASS' || securityType === 'OPEN' || !password;
      const anomalies = isUnencrypted ? ['Unencrypted Open Wi-Fi Network (Vulnerable to credential sniffing)'] : [];

      return {
        type: 'WIFI',
        target: clean,
        parsedData: { ssid, securityType, password },
        isSuspicious: isUnencrypted,
        claimedIdentity: `Wi-Fi SSID: ${ssid}`,
        anomalies,
        actionPreview: {
          action: 'WIFI_CONNECT',
          ssid,
          securityType,
          warning: isUnencrypted ? 'Open Wi-Fi without encryption. Connecting exposes device network traffic.' : null
        }
      };
    }

    // 3. Contact Card (vCard)
    if (clean.toUpperCase().startsWith('BEGIN:VCARD')) {
      const fnMatch = clean.match(/FN:([^\n\r]+)/i);
      const telMatch = clean.match(/TEL[^\:]*:([^\n\r]+)/i);
      const emailMatch = clean.match(/EMAIL[^\:]*:([^\n\r]+)/i);
      const urlMatch = clean.match(/URL[^\:]*:([^\n\r]+)/i);

      const name = fnMatch ? fnMatch[1].trim() : 'Unknown Contact';
      const phone = telMatch ? telMatch[1].trim() : null;
      const email = emailMatch ? emailMatch[1].trim() : null;
      const embeddedUrl = urlMatch ? urlMatch[1].trim() : null;

      const anomalies = [];
      if (embeddedUrl && (embeddedUrl.includes('login') || embeddedUrl.includes('verify') || embeddedUrl.includes('claim'))) {
        anomalies.push(`vCard contains high-risk embedded link: ${embeddedUrl}`);
      }

      return {
        type: 'VCARD',
        target: clean,
        parsedData: { name, phone, email, embeddedUrl },
        isSuspicious: anomalies.length > 0,
        claimedIdentity: name,
        anomalies,
        actionPreview: {
          action: 'CONTACT_SAVE',
          name,
          phone: phone || 'None',
          email: email || 'None',
          embeddedUrl: embeddedUrl || 'None',
          warning: anomalies.length > 0 ? anomalies[0] : null
        }
      };
    }

    // 4. Email Link (mailto:)
    if (clean.toLowerCase().startsWith('mailto:')) {
      let recipient = '';
      let subject = '';
      let body = '';
      try {
        const u = new URL(clean);
        recipient = u.pathname;
        subject = u.searchParams.get('subject') || '';
        body = u.searchParams.get('body') || '';
      } catch {
        recipient = clean.replace(/^mailto:/i, '').split('?')[0];
      }

      return {
        type: 'EMAIL',
        target: clean,
        parsedData: { recipient, subject, body },
        isSuspicious: false,
        claimedIdentity: recipient,
        anomalies: [],
        actionPreview: {
          action: 'SEND_EMAIL',
          recipient,
          subject: subject || 'No subject',
          bodySnippet: body ? body.substring(0, 100) : 'None'
        }
      };
    }

    // 5. Telephone Call Link (tel:)
    if (clean.toLowerCase().startsWith('tel:')) {
      const phone = clean.replace(/^tel:/i, '').trim();
      const anomalies = [];
      if (phone.startsWith('+1900') || phone.startsWith('+91900') || phone.startsWith('1900')) {
        anomalies.push('Premium-rate phone number detected (Potential toll fraud)');
      }

      return {
        type: 'TEL',
        target: clean,
        parsedData: { phone },
        isSuspicious: anomalies.length > 0,
        claimedIdentity: phone,
        anomalies,
        actionPreview: {
          action: 'PHONE_CALL',
          phone,
          warning: anomalies.length > 0 ? anomalies[0] : null
        }
      };
    }

    // 6. SMS Message Link (sms: / smsto:)
    if (clean.toLowerCase().startsWith('sms:') || clean.toLowerCase().startsWith('smsto:')) {
      const parts = clean.replace(/^sms(to)?:/i, '').split(/[\?\&:]/);
      const recipient = parts[0] || '';
      const bodyMatch = clean.match(/[?&]body=([^&]+)/i);
      const body = bodyMatch ? decodeURIComponent(bodyMatch[1]) : '';

      return {
        type: 'SMS',
        target: clean,
        parsedData: { recipient, body },
        isSuspicious: false,
        claimedIdentity: recipient,
        anomalies: [],
        actionPreview: {
          action: 'SEND_SMS',
          recipient,
          message: body || 'Empty message'
        }
      };
    }

    // 7. Web URL (http://, https://, or standard domain without spaces)
    const isExplicitUrl = clean.startsWith('http://') || clean.startsWith('https://');
    const isDomainPattern = !clean.includes(' ') && !clean.includes('\n') && /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?(\?.*)?$/i.test(clean);

    if (isExplicitUrl || isDomainPattern) {
      const targetUrl = isExplicitUrl ? clean : ('https://' + clean);
      const parsed = URLParser.parse(targetUrl);
      return {
        type: 'URL',
        target: parsed.isValid ? parsed.normalizedUrl : targetUrl,
        parsedData: { ...parsed },
        isSuspicious: false,
        claimedIdentity: parsed.hostname,
        anomalies: [],
        actionPreview: {
          action: 'OPEN_WEBSITE',
          url: parsed.isValid ? parsed.normalizedUrl : targetUrl,
          hostname: parsed.hostname,
          protocol: parsed.protocol
        }
      };
    }

    // 8. Plain Text Payload
    return {
      type: 'TEXT',
      target: clean,
      parsedData: { text: clean },
      isSuspicious: false,
      claimedIdentity: null,
      anomalies: [],
      actionPreview: {
        action: 'DISPLAY_TEXT',
        preview: clean.length > 120 ? clean.substring(0, 120) + '…' : clean
      }
    };
  }

  /**
   * QR Intent Mismatch Detection
   * Compares the user's expected context against the decoded payload.
   * @param {string} expectedContext User-provided context, e.g. 'RESTAURANT_MENU', 'PARCEL_TRACKING', etc.
   * @param {object} payloadAnalysis Output from analyzePayload()
   * @returns {{
   *   isMatch: boolean,
   *   status: 'MATCH' | 'POTENTIAL_MISMATCH' | 'MISMATCH' | 'UNKNOWN',
   *   expectedAction: string,
   *   decodedAction: string,
   *   explanation: string
   * }}
   */
  static evaluateContextConsistency(expectedContext, payloadAnalysis) {
    if (!expectedContext || expectedContext === 'NONE' || expectedContext === 'UNKNOWN') {
      return {
        isMatch: true,
        status: 'UNKNOWN',
        expectedAction: 'Unspecified Context',
        decodedAction: payloadAnalysis.actionPreview?.action || payloadAnalysis.type,
        explanation: 'No expected QR context provided for intent comparison.'
      };
    }

    const normContext = expectedContext.toUpperCase();
    const type = payloadAnalysis.type;

    // 1. Restaurant Menu Context
    if (normContext.includes('MENU')) {
      const expectedAction = 'View Food / Drink Menu (Document or Content Page)';
      if (type === 'UPI') {
        return {
          isMatch: false,
          status: 'MISMATCH',
          expectedAction,
          decodedAction: 'Initiate Direct UPI Payment Transfer',
          explanation: 'Stated context is a Restaurant Menu, but the QR code directly requests a financial payment. Review before proceeding.'
        };
      }
      if (type === 'WIFI') {
        return {
          isMatch: false,
          status: 'POTENTIAL_MISMATCH',
          expectedAction,
          decodedAction: 'Configure Wi-Fi Network Settings',
          explanation: 'QR code sets up a Wi-Fi connection rather than opening a digital menu.'
        };
      }
      return {
        isMatch: true,
        status: 'MATCH',
        expectedAction,
        decodedAction: 'Open Web Menu Link',
        explanation: 'QR code points to a web address consistent with a digital menu.'
      };
    }

    // 2. Parking Payment Context
    if (normContext.includes('PARKING')) {
      const expectedAction = 'Parking Fee Payment or Validation Portal';
      if (type === 'UPI' || type === 'URL') {
        return {
          isMatch: true,
          status: 'MATCH',
          expectedAction,
          decodedAction: type === 'UPI' ? 'UPI Payment Request' : 'Parking Web Portal',
          explanation: 'Payload type aligns with parking payment or digital ticket validation.'
        };
      }
      return {
        isMatch: false,
        status: 'POTENTIAL_MISMATCH',
        expectedAction,
        decodedAction: payloadAnalysis.actionPreview?.action || type,
        explanation: `QR code payload (${type}) is unusual for a parking payment terminal.`
      };
    }

    // 3. Parcel / Courier Tracking
    if (normContext.includes('PARCEL') || normContext.includes('PACKAGE') || normContext.includes('COURIER')) {
      const expectedAction = 'Shipment Status Tracking Portal';
      if (type === 'UPI') {
        return {
          isMatch: false,
          status: 'MISMATCH',
          expectedAction,
          decodedAction: 'UPI Debit Payment Transfer',
          explanation: 'Courier delivery notifications should not request direct money transfers. Possible fee extortion scam.'
        };
      }
      return {
        isMatch: true,
        status: 'MATCH',
        expectedAction,
        decodedAction: 'Tracking URL Navigation',
        explanation: 'QR payload provides a web tracking link.'
      };
    }

    // 4. Wi-Fi Access
    if (normContext.includes('WIFI')) {
      const expectedAction = 'Wi-Fi Network Configuration';
      if (type === 'WIFI') {
        return {
          isMatch: true,
          status: 'MATCH',
          expectedAction,
          decodedAction: 'Wi-Fi Network Profile',
          explanation: 'QR contains authentic Wi-Fi credentials profile.'
        };
      }
      return {
        isMatch: false,
        status: 'MISMATCH',
        expectedAction,
        decodedAction: payloadAnalysis.actionPreview?.action || type,
        explanation: `Expected Wi-Fi setup parameters, but QR provides ${type} instead.`
      };
    }

    // 5. Merchant Payment
    if (normContext.includes('MERCHANT') || normContext.includes('PAYMENT')) {
      const expectedAction = 'Merchant UPI / Payment Transfer';
      if (type === 'UPI') {
        return {
          isMatch: true,
          status: 'MATCH',
          expectedAction,
          decodedAction: 'UPI Payment Request',
          explanation: 'QR initiates a UPI payment as expected.'
        };
      }
      return {
        isMatch: false,
        status: 'POTENTIAL_MISMATCH',
        expectedAction,
        decodedAction: payloadAnalysis.actionPreview?.action || type,
        explanation: `Expected direct merchant payment QR, but received ${type}.`
      };
    }

    return {
      isMatch: true,
      status: 'UNKNOWN',
      expectedAction: expectedContext,
      decodedAction: payloadAnalysis.actionPreview?.action || type,
      explanation: `Action is ${payloadAnalysis.actionPreview?.action || type}.`
    };
  }

  /**
   * Payment Payload Integrity Checker (Section 10)
   */
  static validatePaymentIntegrity(upiData) {
    if (!upiData || !upiData.payeeVpa) {
      return {
        status: 'UNKNOWN',
        consistency: 'UNKNOWN',
        claims: {},
        observed: {},
        anomalies: ['Missing or malformed UPI payment parameters']
      };
    }

    const anomalies = [];
    let consistency = 'MATCH';

    // 1. Check VPA handle validity
    const hasValidHandle = upiData.payeeVpa.includes('@');
    if (!hasValidHandle) {
      anomalies.push('VPA address missing standard banking domain delimiter (@)');
      consistency = 'MISMATCH';
    }

    // 2. Check for reverse debit scam note
    const note = (upiData.note || '').toLowerCase();
    const isReverseDebit = ['refund', 'cashback', 'reward', 'claim', 'receive'].some(w => note.includes(w));
    if (isReverseDebit) {
      anomalies.push(`Transaction note claims "${upiData.note}" while initiating an account debit`);
      consistency = 'MISMATCH';
    }

    // 3. Check official vs personal handle
    const vpaDomain = upiData.payeeVpa.split('@')[1] || '';
    const recognizedHandles = ['okaxis', 'okhdfcbank', 'okicici', 'oksbi', 'paytm', 'ybl', 'axl', 'ibl'];
    const isRecognizedPsp = recognizedHandles.includes(vpaDomain.toLowerCase());

    return {
      status: anomalies.length > 0 ? 'SUSPICIOUS' : 'VALID_FORMAT',
      consistency,
      claims: {
        payeeVpa: upiData.payeeVpa,
        payeeName: upiData.payeeName || 'Not specified in QR',
        amount: upiData.amount ? `₹${upiData.amount}` : 'Open / Variable',
        note: upiData.note || 'None'
      },
      observed: {
        pspDomain: vpaDomain || 'Unknown',
        isRecognizedPsp,
        isDebitRequest: true,
        noteRisk: isReverseDebit ? 'HIGH (Reverse debit lure)' : 'STANDARD'
      },
      anomalies
    };
  }
}

