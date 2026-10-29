/**
 * Trust Layer — Robust URL Normalizer & Parser
 * Complies with WHATWG URL standards and strictly handles edge cases:
 * IP addresses, Punycode, ports, authentication tokens, deep paths, query strings, and fragments.
 */

export class URLParser {
  /**
   * Normalizes raw input string into a valid absolute URL format.
   * Ensures protocols are standard and removes leading/trailing whitespace.
   * @param {string} rawInput 
   * @returns {string}
   */
  static normalizeInput(rawInput) {
    if (!rawInput || typeof rawInput !== 'string') return '';
    let clean = rawInput.trim();

    // Preserve non-HTTP schemes if already present (e.g. upi://, mailto:)
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(clean)) {
      return clean;
    }

    // Default to https:// if scheme is missing
    return 'https://' + clean;
  }

  /**
   * Robustly parses a URL string into structured components.
   * Guaranteed: protocol is never parsed as hostname.
   * @param {string} input 
   * @returns {{
   *   isValid: boolean,
   *   rawInput: string,
   *   normalizedUrl: string,
   *   protocol: string,
   *   hostname: string,
   *   port: string,
   *   pathname: string,
   *   query: string,
   *   fragment: string,
   *   subdomains: string[],
   *   domain: string,
   *   tld: string,
   *   isIp: boolean,
   *   isPunycode: boolean,
   *   error: string|null
   * }}
   */
  static parse(input) {
    const raw = typeof input === 'string' ? input.trim() : '';
    if (!raw) {
      return this._invalidResult(raw, 'Empty URL string');
    }

    const normalized = this.normalizeInput(raw);

    let parsed;
    try {
      parsed = new URL(normalized);
    } catch (err) {
      return this._invalidResult(raw, `URL parsing failed: ${err.message}`);
    }

    const protocol = parsed.protocol || '';
    let hostname = parsed.hostname || '';

    // Safety guard: hostname must never be a protocol token
    if (['http:', 'https:', 'ftp:', 'ws:', 'wss:', 'http', 'https'].includes(hostname.toLowerCase())) {
      return this._invalidResult(raw, 'Malformed URL: Protocol parsed as hostname');
    }

    // Lowercase hostname for consistent processing
    hostname = hostname.toLowerCase();

    // Check IP address format (IPv4)
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[?[a-fA-F0-9:]+\]?$/.test(hostname);

    // Check Punycode / IDN
    const isPunycode = hostname.includes('xn--') || /[^\u0000-\u007F]/.test(hostname);

    // Subdomain decomposition
    const parts = hostname.split('.').filter(Boolean);
    let subdomains = [];
    let domain = hostname;
    let tld = '';

    if (isIp) {
      domain = hostname;
      tld = '';
    } else if (parts.length >= 2) {
      tld = '.' + parts[parts.length - 1];
      // Handle known two-part TLDs (e.g. .co.in, .co.uk, .com.au, .gov.in)
      const secondLevelTlds = ['co.in', 'co.uk', 'com.au', 'co.jp', 'gov.in', 'org.in', 'ac.in', 'edu.in'];
      const lastTwo = parts.slice(-2).join('.');
      if (secondLevelTlds.includes(lastTwo) && parts.length >= 3) {
        tld = '.' + lastTwo;
        domain = parts.slice(-3).join('.');
        subdomains = parts.slice(0, -3);
      } else {
        domain = parts.slice(-2).join('.');
        subdomains = parts.slice(0, -2);
      }
    }

    // Tracking & Functional parameter decomposition (Section 8)
    const TRACKING_KEYS = new Set([
      'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
      'fbclid', 'gclid', 'gclsrc', 'dclid', 'msclkid', 'mc_eid', '_ga',
      'ref', 'fref'
    ]);

    const trackingParameters = {};
    const functionalParameters = {};
    const cleanUrlObj = new URL(parsed.href);
    let hasTrackingParams = false;

    for (const [key, val] of parsed.searchParams.entries()) {
      const keyLower = key.toLowerCase();
      if (TRACKING_KEYS.has(keyLower)) {
        trackingParameters[key] = val;
        hasTrackingParams = true;
        cleanUrlObj.searchParams.delete(key);
      } else {
        functionalParameters[key] = val;
      }
    }

    const cleanNormalizedUrl = cleanUrlObj.href;

    return {
      isValid: true,
      rawInput: raw,
      normalizedUrl: parsed.href,
      cleanNormalizedUrl,
      protocol,
      hostname,
      port: parsed.port || '',
      pathname: parsed.pathname || '/',
      query: parsed.search || '',
      fragment: parsed.hash || '',
      subdomains,
      domain,
      tld,
      isIp,
      isPunycode,
      trackingParameters,
      functionalParameters,
      hasTrackingParams,
      error: null
    };
  }

  static _invalidResult(raw, errorMsg) {
    return {
      isValid: false,
      rawInput: raw,
      normalizedUrl: '',
      protocol: '',
      hostname: '',
      port: '',
      pathname: '',
      query: '',
      fragment: '',
      subdomains: [],
      domain: '',
      tld: '',
      isIp: false,
      isPunycode: false,
      error: errorMsg
    };
  }
}
