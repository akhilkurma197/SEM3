/**
 * Trust Layer — Independent URL Feature Extractor
 * Extracts 28 deterministic structural, statistical, lexical, and information-theoretic features.
 * Features match standard academic literature and Kaggle datasets (PhiUSIIL / PhishTank).
 */

import { URLParser } from './url_parser.js';

export const SUSPICIOUS_TLDS_LIST = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.click',
  '.monster', '.fit', '.icu', '.loan', '.vip', '.rest', '.country', '.kim',
  '.science', '.gdn', '.racing', '.surf', '.fun', '.online', '.site', '.space',
  '.pw', '.cc', '.ws', '.biz', '.info', '.live', '.cyou'
];

export const URL_SHORTENERS_LIST = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'rb.gy', 'cutt.ly', 'ow.ly',
  'short.io', 'tiny.cc', 'lnkd.in', 'buff.ly', 'ift.tt', 'dlvr.it', 'soo.gd',
  'shorturl.at', 'url.ie', 'adf.ly', 'shrink.me', 'bl.ink'
];

export const SENSITIVE_KEYWORDS_LIST = [
  'login', 'signin', 'verify', 'verification', 'update', 'banking', 'secure',
  'account', 'credential', 'password', 'refund', 'reward', 'cashback', 'kyc',
  'support', 'otp', 'pin', 'payment', 'transaction', 'free', 'bonus', 'claim',
  'authenticate', 'wallet', 'security'
];

export const BRAND_TOKENS_LIST = [
  'hdfc', 'icici', 'sbi', 'onlinesbi', 'axis', 'paytm', 'phonepe', 'gpay',
  'google', 'amazon', 'flipkart', 'paypal', 'microsoft', 'apple', 'netflix',
  'whatsapp', 'facebook', 'instagram', 'binance', 'coinbase', 'metamask'
];

export const HOMOGLYPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'Ү': 'Y'
};

export class URLFeatureExtractor {
  /**
   * Complete Feature Schema definition
   */
  static get SCHEMA() {
    return [
      { name: 'url_length', type: 'numeric', description: 'Total character length of the normalized URL' },
      { name: 'hostname_length', type: 'numeric', description: 'Character length of the hostname' },
      { name: 'path_length', type: 'numeric', description: 'Character length of the pathname' },
      { name: 'query_length', type: 'numeric', description: 'Character length of the query string' },
      { name: 'num_dots', type: 'numeric', description: 'Number of dot (.) characters in URL' },
      { name: 'num_hyphens', type: 'numeric', description: 'Number of hyphen (-) characters in hostname' },
      { name: 'num_digits', type: 'numeric', description: 'Total digit count in URL' },
      { name: 'num_special_chars', type: 'numeric', description: 'Total special characters count in URL' },
      { name: 'num_slashes', type: 'numeric', description: 'Number of slash (/) characters in path' },
      { name: 'num_at_symbols', type: 'numeric', description: 'Count of @ symbols (credential injection)' },
      { name: 'num_percent_encoded', type: 'numeric', description: 'Count of % hex-encoded character sequences' },
      { name: 'num_subdomains', type: 'numeric', description: 'Count of subdomain levels' },
      { name: 'num_parameters', type: 'numeric', description: 'Count of query parameters' },
      { name: 'num_path_segments', type: 'numeric', description: 'Count of directory path segments' },
      { name: 'has_ip_address', type: 'binary', description: '1 if hostname is a raw IPv4/IPv6 address, else 0' },
      { name: 'has_punycode', type: 'binary', description: '1 if hostname contains punycode (xn--) or non-ASCII, else 0' },
      { name: 'has_port', type: 'binary', description: '1 if non-standard port specified in URL, else 0' },
      { name: 'has_https', type: 'binary', description: '1 if protocol is HTTPS, else 0' },
      { name: 'has_suspicious_tld', type: 'binary', description: '1 if TLD is in high-abuse registrar list, else 0' },
      { name: 'digit_ratio', type: 'numeric', description: 'Ratio of digits to total URL length' },
      { name: 'special_char_ratio', type: 'numeric', description: 'Ratio of special chars to total URL length' },
      { name: 'hostname_entropy', type: 'numeric', description: 'Shannon entropy (randomness) of hostname string' },
      { name: 'path_entropy', type: 'numeric', description: 'Shannon entropy of path string' },
      { name: 'url_entropy', type: 'numeric', description: 'Shannon entropy of entire URL string' },
      { name: 'has_sensitive_keyword', type: 'binary', description: '1 if path/query contains sensitive fraud keywords' },
      { name: 'has_brand_token_mismatch', type: 'binary', description: '1 if brand keyword in path/subdomain but not official domain' },
      { name: 'is_url_shortener', type: 'binary', description: '1 if domain is a known URL shortening service' },
      { name: 'has_homoglyphs', type: 'binary', description: '1 if hostname contains lookalike Cyrillic/Greek characters' }
    ];
  }

  /**
   * Computes Shannon Entropy: H(X) = -Σ P(x) * log2(P(x))
   * @param {string} str 
   * @returns {number}
   */
  static calculateShannonEntropy(str) {
    if (!str || typeof str !== 'string' || str.length === 0) return 0.0;
    const len = str.length;
    const freqs = {};
    for (let i = 0; i < len; i++) {
      const c = str[i];
      freqs[c] = (freqs[c] || 0) + 1;
    }

    let entropy = 0.0;
    for (const char in freqs) {
      const p = freqs[char] / len;
      entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(4));
  }

  /**
   * Main Feature Extraction Entry Point
   * @param {string} rawUrl 
   * @returns {{
   *   extractionStatus: string,
   *   parsed: object,
   *   features: object,
   *   featureVector: number[],
   *   schemaVersion: string
   * }}
   */
  static extract(rawUrl) {
    const parsed = URLParser.parse(rawUrl);
    if (!parsed.isValid) {
      return {
        extractionStatus: 'FAILED',
        error: parsed.error,
        parsed,
        features: null,
        featureVector: null,
        schemaVersion: 'url_features_v1.0'
      };
    }

    const url = parsed.normalizedUrl;
    const host = parsed.hostname;
    const path = parsed.pathname;
    const query = parsed.query;

    // Character metrics
    const num_dots = (url.match(/\./g) || []).length;
    const num_hyphens = (host.match(/-/g) || []).length;
    const num_digits = (url.match(/\d/g) || []).length;
    const num_special_chars = (url.match(/[^a-zA-Z0-9]/g) || []).length;
    const num_slashes = (path.match(/\//g) || []).length;
    const num_at_symbols = (url.match(/@/g) || []).length;
    const num_percent_encoded = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;

    // Path segments & query params
    const pathSegments = path.split('/').filter(Boolean);
    const num_path_segments = pathSegments.length;
    let num_parameters = 0;
    if (query && query.length > 1) {
      num_parameters = query.substring(1).split('&').filter(Boolean).length;
    }

    // Binary indicators
    const has_ip_address = parsed.isIp ? 1 : 0;
    const has_punycode = parsed.isPunycode ? 1 : 0;
    const has_port = parsed.port && parsed.port !== '80' && parsed.port !== '443' ? 1 : 0;
    const has_https = parsed.protocol === 'https:' ? 1 : 0;
    const has_suspicious_tld = SUSPICIOUS_TLDS_LIST.some(tld => host.endsWith(tld)) ? 1 : 0;
    const is_url_shortener = URL_SHORTENERS_LIST.some(s => host === s || host.endsWith('.' + s)) ? 1 : 0;

    // Ratios
    const url_length = url.length;
    const digit_ratio = url_length > 0 ? parseFloat((num_digits / url_length).toFixed(4)) : 0;
    const special_char_ratio = url_length > 0 ? parseFloat((num_special_chars / url_length).toFixed(4)) : 0;

    // Entropies
    const hostname_entropy = this.calculateShannonEntropy(host);
    const path_entropy = this.calculateShannonEntropy(path);
    const url_entropy = this.calculateShannonEntropy(url);

    // Semantic tokens
    const pathAndQueryLower = (path + query).toLowerCase();
    let sensitive_word_count = 0;
    for (const kw of SENSITIVE_KEYWORDS_LIST) {
      if (pathAndQueryLower.includes(kw) || host.includes(kw)) {
        sensitive_word_count++;
      }
    }
    const has_sensitive_keyword = sensitive_word_count > 0 ? 1 : 0;

    // Brand mismatch
    let has_brand_token_mismatch = 0;
    let brand_token_count = 0;
    const detected_brands = [];
    for (const b of BRAND_TOKENS_LIST) {
      if (pathAndQueryLower.includes(b) || host.includes(b)) {
        brand_token_count++;
        detected_brands.push(b);
        const dom = (parsed.domain || '').toLowerCase();
        const isOfficialApex = dom === `${b}.com` ||
          dom === `${b}.in` ||
          dom === `${b}.co.in` ||
          dom === `${b}.org` ||
          dom === `${b}bank.com` ||
          dom === `onlinesbi.sbi`;
        if (!isOfficialApex) {
          has_brand_token_mismatch = 1;
        }
      }
    }

    // Homoglyphs (check raw input string, punycode and normalized host)
    let has_homoglyphs = parsed.isPunycode ? 1 : 0;
    if (!has_homoglyphs) {
      const checkStr = (parsed.rawInput || '') + host;
      for (let char of checkStr) {
        if (HOMOGLYPH_MAP[char]) {
          has_homoglyphs = 1;
          break;
        }
      }
    }

    const features = {
      url_length,
      hostname_length: host.length,
      path_length: path.length,
      query_length: query.length,
      num_dots,
      num_hyphens,
      num_digits,
      num_special_chars,
      num_slashes,
      num_at_symbols,
      num_percent_encoded,
      num_subdomains: parsed.subdomains.length,
      num_parameters,
      num_path_segments,
      has_ip_address,
      has_punycode,
      has_port,
      has_https,
      has_suspicious_tld,
      digit_ratio,
      special_char_ratio,
      hostname_entropy,
      path_entropy,
      url_entropy,
      has_sensitive_keyword,
      has_brand_token_mismatch,
      is_url_shortener,
      has_homoglyphs,
      sensitive_word_count,
      brand_token_count,
      detected_brands
    };

    const featureVector = [
      features.url_length,
      features.hostname_length,
      features.path_length,
      features.query_length,
      features.num_dots,
      features.num_hyphens,
      features.num_digits,
      features.num_special_chars,
      features.num_slashes,
      features.num_at_symbols,
      features.num_percent_encoded,
      features.num_subdomains,
      features.num_parameters,
      features.num_path_segments,
      features.has_ip_address,
      features.has_punycode,
      features.has_port,
      features.has_https,
      features.has_suspicious_tld,
      features.digit_ratio,
      features.special_char_ratio,
      features.hostname_entropy,
      features.path_entropy,
      features.url_entropy,
      features.has_sensitive_keyword,
      features.has_brand_token_mismatch,
      features.is_url_shortener,
      features.has_homoglyphs
    ];

    return {
      extractionStatus: 'SUCCESS',
      parsed,
      features,
      featureVector,
      schemaVersion: 'url_features_v1.0'
    };
  }
}
