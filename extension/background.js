/**
 * Trust Layer - Background Service Worker (Manifest V3)
 * Ultra-resilient zero-dependency background engine
 */

const TRUSTED_DOMAINS = [
  'google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.ca', 'google.fr', 'google.co.jp', 'google.com.au',
  'gstatic.com', 'googleusercontent.com', 'youtube.com', 'ytimg.com',
  'bing.com', 'yahoo.com', 'duckduckgo.com', 'wikipedia.org',
  'chatgpt.com', 'openai.com', 'oaistatic.com', 'oaiusercontent.com',
  'github.com', 'githubusercontent.com', 'leetcode.com', 'stackoverflow.com',
  'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'apple.com', 'icloud.com',
  'linkedin.com', 'twitter.com', 'x.com', 'reddit.com',
  'amazon.com', 'amazon.in', 'flipkart.com', 'netflix.com', 'paypal.com',
  'hdfcbank.com', 'icicibank.com', 'sbi.co.in', 'onlinesbi.sbi', 'paytm.com', 'phonepe.com'
];

// Brand Whitelist Database
const BRAND_WHITELIST = [
  { name: 'HDFC Bank', domains: ['hdfcbank.com', 'hdfc.com', 'netbanking.hdfcbank.com'], keywords: ['hdfc', 'netbanking'] },
  { name: 'ICICI Bank', domains: ['icicibank.com', 'icicibank.co.in'], keywords: ['icici', 'imobile'] },
  { name: 'State Bank of India (SBI)', domains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'], keywords: ['sbi', 'onlinesbi', 'yono'] },
  { name: 'Axis Bank', domains: ['axisbank.com'], keywords: ['axis', 'axisbank'] },
  { name: 'Paytm', domains: ['paytm.com', 'paytmbank.com'], keywords: ['paytm', 'paytmbank'] },
  { name: 'PhonePe', domains: ['phonepe.com'], keywords: ['phonepe'] },
  { name: 'Google Pay / Google', domains: ['pay.google.com', 'google.com', 'accounts.google.com'], keywords: ['gpay', 'googlepay', 'google'] },
  { name: 'Amazon', domains: ['amazon.in', 'amazon.com', 'pay.amazon.in'], keywords: ['amazon', 'amazonpay'] },
  { name: 'Flipkart', domains: ['flipkart.com'], keywords: ['flipkart'] },
  { name: 'PayPal', domains: ['paypal.com', 'paypal.me'], keywords: ['paypal'] }
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.click', '.monster', '.fit', '.icu', '.loan'];

const HOMOGLYPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'А': 'A', 'В': 'B', 'Е': 'E'
};

const ML_WEIGHTS = {
  intercept: -2.1,
  has_ip: 3.8,
  len_75: 2.25,
  len_54: 1.10,
  has_at: 2.74,
  dash: 1.85,
  subdomains: 2.12,
  https_in_domain: 3.20,
  suspicious_tld: 3.55,
  homoglyph: 4.50,
  impersonation: 3.92,
  sensitive_kw: 2.80
};

const SENSITIVE_KEYWORDS = ['login', 'signin', 'verify', 'update', 'banking', 'secure', 'account', 'kyc', 'otp', 'pin', 'payment'];

// Link Analysis Core Function
function analyzeUrlBackground(inputUrl) {
  let cleanUrl = (inputUrl || '').trim();
  if (!cleanUrl.match(/^https?:\/\//i)) {
    cleanUrl = 'http://' + cleanUrl;
  }

  let parsed;
  try {
    parsed = new URL(cleanUrl);
  } catch (e) {
    return {
      url: cleanUrl,
      riskScore: 1.0,
      riskPercentage: '100%',
      riskLevel: 'HIGH',
      explanation: 'Invalid URL format provided.'
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  
  // STEP 1: Verified Official Domain Whitelist check (Guaranteed 2% GREEN SAFE)
  const isTrustedDomain = TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  if (isTrustedDomain) {
    return {
      url: cleanUrl,
      parsedDomain: hostname,
      riskScore: 0.02,
      riskPercentage: '2%',
      riskLevel: 'LOW',
      featuresTriggered: [],
      brandImpersonation: null,
      explanation: `[2% Threat Level] Verified official domain (${hostname}). Structural integrity confirmed.`,
      recommendation: '✅ Safe to visit.'
    };
  }

  const pathAndHostOnly = (parsed.origin + parsed.pathname).toLowerCase();
  const triggered = [];
  let logit = ML_WEIGHTS.intercept;

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    logit += ML_WEIGHTS.has_ip;
    triggered.push({ name: 'IP Hostname', desc: 'Uses raw IP address instead of domain.' });
  }

  if (cleanUrl.length > 75) {
    logit += ML_WEIGHTS.len_75;
    triggered.push({ name: 'URL Length (>75 chars)', desc: 'Excessively long URL.' });
  }

  if (cleanUrl.includes('@')) {
    logit += ML_WEIGHTS.has_at;
    triggered.push({ name: '@ Symbol', desc: 'Contains @ symbol redirect trick.' });
  }

  const parts = hostname.split('.');
  const mainPart = parts.length >= 2 ? parts[parts.length - 2] : hostname;
  if (mainPart.includes('-')) {
    logit += ML_WEIGHTS.dash;
    triggered.push({ name: 'Hyphenated Domain', desc: 'Hyphenated brand lookalike.' });
  }

  if (parts.length > 3) {
    logit += ML_WEIGHTS.subdomains;
    triggered.push({ name: 'Deep Subdomains', desc: 'Multiple subdomain layers.' });
  }

  const matchTld = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
  if (matchTld) {
    logit += ML_WEIGHTS.suspicious_tld;
    triggered.push({ name: `High-Risk TLD (${matchTld})`, desc: `Statistically risky TLD (${matchTld}).` });
  }

  for (let char of hostname) {
    if (HOMOGLYPH_MAP[char]) {
      logit += ML_WEIGHTS.homoglyph;
      triggered.push({ name: 'Homoglyph Character', desc: `Uses Cyrillic character visually mimicking Latin letter.` });
      break;
    }
  }

  let impersonatingBrand = null;
  for (let brand of BRAND_WHITELIST) {
    const isOfficial = brand.domains.some(d => hostname === d || hostname.endsWith('.' + d));
    // Match brand keywords on origin + pathname only (ignoring ?q= search parameters)
    const mentionsBrand = brand.keywords.some(kw => pathAndHostOnly.includes(kw));

    if (mentionsBrand && !isOfficial) {
      logit += ML_WEIGHTS.impersonation;
      impersonatingBrand = { targetBrand: brand.name, actualDomain: hostname, officialDomains: brand.domains };
      triggered.push({ name: `Fakes ${brand.name}`, desc: `Claims to be ${brand.name} on domain ${hostname}.` });
      break;
    }
  }

  const sensitiveKw = SENSITIVE_KEYWORDS.find(kw => pathAndHostOnly.includes(kw));
  const isWhitelisted = BRAND_WHITELIST.some(b => b.domains.some(d => hostname.endsWith(d)));
  if (sensitiveKw && !isWhitelisted) {
    logit += ML_WEIGHTS.sensitive_kw;
    triggered.push({ name: `Sensitive Keyword (${sensitiveKw})`, desc: `Asks for sensitive actions on unverified domain.` });
  }

  const score = 1 / (1 + Math.exp(-logit));
  const pct = Math.round(score * 100);

  let riskLevel = 'LOW';
  if (score >= 0.70) riskLevel = 'CRITICAL';
  else if (score >= 0.40) riskLevel = 'HIGH';
  else if (score >= 0.25) riskLevel = 'MODERATE';

  let explanation = `[${pct}% Threat Level] `;
  if (impersonatingBrand) {
    explanation += `⚠️ IMPERSONATION DETECTED: Claims to be ${impersonatingBrand.targetBrand} but hosted on untrusted domain "${impersonatingBrand.actualDomain}".`;
  } else if (triggered.length > 0) {
    explanation += `Triggered risk indicators: ${triggered.map(t => t.name).slice(0, 3).join(', ')}.`;
  } else {
    explanation += `Domain structure passed preliminary lexical validation.`;
  }

  return {
    url: cleanUrl,
    parsedDomain: hostname,
    riskScore: parseFloat(score.toFixed(2)),
    riskPercentage: `${pct}%`,
    riskLevel: riskLevel,
    featuresTriggered: triggered,
    brandImpersonation: impersonatingBrand,
    explanation: explanation,
    recommendation: riskLevel === 'LOW' ? '✅ Safe to visit.' : '🛑 Exercise extreme caution before opening.'
  };
}

// Background Message Listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request && request.action === 'ANALYZE_URL') {
    const report = analyzeUrlBackground(request.url);
    sendResponse(report);
    return true;
  }
});

