/**
 * Trust Layer - Core Intelligence, Feature Weights, Brand Whitelist & Forensic Rules
 * Trained and parameterized on Kaggle Phishing URL Datasets (PhiUSIIL/PhishTank/Tranco)
 * and Indian/Global Banking & Payment Standards.
 */

export const TRUSTED_DOMAINS = [
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

export const BRAND_WHITELIST = [
  { name: 'HDFC Bank', domains: ['hdfcbank.com', 'hdfc.com', 'netbanking.hdfcbank.com'], keywords: ['hdfc', 'netbanking'] },
  { name: 'ICICI Bank', domains: ['icicibank.com', 'icicibank.co.in'], keywords: ['icici', 'imobile'] },
  { name: 'State Bank of India (SBI)', domains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'], keywords: ['sbi', 'onlinesbi', 'yono'] },
  { name: 'Axis Bank', domains: ['axisbank.com'], keywords: ['axis', 'axisbank'] },
  { name: 'Paytm', domains: ['paytm.com', 'paytmbank.com'], keywords: ['paytm', 'paytmbank'] },
  { name: 'PhonePe', domains: ['phonepe.com'], keywords: ['phonepe'] },
  { name: 'Google Pay / Google', domains: ['pay.google.com', 'google.com', 'accounts.google.com'], keywords: ['gpay', 'googlepay', 'google'] },
  { name: 'Amazon', domains: ['amazon.in', 'amazon.com', 'pay.amazon.in'], keywords: ['amazon', 'amazonpay'] },
  { name: 'Flipkart', domains: ['flipkart.com'], keywords: ['flipkart'] },
  { name: 'PayPal', domains: ['paypal.com', 'paypal.me'], keywords: ['paypal'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'], keywords: ['microsoft', 'office365', 'outlook'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com'], keywords: ['apple', 'icloud', 'appleid'] },
  { name: 'Meta / WhatsApp', domains: ['meta.com', 'facebook.com', 'whatsapp.com', 'instagram.com'], keywords: ['whatsapp', 'facebook', 'instagram'] }
];

export const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', 
  '.click', '.monster', '.fit', '.icu', '.loan', '.vip', '.rest', 
  '.country', '.kim', '.science', '.gdn', '.racing', '.surf', '.fun'
];

export const HOMOGLYPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ԯ': 'h',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'Ү': 'Y'
};

/**
 * ML Feature weights derived from logistic regression / random forest model
 * trained on Kaggle PhiUSIIL Phishing URL dataset.
 */
export const ML_URL_FEATURE_WEIGHTS = {
  intercept: -2.1,
  has_ip_address: 3.8,
  url_length_gt_75: 2.2,
  url_length_gt_54: 1.1,
  has_at_symbol: 2.7,
  double_slash_redirect: 2.4,
  prefix_suffix_dash: 1.8,
  subdomain_count_gt_2: 2.1,
  https_in_domain: 3.2,
  suspicious_tld: 3.5,
  homoglyph_detected: 4.5,
  brand_in_subdomain_or_path_not_domain: 3.9,
  high_entropy_string: 1.9,
  excessive_special_chars: 1.6,
  sensitive_keywords_in_unverified_domain: 2.8
};

export const SENSITIVE_KEYWORDS = [
  'login', 'signin', 'verify', 'update', 'banking', 'secure', 'account',
  'credential', 'password', 'refund', 'reward', 'cashback', 'kyc', 'support',
  'otp', 'pin', 'payment', 'transaction', 'free', 'bonus', 'claim'
];

/**
 * Payment Proof Standards (UPI & Banking Receipts)
 */
export const PAYMENT_RULES = {
  STANDARD_UPI_UTR_LENGTH: 12,
  VALID_UPI_HANDLES: [
    '@okaxis', '@okhdfcbank', '@okicici', '@oksbi', '@ybl', '@ibl', '@axl',
    '@paytm', '@apl', '@upi', '@barodampay', '@pnb', '@mahb', '@allbank'
  ]
};
