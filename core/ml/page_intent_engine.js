/**
 * Trust Layer — Page Intent Engine & Data Flow Analyzer v2.2
 * Hybrid Rule Baseline + Trained Multi-Class ML Model + Claimed vs Observed Purpose + Structured Page Intelligence Summary.
 */

import { PageIntentClassifier } from './page_intent_classifier.js';

export const PAGE_INTENT = {
  LOGIN:                  'LOGIN',
  PAYMENT:                'PAYMENT',
  BANKING:                'BANKING',
  CHECKOUT:               'CHECKOUT',
  ACCOUNT_CREATION:       'ACCOUNT_CREATION',
  ACCOUNT_RECOVERY:       'ACCOUNT_RECOVERY',
  IDENTITY_VERIFICATION:  'IDENTITY_VERIFICATION',
  KYC:                    'KYC',
  DOWNLOAD:               'DOWNLOAD',
  FILE_UPLOAD:            'FILE_UPLOAD',
  SEARCH:                 'SEARCH',
  CONTENT_READING:        'CONTENT_READING',
  DOCUMENTATION:          'DOCUMENTATION',
  HOMEPAGE_PORTAL:        'HOMEPAGE_PORTAL',
  DEVELOPER_PLATFORM:     'DEVELOPER_PLATFORM',
  CONTACT_FORM:           'CONTACT_FORM',
  SUPPORT:                'SUPPORT',
  OAUTH_AUTHORIZATION:    'OAUTH_AUTHORIZATION',
  OTP_VERIFICATION:       'OTP_VERIFICATION',
  REDIRECTOR:             'REDIRECTOR',
  ERROR_PAGE:             'ERROR_PAGE',
  UNKNOWN:                'UNKNOWN'
};

export class PageIntentEngine {
  /**
   * Analyzes extracted DOM structure, forms, headings, and targets to determine page intent,
   * requested data, actions, claimed vs observed purpose, and data flow paths.
   * @param {object} pageExt Output from PageStructureExtractor
   * @param {object} urlParsed Output from URLParser
   * @param {object} identityAnalysis Optional identity context
   * @returns {object} Structured Intent & Data Flow Analysis
   */
  static analyze(pageExt, urlParsed = {}, identityAnalysis = {}) {
    if (!pageExt || pageExt.status === 'NOT_AVAILABLE') {
      return {
        primary: PAGE_INTENT.UNKNOWN,
        primaryPageRole: PAGE_INTENT.UNKNOWN,
        secondary: null,
        confidence: 0.0,
        modelResult: {
          modelName: 'PAGE-INTENT-v1',
          modelVersion: '1.1.0',
          prediction: 'UNKNOWN',
          probability: 0.0,
          abstain: true,
          abstainReason: 'DOM analysis not run or unavailable'
        },
        ruleBaseline: PAGE_INTENT.UNKNOWN,
        intentConsistency: 'UNKNOWN',
        claimedPurpose: 'UNKNOWN',
        observedPurpose: 'NOT_OBSERVED',
        purposeConsistency: 'UNKNOWN',
        purposeMismatch: false,
        mismatchReason: null,
        availableActions: [],
        requiredActions: [],
        requestedActions: [],
        requestedData: [],
        dataFlow: [],
        summary: null
      };
    }

    const title = (pageExt.title || '').toLowerCase();
    const headingsText = (pageExt.headings || []).join(' ').toLowerCase();
    const metaDesc = (pageExt.metaDescription || '').toLowerCase();
    const buttonsText = (pageExt.buttons || []).join(' ').toLowerCase();
    const allTextContext = `${title} ${headingsText} ${metaDesc} ${buttonsText}`;

    const forms = pageExt.forms || [];
    const scripts = pageExt.scripts || [];
    const links = pageExt.links || [];

    const requiredActionsSet = new Set();
    const availableActionsSet = new Set();
    const requestedDataSet = new Set();
    const dataFlow = [];

    let hasPasswordInput = false;
    let hasOtpInput = false;
    let hasPaymentInput = false;
    let hasKycInput = false;
    let hasSearchInput = false;
    let hasEmailInput = false;
    let hasRegistrationSignals = false;

    // ── 1. Form & Input Deep Semantic Analysis ──
    for (const form of forms) {
      for (const input of (form.inputs || [])) {
        const n = (input.name || '').toLowerCase();
        const t = (input.type || '').toLowerCase();
        const p = (input.placeholder || '').toLowerCase();

        const isHidden = input.isHidden ?? (t === 'hidden');
        const isSystem = input.isSystemParam ?? false;
        const isUserEditable = input.isUserEditable ?? (!isHidden && !isSystem && t !== 'submit' && t !== 'button');

        let dataCategory = 'GENERIC_TEXT';
        let isFieldSensitive = false;

        // Check specific sensitive tokens before falling back to generic type="password"
        if (n.includes('cvv') || n.includes('cvc') || p.includes('cvv') || p.includes('cvc') || n.includes('security_code')) {
          hasPaymentInput = true;
          isFieldSensitive = true;
          dataCategory = 'CARD_CVV';
          requestedDataSet.add('CARD_CVV');
          requiredActionsSet.add('MAKE_PAYMENT');
          availableActionsSet.add('MAKE_PAYMENT');
        } else if (n.includes('exp') || p.includes('exp') || p.includes('mm/yy') || n.includes('expiry')) {
          hasPaymentInput = true;
          isFieldSensitive = true;
          dataCategory = 'CARD_EXPIRATION';
          requestedDataSet.add('CARD_EXPIRATION');
          requiredActionsSet.add('MAKE_PAYMENT');
          availableActionsSet.add('MAKE_PAYMENT');
        } else if (n.includes('card') || n.includes('cc_') || p.includes('card number') || n.includes('debit') || n.includes('credit')) {
          hasPaymentInput = true;
          isFieldSensitive = true;
          dataCategory = 'CREDIT_CARD';
          requestedDataSet.add('CREDIT_CARD_NUMBER');
          requiredActionsSet.add('MAKE_PAYMENT');
          availableActionsSet.add('MAKE_PAYMENT');
        } else if (n.includes('otp') || n.includes('2fa') || n.includes('pin') || n.includes('verification_code') || p.includes('otp') || p.includes('pin')) {
          hasOtpInput = true;
          isFieldSensitive = true;
          dataCategory = 'OTP_CODE';
          requestedDataSet.add('OTP_CODE');
          requiredActionsSet.add('ENTER_OTP');
          availableActionsSet.add('ENTER_OTP');
        } else if (n.includes('aadhaar') || n.includes('pan') || n.includes('ssn') || n.includes('govt_id') || n.includes('passport')) {
          hasKycInput = true;
          isFieldSensitive = true;
          dataCategory = 'GOVERNMENT_ID';
          requestedDataSet.add('GOVERNMENT_ID');
          requiredActionsSet.add('VERIFY_IDENTITY');
          availableActionsSet.add('VERIFY_IDENTITY');
        } else if (t === 'password' || n.includes('pass') || n.includes('pwd') || p.includes('password')) {
          hasPasswordInput = true;
          isFieldSensitive = true;
          dataCategory = 'PASSWORD';
          requestedDataSet.add('PASSWORD');
          requiredActionsSet.add('SUBMIT_CREDENTIALS');
          availableActionsSet.add('SUBMIT_CREDENTIALS');
        } else if (t === 'email' || n.includes('email') || p.includes('email') || n.includes('mail')) {
          hasEmailInput = true;
          dataCategory = 'EMAIL_ADDRESS';
          if (isUserEditable) requestedDataSet.add('EMAIL_ADDRESS');
        } else if (t === 'tel' || n.includes('phone') || n.includes('mobile') || p.includes('phone')) {
          dataCategory = 'PHONE_NUMBER';
          if (isUserEditable) requestedDataSet.add('PHONE_NUMBER');
        } else if (t === 'search' || n === 'q' || n === 'query' || n === 'search' || p.includes('search')) {
          hasSearchInput = true;
          dataCategory = 'SEARCH_QUERY';
          if (isUserEditable) requestedDataSet.add('SEARCH_QUERY');
          requiredActionsSet.add('SUBMIT_SEARCH');
          availableActionsSet.add('SUBMIT_SEARCH');
        } else if (n.includes('user') || n.includes('login') || n.includes('uname') || p.includes('username')) {
          dataCategory = 'USERNAME';
          if (isUserEditable) requestedDataSet.add('USERNAME');
        }

        // Determine data flow entry risk & potential routing (Section 4)
        let flowRisk = 'LOW';
        let routingStatus = 'CONFIGURED_SAME_ORIGIN_DESTINATION';
        if (form.isExternal) {
          routingStatus = isFieldSensitive ? 'EXTERNAL_CREDENTIAL_DESTINATION' : 'CONFIGURED_EXTERNAL_DESTINATION';
          flowRisk = isFieldSensitive ? 'CRITICAL' : 'HIGH';
        } else if (isFieldSensitive) {
          routingStatus = 'SAME_ORIGIN_AUTHENTICATION';
          flowRisk = 'INFO';
        }

        dataFlow.push({
          fieldName: input.name || `unnamed_${input.type}`,
          fieldType: input.type,
          fieldPlaceholder: input.placeholder || '',
          dataCategory,
          formAction: form.action,
          destinationHost: form.destinationHost || urlParsed.hostname || 'same-origin',
          formMethod: form.method,
          isExternal: form.isExternal,
          isSensitive: isFieldSensitive,
          isUserEditable,
          isSystemParam: isSystem,
          transmissionObserved: false,
          routingStatus,
          riskLevel: flowRisk
        });
      }
    }

    // Check for registration signals (e.g. repeat password, signup text)
    if (allTextContext.includes('confirm password') || allTextContext.includes('sign up') || allTextContext.includes('register') || allTextContext.includes('create account')) {
      hasRegistrationSignals = true;
      availableActionsSet.add('CREATE_ACCOUNT');
      if (hasPasswordInput) {
        requiredActionsSet.add('CREATE_ACCOUNT');
      }
    }

    // Check for sign in navigation options
    if (allTextContext.includes('sign in') || allTextContext.includes('login') || allTextContext.includes('log in')) {
      availableActionsSet.add('SIGN_IN');
    }

    // Check for documentation reading option
    if (allTextContext.includes('documentation') || allTextContext.includes('web docs') || allTextContext.includes('docs') || allTextContext.includes('reference')) {
      availableActionsSet.add('BROWSE_DOCUMENTATION');
    }

    // Check for available download links (Section 2: available action != primary role)
    const hasDownloadLink = buttonsText.includes('download') || buttonsText.includes('get invoice') ||
                           links.some(l => /\.(pdf|zip|tar\.gz|tgz|exe|apk|dmg|iso|msi|docx|pkg)(\?.*)?$/i.test(l.href) ||
                                           /\/downloads?(\/|$)/i.test(l.href) ||
                                           /\bdownload\b/i.test(l.href) ||
                                           /\bdownload\b/i.test(l.text || ''));
    if (hasDownloadLink) {
      availableActionsSet.add('DOWNLOAD_FILE');
    }

    // Primary download tool check: only if main title explicitly focuses on downloading
    const primaryTitle = (pageExt.title || '').toLowerCase() || (pageExt.headings && pageExt.headings[0] ? pageExt.headings[0].toLowerCase() : '');
    const isPrimaryDownload = /\b(download|installer|get invoice|setup\.exe)\b/i.test(primaryTitle);

    // Check for contact / feedback form
    const hasContactSignal = allTextContext.includes('contact us') || allTextContext.includes('send message') || allTextContext.includes('leave a reply') || allTextContext.includes('feedback');
    if (hasContactSignal && forms.length > 0 && !hasPasswordInput && !hasPaymentInput) {
      requiredActionsSet.add('SUBMIT_CONTACT_MESSAGE');
      availableActionsSet.add('SUBMIT_CONTACT_MESSAGE');
      requestedDataSet.add('MESSAGE_BODY');
    }

    // ── 2. Determine Claimed Purpose ──
    let claimedPurpose = 'GENERAL_WEB_CONTENT';

    if (allTextContext.includes('track') || allTextContext.includes('delivery') || allTextContext.includes('shipment') || allTextContext.includes('courier') || allTextContext.includes('dhl') || allTextContext.includes('fedex') || allTextContext.includes('package')) {
      claimedPurpose = 'SHIPPING_TRACKING';
    } else if (allTextContext.includes('invoice') || allTextContext.includes('receipt') || allTextContext.includes('billing statement') || allTextContext.includes('document')) {
      claimedPurpose = 'DOCUMENT_DELIVERY';
    } else if (allTextContext.includes('search') || urlParsed.hostname === 'google.com' || urlParsed.hostname === 'www.google.com' || urlParsed.hostname === 'bing.com') {
      claimedPurpose = 'SEARCH_ENGINE';
    } else if (allTextContext.includes('documentation') || allTextContext.includes('web docs') || allTextContext.includes('docs') || allTextContext.includes('api reference')) {
      claimedPurpose = 'DOCUMENTATION';
    } else if (allTextContext.includes('developer platform') || allTextContext.includes('github') || allTextContext.includes('build software') || allTextContext.includes('git repository')) {
      claimedPurpose = 'DEVELOPER_PLATFORM';
    } else if (allTextContext.includes('foundation') || allTextContext.includes('python.org') || allTextContext.includes('community portal') || allTextContext.includes('official website')) {
      claimedPurpose = 'HOMEPAGE_PORTAL';
    } else if (allTextContext.includes('net banking') || allTextContext.includes('internet banking') || allTextContext.includes('bank account') || allTextContext.includes('hdfc bank')) {
      claimedPurpose = 'BANKING_PORTAL';
    } else if (allTextContext.includes('payment') || allTextContext.includes('pay now') || allTextContext.includes('checkout') || allTextContext.includes('paypal')) {
      claimedPurpose = 'PAYMENT_CHECKOUT';
    } else if (allTextContext.includes('security update') || allTextContext.includes('account suspended') || allTextContext.includes('verify your account') || allTextContext.includes('identity verification')) {
      claimedPurpose = 'SECURITY_VERIFICATION';
    } else if (allTextContext.includes('sign in') || allTextContext.includes('log in') || allTextContext.includes('login') || allTextContext.includes('welcome back')) {
      claimedPurpose = 'ACCOUNT_LOGIN';
    } else if (allTextContext.includes('wikipedia') || allTextContext.includes('encyclopedia') || allTextContext.includes('article') || allTextContext.includes('news')) {
      claimedPurpose = 'CONTENT_READING';
    } else if (hasContactSignal) {
      claimedPurpose = 'CUSTOMER_SUPPORT';
    }

    // ── 3. Determine Observed Purpose ──
    let observedPurpose = 'INFORMATION_DISPLAY';

    const hasExternalExfil = dataFlow.some(f => f.isExternal && f.isSensitive);

    if (hasExternalExfil) {
      observedPurpose = 'EXTERNAL_CREDENTIAL_EXFILTRATION';
    } else if (hasPaymentInput) {
      observedPurpose = 'PAYMENT_TRANSACTION_PROCESSING';
    } else if (hasPasswordInput && hasOtpInput) {
      observedPurpose = 'MULTI_FACTOR_CREDENTIAL_CAPTURE';
    } else if (hasPasswordInput) {
      observedPurpose = hasRegistrationSignals ? 'ACCOUNT_REGISTRATION_INTAKE' : 'CREDENTIAL_AUTHENTICATION_INTAKE';
    } else if (hasKycInput) {
      observedPurpose = 'IDENTITY_DOCUMENT_INTAKE';
    } else if (hasSearchInput && forms.length > 0) {
      observedPurpose = 'SEARCH_QUERY_EXECUTION';
    } else if (hasContactSignal && forms.length > 0) {
      observedPurpose = 'USER_INQUIRY_INTAKE';
    } else if (allTextContext.includes('documentation') || allTextContext.includes('web docs') || allTextContext.includes('api reference')) {
      observedPurpose = 'DOCUMENTATION_REFERENCE';
    } else if (allTextContext.includes('developer platform') || allTextContext.includes('github') || allTextContext.includes('build software')) {
      observedPurpose = 'DEVELOPER_COLLABORATION_PLATFORM';
    } else if (pageExt.domNodes > 0 && forms.length === 0) {
      observedPurpose = 'STATIC_CONTENT_PRESENTATION';
    }

    // ── 4. Rule Baseline Classification ──
    let ruleBaseline = PAGE_INTENT.UNKNOWN;
    if (hasPaymentInput) {
      ruleBaseline = PAGE_INTENT.PAYMENT;
    } else if (hasOtpInput) {
      ruleBaseline = PAGE_INTENT.OTP_VERIFICATION;
    } else if (hasPasswordInput) {
      ruleBaseline = hasRegistrationSignals ? PAGE_INTENT.ACCOUNT_CREATION : PAGE_INTENT.LOGIN;
    } else if (hasKycInput) {
      ruleBaseline = PAGE_INTENT.IDENTITY_VERIFICATION;
    } else if (hasSearchInput) {
      ruleBaseline = PAGE_INTENT.SEARCH;
    } else if (hasContactSignal && forms.length > 0) {
      ruleBaseline = PAGE_INTENT.CONTACT_FORM;
    } else if (isPrimaryDownload) {
      ruleBaseline = PAGE_INTENT.DOWNLOAD;
    } else if (allTextContext.includes('documentation') || allTextContext.includes('web docs') || allTextContext.includes('api reference')) {
      ruleBaseline = PAGE_INTENT.DOCUMENTATION;
    } else if (allTextContext.includes('developer platform') || allTextContext.includes('github') || allTextContext.includes('build software')) {
      ruleBaseline = PAGE_INTENT.DEVELOPER_PLATFORM;
    } else if (allTextContext.includes('foundation') || allTextContext.includes('python.org') || allTextContext.includes('community portal') || allTextContext.includes('official website')) {
      ruleBaseline = PAGE_INTENT.HOMEPAGE_PORTAL;
    } else if (pageExt.domNodes > 0) {
      ruleBaseline = PAGE_INTENT.CONTENT_READING;
    }

    // ── 5. Machine Learning Page Intent Inference ──
    const mlPred = PageIntentClassifier.predict(pageExt, urlParsed);

    let finalPrimary = ruleBaseline;
    let finalSecondary = mlPred.secondaryIntent;
    let finalConfidence = mlPred.primaryProbability || 0.85;
    let intentConsistency = 'AGREED';

    if (!mlPred.abstain && mlPred.primaryIntent !== 'UNKNOWN') {
      if (mlPred.primaryIntent === ruleBaseline) {
        intentConsistency = 'MODEL_AGREEMENT';
        finalPrimary = ruleBaseline;
        finalConfidence = mlPred.primaryProbability;
      } else {
        // High security signals (auth/payment) take precedence over general content predictions
        if (['LOGIN', 'BANKING', 'PAYMENT', 'OTP_VERIFICATION', 'IDENTITY_VERIFICATION'].includes(ruleBaseline)) {
          finalPrimary = ruleBaseline;
          finalSecondary = mlPred.primaryIntent;
          intentConsistency = 'RULE_PRIORITIZED';
        } else if (ruleBaseline === PAGE_INTENT.SEARCH && hasSearchInput) {
          finalPrimary = PAGE_INTENT.SEARCH;
          finalSecondary = mlPred.primaryIntent;
          intentConsistency = 'SEARCH_CONFIRMED';
        } else {
          finalPrimary = mlPred.primaryIntent;
          finalSecondary = ruleBaseline;
          intentConsistency = 'MODEL_PRIORITIZED';
        }
      }
    }

    // ── 6. Purpose Consistency & Deception Detection ──
    let purposeConsistency = 'MATCH';
    let purposeMismatch = false;
    let mismatchReason = null;

    const isBenignLureClaim = ['DOCUMENT_DELIVERY', 'SHIPPING_TRACKING', 'CUSTOMER_SUPPORT'].includes(claimedPurpose);
    const isSensitiveObserved = ['CREDENTIAL_AUTHENTICATION_INTAKE', 'MULTI_FACTOR_CREDENTIAL_CAPTURE', 'PAYMENT_TRANSACTION_PROCESSING', 'EXTERNAL_CREDENTIAL_EXFILTRATION'].includes(observedPurpose);

    if (isBenignLureClaim && isSensitiveObserved) {
      purposeConsistency = 'MISMATCH';
      purposeMismatch = true;
      mismatchReason = `Deceptive Purpose Mismatch: Page pretext claims to be "${claimedPurpose}" (e.g. document download / tracking lure), but observed interactive DOM demands sensitive credentials (${Array.from(requestedDataSet).join(', ')}).`;
    } else if (hasExternalExfil) {
      purposeConsistency = 'MISMATCH';
      purposeMismatch = true;
      mismatchReason = `Deceptive Data Routing: Page presents interactive authentication forms that route submitted user credentials directly to an unverified third-party collection endpoint (${dataFlow.find(d => d.isExternal)?.destinationHost}).`;
    } else if (claimedPurpose === 'GENERAL_WEB_CONTENT' && isSensitiveObserved) {
      purposeConsistency = 'POTENTIAL_MISMATCH';
    }

    // ── 7. Generate Structured Page Intelligence Summary ──
    const summary = this.generatePageIntelligenceSummary({
      targetUrl: urlParsed.normalizedUrl || '—',
      primaryIntent: finalPrimary,
      primaryPageRole: finalPrimary,
      secondaryIntent: finalSecondary,
      modelName: mlPred.modelName,
      modelProbability: finalConfidence,
      availableActions: Array.from(availableActionsSet),
      requiredActions: Array.from(requiredActionsSet),
      requestedActions: Array.from(requiredActionsSet),
      requestedData: Array.from(requestedDataSet),
      dataFlow,
      claimedEntity: identityAnalysis.claimedEntity || 'UNKNOWN',
      observedDomain: urlParsed.hostname || '—',
      claimedPurpose,
      observedPurpose,
      purposeConsistency,
      purposeMismatch,
      mismatchReason,
      identityContinuity: identityAnalysis.identityContinuity || 'UNKNOWN'
    });

    return {
      primary: finalPrimary,
      primaryPageRole: finalPrimary,
      secondary: finalSecondary,
      confidence: finalConfidence,
      modelResult: mlPred,
      ruleBaseline,
      intentConsistency,
      claimedPurpose,
      observedPurpose,
      purposeConsistency,
      purposeMismatch,
      mismatchReason,
      availableActions: Array.from(availableActionsSet),
      requiredActions: Array.from(requiredActionsSet),
      requestedActions: Array.from(requiredActionsSet),
      requestedData: Array.from(requestedDataSet),
      dataFlow,
      summary
    };
  }

  /**
   * Generates a structured, evidence-traceable human-readable Page Intelligence Summary (Section 29 & 66).
   */
  static generatePageIntelligenceSummary(ctx) {
    const availableActions = ctx.availableActions || ctx.requestedActions || [];
    const requiredActions = ctx.requiredActions || ctx.requestedActions || [];

    const actionsList = availableActions.length > 0
      ? availableActions.map(a => `  ✓ ${a.replace(/_/g, ' ')}`).join('\n')
      : '  • No active user submissions requested.';

    const dataList = ctx.requestedData.length > 0
      ? ctx.requestedData.join(', ')
      : 'None (Passive browsing / no required inputs)';

    const destinationsList = ctx.dataFlow.length > 0
      ? ctx.dataFlow.map(df => `  • ${df.fieldName} (${df.dataCategory}) → ${df.formAction} [${df.isExternal ? 'EXTERNAL: ' + df.destinationHost : 'SAME-ORIGIN'} - Configured routing only, not observed transfer]`).join('\n')
      : '  • No form submissions or external data routes observed.';

    const text = [
      `===============================================================`,
      `PAGE INTELLIGENCE SUMMARY`,
      `===============================================================`,
      ``,
      `WHAT THIS PAGE APPEARS TO DO (PAGE PURPOSE)`,
      `Primary Role:      ${ctx.primaryPageRole || ctx.primaryIntent}`,
      ctx.secondaryIntent ? `Secondary Role:    ${ctx.secondaryIntent}` : null,
      `Classification:    ${ctx.modelName} (P=${(ctx.modelProbability * 100).toFixed(1)}%)`,
      ``,
      `WHAT THE USER IS ASKED TO DO (AVAILABLE ACTIONS)`,
      actionsList,
      ``,
      `WHAT INFORMATION IS REQUESTED (REQUIRED USER INPUTS)`,
      `User Inputs:       ${dataList}`,
      ``,
      `WHERE THE INFORMATION IS SENT (CONFIGURED FORM DESTINATIONS)`,
      `NOTE: No user data was transmitted. Configured form destinations:`,
      destinationsList,
      ``,
      `IDENTITY & ENTITY RECONCILIATION`,
      `Claimed Entity:    ${ctx.claimedEntity || 'UNKNOWN'}`,
      `Observed Domain:   ${ctx.observedDomain}`,
      `Identity State:    ${ctx.identityContinuity}`,
      ``,
      `PURPOSE CONSISTENCY ANALYSIS`,
      `Claimed Pretext:   ${ctx.claimedPurpose}`,
      `Observed Reality:  ${ctx.observedPurpose}`,
      `Consistency:       ${ctx.purposeConsistency}${ctx.purposeMismatch ? ' (MISMATCH DETECTED)' : ''}`,
      ctx.mismatchReason ? `Deception Reason:  ${ctx.mismatchReason}` : null,
      `===============================================================`
    ].filter(line => line !== null).join('\n');

    return {
      text,
      primaryIntent: ctx.primaryPageRole || ctx.primaryIntent,
      primaryPageRole: ctx.primaryPageRole || ctx.primaryIntent,
      secondaryIntent: ctx.secondaryIntent,
      claimedPurpose: ctx.claimedPurpose,
      observedPurpose: ctx.observedPurpose,
      purposeConsistency: ctx.purposeConsistency,
      availableActions: ctx.availableActions || [],
      requiredActions: ctx.requiredActions || [],
      requestedActions: ctx.requestedActions || [],
      requestedData: ctx.requestedData
    };
  }
}
