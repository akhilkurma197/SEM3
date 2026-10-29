/**
 * Trust Layer — Real Page & DOM Structure Extractor v2.2
 * Autopsies DOM structure, semantic headings, inputs, forms, scripts, and exfiltration vectors.
 */

export class PageStructureExtractor {
  /**
   * Analyzes raw HTML payload or DOM string and extracts structural security signals.
   * @param {string} htmlContent 
   * @param {string} baseHostname 
   * @returns {{
   *   status: string,
   *   title: string|null,
   *   headings: string[],
   *   metaDescription: string|null,
   *   buttons: string[],
   *   domNodes: number,
   *   htmlBytes: number,
   *   forms: Array<{
   *     action: string,
   *     method: string,
   *     destinationHost: string,
   *     fields: string[],
   *     inputs: Array<{name: string, type: string, placeholder: string, isPassword: boolean, isSensitive: boolean}>,
   *     hasPassword: boolean,
   *     hasSensitive: boolean,
   *     isExternal: boolean
   *   }>,
   *   scripts: Array<{src: string|null, domain: string|null, isExternal: boolean, isInline: boolean}>,
   *   iframes: Array<{src: string, isExternal: boolean}>,
   *   links: Array<{href: string, isExternal: boolean}>,
   *   externalDomains: string[],
   *   domFingerprint: string|null
   * }}
   */
  static extract(htmlContent, baseHostname = '') {
    if (!htmlContent || typeof htmlContent !== 'string' || htmlContent.trim().length === 0) {
      return {
        status: 'NOT_AVAILABLE',
        title: null,
        headings: [],
        metaDescription: null,
        buttons: [],
        domNodes: 0,
        htmlBytes: 0,
        forms: [],
        scripts: [],
        iframes: [],
        links: [],
        externalDomains: [],
        domFingerprint: null
      };
    }

    const html = htmlContent;
    const htmlBytes = typeof Blob !== 'undefined' ? new Blob([html]).size : Buffer.byteLength(html, 'utf8');
    const externalDomainsSet = new Set();

    // 1. Page Title
    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : null;

    // 2. Meta Description
    const metaDescMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["'][^>]*>/i) ||
                          html.match(/<meta[^>]*content=["']([^"']*)["'][^>]*name=["']description["'][^>]*>/i);
    const metaDescription = metaDescMatch ? metaDescMatch[1].trim() : null;

    // 3. Headings (h1, h2, h3)
    const headings = [];
    const headingMatches = html.matchAll(/<h[1-3][^>]*>([\s\S]*?)<\/h[1-3]>/gi);
    for (const match of headingMatches) {
      const cleanText = match[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
      if (cleanText && cleanText.length > 1 && !headings.includes(cleanText)) {
        headings.push(cleanText);
      }
    }

    // 4. Buttons / Action CTAs
    const buttons = [];
    const buttonMatches = html.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/gi);
    for (const match of buttonMatches) {
      const cleanText = match[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
      if (cleanText && !buttons.includes(cleanText)) {
        buttons.push(cleanText);
      }
    }
    const inputSubmitMatches = html.matchAll(/<input[^>]*type=["'](?:submit|button)["'][^>]*value=["']([^"']+)["'][^>]*>/gi);
    for (const match of inputSubmitMatches) {
      const val = match[1].trim();
      if (val && !buttons.includes(val)) {
        buttons.push(val);
      }
    }

    // 5. Approximate DOM Nodes
    const tagMatches = html.match(/<[a-zA-Z0-9-]+(?:\s+[^>]*)?>/g) || [];
    const domNodes = tagMatches.length;

    // 6. Form Analysis & Inputs
    const forms = [];
    const formBlocks = html.matchAll(/<form(?:\s+([^>]*))?>([\s\S]*?)<\/form>/gi);
    for (const match of formBlocks) {
      const formAttrs = match[1] || '';
      const formInner = match[2] || '';

      const actionMatch = formAttrs.match(/action=["']([^"']*?)["']/i);
      const methodMatch = formAttrs.match(/method=["']([^"']*?)["']/i);

      let action = actionMatch ? actionMatch[1].trim() : '';
      const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';

      let destinationHost = baseHostname;
      let isExternal = false;

      if (action.startsWith('http://') || action.startsWith('https://') || action.startsWith('//')) {
        try {
          const fullAction = action.startsWith('//') ? 'https:' + action : action;
          const parsedActionUrl = new URL(fullAction);
          destinationHost = parsedActionUrl.hostname;
          if (destinationHost && destinationHost !== baseHostname) {
            isExternal = true;
            externalDomainsSet.add(destinationHost);
          }
        } catch {}
      }

      // Common technical/framework system parameters that are NOT user-provided inputs
      const SYSTEM_PARAM_NAMES = [
        'ie', 'hl', 'biw', 'bih', 'iflsig', 'source', 'ved', 'ei', 'gbv',
        '_charset_', 'authenticity_token', 'utf8', 'commit', '_method',
        'csrf', 'csrf_token', 'csrfmiddlewaretoken', 'timestamp', '_csrf'
      ];

      // Parse input fields
      const fields = [];
      const inputs = [];
      let hasPassword = false;
      let hasSensitive = false;

      const inputMatches = formInner.matchAll(/<input(?:\s+([^>]*))?>/gi);
      for (const input of inputMatches) {
        const attrs = input[1] || '';
        const nameMatch = attrs.match(/name=["']([^"']*?)["']/i);
        const typeMatch = attrs.match(/type=["']([^"']*?)["']/i);
        const placeholderMatch = attrs.match(/placeholder=["']([^"']*?)["']/i);
        const idMatch = attrs.match(/id=["']([^"']*?)["']/i);

        const name = nameMatch ? nameMatch[1].trim() : (idMatch ? idMatch[1].trim() : '');
        const type = typeMatch ? typeMatch[1].toLowerCase().trim() : 'text';
        const placeholder = placeholderMatch ? placeholderMatch[1].trim() : '';

        const nameLower = name.toLowerCase();
        const placeholderLower = placeholder.toLowerCase();

        const isHidden = type === 'hidden';
        const isDisabled = /\bdisabled\b/i.test(attrs);
        const isReadOnly = /\breadonly\b/i.test(attrs);
        const isSubmit = type === 'submit' || type === 'button' || type === 'image';
        const isSystemParam = isHidden && SYSTEM_PARAM_NAMES.includes(nameLower);
        const isUserEditable = !isHidden && !isDisabled && !isReadOnly && !isSubmit && !isSystemParam;

        let isPwd = (type === 'password' || nameLower.includes('pass') || nameLower.includes('pwd'));
        // Sensitive data only applies to editable or non-system fields
        let isSens = isPwd || (!isSystemParam && ['otp', 'pin', 'ssn', 'card', 'cvv', 'cvc', 'exp', 'account', 'token', 'aadhaar', 'pan'].some(s => nameLower.includes(s) || placeholderLower.includes(s)));

        if (isPwd) hasPassword = true;
        if (isSens) hasSensitive = true;

        if (name) fields.push(name);
        inputs.push({
          name: name || `field_${inputs.length + 1}`,
          type,
          placeholder,
          isPassword: isPwd,
          isSensitive: isSens,
          isHidden,
          isDisabled,
          isReadOnly,
          isSubmit,
          isSystemParam,
          isUserEditable
        });
      }

      // Also parse select and textarea
      const textareas = formInner.matchAll(/<textarea(?:\s+([^>]*))?>/gi);
      for (const ta of textareas) {
        const attrs = ta[1] || '';
        const nameMatch = attrs.match(/name=["']([^"']*?)["']/i);
        const name = nameMatch ? nameMatch[1].trim() : `textarea_${inputs.length + 1}`;
        fields.push(name);
        inputs.push({
          name,
          type: 'textarea',
          placeholder: '',
          isPassword: false,
          isSensitive: false,
          isHidden: false,
          isDisabled: /\bdisabled\b/i.test(attrs),
          isReadOnly: /\breadonly\b/i.test(attrs),
          isSubmit: false,
          isSystemParam: false,
          isUserEditable: !/\bdisabled\b/i.test(attrs) && !/\breadonly\b/i.test(attrs)
        });
      }

      forms.push({
        action: action || '(same-origin)',
        method,
        destinationHost: destinationHost || baseHostname,
        fields,
        inputs,
        userEditableInputs: inputs.filter(i => i.isUserEditable),
        hiddenInputs: inputs.filter(i => i.isHidden),
        systemParams: inputs.filter(i => i.isSystemParam),
        hasPassword,
        hasSensitive,
        isExternal
      });
    }

    // 7. Scripts
    const scripts = [];
    const scriptTags = html.matchAll(/<script(?:\s+([^>]*))?>([\s\S]*?)<\/script>/gi);
    for (const match of scriptTags) {
      const attrs = match[1] || '';
      const srcMatch = attrs.match(/src=["']([^"']*?)["']/i);
      const src = srcMatch ? srcMatch[1].trim() : null;

      let isExternal = false;
      let domain = null;

      if (src && (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//'))) {
        try {
          const fullSrc = src.startsWith('//') ? 'https:' + src : src;
          domain = new URL(fullSrc).hostname;
          if (domain && domain !== baseHostname) {
            isExternal = true;
            externalDomainsSet.add(domain);
          }
        } catch {}
      }

      scripts.push({
        src,
        domain,
        isExternal,
        isInline: !src
      });
    }

    // 8. iFrames
    const iframes = [];
    const iframeTags = html.matchAll(/<iframe(?:\s+([^>]*))?>/gi);
    for (const match of iframeTags) {
      const attrs = match[1] || '';
      const srcMatch = attrs.match(/src=["']([^"']*?)["']/i);
      const src = srcMatch ? srcMatch[1].trim() : '';
      let isExternal = false;
      try {
        if (src) {
          const frameHost = new URL(src.startsWith('//') ? 'https:' + src : src).hostname;
          if (frameHost && frameHost !== baseHostname) {
            isExternal = true;
            externalDomainsSet.add(frameHost);
          }
        }
      } catch {}
      iframes.push({ src, isExternal });
    }

    // 9. Outbound Links
    const links = [];
    const anchorTags = html.matchAll(/<a(?:\s+([^>]*))?>([\s\S]*?)<\/a>/gi);
    for (const match of anchorTags) {
      const attrs = match[1] || '';
      const hrefMatch = attrs.match(/href=["']([^"']*?)["']/i);
      const href = hrefMatch ? hrefMatch[1].trim() : '';
      let isExternal = false;
      if (href.startsWith('http://') || href.startsWith('https://')) {
        try {
          const linkHost = new URL(href).hostname;
          if (linkHost && linkHost !== baseHostname) {
            isExternal = true;
            externalDomainsSet.add(linkHost);
          }
        } catch {}
      }
      const rawText = match[2] || '';
      const text = rawText.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
      if (href) {
        links.push({ href, text, isExternal });
      }
    }

    // 10. Deterministic DOM Fingerprint Hash
    const hashBasis = `${title || ''}|${domNodes}|${forms.length}|${scripts.length}|${iframes.length}|${headings.length}`;
    let hash = 0;
    for (let i = 0; i < hashBasis.length; i++) {
      hash = ((hash << 5) - hash + hashBasis.charCodeAt(i)) | 0;
    }
    const domFingerprint = `DOM-0x${Math.abs(hash).toString(16).padStart(8, '0').toUpperCase()}`;

    return {
      status: 'SUCCESS',
      title,
      headings: headings.slice(0, 10),
      metaDescription,
      buttons: buttons.slice(0, 10),
      domNodes,
      htmlBytes,
      forms,
      scripts,
      iframes,
      links: links.slice(0, 50),
      externalDomains: Array.from(externalDomainsSet),
      domFingerprint
    };
  }
}
