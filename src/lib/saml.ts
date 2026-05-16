import { inflateRaw } from 'pako';

const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
const NS_XENC = 'http://www.w3.org/2001/04/xmlenc#';

export type MessageType = 'SAMLRequest' | 'SAMLResponse' | 'unknown';
export type BindingType = 'redirect' | 'post';

export interface TimestampField {
    label: string;
    raw: string;
    date: Date;
}

export interface SamlStatus {
    code: string;
    subCode?: string;
    message?: string;
}

export interface AttributeField {
    name: string;
    friendlyName?: string;
    values: string[];
}

export interface SamlSummary {
    messageType: MessageType;
    binding: BindingType;
    issuer?: string;
    nameId?: { value: string; format?: string };
    authnContext?: { classRef: string; declRef?: string };
    requestedAuthnContext?: { classRefs: string[]; comparison: string };
    destination?: string;
    acsUrl?: string;
    inResponseTo?: string;
    relayState?: string;
    status?: SamlStatus;
    timestamps: TimestampField[];
    encrypted: { assertion: boolean; nameId: boolean };
    signingCertificate?: string;
    attributes: AttributeField[];
}

const AC_PFX = 'urn:oasis:names:tc:SAML:2.0:ac:classes:';
const NIST_HTTP_PFX = 'http://idmanagement.gov/ns/assurance/';
const RAF = 'https://refeds.org/assurance';

export const AUTHN_CONTEXT_LABELS: Record<string, string> = {
    // SAML 2.0 Authentication Context spec
    [`${AC_PFX}Password`]: 'Password',
    [`${AC_PFX}PasswordProtectedTransport`]: 'Password (HTTPS)',
    [`${AC_PFX}X509`]: 'X.509 Certificate',
    [`${AC_PFX}Kerberos`]: 'Kerberos',
    [`${AC_PFX}TimeSyncToken`]: 'Time-sync Token (OTP)',
    [`${AC_PFX}SmartcardPKI`]: 'Smartcard + PKI',
    [`${AC_PFX}Smartcard`]: 'Smartcard',
    [`${AC_PFX}TLSClient`]: 'TLS Client Certificate',
    [`${AC_PFX}SoftwarePKI`]: 'Software PKI Certificate',
    [`${AC_PFX}InternetProtocol`]: 'IP Address',
    [`${AC_PFX}InternetProtocolPassword`]: 'IP + Password',
    [`${AC_PFX}MobileOneFactor`]: 'Mobile One-Factor',
    [`${AC_PFX}MobileTwofactorContract`]: 'Mobile Two-Factor',
    [`${AC_PFX}SecureRemotePassword`]: 'Secure Remote Password (SRP)',
    [`${AC_PFX}PreviousSession`]: 'Previous Session',
    [`${AC_PFX}NomadTelephony`]: 'Nomadic Telephony',
    [`${AC_PFX}PersonalTelephony`]: 'Personal Telephony',
    [`${AC_PFX}AuthenticatedTelephony`]: 'Authenticated Telephony',
    [`${AC_PFX}unspecified`]: 'Unspecified',
    // REFEDS profiles
    'https://refeds.org/profile/mfa': 'REFEDS MFA',
    'https://refeds.org/profile/sfa': 'REFEDS SFA',
    // REFEDS Assurance Framework (RAF)
    [`${RAF}/IAP/low`]: 'REFEDS IAP Low',
    [`${RAF}/IAP/medium`]: 'REFEDS IAP Medium',
    [`${RAF}/IAP/high`]: 'REFEDS IAP High',
    [`${RAF}/ATP/ePA-1m`]: 'REFEDS ePA-1m',
    [`${RAF}/ATP/ePA-1d`]: 'REFEDS ePA-1d',
    [`${RAF}/ID/unique`]: 'REFEDS ID Unique',
    [`${RAF}/ID/eppn-unique-no-reassign`]: 'REFEDS EPPN (no reassign)',
    [`${RAF}/ID/eppn-unique-reassign-1y`]: 'REFEDS EPPN (reassign 1y)',
    // NIST SP 800-63 / FICAM (http: identifiers, not URLs)
    [`${NIST_HTTP_PFX}ial/1`]: 'IAL1',
    [`${NIST_HTTP_PFX}ial/2`]: 'IAL2',
    [`${NIST_HTTP_PFX}aal/1`]: 'AAL1',
    [`${NIST_HTTP_PFX}aal/2`]: 'AAL2',
    [`${NIST_HTTP_PFX}aal/3`]: 'AAL3',
};

const OASIS_AC_SPEC = 'https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf';
const NIST_800_63 = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf';

export const AUTHN_CONTEXT_SPEC_URLS: Record<string, string> = {
    // SAML 2.0 baseline → OASIS spec PDF
    [`${AC_PFX}Password`]: OASIS_AC_SPEC,
    [`${AC_PFX}PasswordProtectedTransport`]: OASIS_AC_SPEC,
    [`${AC_PFX}X509`]: OASIS_AC_SPEC,
    [`${AC_PFX}Kerberos`]: OASIS_AC_SPEC,
    [`${AC_PFX}TimeSyncToken`]: OASIS_AC_SPEC,
    [`${AC_PFX}SmartcardPKI`]: OASIS_AC_SPEC,
    [`${AC_PFX}Smartcard`]: OASIS_AC_SPEC,
    [`${AC_PFX}TLSClient`]: OASIS_AC_SPEC,
    [`${AC_PFX}SoftwarePKI`]: OASIS_AC_SPEC,
    [`${AC_PFX}InternetProtocol`]: OASIS_AC_SPEC,
    [`${AC_PFX}InternetProtocolPassword`]: OASIS_AC_SPEC,
    [`${AC_PFX}MobileOneFactor`]: OASIS_AC_SPEC,
    [`${AC_PFX}MobileTwofactorContract`]: OASIS_AC_SPEC,
    [`${AC_PFX}SecureRemotePassword`]: OASIS_AC_SPEC,
    [`${AC_PFX}PreviousSession`]: OASIS_AC_SPEC,
    [`${AC_PFX}NomadTelephony`]: OASIS_AC_SPEC,
    [`${AC_PFX}PersonalTelephony`]: OASIS_AC_SPEC,
    [`${AC_PFX}AuthenticatedTelephony`]: OASIS_AC_SPEC,
    [`${AC_PFX}unspecified`]: OASIS_AC_SPEC,
    // REFEDS profiles → URI is the canonical link
    'https://refeds.org/profile/mfa': 'https://refeds.org/profile/mfa',
    'https://refeds.org/profile/sfa': 'https://refeds.org/profile/sfa',
    // REFEDS Assurance Framework → RAF landing page
    [`${RAF}/IAP/low`]: RAF,
    [`${RAF}/IAP/medium`]: RAF,
    [`${RAF}/IAP/high`]: RAF,
    [`${RAF}/ATP/ePA-1m`]: RAF,
    [`${RAF}/ATP/ePA-1d`]: RAF,
    [`${RAF}/ID/unique`]: RAF,
    [`${RAF}/ID/eppn-unique-no-reassign`]: RAF,
    [`${RAF}/ID/eppn-unique-reassign-1y`]: RAF,
    // NIST/FICAM → NIST SP 800-63-3 (identifiers use http:, spec is https:)
    [`${NIST_HTTP_PFX}ial/1`]: NIST_800_63,
    [`${NIST_HTTP_PFX}ial/2`]: NIST_800_63,
    [`${NIST_HTTP_PFX}aal/1`]: NIST_800_63,
    [`${NIST_HTTP_PFX}aal/2`]: NIST_800_63,
    [`${NIST_HTTP_PFX}aal/3`]: NIST_800_63,
};

const ST_PFX = 'urn:oasis:names:tc:SAML:2.0:status:';

export const STATUS_DESCRIPTIONS: Record<string, string> = {
    [`${ST_PFX}Requester`]:
        'The request could not be fulfilled due to an error in the request itself — an SP-side problem. Fixing the request may resolve this.',
    [`${ST_PFX}Responder`]:
        'The request could not be fulfilled due to an error at the IdP. The request was valid; the problem is on the IdP side.',
    [`${ST_PFX}VersionMismatch`]:
        'The SAML version specified in the request is not supported by this IdP.',
    [`${ST_PFX}AuthnFailed`]:
        "The IdP was unable to authenticate the principal — wrong credentials, locked account, or a failed MFA step.",
    [`${ST_PFX}InvalidAttrNameOrValue`]:
        'An Attribute or AttributeValue element contained unexpected or invalid content — often a misconfigured attribute release policy.',
    [`${ST_PFX}InvalidNameIDPolicy`]:
        'The requested NameID format or SPNameQualifier cannot be honored by this IdP.',
    [`${ST_PFX}NoAuthnContext`]:
        "The IdP cannot satisfy the AuthnContext requested by the SP. The user's authentication method doesn't meet the SP's requirements — typically MFA was required but not performed.",
    [`${ST_PFX}NoAvailableIDP`]:
        'No proxied IdP is available to authenticate the principal (IdP-proxy scenario).',
    [`${ST_PFX}NoPassive`]:
        'The request required passive authentication (IsPassive=true), but the user is not already authenticated and interaction would be required.',
    [`${ST_PFX}NoSupportedIDP`]:
        'The IdP proxy could not find a supported IdP for the requested principal.',
    [`${ST_PFX}PartialLogout`]:
        'Single logout completed only partially — not all sessions at participating SPs could be terminated.',
    [`${ST_PFX}ProxyCountExceeded`]:
        'The ProxyCount limit was exceeded in an IdP-proxy chain.',
    [`${ST_PFX}RequestDenied`]:
        'The IdP refused to perform the requested operation — typically a policy block, consent requirement, or SP not authorized.',
    [`${ST_PFX}RequestUnsupported`]:
        'The requested operation or profile is not supported by this IdP.',
    [`${ST_PFX}RequestVersionDeprecated`]:
        'The SAML version used in the request has been deprecated by this IdP.',
    [`${ST_PFX}RequestVersionTooHigh`]:
        'The SAML version in the request is higher than what this IdP supports.',
    [`${ST_PFX}RequestVersionTooLow`]:
        'The SAML version in the request is lower than the minimum supported by this IdP.',
    [`${ST_PFX}ResourceNotRecognized`]:
        'The resource specified in the request is not recognized by this IdP.',
    [`${ST_PFX}TooManyResponses`]:
        'Too many matching responses exist; the IdP cannot return all of them.',
    [`${ST_PFX}UnknownAttrProfile`]:
        'An unknown attribute profile was requested.',
    [`${ST_PFX}UnknownPrincipal`]:
        'The specified principal is not known to this IdP.',
    [`${ST_PFX}UnsupportedBinding`]:
        'The binding specified in the request is not supported by this IdP.',
};

const SAML_CORE_SPEC = 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf';

export const STATUS_SPEC_URLS: Record<string, string> = {
    [`${ST_PFX}Success`]: SAML_CORE_SPEC,
    [`${ST_PFX}Requester`]: SAML_CORE_SPEC,
    [`${ST_PFX}Responder`]: SAML_CORE_SPEC,
    [`${ST_PFX}VersionMismatch`]: SAML_CORE_SPEC,
    [`${ST_PFX}AuthnFailed`]: SAML_CORE_SPEC,
    [`${ST_PFX}InvalidAttrNameOrValue`]: SAML_CORE_SPEC,
    [`${ST_PFX}InvalidNameIDPolicy`]: SAML_CORE_SPEC,
    [`${ST_PFX}NoAuthnContext`]: SAML_CORE_SPEC,
    [`${ST_PFX}NoAvailableIDP`]: SAML_CORE_SPEC,
    [`${ST_PFX}NoPassive`]: SAML_CORE_SPEC,
    [`${ST_PFX}NoSupportedIDP`]: SAML_CORE_SPEC,
    [`${ST_PFX}PartialLogout`]: SAML_CORE_SPEC,
    [`${ST_PFX}ProxyCountExceeded`]: SAML_CORE_SPEC,
    [`${ST_PFX}RequestDenied`]: SAML_CORE_SPEC,
    [`${ST_PFX}RequestUnsupported`]: SAML_CORE_SPEC,
    [`${ST_PFX}RequestVersionDeprecated`]: SAML_CORE_SPEC,
    [`${ST_PFX}RequestVersionTooHigh`]: SAML_CORE_SPEC,
    [`${ST_PFX}RequestVersionTooLow`]: SAML_CORE_SPEC,
    [`${ST_PFX}ResourceNotRecognized`]: SAML_CORE_SPEC,
    [`${ST_PFX}TooManyResponses`]: SAML_CORE_SPEC,
    [`${ST_PFX}UnknownAttrProfile`]: SAML_CORE_SPEC,
    [`${ST_PFX}UnknownPrincipal`]: SAML_CORE_SPEC,
    [`${ST_PFX}UnsupportedBinding`]: SAML_CORE_SPEC,
};

export interface SamlDecodeResult {
    xml: string;
    summary: SamlSummary;
}

export function decodeSaml(raw: string): SamlDecodeResult {
    const input = raw.trim();
    const { samlValue, relayState, paramName } = extractSamlParam(input);
    const { xml, binding } = decodeValue(samlValue);

    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    if (doc.querySelector('parsererror')) {
        throw new Error('Decoded content is not valid XML');
    }

    return { xml: prettyPrintXml(xml), summary: parseSummary(doc, binding, relayState, paramName) };
}

export function decodeAllSaml(raw: string): SamlDecodeResult[] {
    const pattern = /(SAMLRequest|SAMLResponse)\s*[:=]\s*([^\s&"'\n\r<>]+)/gi;
    const results: SamlDecodeResult[] = [];
    const seen = new Set<string>();
    let m: RegExpExecArray | null;

    while ((m = pattern.exec(raw)) !== null) {
        const [, paramName, value] = m;
        const key = value.slice(0, 60);
        if (seen.has(key)) continue;
        seen.add(key);
        try {
            // Use colon format to avoid URLSearchParams treating '+' as a space
            results.push(decodeSaml(`${paramName}: ${value.trim()}`));
        } catch {
            // skip unparseable matches
        }
    }

    return results;
}

// ── Input extraction ──────────────────────────────────────────────────────────

function extractSamlParam(input: string): {
    samlValue: string;
    relayState?: string;
    paramName: MessageType | 'raw';
} {
    const qs = extractQueryString(input);

    if (qs) {
        const params = new URLSearchParams(qs);
        const req = params.get('SAMLRequest');
        const res = params.get('SAMLResponse');
        const rs = params.get('RelayState') ?? undefined;
        if (req) return { samlValue: req, relayState: rs, paramName: 'SAMLRequest' };
        if (res) return { samlValue: res, relayState: rs, paramName: 'SAMLResponse' };
    }

    // Colon-separated format from HTTP proxy tools / Burp: "SAMLRequest: <value>"
    const colonReqMatch = input.match(/SAMLRequest\s*:\s*([^\n\r]+)/i);
    const colonResMatch = input.match(/SAMLResponse\s*:\s*([^\n\r]+)/i);
    const colonRsMatch = input.match(/RelayState\s*:\s*([^\n\r]+)/i);
    if (colonReqMatch)
        return {
            samlValue: colonReqMatch[1].trim(),
            relayState: colonRsMatch?.[1].trim(),
            paramName: 'SAMLRequest'
        };
    if (colonResMatch)
        return {
            samlValue: colonResMatch[1].trim(),
            relayState: colonRsMatch?.[1].trim(),
            paramName: 'SAMLResponse'
        };

    return { samlValue: input, paramName: 'raw' };
}

function extractQueryString(input: string): string | null {
    // Full URL
    try {
        const url = new URL(input);
        if (url.search) return url.search;
    } catch {
        // not a URL
    }

    // HTTP log line: GET /path?query HTTP/1.1 (optionally quoted)
    const logMatch = input.match(/(?:GET|POST)\s+(\S*\?[^\s"']+)/i);
    if (logMatch) {
        try {
            const path = logMatch[1];
            const url = new URL(`http://x${path.startsWith('/') ? '' : '/'}${path}`);
            /* v8 ignore next */
            if (url.search) return url.search;
        } catch {
            // not parseable
        }
    }

    // Raw query string
    if (input.startsWith('?')) return input;
    if (input.includes('SAMLRequest=') || input.includes('SAMLResponse=')) return `?${input}`;

    return null;
}

// ── Decode ────────────────────────────────────────────────────────────────────

function decodeValue(raw: string): { xml: string; binding: BindingType } {
    // Already XML
    if (raw.trimStart().startsWith('<')) {
        return { xml: raw, binding: 'post' };
    }

    // Iteratively URL-decode until stable (handles double-encoding like %252F)
    let value = raw;
    for (let i = 0; i < 5; i++) {
        const next = safeDecode(value);
        if (next === value) break;
        value = next;
    }

    // Strip whitespace that sneaks in when copy-pasting base64
    const b64 = value.replace(/\s+/g, '');
    const bytes = base64ToBytes(b64);

    // Try HTTP-Redirect binding: raw DEFLATE + base64
    try {
        const inflated = inflateRaw(bytes);
        const xml = new TextDecoder().decode(inflated);
        if (xml.trimStart().startsWith('<')) return { xml, binding: 'redirect' };
    } catch {
        // not deflated
    }

    // Try HTTP-POST binding: plain base64
    const xml = new TextDecoder().decode(bytes);
    if (xml.trimStart().startsWith('<')) return { xml, binding: 'post' };

    throw new Error(
        'Could not decode input. Paste a SAMLRequest, SAMLResponse, query string, or URL.'
    );
}

function base64ToBytes(b64: string): Uint8Array {
    // Accept both standard base64 (+/) and base64url (-_)
    const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '=='.slice(0, (4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function safeDecode(s: string): string {
    try {
        return decodeURIComponent(s);
    } catch {
        return s;
    }
}

// ── Summary extraction ────────────────────────────────────────────────────────

function getEl(parent: Document | Element, ns: string, localName: string): Element | null {
    return parent.getElementsByTagNameNS(ns, localName).item(0);
}

function getEls(parent: Document | Element, ns: string, localName: string): Element[] {
    return Array.from(parent.getElementsByTagNameNS(ns, localName));
}

function attr(el: Element | null, name: string): string | undefined {
    return el?.getAttribute(name) ?? undefined;
}

function txt(el: Element | null): string | undefined {
    const t = el?.textContent?.trim();
    return t || undefined;
}

function parseSummary(
    doc: Document,
    binding: BindingType,
    relayState: string | undefined,
    paramName: MessageType | 'raw'
): SamlSummary {
    const root = doc.documentElement;
    const ln = root.localName;

    const messageType: MessageType =
        ln === 'AuthnRequest' || ln === 'LogoutRequest'
            ? 'SAMLRequest'
            : ln === 'Response' || ln === 'LogoutResponse'
              ? 'SAMLResponse'
              : paramName === 'raw'
                ? 'unknown'
                : paramName;

    const timestamps: TimestampField[] = [];
    const addTs = (label: string, raw: string | null | undefined) => {
        if (!raw) return;
        const date = new Date(raw);
        if (!isNaN(date.getTime())) timestamps.push({ label, raw, date });
    };

    const authnStmt = getEl(doc, NS_SAML, 'AuthnStatement');
    addTs('AuthnInstant', attr(authnStmt, 'AuthnInstant'));
    addTs('SessionNotOnOrAfter', attr(authnStmt, 'SessionNotOnOrAfter'));

    const authnCtxEl = authnStmt ? getEl(authnStmt, NS_SAML, 'AuthnContext') : null;
    const authnContext = authnCtxEl
        ? {
              /* v8 ignore next */
              classRef: txt(getEl(authnCtxEl, NS_SAML, 'AuthnContextClassRef')) ?? '',
              declRef: txt(getEl(authnCtxEl, NS_SAML, 'AuthnContextDeclRef'))
          }
        : undefined;

    const reqAuthnCtxEl = getEl(doc, NS_SAMLP, 'RequestedAuthnContext');
    const requestedAuthnContext = reqAuthnCtxEl
        ? {
              classRefs: getEls(reqAuthnCtxEl, NS_SAML, 'AuthnContextClassRef')
                  .map((el) => txt(el) ?? '')
                  .filter(Boolean),
              comparison: attr(reqAuthnCtxEl, 'Comparison') ?? 'exact'
          }
        : undefined;

    const conditions = getEl(doc, NS_SAML, 'Conditions');
    addTs('NotBefore', attr(conditions, 'NotBefore'));
    addTs('NotOnOrAfter', attr(conditions, 'NotOnOrAfter'));

    // Only add SubjectConfirmation NotOnOrAfter if it differs from Conditions
    const scd = getEl(doc, NS_SAML, 'SubjectConfirmationData');
    const scdExp = attr(scd, 'NotOnOrAfter');
    if (scdExp && scdExp !== attr(conditions, 'NotOnOrAfter')) {
        addTs('SubjectConfirmation NotOnOrAfter', scdExp);
    }

    const statusEl = getEl(doc, NS_SAMLP, 'Status');
    let status: SamlStatus | undefined;
    if (statusEl) {
        const codeEl = getEl(statusEl, NS_SAMLP, 'StatusCode');
        const subCodeEl = codeEl ? getEl(codeEl, NS_SAMLP, 'StatusCode') : null;
        const messageEl = getEl(statusEl, NS_SAMLP, 'StatusMessage');
        status = {
            code: attr(codeEl, 'Value') ?? '',
            subCode: subCodeEl ? attr(subCodeEl, 'Value') : undefined,
            message: txt(messageEl)
        };
    }

    const assertionEncrypted =
        getEl(doc, NS_SAML, 'EncryptedAssertion') !== null ||
        getEl(doc, NS_XENC, 'EncryptedData') !== null;
    const nameIdEncrypted = getEl(doc, NS_SAML, 'EncryptedID') !== null;

    const nameIdEl = nameIdEncrypted ? null : getEl(doc, NS_SAML, 'NameID');

    // Signing cert lives inside ds:Signature — don't pick up encryption key certs
    const signatureEl = getEl(doc, NS_DS, 'Signature');
    const signingCertificate = signatureEl
        ? txt(getEl(signatureEl, NS_DS, 'X509Certificate'))?.replace(/\s+/g, '')
        : undefined;

    const attributes: AttributeField[] = getEls(doc, NS_SAML, 'Attribute').map((attrEl) => ({
        name: attr(attrEl, 'Name') ?? '',
        friendlyName: attr(attrEl, 'FriendlyName'),
        values: getEls(attrEl, NS_SAML, 'AttributeValue').map((v) => txt(v) ?? '')
    }));

    return {
        messageType,
        binding,
        relayState,
        issuer: txt(getEl(doc, NS_SAML, 'Issuer')),
        nameId: nameIdEl
            ? { value: txt(nameIdEl) ?? '', format: attr(nameIdEl, 'Format') }
            : undefined,
        authnContext,
        requestedAuthnContext,
        destination: attr(root, 'Destination'),
        acsUrl: attr(root, 'AssertionConsumerServiceURL'),
        inResponseTo: attr(root, 'InResponseTo'),
        status,
        timestamps,
        encrypted: { assertion: assertionEncrypted, nameId: nameIdEncrypted },
        signingCertificate,
        attributes
    };
}

// ── XML pretty printer ────────────────────────────────────────────────────────

function splitAttrs(s: string): string[] {
    const result: string[] = [];
    let i = 0;
    while (i < s.length) {
        while (i < s.length && (s[i] === ' ' || s[i] === '\n' || s[i] === '\r' || s[i] === '\t')) i++;
        if (i >= s.length) break;
        const start = i;
        while (i < s.length && s[i] !== '=' && s[i] !== ' ' && s[i] !== '\n' && s[i] !== '\r' && s[i] !== '\t') i++;
        if (i < s.length && s[i] === '=') {
            i++;
            /* v8 ignore next */
            if (i < s.length && (s[i] === '"' || s[i] === "'")) {
                const q = s[i++];
                while (i < s.length && s[i] !== q) i++;
                i++;
            }
        }
        const attr = s.slice(start, i).trim();
        /* v8 ignore next */
        if (attr) result.push(attr);
    }
    return result;
}

function wrapOpenTag(tag: string, baseIndent: string): string {
    const selfClose = tag.endsWith('/>');
    const inner = tag.slice(1, selfClose ? -2 : -1);
    const spaceIdx = inner.search(/\s/);
    if (spaceIdx === -1) return baseIndent + tag;

    const name = inner.slice(0, spaceIdx);
    const attrs = splitAttrs(inner.slice(spaceIdx));
    /* v8 ignore next */
    if (attrs.length === 0) return baseIndent + tag;

    const close = selfClose ? '/>' : '>';
    const firstLine = baseIndent + '<' + name + ' ' + attrs[0];
    if (attrs.length === 1) return firstLine + close;

    // Check if everything fits on one line
    const full = firstLine + ' ' + attrs.slice(1).join(' ') + close;
    if (full.length <= 100) return full;

    // Width-based wrapping: pack attrs onto continuation lines up to 100 chars
    const continuation = baseIndent + ' '.repeat(name.length + 2);
    const lines: string[] = [];
    let current = firstLine;
    for (const attr of attrs.slice(1)) {
        const candidate = current + ' ' + attr;
        if (candidate.length <= 100) {
            current = candidate;
        } else {
            lines.push(current);
            current = continuation + attr;
        }
    }
    lines.push(current + close);
    return lines.join('\n');
}

export function prettyPrintXml(xml: string): string {
    const compact = xml.replace(/>\s+</g, '><').trim();
    let indent = 0;
    const lines: string[] = [];
    let current = '';

    const re = /(<[^>]+>)|([^<]+)/g;
    let m: RegExpExecArray | null;

    while ((m = re.exec(compact)) !== null) {
        const [, tag, text] = m;

        if (tag) {
            if (tag.startsWith('</')) {
                indent = Math.max(0, indent - 1);
                if (current) {
                    // text content on same line as open tag — keep closing tag there too
                    lines.push(current + tag);
                    current = '';
                } else {
                    lines.push('  '.repeat(indent) + tag);
                }
            } else if (tag.endsWith('/>') || tag.startsWith('<?') || tag.startsWith('<!')) {
                if (current) {
                    lines.push(current);
                    current = '';
                }
                lines.push(tag.endsWith('/>') ? wrapOpenTag(tag, '  '.repeat(indent)) : '  '.repeat(indent) + tag);
            } else {
                // Opening tag
                if (current) lines.push(current);
                current = wrapOpenTag(tag, '  '.repeat(indent));
                indent++;
            }
        } else {
            const t = text!.trim();
            if (t && current) current += t;
        }
    }

    if (current) lines.push(current);
    return lines.join('\n');
}
