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

    // Equals-separated fallback for partial / malformed query strings
    const reqMatch = input.match(/SAMLRequest=([^&\s]+)/);
    const resMatch = input.match(/SAMLResponse=([^&\s]+)/);
    const rsMatch = input.match(/RelayState=([^&\s]+)/);
    const rs = rsMatch ? safeDecode(rsMatch[1]) : undefined;

    if (reqMatch)
        return { samlValue: safeDecode(reqMatch[1]), relayState: rs, paramName: 'SAMLRequest' };
    if (resMatch)
        return { samlValue: safeDecode(resMatch[1]), relayState: rs, paramName: 'SAMLResponse' };

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
                lines.push('  '.repeat(indent) + tag);
            } else {
                // Opening tag
                if (current) {
                    lines.push(current);
                    current = '';
                }
                current = '  '.repeat(indent) + tag;
                indent++;
            }
        } else if (text) {
            const t = text.trim();
            if (t && current) current += t;
        }
    }

    if (current) lines.push(current);
    return lines.join('\n');
}
