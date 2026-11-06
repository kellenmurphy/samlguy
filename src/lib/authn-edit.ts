/**
 * Edit a decoded AuthnRequest and re-encode it for its binding (SAML 2.0
 * Core §3.4.1, Bindings §3.4 HTTP-Redirect and §3.5 HTTP-POST). Edits work on
 * the DOM of the message as received, so everything not edited is preserved.
 */
import { deflateRaw } from 'pako';
import type { BindingType } from './saml.js';

const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

export type Comparison = 'exact' | 'minimum' | 'maximum' | 'better';
export const COMPARISONS: Comparison[] = ['exact', 'minimum', 'maximum', 'better'];

export interface AuthnRequestFields {
    issueInstant: string;
    /** AssertionConsumerServiceURL, or '' when the request uses an index or neither. */
    acsUrl: string;
    /** AssertionConsumerServiceIndex, or '' when the request uses a URL or neither. */
    acsIndex: string;
    /** RequestedAuthnContext class references; empty means no RequestedAuthnContext. */
    classRefs: string[];
    comparison: Comparison;
}

function parse(xml: string): Document {
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    if (doc.querySelector('parsererror')) throw new Error('Not valid XML');
    return doc;
}

/** The AuthnRequest root, or null when the message is something else. */
function authnRequest(doc: Document): Element | null {
    const root = doc.documentElement;
    return root.namespaceURI === NS_SAMLP && root.localName === 'AuthnRequest' ? root : null;
}

/** Direct children of `parent` with this namespace and local name. */
function childrenNS(parent: Element, ns: string, local: string): Element[] {
    return Array.from(parent.children).filter(
        (c) => c.namespaceURI === ns && c.localName === local
    );
}

function trimmedText(el: Element): string {
    // an element's textContent is never null; the guard is only for the DOM type
    /* v8 ignore next */
    return el.textContent?.trim() ?? '';
}

function isComparison(v: string | null): v is Comparison {
    return v !== null && (COMPARISONS as string[]).includes(v);
}

/** Whether this XML is an AuthnRequest the editor can work on. */
export function isAuthnRequest(xml: string): boolean {
    try {
        return authnRequest(parse(xml)) !== null;
    } catch {
        return false;
    }
}

/** The editable fields of an AuthnRequest. Throws when the XML is not one. */
export function readFields(xml: string): AuthnRequestFields {
    const req = authnRequest(parse(xml));
    if (!req) throw new Error('Not an AuthnRequest');
    const rac = childrenNS(req, NS_SAMLP, 'RequestedAuthnContext')[0];
    const comparison = rac?.getAttribute('Comparison') ?? null;
    return {
        issueInstant: req.getAttribute('IssueInstant') ?? '',
        acsUrl: req.getAttribute('AssertionConsumerServiceURL') ?? '',
        acsIndex: req.getAttribute('AssertionConsumerServiceIndex') ?? '',
        classRefs: rac
            ? childrenNS(rac, NS_SAML, 'AuthnContextClassRef').map(trimmedText).filter(Boolean)
            : [],
        comparison: isComparison(comparison) ? comparison : 'exact'
    };
}

/** Whether the XML carries an enveloped ds:Signature on the request itself. */
export function hasEmbeddedSignature(xml: string): boolean {
    const req = authnRequest(parse(xml));
    return req !== null && childrenNS(req, NS_DS, 'Signature').length > 0;
}

/** Problems with the fields that would make the request invalid. Empty when it is fine. */
export function validateFields(f: AuthnRequestFields): string[] {
    const problems: string[] = [];
    if (Number.isNaN(Date.parse(f.issueInstant)) || !/Z$|[+-]\d\d:\d\d$/.test(f.issueInstant)) {
        problems.push(
            'IssueInstant must be an xs:dateTime with a time zone, e.g. 2026-11-06T20:00:00Z'
        );
    }
    if (f.acsUrl && f.acsIndex) {
        problems.push('Use an ACS URL or an ACS index, not both (SAML Core §3.4.1)');
    }
    if (f.acsUrl) {
        try {
            new URL(f.acsUrl);
        } catch {
            problems.push('ACS URL must be an absolute URL');
        }
    }
    if (f.acsIndex && !(/^\d+$/.test(f.acsIndex) && Number(f.acsIndex) <= 65535)) {
        problems.push('ACS index must be a whole number from 0 to 65535');
    }
    return problems;
}

/** Elements that may follow RequestedAuthnContext in an AuthnRequest. */
const AFTER_RAC = ['Scoping'];

/**
 * Apply the fields to the request and serialize it. An embedded ds:Signature
 * is left in place; it no longer matches, which the caller should say.
 */
export function applyEdits(xml: string, f: AuthnRequestFields): string {
    const doc = parse(xml);
    const req = authnRequest(doc);
    if (!req) throw new Error('Not an AuthnRequest');

    req.setAttribute('IssueInstant', f.issueInstant);

    // URL and index are mutually exclusive; ProtocolBinding goes with the URL
    if (f.acsIndex) {
        req.removeAttribute('AssertionConsumerServiceURL');
        req.removeAttribute('ProtocolBinding');
        req.setAttribute('AssertionConsumerServiceIndex', f.acsIndex);
    } else {
        req.removeAttribute('AssertionConsumerServiceIndex');
        if (f.acsUrl) req.setAttribute('AssertionConsumerServiceURL', f.acsUrl);
        else req.removeAttribute('AssertionConsumerServiceURL');
    }

    for (const old of childrenNS(req, NS_SAMLP, 'RequestedAuthnContext')) old.remove();
    const refs = f.classRefs.map((r) => r.trim()).filter(Boolean);
    if (refs.length > 0) {
        const pfx = req.prefix ? `${req.prefix}:` : '';
        const rac = doc.createElementNS(NS_SAMLP, `${pfx}RequestedAuthnContext`);
        if (f.comparison !== 'exact') rac.setAttribute('Comparison', f.comparison);
        const samlPrefix = req.lookupPrefix(NS_SAML);
        for (const ref of refs) {
            const el = doc.createElementNS(
                NS_SAML,
                samlPrefix ? `${samlPrefix}:AuthnContextClassRef` : 'saml:AuthnContextClassRef'
            );
            el.textContent = ref;
            rac.appendChild(el);
        }
        const before = Array.from(req.children).find(
            (c) => c.namespaceURI === NS_SAMLP && AFTER_RAC.includes(c.localName)
        );
        req.insertBefore(rac, before ?? null);
    }

    return new XMLSerializer().serializeToString(doc);
}

/** The current time as an xs:dateTime in UTC, to the second. */
export function nowInstant(now: Date = new Date()): string {
    return now.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
}

/** The SAMLRequest parameter value for a binding: DEFLATE + base64 for Redirect, base64 for POST. */
export function encodeRequest(xml: string, binding: BindingType): string {
    const utf8 = new TextEncoder().encode(xml);
    return bytesToBase64(binding === 'redirect' ? deflateRaw(utf8) : utf8);
}

/**
 * The HTTP-Redirect URL for an endpoint. Any SAML parameters already on the
 * endpoint are replaced, and no Signature or SigAlg is added: the request
 * cannot be re-signed in the browser.
 */
export function redirectUrl(endpoint: string, samlRequest: string, relayState?: string): string {
    const url = new URL(endpoint);
    for (const p of ['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg', 'Signature']) {
        url.searchParams.delete(p);
    }
    url.searchParams.append('SAMLRequest', samlRequest);
    if (relayState) url.searchParams.append('RelayState', relayState);
    return url.toString();
}
