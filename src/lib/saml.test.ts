import { describe, it, expect } from 'vitest';
import { decodeSaml, decodeAllSaml, prettyPrintXml } from '$lib/saml';
import {
    AUTHN_REQUEST_XML,
    RESPONSE_XML,
    RESPONSE_WITH_SCD_XML,
    toRedirectBlob,
    toPostBlob
} from './fixtures.test-helper';

// ── decodeSaml ────────────────────────────────────────────────────────────────

describe('decodeSaml — redirect binding (base64+deflate)', () => {
    const blob = toRedirectBlob(AUTHN_REQUEST_XML);

    it('decodes a raw blob', () => {
        const r = decodeSaml(blob);
        expect(r.summary.binding).toBe('redirect');
        expect(r.summary.messageType).toBe('SAMLRequest');
        expect(r.summary.issuer).toBe('https://sp.example.com');
        expect(r.summary.destination).toBe('https://idp.example.com/sso');
        expect(r.summary.acsUrl).toBe('https://sp.example.com/acs');
    });

    it('decodes SAMLRequest=<blob> query string', () => {
        const r = decodeSaml(`SAMLRequest=${encodeURIComponent(blob)}`);
        expect(r.summary.issuer).toBe('https://sp.example.com');
        expect(r.summary.binding).toBe('redirect');
    });

    it('extracts RelayState from query string', () => {
        const r = decodeSaml(
            `SAMLRequest=${encodeURIComponent(blob)}&RelayState=https%3A%2F%2Fapp.example.com`
        );
        expect(r.summary.relayState).toBe('https://app.example.com');
    });

    it('decodes a full URL', () => {
        const r = decodeSaml(
            `https://idp.example.com/sso?SAMLRequest=${encodeURIComponent(blob)}`
        );
        expect(r.summary.issuer).toBe('https://sp.example.com');
    });

    it('decodes an HTTP log line (GET format)', () => {
        const r = decodeSaml(
            `GET /sso?SAMLRequest=${encodeURIComponent(blob)} HTTP/1.1`
        );
        expect(r.summary.issuer).toBe('https://sp.example.com');
    });

    it('decodes a Burp-style colon format (SAMLRequest: <blob>)', () => {
        const r = decodeSaml(`SAMLRequest: ${blob}`);
        expect(r.summary.issuer).toBe('https://sp.example.com');
        expect(r.summary.binding).toBe('redirect');
    });

    it('handles double URL-encoding (%25-encoded blob)', () => {
        const doubleEncoded = encodeURIComponent(encodeURIComponent(blob));
        const r = decodeSaml(`SAMLRequest=${doubleEncoded}`);
        expect(r.summary.issuer).toBe('https://sp.example.com');
    });
});

describe('decodeSaml — POST binding (plain base64)', () => {
    const blob = toPostBlob(RESPONSE_XML);

    it('decodes a SAMLResponse POST blob', () => {
        const r = decodeSaml(blob);
        expect(r.summary.binding).toBe('post');
        expect(r.summary.messageType).toBe('SAMLResponse');
        expect(r.summary.issuer).toBe('https://idp.example.com');
    });

    it('parses status as Success', () => {
        const r = decodeSaml(blob);
        expect(r.summary.status?.code).toBe('urn:oasis:names:tc:SAML:2.0:status:Success');
    });

    it('parses NameID value and format', () => {
        const r = decodeSaml(blob);
        expect(r.summary.nameId?.value).toBe('user@example.com');
        expect(r.summary.nameId?.format).toBe(
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        );
    });

    it('parses InResponseTo', () => {
        const r = decodeSaml(blob);
        expect(r.summary.inResponseTo).toBe('_req1');
    });

    it('parses timestamps', () => {
        const r = decodeSaml(blob);
        const labels = r.summary.timestamps.map((t) => t.label);
        expect(labels).toContain('AuthnInstant');
        expect(labels).toContain('NotBefore');
        expect(labels).toContain('NotOnOrAfter');
        expect(labels).toContain('SessionNotOnOrAfter');
    });

    it('parses attributes', () => {
        const r = decodeSaml(blob);
        const attrs = r.summary.attributes;
        const email = attrs.find((a) => a.name === 'email');
        expect(email?.values).toEqual(['user@example.com']);
        expect(email?.friendlyName).toBe('email');

        const given = attrs.find((a) => a.name === 'urn:oid:2.5.4.42');
        expect(given?.values).toEqual(['Test', 'User']);
    });

    it('returns pretty-printed XML', () => {
        const r = decodeSaml(blob);
        expect(r.xml).toContain('\n');
        expect(r.xml).toContain('samlp:Response');
    });
});

describe('decodeSaml — passthrough for raw XML', () => {
    it('accepts already-decoded XML directly', () => {
        const r = decodeSaml(AUTHN_REQUEST_XML);
        expect(r.summary.binding).toBe('post');
        expect(r.summary.issuer).toBe('https://sp.example.com');
    });
});

describe('decodeSaml — error cases', () => {
    it('throws on empty input', () => {
        expect(() => decodeSaml('   ')).toThrow();
    });

    it('throws on unrecognizable garbage', () => {
        expect(() => decodeSaml('not-saml-at-all-$$$')).toThrow();
    });

    it('throws when decoded content is not XML', () => {
        // valid base64 of plain text
        expect(() => decodeSaml(btoa('hello world'))).toThrow();
    });

    it('throws when decoded content looks like XML but is malformed', () => {
        // base64 of text starting with '<' but failing XML parse
        expect(() => decodeSaml(btoa('<malformed &xml>'))).toThrow('Decoded content is not valid XML');
    });

    it('handles malformed percent-encoding in query strings gracefully', () => {
        // %ZZ is an invalid percent sequence — safeDecode catches the URIError
        expect(() => decodeSaml('SAMLRequest=%ZZ')).toThrow();
    });
});

describe('decodeSaml — SAMLResponse via URLSearchParams', () => {
    it('decodes SAMLResponse from a query string', () => {
        const blob = toPostBlob(RESPONSE_XML);
        const r = decodeSaml(`SAMLResponse=${encodeURIComponent(blob)}`);
        expect(r.summary.messageType).toBe('SAMLResponse');
        expect(r.summary.issuer).toBe('https://idp.example.com');
    });

    it('decodes a Burp-style colon format (SAMLResponse: <blob>)', () => {
        const blob = toPostBlob(RESPONSE_XML);
        const r = decodeSaml(`SAMLResponse: ${blob}`);
        expect(r.summary.messageType).toBe('SAMLResponse');
        expect(r.summary.binding).toBe('post');
    });
});

describe('decodeSaml — SubjectConfirmationData timestamp', () => {
    it('includes SubjectConfirmation NotOnOrAfter when it differs from Conditions', () => {
        const blob = toPostBlob(RESPONSE_WITH_SCD_XML);
        const r = decodeSaml(blob);
        const labels = r.summary.timestamps.map((t) => t.label);
        expect(labels).toContain('SubjectConfirmation NotOnOrAfter');
    });
});

describe('decodeSaml — LogoutRequest and LogoutResponse', () => {
    const LOGOUT_REQUEST_XML =
        '<?xml version="1.0"?>' +
        '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_lr1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z">' +
        '<saml:Issuer>https://sp.example.com</saml:Issuer>' +
        '<saml:NameID>user@example.com</saml:NameID>' +
        '</samlp:LogoutRequest>';

    const LOGOUT_RESPONSE_XML =
        '<?xml version="1.0"?>' +
        '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_ls1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z">' +
        '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '</samlp:LogoutResponse>';

    it('detects LogoutRequest as SAMLRequest', () => {
        const r = decodeSaml(LOGOUT_REQUEST_XML);
        expect(r.summary.messageType).toBe('SAMLRequest');
        expect(r.summary.issuer).toBe('https://sp.example.com');
    });

    it('detects LogoutResponse as SAMLResponse', () => {
        const r = decodeSaml(LOGOUT_RESPONSE_XML);
        expect(r.summary.messageType).toBe('SAMLResponse');
        expect(r.summary.issuer).toBe('https://idp.example.com');
    });
});

describe('decodeSaml — invalid timestamp values are silently ignored', () => {
    const BAD_DATE_XML =
        '<?xml version="1.0"?>' +
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_bd1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z">' +
        '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z">' +
        '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
        '<saml:AuthnStatement AuthnInstant="not-a-valid-date"/>' +
        '</saml:Assertion>' +
        '</samlp:Response>';

    it('drops timestamps that do not parse as a valid date', () => {
        const r = decodeSaml(toPostBlob(BAD_DATE_XML));
        const labels = r.summary.timestamps.map((t) => t.label);
        expect(labels).not.toContain('AuthnInstant');
    });
});

describe('decodeSaml — messageType fallback paths', () => {
    it('returns messageType=unknown when XML root is unrecognized and input is raw', () => {
        // Raw XML (no SAMLRequest/SAMLResponse param) with a non-SAML root element
        const r = decodeSaml('<foo xmlns="urn:test">bar</foo>');
        expect(r.summary.messageType).toBe('unknown');
    });

    it('falls back to paramName when XML root is unrecognized but param name is known', () => {
        // SAMLRequest colon format but with non-standard XML root
        const blob = toRedirectBlob('<foo xmlns="urn:test">bar</foo>');
        const r = decodeSaml(`SAMLRequest: ${blob}`);
        expect(r.summary.messageType).toBe('SAMLRequest');
    });
});

describe('decodeSaml — encrypted NameID', () => {
    const ENCRYPTED_NAMEID_XML =
        '<?xml version="1.0"?>' +
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_enc1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z">' +
        '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z">' +
        '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
        '<saml:Subject>' +
        '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">' +
        '<xenc:CipherData><xenc:CipherValue>ZmFrZQ==</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedData></saml:EncryptedID>' +
        '</saml:Subject>' +
        '</saml:Assertion>' +
        '</samlp:Response>';

    it('detects encrypted NameID and omits nameId from summary', () => {
        const r = decodeSaml(toPostBlob(ENCRYPTED_NAMEID_XML));
        expect(r.summary.encrypted.nameId).toBe(true);
        expect(r.summary.nameId).toBeUndefined();
    });
});

describe('decodeSaml — response with signing certificate', () => {
    const SIGNED_RESPONSE_XML =
        '<?xml version="1.0"?>' +
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
        'ID="_sig1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z">' +
        '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
        '<ds:Signature>' +
        '<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:SignedInfo>' +
        '<ds:KeyInfo><ds:X509Data>' +
        '<ds:X509Certificate>MIIFAKE</ds:X509Certificate>' +
        '</ds:X509Data></ds:KeyInfo>' +
        '</ds:Signature>' +
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '</samlp:Response>';

    it('extracts the signing certificate from ds:Signature', () => {
        const r = decodeSaml(toPostBlob(SIGNED_RESPONSE_XML));
        expect(r.summary.signingCertificate).toBe('MIIFAKE');
    });
});

describe('decodeSaml — error response with sub-status and message', () => {
    const ERROR_RESPONSE_XML =
        '<?xml version="1.0"?>' +
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_err1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z">' +
        '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
        '<samlp:Status>' +
        '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">' +
        '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>' +
        '</samlp:StatusCode>' +
        '<samlp:StatusMessage>Authentication failed</samlp:StatusMessage>' +
        '</samlp:Status>' +
        '</samlp:Response>';

    it('parses nested StatusCode as subCode', () => {
        const r = decodeSaml(toPostBlob(ERROR_RESPONSE_XML));
        expect(r.summary.status?.code).toBe('urn:oasis:names:tc:SAML:2.0:status:Responder');
        expect(r.summary.status?.subCode).toBe('urn:oasis:names:tc:SAML:2.0:status:AuthnFailed');
    });

    it('parses StatusMessage', () => {
        const r = decodeSaml(toPostBlob(ERROR_RESPONSE_XML));
        expect(r.summary.status?.message).toBe('Authentication failed');
    });
});

// ── extractQueryString / extractSamlParam branch coverage ────────────────────

describe('decodeSaml — URL with non-SAML query params falls through', () => {
    it('throws when URL has query params but no SAMLRequest or SAMLResponse', () => {
        expect(() => decodeSaml('https://example.com?foo=bar')).toThrow();
    });
});

describe('decodeSaml — HTTP log line with non-slash-prefixed path', () => {
    it('decodes when path does not start with /', () => {
        const blob = toRedirectBlob(AUTHN_REQUEST_XML);
        const r = decodeSaml(`GET sso.php?SAMLRequest=${encodeURIComponent(blob)} HTTP/1.1`);
        expect(r.summary.issuer).toBe('https://sp.example.com');
    });
});

describe('decodeSaml — ?-prefixed raw query string', () => {
    it('accepts input starting with "?"', () => {
        const blob = toRedirectBlob(AUTHN_REQUEST_XML);
        const r = decodeSaml(`?SAMLRequest=${encodeURIComponent(blob)}`);
        expect(r.summary.issuer).toBe('https://sp.example.com');
        expect(r.summary.binding).toBe('redirect');
    });
});

// ── parseSummary branch coverage ──────────────────────────────────────────────

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

describe('decodeSaml — Status element with no StatusCode child', () => {
    const xml = `<?xml version="1.0"?><samlp:Response xmlns:samlp="${NS_SAMLP}" xmlns:saml="${NS_SAML}" ID="_r" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><samlp:Status/></samlp:Response>`;

    it('sets status.code to empty string when StatusCode is absent', () => {
        const r = decodeSaml(xml);
        expect(r.summary.status?.code).toBe('');
    });
});

describe('decodeSaml — StatusCode with no Value attribute', () => {
    const xml = `<?xml version="1.0"?><samlp:Response xmlns:samlp="${NS_SAMLP}" xmlns:saml="${NS_SAML}" ID="_r" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><samlp:Status><samlp:StatusCode/></samlp:Status></samlp:Response>`;

    it('sets status.code to empty string when Value attribute is absent', () => {
        const r = decodeSaml(xml);
        expect(r.summary.status?.code).toBe('');
    });
});

describe('decodeSaml — Attribute with no Name + empty AttributeValue', () => {
    const xml = `<?xml version="1.0"?><samlp:Response xmlns:samlp="${NS_SAMLP}" xmlns:saml="${NS_SAML}" ID="_r" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Assertion ID="_a" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:AttributeStatement><saml:Attribute><saml:AttributeValue></saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;

    it('uses empty string for missing Name attribute', () => {
        const r = decodeSaml(xml);
        expect(r.summary.attributes[0].name).toBe('');
    });

    it('uses empty string for empty AttributeValue text content', () => {
        const r = decodeSaml(xml);
        expect(r.summary.attributes[0].values[0]).toBe('');
    });
});

describe('decodeSaml — NameID with empty text content', () => {
    const xml = `<?xml version="1.0"?><samlp:Response xmlns:samlp="${NS_SAMLP}" xmlns:saml="${NS_SAML}" ID="_r" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Assertion ID="_a" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Subject><saml:NameID></saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`;

    it('uses empty string when NameID has no text content', () => {
        const r = decodeSaml(xml);
        expect(r.summary.nameId?.value).toBe('');
    });
});

// ── decodeAllSaml ─────────────────────────────────────────────────────────────

describe('decodeAllSaml', () => {
    it('returns a single result for one SAML message', () => {
        const blob = toRedirectBlob(AUTHN_REQUEST_XML);
        const results = decodeAllSaml(`SAMLRequest=${blob}`);
        expect(results).toHaveLength(1);
        expect(results[0].summary.messageType).toBe('SAMLRequest');
    });

    it('returns two results when both a request and response are present', () => {
        const req = toRedirectBlob(AUTHN_REQUEST_XML);
        const res = toPostBlob(RESPONSE_XML);
        const combined = `SAMLRequest=${req}\nSAMLResponse=${res}`;
        const results = decodeAllSaml(combined);
        expect(results).toHaveLength(2);
        const types = results.map((r) => r.summary.messageType).sort();
        expect(types).toEqual(['SAMLRequest', 'SAMLResponse']);
    });

    it('deduplicates identical values', () => {
        const blob = toRedirectBlob(AUTHN_REQUEST_XML);
        const doubled = `SAMLRequest=${blob}\nSAMLRequest=${blob}`;
        const results = decodeAllSaml(doubled);
        expect(results).toHaveLength(1);
    });

    it('returns empty array for input with no SAML params', () => {
        expect(decodeAllSaml('nothing here')).toHaveLength(0);
    });
});

// ── prettyPrintXml ────────────────────────────────────────────────────────────

describe('prettyPrintXml', () => {
    it('indents child elements', () => {
        const xml = '<root><child>text</child></root>';
        const pretty = prettyPrintXml(xml);
        expect(pretty).toContain('\n  <child>');
    });

    it('keeps text content on the same line as its tag', () => {
        const pretty = prettyPrintXml('<root><child>value</child></root>');
        expect(pretty).toMatch(/<child>value<\/child>/);
    });

    it('handles self-closing tags', () => {
        const pretty = prettyPrintXml('<root><empty/></root>');
        expect(pretty).toContain('<empty/>');
    });

    it('collapses whitespace-only text nodes between tags', () => {
        const pretty = prettyPrintXml('<root>   <child/>   </root>');
        expect(pretty).not.toContain('>   <');
        expect(pretty).toContain('<child/>');
    });

    it('flushes a pending open tag when input ends without a closing tag', () => {
        const pretty = prettyPrintXml('<root><unclosed>');
        expect(pretty).toContain('<unclosed>');
    });

    it('drops text that appears after a closing tag with no open tag pending', () => {
        const pretty = prettyPrintXml('<a>foo</a>tail');
        expect(pretty).toContain('<a>foo</a>');
        expect(pretty).not.toContain('tail');
    });
});
