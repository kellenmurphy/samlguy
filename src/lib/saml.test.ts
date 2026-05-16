import { describe, it, expect } from 'vitest';
import { decodeSaml, decodeAllSaml, prettyPrintXml, AUTHN_CONTEXT_LABELS, AUTHN_CONTEXT_SPEC_URLS, STATUS_DESCRIPTIONS, STATUS_SPEC_URLS } from '$lib/saml';
import {
    AUTHN_REQUEST_XML,
    AUTHN_REQUEST_WITH_CONTEXT_XML,
    ERROR_RESPONSE_XML,
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

    it('leaves short tags on a single line without wrapping attributes', () => {
        const pretty = prettyPrintXml('<root><el a="1" b="2"/></root>');
        // tag itself must appear intact on one line (no newline within the tag)
        expect(pretty).toContain('<el a="1" b="2"/>');
    });

    it('wraps opening tags whose line exceeds 100 chars', () => {
        const longAttr = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"';
        const longAttr2 = 'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
        const xml = `<samlp:Response ${longAttr} ${longAttr2} ID="_r1"></samlp:Response>`;
        const pretty = prettyPrintXml(xml);
        const firstLine = pretty.split('\n')[0];
        expect(firstLine.length).toBeLessThanOrEqual(100);
        expect(pretty).toContain('\n');
        expect(pretty).toContain(longAttr2);
    });

    it('wraps self-closing tags whose line exceeds 100 chars', () => {
        const xml = `<sc:Code ${`a="${'x'.repeat(40)}"`.repeat(3)}/>`;
        const pretty = prettyPrintXml(`<root>${xml}</root>`);
        const codeLine = pretty.split('\n').find(l => l.includes('sc:Code'))!;
        expect(codeLine.length).toBeLessThanOrEqual(100);
    });

    it('packs multiple short attributes onto the same continuation line', () => {
        // tag is long due to namespace, but short attrs should pack together
        const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"></samlp:Response>';
        const pretty = prettyPrintXml(xml);
        // ID and Version are short — both should appear on the same continuation line
        expect(pretty).toMatch(/ID="_r1" Version="2\.0"/);
    });

    it('wraps a tag with a single attribute if line still exceeds 100 chars', () => {
        const veryLongName = 'x'.repeat(60);
        const xml = `<root><el attr="${veryLongName}"/></root>`;
        const pretty = prettyPrintXml(xml);
        expect(pretty).toContain(`attr="${veryLongName}"`);
    });

    it('handles a tag with no attributes (no wrapping)', () => {
        const pretty = prettyPrintXml('<root><saml:Issuer>text</saml:Issuer></root>');
        expect(pretty).toContain('<saml:Issuer>text</saml:Issuer>');
    });

    it('handles standalone (boolean) attributes in long tags', () => {
        const xml = '<el xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" standalone/>';
        const pretty = prettyPrintXml(`<root>${xml}</root>`);
        expect(pretty).toContain('standalone');
    });

    it('handles self-closing tags with trailing space before />', () => {
        // space before /> causes splitAttrs to process trailing whitespace
        const pretty = prettyPrintXml('<root><el a="1" /></root>');
        expect(pretty).toContain('a="1"');
    });

    it('handles single-quoted attribute values in long tags', () => {
        const xml = "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='_r1'></samlp:Response>";
        const pretty = prettyPrintXml(xml);
        expect(pretty).toContain("xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'");
    });
});

// ── AuthnContext extraction ───────────────────────────────────────────────────

describe('parseSummary — authnContext', () => {
    const r = decodeSaml(toPostBlob(RESPONSE_XML));

    it('extracts classRef from AuthnStatement/AuthnContext', () => {
        expect(r.summary.authnContext?.classRef).toBe(
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        );
    });

    it('leaves declRef undefined when not present', () => {
        expect(r.summary.authnContext?.declRef).toBeUndefined();
    });

    it('is undefined for messages without an AuthnStatement', () => {
        const req = decodeSaml(toRedirectBlob(AUTHN_REQUEST_XML));
        expect(req.summary.authnContext).toBeUndefined();
    });
});

// ── RequestedAuthnContext extraction ─────────────────────────────────────────

describe('parseSummary — requestedAuthnContext', () => {
    const r = decodeSaml(toRedirectBlob(AUTHN_REQUEST_WITH_CONTEXT_XML));

    it('extracts all classRefs', () => {
        expect(r.summary.requestedAuthnContext?.classRefs).toEqual([
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            'https://refeds.org/profile/mfa'
        ]);
    });

    it('extracts the Comparison attribute', () => {
        expect(r.summary.requestedAuthnContext?.comparison).toBe('minimum');
    });

    it('defaults Comparison to "exact" when attribute is absent', () => {
        const xml = AUTHN_REQUEST_WITH_CONTEXT_XML.replace(' Comparison="minimum"', '');
        const r2 = decodeSaml(toRedirectBlob(xml));
        expect(r2.summary.requestedAuthnContext?.comparison).toBe('exact');
    });

    it('is undefined for responses without RequestedAuthnContext', () => {
        const resp = decodeSaml(toPostBlob(RESPONSE_XML));
        expect(resp.summary.requestedAuthnContext).toBeUndefined();
    });

    it('filters out empty AuthnContextClassRef elements', () => {
        const xml = AUTHN_REQUEST_WITH_CONTEXT_XML.replace(
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ''
        );
        const r = decodeSaml(toRedirectBlob(xml));
        expect(r.summary.requestedAuthnContext?.classRefs).toEqual(['https://refeds.org/profile/mfa']);
    });
});

// ── Error response status ─────────────────────────────────────────────────────

describe('parseSummary — error response', () => {
    const r = decodeSaml(toPostBlob(ERROR_RESPONSE_XML));

    it('parses top-level Responder code', () => {
        expect(r.summary.status?.code).toBe('urn:oasis:names:tc:SAML:2.0:status:Responder');
    });

    it('parses nested AuthnFailed sub-code', () => {
        expect(r.summary.status?.subCode).toBe('urn:oasis:names:tc:SAML:2.0:status:AuthnFailed');
    });

    it('parses StatusMessage', () => {
        expect(r.summary.status?.message).toBe('The user failed to authenticate.');
    });

    it('has no authnContext (no assertion)', () => {
        expect(r.summary.authnContext).toBeUndefined();
    });
});

// ── Exported maps ─────────────────────────────────────────────────────────────

describe('AUTHN_CONTEXT_LABELS', () => {
    it('has a label for PasswordProtectedTransport', () => {
        expect(AUTHN_CONTEXT_LABELS['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport']).toBe('Password (HTTPS)');
    });

    it('has labels for REFEDS MFA and SFA', () => {
        expect(AUTHN_CONTEXT_LABELS['https://refeds.org/profile/mfa']).toBe('REFEDS MFA');
        expect(AUTHN_CONTEXT_LABELS['https://refeds.org/profile/sfa']).toBe('REFEDS SFA');
    });

    it('has labels for REFEDS Assurance Framework entries', () => {
        expect(AUTHN_CONTEXT_LABELS['https://refeds.org/assurance/IAP/high']).toBe('REFEDS IAP High');
        expect(AUTHN_CONTEXT_LABELS['https://refeds.org/assurance/ID/eppn-unique-no-reassign']).toBe('REFEDS EPPN (no reassign)');
    });

    it('has labels for NIST/FICAM entries', () => {
        expect(AUTHN_CONTEXT_LABELS['http://idmanagement.gov/ns/assurance/aal/2']).toBe('AAL2');
        expect(AUTHN_CONTEXT_LABELS['http://idmanagement.gov/ns/assurance/ial/1']).toBe('IAL1');
    });

    it('has no empty label values', () => {
        for (const [uri, label] of Object.entries(AUTHN_CONTEXT_LABELS)) {
            expect(label.length, `empty label for ${uri}`).toBeGreaterThan(0);
        }
    });
});

describe('AUTHN_CONTEXT_SPEC_URLS', () => {
    it('maps SAML 2.0 URNs to the OASIS spec PDF', () => {
        const ppt = AUTHN_CONTEXT_SPEC_URLS['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'];
        expect(ppt).toContain('oasis-open.org');
        expect(ppt).toContain('.pdf');
    });

    it('maps REFEDS MFA to its own URI', () => {
        expect(AUTHN_CONTEXT_SPEC_URLS['https://refeds.org/profile/mfa']).toBe('https://refeds.org/profile/mfa');
    });

    it('maps REFEDS Assurance entries to the RAF landing page', () => {
        expect(AUTHN_CONTEXT_SPEC_URLS['https://refeds.org/assurance/IAP/medium']).toBe('https://refeds.org/assurance');
        expect(AUTHN_CONTEXT_SPEC_URLS['https://refeds.org/assurance/ID/eppn-unique-no-reassign']).toBe('https://refeds.org/assurance');
    });

    it('maps NIST/FICAM entries to the NIST 800-63 PDF', () => {
        const aal2 = AUTHN_CONTEXT_SPEC_URLS['http://idmanagement.gov/ns/assurance/aal/2'];
        expect(aal2).toContain('nist.gov');
        expect(aal2).toContain('.pdf');
    });

    it('every entry in AUTHN_CONTEXT_LABELS has a corresponding spec URL', () => {
        for (const uri of Object.keys(AUTHN_CONTEXT_LABELS)) {
            expect(AUTHN_CONTEXT_SPEC_URLS[uri], `missing spec URL for ${uri}`).toBeDefined();
        }
    });

    it('all spec URLs are valid HTTPS URLs', () => {
        for (const [uri, specUrl] of Object.entries(AUTHN_CONTEXT_SPEC_URLS)) {
            expect(specUrl.startsWith('https://'), `spec URL not HTTPS for ${uri}: ${specUrl}`).toBe(true);
        }
    });
});

describe('STATUS_DESCRIPTIONS', () => {
    it('has descriptions for top-level codes', () => {
        expect(STATUS_DESCRIPTIONS['urn:oasis:names:tc:SAML:2.0:status:Requester']).toBeTruthy();
        expect(STATUS_DESCRIPTIONS['urn:oasis:names:tc:SAML:2.0:status:Responder']).toBeTruthy();
        expect(STATUS_DESCRIPTIONS['urn:oasis:names:tc:SAML:2.0:status:VersionMismatch']).toBeTruthy();
    });

    it('has a description for AuthnFailed', () => {
        expect(STATUS_DESCRIPTIONS['urn:oasis:names:tc:SAML:2.0:status:AuthnFailed']).toBeTruthy();
    });

    it('has a description for NoAuthnContext', () => {
        expect(STATUS_DESCRIPTIONS['urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext']).toBeTruthy();
    });

    it('has no empty description values', () => {
        for (const [uri, desc] of Object.entries(STATUS_DESCRIPTIONS)) {
            expect(desc.length, `empty description for ${uri}`).toBeGreaterThan(0);
        }
    });
});

describe('STATUS_SPEC_URLS', () => {
    it('has a spec URL for every STATUS_DESCRIPTIONS key', () => {
        for (const uri of Object.keys(STATUS_DESCRIPTIONS)) {
            expect(STATUS_SPEC_URLS[uri], `missing spec URL for ${uri}`).toBeTruthy();
        }
    });

    it('has a spec URL for the Success top-level code', () => {
        expect(STATUS_SPEC_URLS['urn:oasis:names:tc:SAML:2.0:status:Success']).toBeTruthy();
    });

    it('all spec URLs are HTTPS', () => {
        for (const [uri, url] of Object.entries(STATUS_SPEC_URLS)) {
            expect(url.startsWith('https://'), `non-HTTPS spec URL for ${uri}: ${url}`).toBe(true);
        }
    });

    it('all spec URLs point to the SAML Core spec', () => {
        const SAML_CORE = 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf';
        for (const [uri, url] of Object.entries(STATUS_SPEC_URLS)) {
            expect(url, `unexpected spec URL for ${uri}`).toBe(SAML_CORE);
        }
    });
});
