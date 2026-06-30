import { describe, it, expect } from 'vitest';
import { highlightXml, XML_ELEMENT_TIPS } from './xml-highlight';

describe('highlightXml — element names', () => {
    it('wraps element names in xml-el spans', () => {
        const result = highlightXml('<foo>text</foo>');
        expect(result).toContain('<span class="xml-el">foo</span>');
    });

    it('adds data-el and xml-el-tip for known SAML elements', () => {
        const result = highlightXml('<saml:Assertion>');
        expect(result).toContain('class="xml-el xml-el-tip"');
        expect(result).toContain('data-el="Assertion"');
        expect(result).toContain('>saml:Assertion<');
    });

    it('does not add data-el for unknown elements', () => {
        const result = highlightXml('<foo:Unknown>');
        expect(result).toContain('class="xml-el"');
        expect(result).not.toContain('data-el');
    });

    it('handles namespace-prefixed closing tags', () => {
        const result = highlightXml('</saml:Issuer>');
        expect(result).toContain('data-el="Issuer"');
        expect(result).toContain('&lt;/');
        expect(result).toContain('&gt;');
    });

    it('handles self-closing tags', () => {
        const result = highlightXml(
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        );
        expect(result).toContain('data-el="StatusCode"');
        expect(result).toContain('/&gt;');
    });
});

describe('highlightXml — punctuation', () => {
    it('wraps < and > in xml-punct spans', () => {
        const result = highlightXml('<foo>');
        expect(result).toContain('<span class="xml-punct">&lt;</span>');
        expect(result).toContain('<span class="xml-punct">&gt;</span>');
    });

    it('wraps </ in xml-punct span for closing tags', () => {
        const result = highlightXml('</foo>');
        expect(result).toContain('<span class="xml-punct">&lt;/</span>');
    });

    it('wraps /> in xml-punct span for self-closing tags', () => {
        const result = highlightXml('<foo/>');
        expect(result).toContain('<span class="xml-punct">/&gt;</span>');
    });
});

describe('highlightXml — attributes', () => {
    it('wraps attribute names in xml-attr-name spans', () => {
        const result = highlightXml('<foo bar="baz">');
        expect(result).toContain('<span class="xml-attr-name">bar</span>');
    });

    it('wraps attribute values in xml-attr-val spans', () => {
        const result = highlightXml('<foo bar="baz">');
        expect(result).toContain('<span class="xml-attr-val">&quot;baz&quot;</span>');
    });

    it('wraps = in xml-punct span', () => {
        const result = highlightXml('<foo bar="baz">');
        expect(result).toContain('<span class="xml-punct">=</span>');
    });

    it('escapes special chars in attribute values', () => {
        const result = highlightXml('<foo attr="a&b<c">');
        expect(result).toContain('&amp;b&lt;c');
    });

    it('handles multiple attributes', () => {
        const result = highlightXml('<foo a="1" b="2">');
        expect(result).toContain('<span class="xml-attr-name">a</span>');
        expect(result).toContain('<span class="xml-attr-name">b</span>');
    });

    it('handles namespace-prefixed attributes', () => {
        const result = highlightXml('<foo xsi:type="xs:string">');
        expect(result).toContain('xsi:type');
    });

    it('handles single-quoted attribute values', () => {
        const result = highlightXml("<foo bar='baz'>");
        expect(result).toContain('<span class="xml-attr-name">bar</span>');
        expect(result).toContain('<span class="xml-attr-val">\'baz\'</span>');
    });

    it('handles attributes without a value at end of tag', () => {
        const result = highlightXml('<foo selected>');
        expect(result).toContain('<span class="xml-attr-name">selected</span>');
    });

    it('handles two consecutive valueless attributes', () => {
        const result = highlightXml('<foo a b>');
        expect(result).toContain('<span class="xml-attr-name">a</span>');
        expect(result).toContain('<span class="xml-attr-name">b</span>');
    });

    it('handles newline whitespace in attribute string', () => {
        const result = highlightXml('<foo\n  bar="baz">');
        expect(result).toContain('<span class="xml-attr-name">bar</span>');
    });

    it('handles tab whitespace in attribute string', () => {
        const result = highlightXml('<foo\tbar="baz">');
        expect(result).toContain('<span class="xml-attr-name">bar</span>');
    });
});

describe('highlightXml — text content', () => {
    it('escapes & in text nodes', () => {
        const result = highlightXml('<foo>a &amp; b</foo>');
        // &amp; in XML text becomes &amp;amp; in HTML (shows as &amp; in browser)
        expect(result).toContain('a &amp;amp; b');
    });

    it('passes through plain text unchanged except escaping', () => {
        const result = highlightXml('<foo>hello world</foo>');
        expect(result).toContain('hello world');
    });
});

describe('highlightXml — prolog and comments', () => {
    it('wraps XML declaration in xml-prolog span', () => {
        const result = highlightXml('<?xml version="1.0" encoding="UTF-8"?>');
        expect(result).toContain('<span class="xml-prolog">');
        expect(result).toContain('&lt;?xml');
        expect(result).toContain('?&gt;');
    });

    it('wraps comments in xml-comment span', () => {
        const result = highlightXml('<!-- this is a comment -->');
        expect(result).toContain('<span class="xml-comment">');
        expect(result).toContain('&lt;!-- this is a comment --&gt;');
    });
});

describe('highlightXml — full round-trip', () => {
    it('produces valid HTML for a minimal SAML snippet', () => {
        const xml = [
            '<?xml version="1.0"?>',
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">',
            '  <saml:Issuer>https://idp.example.com</saml:Issuer>',
            '  <samlp:Status>',
            '    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>',
            '  </samlp:Status>',
            '</samlp:Response>'
        ].join('\n');
        const result = highlightXml(xml);
        expect(result).toContain('data-el="Response"');
        expect(result).toContain('data-el="Issuer"');
        expect(result).toContain('data-el="Status"');
        expect(result).toContain('data-el="StatusCode"');
        expect(result).toContain('https://idp.example.com');
        // issuer text content appears as plain text between spans
        expect(result).toContain('</span>https://idp.example.com<span');
    });

    it('handles empty input', () => {
        expect(highlightXml('')).toBe('');
    });

    it('handles trailing text with no closing tag', () => {
        const result = highlightXml('<foo>trailing');
        expect(result).toContain('trailing');
    });
});

describe('XML_ELEMENT_TIPS', () => {
    it('has non-empty tips for core SAML elements', () => {
        const coreElements = [
            'Assertion',
            'Issuer',
            'Subject',
            'NameID',
            'Conditions',
            'AuthnStatement',
            'AuthnContextClassRef',
            'AttributeStatement',
            'Attribute'
        ];
        for (const el of coreElements) {
            expect(XML_ELEMENT_TIPS[el], `missing tip for ${el}`).toBeTruthy();
        }
    });

    it('has non-empty tips for protocol elements', () => {
        const protoElements = [
            'Response',
            'AuthnRequest',
            'Status',
            'StatusCode',
            'RequestedAuthnContext',
            'NameIDPolicy'
        ];
        for (const el of protoElements) {
            expect(XML_ELEMENT_TIPS[el], `missing tip for ${el}`).toBeTruthy();
        }
    });

    it('has non-empty tips for signature elements', () => {
        const sigElements = [
            'Signature',
            'SignedInfo',
            'SignatureValue',
            'X509Certificate',
            'DigestValue'
        ];
        for (const el of sigElements) {
            expect(XML_ELEMENT_TIPS[el], `missing tip for ${el}`).toBeTruthy();
        }
    });

    it('has non-empty tips for encryption elements', () => {
        const encElements = ['EncryptedAssertion', 'EncryptedData', 'EncryptedKey', 'CipherValue'];
        for (const el of encElements) {
            expect(XML_ELEMENT_TIPS[el], `missing tip for ${el}`).toBeTruthy();
        }
    });

    it('has no empty tip values', () => {
        for (const [el, tip] of Object.entries(XML_ELEMENT_TIPS)) {
            expect(tip.length, `empty tip for ${el}`).toBeGreaterThan(0);
        }
    });
});
