import { describe, it, expect } from 'vitest';
import { deflateRaw } from 'pako';
import {
    applyEdits,
    encodeRequest,
    hasEmbeddedSignature,
    isAuthnRequest,
    nowInstant,
    readFields,
    redirectUrl,
    validateFields,
    type AuthnRequestFields
} from './authn-edit';
import { decodeSaml } from './saml';

const MFA = 'https://refeds.org/profile/mfa';
const PPT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

const REQ = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://idp.example.org/idp/profile/SAML2/Redirect/SSO" AssertionConsumerServiceURL="https://sp.example.org/Shibboleth.sso/SAML2/POST" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://sp.example.org/shibboleth</saml:Issuer><samlp:NameIDPolicy AllowCreate="1"/><samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>${PPT}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext><samlp:Scoping ProxyCount="1"/></samlp:AuthnRequest>`;

const BARE = `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_b" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" AssertionConsumerServiceIndex="2"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.org/</Issuer><Scoping/></AuthnRequest>`;

const SIGNED = REQ.replace(
    '</saml:Issuer>',
    '</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></ds:Signature>'
);

const fields = (over: Partial<AuthnRequestFields> = {}): AuthnRequestFields => ({
    ...readFields(REQ),
    ...over
});

/** Re-read an edited request, plus the order of its child elements. */
function reread(xml: string) {
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    return {
        fields: readFields(xml),
        root: doc.documentElement,
        children: Array.from(doc.documentElement.children).map((c) => c.localName)
    };
}

describe('isAuthnRequest', () => {
    it('accepts an AuthnRequest with any prefix', () => {
        expect(isAuthnRequest(REQ)).toBe(true);
        expect(isAuthnRequest(BARE)).toBe(true);
    });

    it('rejects other messages and broken XML', () => {
        expect(isAuthnRequest(REQ.replace(/AuthnRequest/g, 'LogoutRequest'))).toBe(false);
        expect(isAuthnRequest('<AuthnRequest/>')).toBe(false);
        expect(isAuthnRequest('<nope')).toBe(false);
    });
});

describe('readFields', () => {
    it('reads every editable field', () => {
        expect(readFields(REQ)).toEqual({
            issueInstant: '2026-01-01T00:00:00Z',
            acsUrl: 'https://sp.example.org/Shibboleth.sso/SAML2/POST',
            acsIndex: '',
            classRefs: [PPT],
            comparison: 'minimum'
        });
    });

    it('defaults when the request has no ACS URL, context or IssueInstant', () => {
        expect(readFields(BARE.replace(' IssueInstant="2026-01-01T00:00:00Z"', ''))).toEqual({
            issueInstant: '',
            acsUrl: '',
            acsIndex: '2',
            classRefs: [],
            comparison: 'exact'
        });
    });

    it('treats a missing or unknown Comparison as exact and skips empty refs', () => {
        const xml = REQ.replace(' Comparison="minimum"', ' Comparison="weird"').replace(
            `${PPT}</saml:AuthnContextClassRef>`,
            `${PPT}</saml:AuthnContextClassRef><saml:AuthnContextClassRef> </saml:AuthnContextClassRef>`
        );
        expect(readFields(xml)).toMatchObject({ comparison: 'exact', classRefs: [PPT] });
    });

    it('rejects a message that is not an AuthnRequest', () => {
        expect(() => readFields('<x/>')).toThrow('Not an AuthnRequest');
        expect(() => readFields('<x')).toThrow('Not valid XML');
    });
});

describe('applyEdits', () => {
    it('updates IssueInstant and leaves everything else in place', () => {
        const out = reread(applyEdits(REQ, fields({ issueInstant: '2026-11-06T20:00:00Z' })));
        expect(out.fields).toEqual(fields({ issueInstant: '2026-11-06T20:00:00Z' }));
        expect(out.root.getAttribute('ID')).toBe('_req1');
        expect(out.root.getAttribute('ProtocolBinding')).toContain('HTTP-POST');
        expect(out.children).toEqual([
            'Issuer',
            'NameIDPolicy',
            'RequestedAuthnContext',
            'Scoping'
        ]);
    });

    it('changes the ACS URL', () => {
        const out = reread(applyEdits(REQ, fields({ acsUrl: 'https://sp2.example.org/acs' })));
        expect(out.fields.acsUrl).toBe('https://sp2.example.org/acs');
    });

    it('switches from a URL to an index, dropping ProtocolBinding', () => {
        const out = reread(applyEdits(REQ, fields({ acsUrl: '', acsIndex: '3' })));
        expect(out.fields).toMatchObject({ acsUrl: '', acsIndex: '3' });
        expect(out.root.hasAttribute('ProtocolBinding')).toBe(false);
    });

    it('switches from an index to a URL', () => {
        const base = readFields(BARE);
        const out = reread(
            applyEdits(BARE, { ...base, acsIndex: '', acsUrl: 'https://sp.example.org/acs' })
        );
        expect(out.fields).toMatchObject({ acsUrl: 'https://sp.example.org/acs', acsIndex: '' });
    });

    it('drops both ACS attributes when both are cleared', () => {
        const out = reread(applyEdits(REQ, fields({ acsUrl: '', acsIndex: '' })));
        expect(out.root.hasAttribute('AssertionConsumerServiceURL')).toBe(false);
        expect(out.root.hasAttribute('AssertionConsumerServiceIndex')).toBe(false);
    });

    it('replaces the requested context and comparison', () => {
        const out = reread(
            applyEdits(REQ, fields({ classRefs: [MFA, ' ', PPT], comparison: 'exact' }))
        );
        expect(out.fields).toMatchObject({ classRefs: [MFA, PPT], comparison: 'exact' });
        // exact is the default, so it is not written out
        expect(applyEdits(REQ, fields({ classRefs: [MFA], comparison: 'exact' }))).not.toContain(
            'Comparison='
        );
        expect(
            reread(applyEdits(REQ, fields({ classRefs: [MFA], comparison: 'better' }))).fields
                .comparison
        ).toBe('better');
    });

    it('removes RequestedAuthnContext when no class refs are left', () => {
        const out = reread(applyEdits(REQ, fields({ classRefs: [] })));
        expect(out.children).toEqual(['Issuer', 'NameIDPolicy', 'Scoping']);
    });

    it('adds RequestedAuthnContext before Scoping, declaring the saml prefix it needs', () => {
        const xml = applyEdits(BARE, { ...readFields(BARE), classRefs: [MFA] });
        const out = reread(xml);
        expect(out.children).toEqual(['Issuer', 'RequestedAuthnContext', 'Scoping']);
        expect(out.fields.classRefs).toEqual([MFA]);
        expect(xml).toContain('xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"');
    });

    it('appends RequestedAuthnContext when there is no Scoping', () => {
        const xml = BARE.replace('<Scoping/>', '');
        const out = reread(applyEdits(xml, { ...readFields(xml), classRefs: [MFA] }));
        expect(out.children).toEqual(['Issuer', 'RequestedAuthnContext']);
    });

    it('rejects a message that is not an AuthnRequest', () => {
        expect(() => applyEdits('<x/>', fields())).toThrow('Not an AuthnRequest');
    });
});

describe('hasEmbeddedSignature', () => {
    it('finds an enveloped ds:Signature', () => {
        expect(hasEmbeddedSignature(SIGNED)).toBe(true);
        expect(hasEmbeddedSignature(REQ)).toBe(false);
        expect(hasEmbeddedSignature('<x/>')).toBe(false);
    });
});

describe('validateFields', () => {
    it('accepts a well-formed request', () => {
        expect(validateFields(fields())).toEqual([]);
        expect(validateFields(fields({ issueInstant: '2026-11-06T15:00:00-05:00' }))).toEqual([]);
        expect(validateFields(fields({ acsUrl: '', acsIndex: '65535' }))).toEqual([]);
    });

    it('requires an xs:dateTime with a time zone', () => {
        for (const bad of ['', 'yesterday', '2026-11-06T20:00:00']) {
            expect(validateFields(fields({ issueInstant: bad }))[0]).toMatch(
                /^IssueInstant must be/
            );
        }
    });

    it('refuses an ACS URL and an index together', () => {
        expect(validateFields(fields({ acsIndex: '1' }))).toEqual([
            'Use an ACS URL or an ACS index, not both (SAML Core §3.4.1)'
        ]);
    });

    it('requires an absolute ACS URL', () => {
        expect(validateFields(fields({ acsUrl: '/acs' }))).toEqual([
            'ACS URL must be an absolute URL'
        ]);
    });

    it('requires an unsigned short ACS index', () => {
        for (const bad of ['-1', '1.5', 'two', '65536']) {
            expect(validateFields(fields({ acsUrl: '', acsIndex: bad }))).toEqual([
                'ACS index must be a whole number from 0 to 65535'
            ]);
        }
    });
});

describe('nowInstant', () => {
    it('formats to the second in UTC', () => {
        expect(nowInstant(new Date('2026-11-06T20:01:02.345Z'))).toBe('2026-11-06T20:01:02Z');
        expect(nowInstant()).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    });
});

describe('encodeRequest', () => {
    it('round-trips through the decoder for HTTP-Redirect', () => {
        const edited = applyEdits(REQ, fields({ classRefs: [MFA] }));
        const r = decodeSaml(
            `SAMLRequest=${encodeURIComponent(encodeRequest(edited, 'redirect'))}`
        );
        expect(r.summary.binding).toBe('redirect');
        expect(r.summary.requestedAuthnContext?.classRefs).toEqual([MFA]);
        expect(r.source.xml).toBe(edited);
    });

    it('round-trips through the decoder for HTTP-POST', () => {
        const edited = applyEdits(REQ, fields({ acsUrl: 'https://sp2.example.org/acs' }));
        const r = decodeSaml(encodeRequest(edited, 'post'));
        expect(r.summary.binding).toBe('post');
        expect(r.summary.acsUrl).toBe('https://sp2.example.org/acs');
    });

    it('encodes non-ASCII characters as UTF-8', () => {
        const xml = REQ.replace('https://sp.example.org/shibboleth', 'https://sp.example.org/é');
        expect(decodeSaml(encodeRequest(xml, 'post')).summary.issuer).toBe(
            'https://sp.example.org/é'
        );
    });
});

describe('redirectUrl', () => {
    const value = encodeRequest(REQ, 'redirect');

    it('builds the redirect URL with RelayState', () => {
        const url = new URL(redirectUrl('https://idp.example.org/sso', value, 'ss:mem:123'));
        expect(url.origin + url.pathname).toBe('https://idp.example.org/sso');
        expect(url.searchParams.get('SAMLRequest')).toBe(value);
        expect(url.searchParams.get('RelayState')).toBe('ss:mem:123');
    });

    it('replaces SAML parameters and drops the old signature, keeping others', () => {
        const old =
            'https://idp.example.org/sso?foo=1&SAMLRequest=old&RelayState=x&SigAlg=rsa&Signature=sig';
        const url = new URL(redirectUrl(old, value));
        expect([...url.searchParams.keys()]).toEqual(['foo', 'SAMLRequest']);
    });

    it('is decoded back by the SAML decoder', () => {
        const r = decodeSaml(redirectUrl('https://idp.example.org/sso', value, 'rs'));
        expect(r.source).toMatchObject({
            relayState: 'rs',
            endpoint: 'https://idp.example.org/sso',
            redirectSigned: false
        });
    });
});

describe('decodeSaml source', () => {
    const value = Buffer.from(deflateRaw(new TextEncoder().encode(REQ))).toString('base64');

    it('records the endpoint and a redirect signature', () => {
        const input = `https://idp.example.org/sso?x=1&SAMLRequest=${encodeURIComponent(value)}&RelayState=rs&SigAlg=a&Signature=s`;
        expect(decodeSaml(input).source).toEqual({
            xml: REQ,
            relayState: 'rs',
            endpoint: 'https://idp.example.org/sso?x=1',
            redirectSigned: true,
            query: input.slice(input.indexOf('?') + 1)
        });
    });

    it('has no endpoint for a bare parameter or a non-HTTP URL', () => {
        expect(
            decodeSaml(`SAMLRequest=${encodeURIComponent(value)}`).source.endpoint
        ).toBeUndefined();
        expect(
            decodeSaml(`ftp://idp.example.org/?SAMLRequest=${encodeURIComponent(value)}`).source
                .endpoint
        ).toBeUndefined();
    });
});
