import { describe, it, expect } from 'vitest';
import {
    isMetadata,
    parseMetadata,
    entityCategoryKind,
    BINDING_LABELS,
    ENTITY_CATEGORY_LABELS,
    ENTITY_CATEGORY_SPEC_URLS,
    type RoleDescriptor
} from './metadata';

const NS = `xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
    xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
    xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
    xmlns:shibmd="urn:mace:shibboleth:metadata:1.0"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`;

const SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const B = (b: string) => `urn:oasis:names:tc:SAML:2.0:bindings:${b}`;

const IDP_METADATA = `<?xml version="1.0"?>
<md:EntityDescriptor ${NS}
    entityID="https://shibidp.virginia.edu/idp/shibboleth"
    validUntil="2030-01-01T00:00:00Z" cacheDuration="PT1H">
  <md:Extensions>
    <mdrpi:RegistrationInfo registrationAuthority="https://incommon.org"/>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="http://macedir.org/entity-category">
        <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
        <saml:AttributeValue></saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oasis:names:tc:SAML:attribute:assurance-certification">
        <saml:AttributeValue>https://refeds.org/sirtfi</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6">
        <saml:AttributeValue>ignored@virginia.edu</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:IDPSSODescriptor protocolSupportEnumeration="${SAMLP}" WantAuthnRequestsSigned="true">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="en">University of Virginia</mdui:DisplayName>
        <mdui:Description xml:lang="en">UVA Shibboleth IdP</mdui:Description>
        <mdui:InformationURL xml:lang="en">https://virginia.edu/about</mdui:InformationURL>
        <mdui:PrivacyStatementURL xml:lang="en">https://virginia.edu/privacy</mdui:PrivacyStatementURL>
        <mdui:Logo width="80" height="60">https://virginia.edu/logo.png</mdui:Logo>
      </mdui:UIInfo>
      <shibmd:Scope regexp="false">virginia.edu</shibmd:Scope>
      <shibmd:Scope regexp="false"></shibmd:Scope>
    </md:Extensions>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>
      MIIDsign
      Cert==
      </ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDenc==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService Binding="${B('HTTP-Redirect')}" Location="https://shibidp.virginia.edu/idp/profile/SAML2/Redirect/SSO"/>
    <md:SingleSignOnService Binding="${B('HTTP-POST')}" Location="https://shibidp.virginia.edu/idp/profile/SAML2/POST/SSO"/>
    <md:SingleLogoutService Binding="${B('HTTP-Redirect')}" Location="https://shibidp.virginia.edu/idp/profile/SAML2/Redirect/SLO" ResponseLocation="https://shibidp.virginia.edu/idp/profile/SAML2/Redirect/SLO"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">University of Virginia</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">UVA</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://www.virginia.edu</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:Company>UVA ITS</md:Company>
    <md:GivenName>Kellen</md:GivenName>
    <md:SurName>Murphy</md:SurName>
    <md:EmailAddress>mailto:idm@virginia.edu</md:EmailAddress>
    <md:EmailAddress>backup@virginia.edu</md:EmailAddress>
    <md:EmailAddress></md:EmailAddress>
  </md:ContactPerson>
  <md:ContactPerson contactType="support">
    <md:EmailAddress>help@virginia.edu</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`;

const SP_METADATA = `<md:EntityDescriptor ${NS} entityID="https://sp.example.org/shibboleth">
  <md:SPSSODescriptor protocolSupportEnumeration="${SAMLP}" AuthnRequestsSigned="true" WantAssertionsSigned="false">
    <md:KeyDescriptor>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDspcert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:AssertionConsumerService index="0" isDefault="true" Binding="${B('HTTP-POST')}" Location="https://sp.example.org/acs"/>
    <md:AssertionConsumerService index="1" Binding="${B('HTTP-Artifact')}" Location="https://sp.example.org/acs/artifact"/>
    <md:SingleLogoutService Binding="${B('SOAP')}" Location="https://sp.example.org/slo"/>
    <md:AttributeConsumingService index="0">
      <md:ServiceName>Example SP</md:ServiceName>
      <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="1"/>
      <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

// SP with no AttributeConsumingService and no protocolSupportEnumeration
const SP_MINIMAL = `<md:EntityDescriptor ${NS} entityID="https://sp2.example.org">
  <md:SPSSODescriptor>
    <md:AssertionConsumerService index="0" Binding="${B('HTTP-POST')}" Location="https://sp2.example.org/acs"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

const AGGREGATE = `<md:EntitiesDescriptor ${NS}>
  <md:EntityDescriptor entityID="https://a.example.org">
    <md:IDPSSODescriptor protocolSupportEnumeration="${SAMLP}">
      <md:SingleSignOnService Binding="${B('HTTP-Redirect')}" Location="https://a.example.org/sso"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://b.example.org">
    <md:SPSSODescriptor protocolSupportEnumeration="${SAMLP}"/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`;

const NO_ROLES = `<md:EntityDescriptor ${NS} entityID="https://noroles.example.org"/>`;

// Exercises every empty-string fallback: missing entityID, Attribute Name, contactType,
// endpoint Binding/Location, RequestedAttribute Name, empty-text langString, and Logo URL.
const MALFORMED = `<md:EntityDescriptor ${NS}>
  <md:Extensions>
    <mdattr:EntityAttributes>
      <saml:Attribute><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:SPSSODescriptor protocolSupportEnumeration="${SAMLP}">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="en"></mdui:DisplayName>
        <mdui:Logo width="1" height="1"></mdui:Logo>
      </mdui:UIInfo>
    </md:Extensions>
    <md:AssertionConsumerService index="0"/>
    <md:AttributeConsumingService index="0">
      <md:RequestedAttribute/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:ContactPerson>
    <md:EmailAddress>x@y.z</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`;

const idp = () => parseMetadata(IDP_METADATA).entity;
const role = (kind: 'idp' | 'sp', e = idp()): RoleDescriptor =>
    e.roles.find((r) => r.kind === kind)!;

describe('isMetadata', () => {
    it.each([
        ['raw EntityDescriptor', '<EntityDescriptor entityID="x">'],
        ['prefixed EntityDescriptor', '<md:EntityDescriptor entityID="x">'],
        ['EntitiesDescriptor aggregate', '<md:EntitiesDescriptor>'],
        ['with XML prolog', '<?xml version="1.0"?>\n<md:EntityDescriptor>'],
        ['with leading comment', '<!-- exported --> <md:EntityDescriptor>'],
        [
            'with prolog and multiple comments',
            '<?xml version="1.0"?><!--a--> <!--b--><md:EntityDescriptor>'
        ],
        ['with a BOM', '\uFEFF<md:EntityDescriptor>'],
        ['self-closing', '<md:EntityDescriptor/>']
    ])('detects %s', (_label, input) => {
        expect(isMetadata(input)).toBe(true);
    });

    it.each([
        ['empty', ''],
        ['plain text', 'just some text'],
        ['a JWT', 'eyJhbG.eyJzdWI.sig'],
        ['a SAMLResponse', '<samlp:Response xmlns:samlp="urn:x">'],
        ['unrelated XML', '<EntityThing/>'],
        ['an unterminated prolog', '<?xml version="1.0"'],
        ['an unterminated comment', '<!-- never closed <md:EntityDescriptor>']
    ])('rejects %s', (_label, input) => {
        expect(isMetadata(input)).toBe(false);
    });

    it('does not hang on a ReDoS-style comment payload', () => {
        const evil = '<!--' + '--><!--'.repeat(50_000) + 'x';
        const start = performance.now();
        expect(isMetadata(evil)).toBe(false);
        expect(performance.now() - start).toBeLessThan(500);
    });
});

describe('parseMetadata errors', () => {
    it('throws on invalid XML', () => {
        expect(() => parseMetadata('<md:EntityDescriptor')).toThrow('not valid XML');
    });

    it('throws when no EntityDescriptor present', () => {
        expect(() => parseMetadata('<root xmlns="urn:x"><child/></root>')).toThrow(
            'No EntityDescriptor'
        );
    });
});

describe('parseMetadata — IdP', () => {
    it('parses top-level entity fields', () => {
        const e = idp();
        expect(e.entityId).toBe('https://shibidp.virginia.edu/idp/shibboleth');
        expect(e.validUntil).toBe('2030-01-01T00:00:00Z');
        expect(e.cacheDuration).toBe('PT1H');
        expect(e.registrationAuthority).toBe('https://incommon.org');
        expect(parseMetadata(IDP_METADATA).aggregateCount).toBeUndefined();
    });

    it('collects entity categories and assurance, ignoring non-category attributes', () => {
        expect(idp().entityCategories).toEqual([
            'http://refeds.org/category/research-and-scholarship',
            'https://refeds.org/sirtfi'
        ]);
    });

    it('parses the IdP role descriptor', () => {
        const r = role('idp');
        expect(r.protocolSupport).toEqual([SAMLP]);
        expect(r.wantAuthnRequestsSigned).toBe(true);
        expect(r.scopes).toEqual(['virginia.edu']);
        expect(r.nameIdFormats).toEqual([
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
        ]);
    });

    it('extracts signing + encryption certs and skips certless KeyDescriptors', () => {
        const keys = role('idp').keys;
        expect(keys).toHaveLength(2);
        expect(keys[0]).toEqual({ use: 'signing', certificate: 'MIIDsignCert==' });
        expect(keys[1]).toEqual({ use: 'encryption', certificate: 'MIIDenc==' });
    });

    it('parses SSO and SLO endpoints with response location', () => {
        const r = role('idp');
        expect(r.singleSignOnServices).toEqual([
            {
                binding: B('HTTP-Redirect'),
                location: 'https://shibidp.virginia.edu/idp/profile/SAML2/Redirect/SSO',
                responseLocation: undefined,
                index: undefined,
                isDefault: undefined
            },
            {
                binding: B('HTTP-POST'),
                location: 'https://shibidp.virginia.edu/idp/profile/SAML2/POST/SSO',
                responseLocation: undefined,
                index: undefined,
                isDefault: undefined
            }
        ]);
        expect(r.singleLogoutServices[0].responseLocation).toBe(
            'https://shibidp.virginia.edu/idp/profile/SAML2/Redirect/SLO'
        );
    });

    it('parses MDUI display info', () => {
        const m = role('idp').mdui!;
        expect(m.displayNames).toEqual([{ lang: 'en', value: 'University of Virginia' }]);
        expect(m.descriptions[0].value).toBe('UVA Shibboleth IdP');
        expect(m.informationURLs[0].value).toBe('https://virginia.edu/about');
        expect(m.privacyURLs[0].value).toBe('https://virginia.edu/privacy');
        expect(m.logos).toEqual([
            { url: 'https://virginia.edu/logo.png', width: '80', height: '60' }
        ]);
    });

    it('parses organization', () => {
        const o = idp().organization!;
        expect(o.names[0]).toEqual({ lang: 'en', value: 'University of Virginia' });
        expect(o.displayNames[0].value).toBe('UVA');
        expect(o.urls[0].value).toBe('https://www.virginia.edu');
    });

    it('parses contacts, stripping mailto: and dropping empty emails', () => {
        const c = idp().contacts;
        expect(c).toHaveLength(2);
        expect(c[0]).toEqual({
            type: 'technical',
            company: 'UVA ITS',
            givenName: 'Kellen',
            surName: 'Murphy',
            emails: ['idm@virginia.edu', 'backup@virginia.edu']
        });
        expect(c[1]).toEqual({
            type: 'support',
            company: undefined,
            givenName: undefined,
            surName: undefined,
            emails: ['help@virginia.edu']
        });
    });
});

describe('parseMetadata — SP', () => {
    const sp = () => parseMetadata(SP_METADATA).entity;

    it('parses SP signing flags and a use-less key', () => {
        const r = role('sp', sp());
        expect(r.authnRequestsSigned).toBe(true);
        expect(r.wantAssertionsSigned).toBe(false);
        expect(r.keys).toEqual([{ use: undefined, certificate: 'MIIDspcert==' }]);
    });

    it('parses indexed ACS endpoints with default flag', () => {
        const acs = role('sp', sp()).assertionConsumerServices!;
        expect(acs[0]).toEqual({
            binding: B('HTTP-POST'),
            location: 'https://sp.example.org/acs',
            responseLocation: undefined,
            index: 0,
            isDefault: true
        });
        expect(acs[1].index).toBe(1);
        expect(acs[1].isDefault).toBeUndefined();
    });

    it('parses the attribute consuming service', () => {
        const r = role('sp', sp());
        expect(r.serviceNames).toEqual([{ lang: '', value: 'Example SP' }]);
        expect(r.requestedAttributes).toEqual([
            {
                name: 'urn:oid:1.3.6.1.4.1.5923.1.1.1.6',
                friendlyName: 'eduPersonPrincipalName',
                isRequired: true,
                nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
            },
            {
                name: 'urn:oid:0.9.2342.19200300.100.1.3',
                friendlyName: 'mail',
                isRequired: undefined,
                nameFormat: undefined
            }
        ]);
    });

    it('has no mdui when UIInfo is absent', () => {
        expect(role('sp', sp()).mdui).toBeUndefined();
    });

    it('handles an SP with no AttributeConsumingService and no protocol support', () => {
        const r = role('sp', parseMetadata(SP_MINIMAL).entity);
        expect(r.protocolSupport).toEqual([]);
        expect(r.serviceNames).toBeUndefined();
        expect(r.requestedAttributes).toBeUndefined();
        expect(r.assertionConsumerServices).toHaveLength(1);
    });
});

describe('parseMetadata — aggregate and edge cases', () => {
    it('returns the first entity with an aggregate count', () => {
        const result = parseMetadata(AGGREGATE);
        expect(result.aggregateCount).toBe(2);
        expect(result.entity.entityId).toBe('https://a.example.org');
        expect(result.entity.roles[0].kind).toBe('idp');
    });

    it('falls back to empty strings for every missing required field', () => {
        const e = parseMetadata(MALFORMED).entity;
        expect(e.entityId).toBe('');
        expect(e.entityCategories).toEqual([]); // unnamed Attribute is ignored
        expect(e.contacts[0].type).toBe('');
        const r = role('sp', e);
        expect(r.assertionConsumerServices![0]).toMatchObject({ binding: '', location: '' });
        expect(r.requestedAttributes![0].name).toBe('');
        expect(r.mdui!.displayNames[0].value).toBe('');
        expect(r.mdui!.logos[0].url).toBe('');
    });

    it('records document signature presence and algorithm without verifying it', () => {
        expect(parseMetadata(IDP_METADATA).signature).toBeUndefined();
        const signed = `<md:EntityDescriptor ${NS} entityID="https://idp.example.org/idp">
  <ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo></ds:Signature>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</md:EntityDescriptor>`;
        expect(parseMetadata(signed).signature?.algorithm).toBe(
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        );
    });

    it('handles an entity with no roles or optional sections', () => {
        const e = parseMetadata(NO_ROLES).entity;
        expect(e.entityId).toBe('https://noroles.example.org');
        expect(e.roles).toEqual([]);
        expect(e.organization).toBeUndefined();
        expect(e.contacts).toEqual([]);
        expect(e.entityCategories).toEqual([]);
        expect(e.validUntil).toBeUndefined();
        expect(e.registrationAuthority).toBeUndefined();
    });
});

describe('label maps', () => {
    it('maps known bindings and entity categories with spec URLs', () => {
        expect(BINDING_LABELS[B('HTTP-POST')]).toBe('HTTP-POST');
        expect(BINDING_LABELS[B('HTTP-POST-SimpleSign')]).toBe('HTTP-POST-SimpleSign');
        expect(BINDING_LABELS['urn:mace:shibboleth:1.0:profiles:AuthnRequest']).toBe(
            'Shibboleth 1.0 AuthnRequest'
        );
        expect(ENTITY_CATEGORY_LABELS['https://refeds.org/sirtfi']).toBe('SIRTFI');
        expect(
            ENTITY_CATEGORY_LABELS['http://id.incommon.org/category/registered-by-incommon']
        ).toBe('Registered by InCommon');
        expect(ENTITY_CATEGORY_LABELS['http://www.swamid.se/category/research-and-education']).toBe(
            'R&E (SWAMID)'
        );
        expect(ENTITY_CATEGORY_LABELS['https://idem.garr.it/af/IDEM-P1']).toBe('IDEM P1');
        expect(
            ENTITY_CATEGORY_LABELS['http://www.geant.net/uri/dataprotection-code-of-conduct/v2']
        ).toBe('GÉANT CoCo v2');
        expect(ENTITY_CATEGORY_SPEC_URLS['https://refeds.org/sirtfi']).toMatch(/^https:\/\//);
    });
});

describe('entityCategoryKind', () => {
    it.each([
        ['http://refeds.org/category/research-and-scholarship', 'rs'],
        ['http://www.swamid.se/category/research-and-education', 'rs'],
        ['http://www.geant.net/uri/dataprotection-code-of-conduct/v1', 'coco'],
        ['https://refeds.org/sirtfi', 'assurance'],
        ['http://www.swamid.se/policy/assurance/al2', 'assurance'],
        ['https://idem.garr.it/af/IDEM-P1', 'assurance'],
        ['http://id.elegnamnden.se/ec/1.0/loa3-pnr', 'assurance'],
        ['https://refeds.org/category/personalized', 'access'],
        ['http://id.incommon.org/category/registered-by-incommon', 'registration'],
        ['https://example.org/category/registeredservice', 'registration'],
        ['https://federation.renater.fr/scope/local', 'other'],
        ['https://example.org/category/something-else', 'other']
    ])('classifies %s as %s', (uri, kind) => {
        expect(entityCategoryKind(uri)).toBe(kind);
    });
});
