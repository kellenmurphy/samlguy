import { describe, it, expect } from 'vitest';
import { parseMetadata } from './metadata';
import { checkMetadata, type MetadataCheck } from './metadata-checks';

const NS = `xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`;
const SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const B = (b: string) => `urn:oasis:names:tc:SAML:2.0:bindings:${b}`;

function sigBlock(alg: string): string {
    return `<ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="${alg}"/></ds:SignedInfo></ds:Signature>`;
}
function iso(offsetDays: number): string {
    return new Date(Date.now() + offsetDays * 86_400_000).toISOString();
}
function run(xml: string): MetadataCheck[] {
    return checkMetadata(parseMetadata(xml));
}
function titles(checks: MetadataCheck[]): string[] {
    return checks.map((c) => c.title);
}

// Clean, well-formed IdP — signed (SHA-256), future expiry, HTTPS, one signing cert, SAML2 only.
const CLEAN = `<EntityDescriptor ${NS} entityID="https://idp.example.org/idp/shibboleth" validUntil="${iso(100)}">
  ${sigBlock('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')}
  <IDPSSODescriptor protocolSupportEnumeration="${SAMLP}">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBcleanCert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="${B('HTTP-Redirect')}" Location="https://idp.example.org/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;

// Like the real InCommon per-entity export: no validUntil, unsigned, advertises legacy SAML 1.x.
const UNSIGNED_LEGACY = `<EntityDescriptor ${NS} entityID="urn:mace:incommon:example.edu">
  <IDPSSODescriptor protocolSupportEnumeration="urn:mace:shibboleth:1.0 urn:oasis:names:tc:SAML:1.1:protocol ${SAMLP}">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBcleanCert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="${B('HTTP-Redirect')}" Location="https://idp.example.edu/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;

// Many problems at once: expired, SHA-1 signature, trailing-slash entityID, encryption-only
// KeyDescriptor with PEM armor, and a plaintext HTTP endpoint.
const BROKEN = `<EntityDescriptor ${NS} entityID="https://idp.example.org/" validUntil="2000-01-01T00:00:00Z">
  ${sigBlock('http://www.w3.org/2000/09/xmldsig#rsa-sha1')}
  <IDPSSODescriptor protocolSupportEnumeration="${SAMLP}">
    <KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
-----BEGIN CERTIFICATE-----
MIIBpemCert==
-----END CERTIFICATE-----
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="${B('HTTP-Redirect')}" Location="http://idp.example.org/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;

// Expiring soon, whitespace-padded entityID, and a role with no KeyDescriptor at all.
const SOON = `<EntityDescriptor ${NS} entityID="  urn:x:example  " validUntil="${iso(5)}">
  <SPSSODescriptor protocolSupportEnumeration="${SAMLP}">
    <AssertionConsumerService index="0" Binding="${B('HTTP-POST')}" Location="https://sp.example.org/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>`;

// Non-date validUntil, otherwise signed with a modern algorithm.
const UNPARSEABLE = `<EntityDescriptor ${NS} entityID="https://sp.example.org/shibboleth" validUntil="not-a-date">
  ${sigBlock('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')}
  <SPSSODescriptor protocolSupportEnumeration="${SAMLP}">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBcleanCert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <AssertionConsumerService index="0" Binding="${B('HTTP-POST')}" Location="https://sp.example.org/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>`;

describe('checkMetadata', () => {
    it('returns no findings for clean, signed, current metadata', () => {
        expect(run(CLEAN)).toEqual([]);
    });

    it('flags missing validUntil and legacy SAML 1.x, but does not warn on unsigned metadata', () => {
        const t = titles(run(UNSIGNED_LEGACY));
        expect(t).toContain('No validUntil');
        expect(t).toContain('IdP advertises legacy SAML 1.x');
        expect(t).not.toContain('Metadata not signed');
    });

    it('catches expiry, SHA-1 signature, trailing slash, missing signing cert, PEM armor, and HTTP endpoints', () => {
        const checks = run(BROKEN);
        const t = titles(checks);
        expect(t).toContain('Metadata expired');
        expect(t).toContain('Weak metadata signature algorithm');
        expect(t).toContain('entityID ends with a trailing slash');
        expect(t).toContain('IdP has no signing certificate');
        expect(t).toContain('Certificate contains PEM headers');
        expect(t).toContain('IdP has a plaintext (HTTP) endpoint');
        expect(checks.find((c) => c.title === 'Metadata expired')?.severity).toBe('error');
        expect(checks.find((c) => c.title === 'Certificate contains PEM headers')?.severity).toBe(
            'error'
        );
    });

    it('warns on imminent expiry, whitespace entityID, and a role with no certificate', () => {
        const t = titles(run(SOON));
        expect(t).toContain('Metadata expiring soon');
        expect(t).toContain('entityID has surrounding whitespace');
        expect(t).toContain('SP publishes no certificate');
    });

    it('warns on an unparseable validUntil without false-flagging a good signature', () => {
        const t = titles(run(UNPARSEABLE));
        expect(t).toContain('Unparseable validUntil');
        expect(t).not.toContain('Weak metadata signature algorithm');
    });

    it('flags a misspelled entity category but not the correctly-spelled one alongside it', () => {
        const xml = `<EntityDescriptor ${NS} entityID="https://idp.example.org/idp" validUntil="${iso(100)}">
  ${sigBlock('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')}
  <Extensions>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="urn:oasis:names:tc:SAML:attribute:assurance-certification">
        <saml:AttributeValue>https://refeds.org/sirtf</saml:AttributeValue>
        <saml:AttributeValue>https://refeds.org/sirtfi</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </Extensions>
  <IDPSSODescriptor protocolSupportEnumeration="${SAMLP}">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBcleanCert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="${B('HTTP-Redirect')}" Location="https://idp.example.org/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
        const checks = run(xml);
        const misspelled = checks.filter((c) => c.title === 'Misspelled entity category');
        expect(misspelled).toHaveLength(1);
        expect(misspelled[0].detail).toContain('https://refeds.org/sirtf');
        expect(misspelled[0].detail).toContain('https://refeds.org/sirtfi');
    });

    it('does not flag a weak algorithm when the signature has no SignatureMethod', () => {
        const xml = `<EntityDescriptor ${NS} entityID="https://idp.example.org/idp" validUntil="${iso(100)}">
  <ds:Signature></ds:Signature>
  <IDPSSODescriptor protocolSupportEnumeration="${SAMLP}">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBcleanCert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="${B('HTTP-Redirect')}" Location="https://idp.example.org/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
        expect(titles(run(xml))).not.toContain('Weak metadata signature algorithm');
    });
});
