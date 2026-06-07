import { deflateRaw } from 'pako';

export type ExampleCategory =
    | 'SAMLResponse'
    | 'SAMLRequest'
    | 'Metadata'
    | 'JWT'
    | 'Authorization header'
    | 'Query string'
    | 'Full URL';

export interface Example {
    label: string;
    category: ExampleCategory;
    payload(): string;
}

export const EXAMPLE_CATEGORIES: ExampleCategory[] = [
    'SAMLResponse',
    'SAMLRequest',
    'Metadata',
    'JWT',
    'Authorization header',
    'Query string',
    'Full URL',
];

function ts(offsetSeconds: number): string {
    return new Date(Date.now() + offsetSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function encodeRedirectBinding(xml: string): string {
    const bytes = new TextEncoder().encode(xml);
    const compressed = deflateRaw(bytes) as Uint8Array;
    let binary = '';
    for (let i = 0; i < compressed.length; i++) {
        binary += String.fromCharCode(compressed[i]);
    }
    return encodeURIComponent(btoa(binary));
}

function b64url(obj: object): string {
    return btoa(JSON.stringify(obj))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function makeJwt(header: object, payload: object): string {
    const fakeSig = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    return `${b64url(header)}.${b64url(payload)}.${fakeSig}`;
}

function samlResponse(opts: { mfa?: boolean } = {}): string {
    const authnContextRef = opts.mfa
        ? 'https://refeds.org/profile/mfa'
        : 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

    return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_response_example_001"
    Version="2.0"
    IssueInstant="${ts(-5)}"
    Destination="https://app.example.com/saml/acs"
    InResponseTo="_request_abc123">
  <saml:Issuer>https://idp.university.edu/idp/shibboleth</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion_example_001" Version="2.0" IssueInstant="${ts(-5)}">
    <saml:Issuer>https://idp.university.edu/idp/shibboleth</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_transient_7f2a3b4c5d6e7f8a9b0c</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="${ts(295)}"
            Recipient="https://app.example.com/saml/acs"
            InResponseTo="_request_abc123"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${ts(-2)}" NotOnOrAfter="${ts(295)}">
      <saml:AudienceRestriction>
        <saml:Audience>https://app.example.com/shibboleth</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${ts(-90)}" SessionNotOnOrAfter="${ts(28800)}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>${authnContextRef}</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          FriendlyName="eduPersonPrincipalName">
        <saml:AttributeValue>jsmith@university.edu</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          FriendlyName="mail">
        <saml:AttributeValue>j.smith@university.edu</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          FriendlyName="displayName">
        <saml:AttributeValue>Jane Smith</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:2.5.4.42"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          FriendlyName="givenName">
        <saml:AttributeValue>Jane</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:2.5.4.4"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          FriendlyName="sn">
        <saml:AttributeValue>Smith</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          FriendlyName="eduPersonScopedAffiliation">
        <saml:AttributeValue>member@university.edu</saml:AttributeValue>
        <saml:AttributeValue>staff@university.edu</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.9"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          FriendlyName="schacHomeOrganization">
        <saml:AttributeValue>university.edu</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;
}

function samlRequest(opts: { mfa?: boolean } = {}): string {
    const mfaBlock = opts.mfa
        ? `\n  <samlp:RequestedAuthnContext Comparison="exact">\n    <saml:AuthnContextClassRef>https://refeds.org/profile/mfa</saml:AuthnContextClassRef>\n  </samlp:RequestedAuthnContext>`
        : '';
    return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_request_abc123"
    Version="2.0"
    IssueInstant="${ts(-5)}"
    Destination="https://idp.university.edu/idp/profile/SAML2/Redirect/SSO"
    AssertionConsumerServiceURL="https://app.example.com/saml/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://app.example.com/shibboleth</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate="1" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>${mfaBlock}
</samlp:AuthnRequest>`;
}

function idTokenPayload(): object {
    const now = Math.floor(Date.now() / 1000);
    return {
        iss: 'https://idp.university.edu',
        sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        aud: 'client_abc123',
        iat: now - 30,
        exp: now + 3570,
        nonce: 'n-0S6_WzA2Mj',
        amr: ['pwd', 'mfa'],
        name: 'Jane Smith',
        email: 'jsmith@university.edu',
        preferred_username: 'jsmith',
    };
}

function accessTokenPayload(): object {
    const now = Math.floor(Date.now() / 1000);
    return {
        iss: 'https://auth.example.com',
        sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        aud: 'api.example.com',
        iat: now - 15,
        exp: now + 3585,
        jti: 'jwt_6f84bc2a9d1e3057',
        scope: 'openid email profile',
        client_id: 'app_xyz789',
    };
}

// A throwaway self-signed EC P-256 certificate (public material only, valid 2026–2036)
// so the metadata examples render a complete, parseable signing-certificate card.
const DEMO_CERT =
    'MIIB8TCCAZegAwIBAgIUSb7rnkp6aplEE/6jgG4yV1oHFEgwCgYIKoZIzj0EAwIwTjEfMB0GA1UEAwwWc2hpYmlkcC51bml2ZXJzaXR5LmVkdTEeMBwGA1UECgwVVW5pdmVyc2l0eSBvZiBFeGFtcGxlMQswCQYDVQQGEwJVUzAeFw0yNjA2MDcxNzA5MjhaFw0zNjA2MDQxNzA5MjhaME4xHzAdBgNVBAMMFnNoaWJpZHAudW5pdmVyc2l0eS5lZHUxHjAcBgNVBAoMFVVuaXZlcnNpdHkgb2YgRXhhbXBsZTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQKWACV04QUPk+70Ey8+nPBnvwOE7pRE8I9WihQo3gidepz2rVzhOqSSwlwxnu3MZRd+zb9D5R/tMDw9JQfhFqqo1MwUTAdBgNVHQ4EFgQU9+avq1Q/sirkFJg22WvnP+SsVKcwHwYDVR0jBBgwFoAU9+avq1Q/sirkFJg22WvnP+SsVKcwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiARTVraf6ESX4TafDb8WJgAvSHwblCyYh+w1KFDnA1CCgIhANbchBPrCPEhHTmm5y9m4a87kqhEbNM9vYI2GMKUWo0a';

const B = (b: string) => `urn:oasis:names:tc:SAML:2.0:bindings:${b}`;
const NIDF = (f: string) => `urn:oasis:names:tc:SAML:2.0:nameid-format:${f}`;

function idpMetadata(): string {
    const validUntil = ts(5 * 365 * 24 * 3600);
    return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
    xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
    xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
    xmlns:shibmd="urn:mace:shibboleth:metadata:1.0"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    entityID="https://shibidp.university.edu/idp/shibboleth" validUntil="${validUntil}">
    <md:Extensions>
        <mdrpi:RegistrationInfo registrationAuthority="https://incommon.org"/>
        <mdattr:EntityAttributes>
            <saml:Attribute Name="http://macedir.org/entity-category-support" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oasis:names:tc:SAML:attribute:assurance-certification" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml:AttributeValue>https://refeds.org/sirtfi</saml:AttributeValue>
            </saml:Attribute>
        </mdattr:EntityAttributes>
    </md:Extensions>
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false">
        <md:Extensions>
            <mdui:UIInfo>
                <mdui:DisplayName xml:lang="en">University of Example</mdui:DisplayName>
                <mdui:Description xml:lang="en">Single sign-on for the University of Example.</mdui:Description>
                <mdui:InformationURL xml:lang="en">https://www.university.edu/identity</mdui:InformationURL>
                <mdui:Logo width="160" height="60">https://www.university.edu/logo.png</mdui:Logo>
            </mdui:UIInfo>
            <shibmd:Scope regexp="false">university.edu</shibmd:Scope>
        </md:Extensions>
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${DEMO_CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${DEMO_CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>${NIDF('persistent')}</md:NameIDFormat>
        <md:NameIDFormat>${NIDF('transient')}</md:NameIDFormat>
        <md:SingleSignOnService Binding="${B('HTTP-Redirect')}" Location="https://shibidp.university.edu/idp/profile/SAML2/Redirect/SSO"/>
        <md:SingleSignOnService Binding="${B('HTTP-POST')}" Location="https://shibidp.university.edu/idp/profile/SAML2/POST/SSO"/>
        <md:SingleLogoutService Binding="${B('HTTP-Redirect')}" Location="https://shibidp.university.edu/idp/profile/SAML2/Redirect/SLO"/>
    </md:IDPSSODescriptor>
    <md:Organization>
        <md:OrganizationName xml:lang="en">University of Example</md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="en">University of Example</md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="en">https://www.university.edu</md:OrganizationURL>
    </md:Organization>
    <md:ContactPerson contactType="technical">
        <md:GivenName>Identity</md:GivenName>
        <md:SurName>Services</md:SurName>
        <md:EmailAddress>mailto:identity@university.edu</md:EmailAddress>
    </md:ContactPerson>
</md:EntityDescriptor>`;
}

function spMetadata(): string {
    const validUntil = ts(5 * 365 * 24 * 3600);
    return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
    entityID="https://app.example.org/shibboleth" validUntil="${validUntil}">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">
        <md:Extensions>
            <mdui:UIInfo>
                <mdui:DisplayName xml:lang="en">Example Application</mdui:DisplayName>
                <mdui:Description xml:lang="en">Research collaboration platform.</mdui:Description>
            </mdui:UIInfo>
        </md:Extensions>
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${DEMO_CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>${NIDF('persistent')}</md:NameIDFormat>
        <md:AssertionConsumerService index="0" isDefault="true" Binding="${B('HTTP-POST')}" Location="https://app.example.org/Shibboleth.sso/SAML2/POST"/>
        <md:AssertionConsumerService index="1" Binding="${B('HTTP-Artifact')}" Location="https://app.example.org/Shibboleth.sso/SAML2/Artifact"/>
        <md:SingleLogoutService Binding="${B('HTTP-Redirect')}" Location="https://app.example.org/Shibboleth.sso/SLO/Redirect"/>
        <md:AttributeConsumingService index="0">
            <md:ServiceName xml:lang="en">Example Application</md:ServiceName>
            <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
            <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
            <md:RequestedAttribute Name="urn:oid:2.16.840.1.113730.3.1.241" FriendlyName="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
        </md:AttributeConsumingService>
    </md:SPSSODescriptor>
    <md:ContactPerson contactType="support">
        <md:EmailAddress>mailto:support@example.org</md:EmailAddress>
    </md:ContactPerson>
</md:EntityDescriptor>`;
}

export const EXAMPLES: Example[] = [
    {
        label: 'Successful response (password auth)',
        category: 'SAMLResponse',
        payload: () => samlResponse(),
    },
    {
        label: 'Successful response (REFEDS MFA)',
        category: 'SAMLResponse',
        payload: () => samlResponse({ mfa: true }),
    },
    {
        label: 'Basic authentication request',
        category: 'SAMLRequest',
        payload: () => samlRequest(),
    },
    {
        label: 'Request requiring REFEDS MFA',
        category: 'SAMLRequest',
        payload: () => samlRequest({ mfa: true }),
    },
    {
        label: 'IdP metadata (Shibboleth)',
        category: 'Metadata',
        payload: () => idpMetadata(),
    },
    {
        label: 'SP metadata (Shibboleth)',
        category: 'Metadata',
        payload: () => spMetadata(),
    },
    {
        label: 'OIDC ID token',
        category: 'JWT',
        payload: () => makeJwt({ alg: 'RS256', kid: 'sig-2024-01', typ: 'JWT' }, idTokenPayload()),
    },
    {
        label: 'OAuth 2.0 access token',
        category: 'JWT',
        payload: () =>
            makeJwt({ alg: 'RS256', kid: 'sig-2024-01', typ: 'at+JWT' }, accessTokenPayload()),
    },
    {
        label: 'Bearer token',
        category: 'Authorization header',
        payload: () =>
            `Authorization: Bearer ${makeJwt({ alg: 'RS256', kid: 'sig-2024-01', typ: 'JWT' }, idTokenPayload())}`,
    },
    {
        label: 'Redirect binding query string',
        category: 'Query string',
        payload: () =>
            `SAMLRequest=${encodeRedirectBinding(samlRequest())}&RelayState=%2Fdashboard`,
    },
    {
        label: 'IdP redirect binding URL',
        category: 'Full URL',
        payload: () =>
            `https://idp.university.edu/idp/profile/SAML2/Redirect/SSO?SAMLRequest=${encodeRedirectBinding(samlRequest())}&RelayState=%2Fdashboard`,
    },
];
