import { deflateRaw } from 'pako';

export type ExampleCategory =
    | 'SAMLResponse'
    | 'SAMLRequest'
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

function encodePostBinding(xml: string): string {
    const bytes = new TextEncoder().encode(xml);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
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
        label: 'POST binding form value',
        category: 'Query string',
        payload: () => `SAMLResponse=${encodeURIComponent(encodePostBinding(samlResponse()))}`,
    },
    {
        label: 'IdP redirect binding URL',
        category: 'Full URL',
        payload: () =>
            `https://idp.university.edu/idp/profile/SAML2/Redirect/SSO?SAMLRequest=${encodeRedirectBinding(samlRequest())}&RelayState=%2Fdashboard`,
    },
];
