export const FIELD_EXPLANATIONS: Record<string, string> = {
    // ── SAML summary ──────────────────────────────────────────────────────────
    'saml.binding':
        'How this SAML message was transmitted. HTTP-Redirect compresses and Base64-encodes the message into a URL parameter — typical for AuthnRequests. HTTP-POST delivers it as a Base64-encoded form field — typical for Responses carrying signed assertions.',

    'saml.messageType':
        'The SAML message type. AuthnRequest / SAMLRequest initiates a login; LogoutRequest initiates single logout. Response / SAMLResponse carries the assertion with the authentication result and released attributes.',

    'saml.status':
        'The outcome of the SAML exchange. Success means the IdP authenticated the user. Common failures: AuthnFailed (bad credentials), NoAuthnContext (cannot satisfy the requested authentication context), RequestDenied (policy block), Responder (IdP-side error).',

    'saml.issuer':
        'The EntityID of the party that issued this message — the IdP for a Response, the SP for a Request. Must match the EntityID in the issuer\'s SAML metadata. A mismatch indicates misconfiguration or a spoofing attempt.',

    'saml.destination':
        'The URL this message was addressed to. SAML requires recipients to verify that Destination matches their own endpoint URL. This check prevents message forwarding attacks, where a captured message is replayed at a different service.',

    'saml.acsUrl':
        'Assertion Consumer Service URL — the SP endpoint where the IdP will POST the SAMLResponse. The IdP must validate this against the SP\'s registered metadata and must reject any ACS URL not listed there.',

    'saml.nameId':
        'The identifier for the authenticated user. The Format attribute defines the type: emailAddress (user@domain), persistent (opaque but stable per SP — used for account linking), transient (changes each session — provides anonymity), or unspecified.',

    'saml.inResponseTo':
        'Links this Response to the AuthnRequest that triggered it. The SP must verify this matches the ID of its own request. A missing or mismatched value may indicate an unsolicited (IdP-initiated) response or a replay attack.',

    'saml.relayState':
        'An opaque value the SP includes in the AuthnRequest and expects returned unchanged in the Response. Typically encodes the deep-link URL the user was trying to reach so the SP can redirect there after successful login.',

    'saml.encrypted':
        'Whether the Assertion or NameID has been XML-encrypted. Requires the IdP to have the SP\'s public key from metadata. Protects sensitive attributes and user identifiers from intermediaries who can observe transport-level traffic.',

    'saml.signingCert':
        'The X.509 certificate whose private key signed this message. The relying party should verify the signature using the public key from the issuer\'s SAML metadata. An expired or unknown certificate outside a trusted metadata feed is a security concern.',

    'saml.attributes':
        'Attribute statements contain claims about the authenticated user released by the IdP — such as email, display name, group memberships, or entitlements. Which attributes are released is governed by IdP policy and the SP\'s metadata. These values typically drive authorization decisions at the SP.',

    // ── SAML timestamps ───────────────────────────────────────────────────────
    'saml.ts.authnInstant':
        'When the user last authenticated at the IdP. If this is well in the past, the IdP is reusing an existing SSO session rather than prompting for fresh credentials — relevant when ForceAuthn or a maximum session age policy applies.',

    'saml.ts.sessionNotOnOrAfter':
        'The IdP SSO session expiry. After this time the user must re-authenticate at the IdP. Distinct from the assertion\'s NotOnOrAfter — the session lifetime can be much longer than any individual assertion\'s validity window.',

    'saml.ts.notBefore':
        'The assertion is not valid before this time. Clock skew between the IdP and SP can cause validation failures here. A typical allowed skew is ±2–5 minutes.',

    'saml.ts.notOnOrAfter':
        'The assertion expires at this time and must be rejected after it passes. Short validity windows (minutes rather than hours) reduce the replay attack window if the assertion is captured in transit.',

    'saml.ts.subjectConfirmationNotOnOrAfter':
        'The window during which the bearer can be confirmed as the assertion\'s subject. Often matches Conditions NotOnOrAfter but may differ — the SP must check both, and both must still be within their valid windows.',

    // ── JWT / OIDC ────────────────────────────────────────────────────────────
    'jwt.algorithm':
        'The signing algorithm in the JWT header. RS256/RS384/RS512 and ES256/ES384/ES512 (asymmetric) are preferred — verification uses a public key, keeping the signing key private. HS256/HS384/HS512 (HMAC) require sharing the secret with every verifier. "none" means no signature and must always be rejected.',

    'jwt.tokenType':
        'The "typ" header — declares the token type. "JWT" is the default. "at+JWT" explicitly identifies an OAuth 2.0 Access Token (RFC 9068), allowing resource servers to distinguish it from ID tokens. "JWE" indicates an encrypted token.',

    'jwt.keyId':
        'The "kid" (Key ID) header — identifies which key was used to sign this token. Consumers use it to select the correct public key from the issuer\'s JWKS endpoint (/.well-known/jwks.json) without trying every key in the set.',

    'jwt.issuer':
        'The "iss" claim — the authorization server or identity provider that issued this token. Consumers must validate that iss matches the expected issuer. In OIDC, this is the provider\'s canonical base URL (e.g. https://idp.example.com).',

    'jwt.subject':
        'The "sub" claim — identifies the principal this token is about, typically a user. In OIDC, sub must be a stable, unique identifier for the user within the issuer\'s namespace and must never be reassigned to a different user.',

    'jwt.audience':
        'The "aud" claim — identifies the intended recipient(s) of this token. A resource server must reject tokens where its own identifier does not appear in aud. This prevents tokens issued for one service from being replayed at another.',

    'jwt.jwtId':
        'The "jti" (JWT ID) claim — a unique identifier for this specific token instance. Enables server-side revocation and replay detection: a resource server can track used JTIs and reject any token whose jti has already been seen.',

    'jwt.scopes':
        'OAuth 2.0 scopes granted to this access token. Scopes define what the bearer is permitted to do — e.g., "openid" (OIDC identity), "email" (email claim), "offline_access" (refresh token). The resource server should verify the required scopes are present before granting access.',

    // ── JWT timestamps ────────────────────────────────────────────────────────
    'jwt.ts.issuedAt':
        'The "iat" (Issued At) claim — Unix timestamp of when this token was created. Useful for enforcing a maximum token age independent of expiry — for example, rejecting tokens older than 24 hours even if exp has not yet passed.',

    'jwt.ts.notBefore':
        'The "nbf" (Not Before) claim — the token must not be accepted before this Unix timestamp. Allows tokens to be pre-issued and activated at a specific future moment, useful for scheduled or deferred access grants.',

    'jwt.ts.expires':
        'The "exp" (Expiration Time) claim — the token must be rejected after this Unix timestamp. Access tokens are typically short-lived (minutes to an hour) to limit exposure if a token is stolen or leaked.',
};

export const SAML_TS_KEY: Record<string, string> = {
    AuthnInstant: 'saml.ts.authnInstant',
    SessionNotOnOrAfter: 'saml.ts.sessionNotOnOrAfter',
    NotBefore: 'saml.ts.notBefore',
    NotOnOrAfter: 'saml.ts.notOnOrAfter',
    'SubjectConfirmation NotOnOrAfter': 'saml.ts.subjectConfirmationNotOnOrAfter',
};
