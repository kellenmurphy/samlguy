export const XML_ELEMENT_TIPS: Record<string, string> = {
    // ── SAML assertion ────────────────────────────────────────────────────────
    Assertion:
        'The core SAML 2.0 assertion — a signed, time-bounded statement from the IdP about an authenticated principal. Contains authentication, attribute, and/or authorization decision statements.',
    Issuer:
        "Identifies the entity that issued this message. For a Response this is the IdP's EntityID; for a Request it is the SP's EntityID. Must match the EntityID in the issuer's SAML metadata.",
    Subject:
        'The principal (user) this assertion is about. Contains a NameID and a SubjectConfirmation that together identify who authenticated and allow the recipient to verify they are the intended audience.',
    NameID:
        'The subject identifier, typed by the Format attribute — emailAddress (user@domain), persistent (opaque and SP-scoped, survives sessions), transient (single-session, privacy-preserving), or unspecified.',
    SubjectConfirmation:
        'Specifies the method by which the subject can be confirmed as the intended bearer. For browser SSO the method is always urn:oasis:names:tc:SAML:2.0:cm:bearer.',
    SubjectConfirmationData:
        'Bearer confirmation constraints — the assertion must not be accepted after NotOnOrAfter, must be delivered to the Recipient URL, and must correspond to the InResponseTo request ID.',
    Conditions:
        'Time and audience restrictions on this assertion. The SP must verify the current time falls within [NotBefore, NotOnOrAfter) and that its EntityID appears in AudienceRestriction.',
    AudienceRestriction:
        "Restricts this assertion to one or more intended recipients. The SP must verify that its own EntityID is listed — using an assertion intended for another SP is a security violation.",
    Audience:
        'An EntityID for which this assertion is intended. The SP must reject assertions where its EntityID does not appear in at least one AudienceRestriction.',
    OneTimeUse:
        'Marks this assertion as non-cacheable and non-reusable. SPs that honor this condition must reject any subsequent presentation of this same assertion.',
    ProxyRestriction:
        'Limits how many times this assertion can be re-asserted via SAML IdP proxying. ProxyCount=0 means the assertion must not be proxied at all.',
    AuthnStatement:
        'States that the subject authenticated at the IdP at a specific time (AuthnInstant). May include a session expiry (SessionNotOnOrAfter) and a session index for SLO correlation.',
    AuthnContext:
        'Describes how the user authenticated. Contains an AuthnContextClassRef identifying the authentication mechanism — e.g., PasswordProtectedTransport, Kerberos, or the REFEDS MFA profile.',
    AuthnContextClassRef:
        'A URI identifying the authentication context class. Declares what method the user used to authenticate. Common values: PasswordProtectedTransport (password over HTTPS), Kerberos, or https://refeds.org/profile/mfa.',
    AuthnContextDeclRef:
        'A URI referencing the full authentication context declaration document describing exactly how authentication was performed, in more detail than the class reference alone.',
    AttributeStatement:
        "Claims about the authenticated user released by the IdP — email, display name, group memberships, entitlements. Which attributes are released is governed by IdP policy and the SP's metadata.",
    Attribute:
        'A single named attribute. Name is typically a URI or OID-based identifier; FriendlyName is an optional human-readable label. The NameFormat declares how the Name should be interpreted.',
    AttributeValue:
        'One value within an Attribute. Multi-valued attributes (e.g. group memberships) have multiple AttributeValue children.',

    // ── SAML protocol ─────────────────────────────────────────────────────────
    Response:
        "The IdP's protocol response to an AuthnRequest. Contains one or more Assertions and a Status element. InResponseTo must match the original request ID; the SP must verify this to prevent replay attacks.",
    AuthnRequest:
        "An SP's authentication request to the IdP. Specifies the ACS URL, optional NameID format requirements, and optionally the required AuthnContext. Signed by the SP in many deployments.",
    LogoutRequest:
        "A request to terminate the principal's sessions across the federation. Initiates the single logout (SLO) flow. The SessionIndex links this to the specific IdP session to terminate.",
    LogoutResponse:
        'A response to a LogoutRequest confirming the logout outcome. PartialLogout status means some SP sessions could not be terminated.',
    Status:
        'The outcome of this protocol exchange. Always present in Responses. Contains a StatusCode and optionally a StatusMessage and StatusDetail.',
    StatusCode:
        "A URI identifying the outcome. Top-level: Success, Requester (SP-side error), Responder (IdP-side error), VersionMismatch. Sub-codes provide more specific detail — e.g., AuthnFailed, NoAuthnContext.",
    StatusMessage:
        'A human-readable message from the IdP describing the status outcome. Present primarily on error responses. Content is IdP-specific and not standardized across implementations.',
    StatusDetail:
        'Additional machine-readable detail about the status, in an IdP-specific format. Rarely used in practice.',
    RequestedAuthnContext:
        "The SP's requirements for how the user must authenticate. Contains one or more AuthnContextClassRef values and a Comparison attribute (exact, minimum, better, maximum) controlling how the IdP should match them.",
    NameIDPolicy:
        "The SP's preferred NameID format and allocation policy. AllowCreate=true permits the IdP to create a new persistent identifier if one doesn't exist for this user-SP pair.",
    SessionIndex:
        'The IdP session identifier, correlating this assertion to a specific IdP login session. Required in SLO flows — a LogoutRequest must include the SessionIndex to terminate the correct session.',

    // ── XML Digital Signature ─────────────────────────────────────────────────
    Signature:
        "An XML digital signature over this element. Verifiers must check the signature using the public key from the signer's SAML metadata — not blindly trusting the embedded certificate.",
    SignedInfo:
        'The portion of the XML Signature that is actually signed, after canonicalization. Contains the Reference (what was digested), the CanonicalizationMethod, and the SignatureMethod.',
    SignatureValue:
        'The raw Base64-encoded signature bytes, computed over the canonicalized SignedInfo content using the private key corresponding to the signing certificate.',
    KeyInfo:
        "Advisory information about the signing key — typically an embedded X.509 certificate. Verifiers should match this against the key in the issuer's SAML metadata rather than trusting it directly.",
    X509Data: 'Container for X.509 certificate data within a KeyInfo element.',
    X509Certificate:
        "The Base64-encoded DER-format signing certificate. Advisory only — the verifier should use the public key from the issuer's SAML metadata, not trust this embedded certificate unconditionally.",
    CanonicalizationMethod:
        'The XML canonicalization algorithm applied to SignedInfo before signing. SAML requires Exclusive Canonicalization (http://www.w3.org/2001/10/xml-exc-c14n#) to ensure consistent serialization across implementations.',
    SignatureMethod:
        'The signing algorithm — e.g., RSA-SHA256 (recommended) or RSA-SHA512. RSA-SHA1 is deprecated and should be rejected. Asymmetric algorithms (RSA, ECDSA) are required; HMAC is not used in SAML.',
    Reference:
        'Identifies the XML content that was digested and signed, by the URI attribute pointing to the element by ID. Transforms describe pre-digest processing steps.',
    Transforms:
        'The sequence of transforms applied to the referenced content before computing the digest. SAML uses two: enveloped-signature (remove the Signature from input) and exclusive canonicalization.',
    Transform:
        'A single transform step — either enveloped-signature (strip the Signature element itself from the signed data) or exclusive XML canonicalization (normalize the serialization).',
    DigestMethod:
        'The hash algorithm applied to the canonicalized referenced content. SHA-256 is standard. SHA-1 is deprecated and must not be accepted in new deployments.',
    DigestValue:
        'The Base64-encoded hash of the canonicalized referenced content. Any modification to the signed element will invalidate this digest and cause signature verification to fail.',

    // ── XML Encryption ────────────────────────────────────────────────────────
    EncryptedAssertion:
        "A SAML assertion encrypted for confidentiality using the SP's public key. The SP must decrypt it using its private key before the assertion can be parsed or validated.",
    EncryptedData:
        'The XML Encryption core element. Contains the ciphertext (CipherData) and information needed to decrypt it (KeyInfo with EncryptedKey or KeyName).',
    EncryptedKey:
        "The symmetric session key encrypted with the recipient's public key. Decrypting this with the SP's private key yields the key used to decrypt the EncryptedData content.",
    EncryptionMethod:
        'The encryption algorithm used. Typically AES-128-CBC or AES-256-GCM for assertion content; RSA-OAEP for the wrapped session key.',
    CipherData: 'Container for the encrypted bytes.',
    CipherValue: 'The Base64-encoded ciphertext — the actual encrypted assertion or session key content.',
};

function esc(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function localName(qname: string): string {
    const i = qname.indexOf(':');
    return i >= 0 ? qname.slice(i + 1) : qname;
}

function elSpan(qname: string): string {
    const local = localName(qname);
    const hasTip = local in XML_ELEMENT_TIPS;
    const attrs = hasTip
        ? ` class="xml-el xml-el-tip" data-el="${esc(local)}"`
        : ' class="xml-el"';
    return `<span${attrs}>${esc(qname)}</span>`;
}

function highlightAttrs(s: string): string {
    const out: string[] = [];
    let i = 0;
    while (i < s.length) {
        // whitespace — emit literally to preserve indentation
        if (s[i] === ' ' || s[i] === '\n' || s[i] === '\r' || s[i] === '\t') {
            out.push(s[i] === '\n' ? '\n' : s[i] === '\t' ? '\t' : ' ');
            i++;
            continue;
        }
        // attribute name — scan to '=' or whitespace
        const nameStart = i;
        while (i < s.length && s[i] !== '=' && s[i] !== ' ' && s[i] !== '\n' && s[i] !== '\r' && s[i] !== '\t') i++;
        /* v8 ignore next */
        if (i > nameStart) {
            out.push(`<span class="xml-attr-name">${esc(s.slice(nameStart, i))}</span>`);
        }
        if (i >= s.length) break;
        // '='
        if (s[i] === '=') {
            out.push('<span class="xml-punct">=</span>');
            i++;
        }
        // attribute value (double or single quoted)
        if (i < s.length && (s[i] === '"' || s[i] === "'")) {
            const quote = s[i];
            const valStart = i;
            i++;
            while (i < s.length && s[i] !== quote) i++;
            i++; // include closing quote
            out.push(`<span class="xml-attr-val">${esc(s.slice(valStart, i))}</span>`);
        }
    }
    return out.join('');
}

function highlightOpenTag(tag: string): string {
    const selfClose = tag.endsWith('/>');
    const inner = tag.slice(1, selfClose ? -2 : -1);
    // split element name from attributes on first whitespace
    const spaceIdx = inner.search(/\s/);
    const name = spaceIdx === -1 ? inner : inner.slice(0, spaceIdx);
    const attrs = spaceIdx === -1 ? '' : inner.slice(spaceIdx);
    const close = selfClose ? '/&gt;' : '&gt;';
    return `<span class="xml-punct">&lt;</span>${elSpan(name)}${highlightAttrs(attrs)}<span class="xml-punct">${close}</span>`;
}

export function highlightXml(xml: string): string {
    const out: string[] = [];
    let i = 0;

    while (i < xml.length) {
        if (xml[i] !== '<') {
            const end = xml.indexOf('<', i);
            const chunk = end === -1 ? xml.slice(i) : xml.slice(i, end);
            out.push(esc(chunk));
            i = end === -1 ? xml.length : end;
            continue;
        }

        // Processing instruction
        if (xml.startsWith('<?', i)) {
            const end = xml.indexOf('?>', i);
            /* v8 ignore next */
            if (end === -1) { out.push(esc(xml.slice(i))); break; }
            out.push(`<span class="xml-prolog">${esc(xml.slice(i, end + 2))}</span>`);
            i = end + 2;
            continue;
        }

        // Comment
        if (xml.startsWith('<!--', i)) {
            const end = xml.indexOf('-->', i);
            /* v8 ignore next */
            if (end === -1) { out.push(esc(xml.slice(i))); break; }
            out.push(`<span class="xml-comment">${esc(xml.slice(i, end + 3))}</span>`);
            i = end + 3;
            continue;
        }

        // Closing tag
        if (xml.startsWith('</', i)) {
            const end = xml.indexOf('>', i);
            /* v8 ignore next */
            if (end === -1) { out.push(esc(xml.slice(i))); break; }
            const name = xml.slice(i + 2, end).trim();
            out.push(`<span class="xml-punct">&lt;/</span>${elSpan(name)}<span class="xml-punct">&gt;</span>`);
            i = end + 1;
            continue;
        }

        // Opening / self-closing tag — scan to end, respecting quoted values
        let j = i + 1;
        while (j < xml.length) {
            if (xml[j] === '"') {
                j++;
                while (j < xml.length && xml[j] !== '"') j++;
                j++;
            } else if (xml[j] === "'") {
                j++;
                while (j < xml.length && xml[j] !== "'") j++;
                j++;
            } else if (xml[j] === '>') {
                j++;
                break;
            } else {
                j++;
            }
        }
        out.push(highlightOpenTag(xml.slice(i, j)));
        i = j;
    }

    return out.join('');
}
