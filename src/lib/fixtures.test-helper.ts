import { deflateRaw } from 'pako';

export const AUTHN_REQUEST_XML = `<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z" Destination="https://idp.example.com/sso" AssertionConsumerServiceURL="https://sp.example.com/acs"><saml:Issuer>https://sp.example.com</saml:Issuer></samlp:AuthnRequest>`;

export const RESPONSE_XML = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z" InResponseTo="_req1" Destination="https://sp.example.com/acs"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assert1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID></saml:Subject><saml:Conditions NotBefore="2024-01-01T11:55:00Z" NotOnOrAfter="2024-01-01T13:00:00Z"/><saml:AuthnStatement AuthnInstant="2024-01-01T12:00:00Z" SessionNotOnOrAfter="2024-01-01T20:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email" FriendlyName="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:2.5.4.42" FriendlyName="givenName"><saml:AttributeValue>Test</saml:AttributeValue><saml:AttributeValue>User</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;

// Response with SubjectConfirmationData whose NotOnOrAfter (14:00) differs from Conditions (13:00)
export const RESPONSE_WITH_SCD_XML = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp2" Version="2.0" IssueInstant="2024-01-01T12:00:00Z" InResponseTo="_req1" Destination="https://sp.example.com/acs"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assert2" Version="2.0" IssueInstant="2024-01-01T12:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_req1" NotOnOrAfter="2024-01-01T14:00:00Z" Recipient="https://sp.example.com/acs"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2024-01-01T11:55:00Z" NotOnOrAfter="2024-01-01T13:00:00Z"/><saml:AuthnStatement AuthnInstant="2024-01-01T12:00:00Z" SessionNotOnOrAfter="2024-01-01T20:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`;

// Error response: Responder + AuthnFailed sub-code + StatusMessage, no assertion
export const ERROR_RESPONSE_XML = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_err1" Version="2.0" IssueInstant="2024-01-01T12:00:00Z" InResponseTo="_req1" Destination="https://sp.example.com/acs"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></samlp:StatusCode><samlp:StatusMessage>The user failed to authenticate.</samlp:StatusMessage></samlp:Status></samlp:Response>`;

// AuthnRequest with RequestedAuthnContext — two class refs, Comparison=minimum
export const AUTHN_REQUEST_WITH_CONTEXT_XML = `<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req2" Version="2.0" IssueInstant="2024-01-01T12:00:00Z" Destination="https://idp.example.com/sso" AssertionConsumerServiceURL="https://sp.example.com/acs"><saml:Issuer>https://sp.example.com</saml:Issuer><samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef><saml:AuthnContextClassRef>https://refeds.org/profile/mfa</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`;

export function toRedirectBlob(xml: string): string {
    const compressed = deflateRaw(new TextEncoder().encode(xml));
    return btoa(String.fromCharCode(...compressed));
}

export function toPostBlob(xml: string): string {
    return btoa(xml);
}

// RSA cert with old UTCTime dates (1986-01-01 → 1996-01-01) — year 86 >= 50 covers the 1900+y branch
// in parseTime (the `y >= 50 ? 1900 + y : 2000 + y` ternary)
export const UTCTIME_OLD_CERT_B64 =
    'MIIBrzCCAYgCAQEwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLdXRjdGltZSBvbGQwHhcNODYwMTAxMDAwMDAwWhcNOTYwMTAxMDAwMDAwWjAWMRQwEgYDVQQDDAt1dGN0aW1lIG9sZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIACAwEAATANBgkqhkiG9w0BAQsFAAMSAAAAAAAAAAAAAAAAAAAAAAAA';

// EC cert with no curve OID in AlgorithmIdentifier — covers the EC-without-curve-param branch
// (parseKeyAlg: algId.children[1] is undefined → curveOid = '') and the unknown-curve fallback
// (OID_CURVE[''] is undefined → returns curveOid = '') → keyAlgorithm = 'EC '
export const EC_NO_CURVE_CERT_B64 =
    'MIHZMIGzAgEBMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2VjIG5vIGN1cnZlMB4XDTI2MDUxMTAwMDAwMFoXDTM2MDUwNzAwMDAwMFowFjEUMBIGA1UEAwwLZWMgbm8gY3VydmUwTzAJBgcqhkjOPQIBA0IABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwDQYJKoZIhvcNAQELBQADEgAAAAAAAAAAAAAAAAAAAAAAAA==';

// RSA cert with 1-byte modulus 0x01 (no leading zero byte) — covers line 130 branch 1
// mod.value[0] = 0x01 (not 0x00), so the ternary subtracts 0 → bits = 1*8 = 8 → keyAlgorithm = 'RSA-8'
export const RSA_NO_ZERO_CERT_B64 =
    'MIGoMIGDoAMCAQICAQEwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLcnNhIG5vIHplcm8wHhcNMjYwNTExMDAwMDAwWhcNMzYwNTA3MDAwMDAwWjAWMRQwEgYDVQQDDAtyc2Egbm8gemVybzAaMA0GCSqGSIb3DQEBAQUAAwkAMAYCAQECAQMwDQYJKoZIhvcNAQELBQADEQAAAAAAAAAAAAAAAAAAAAAA';

// RSA cert with title (OID 2.5.4.12) in DN — 2.5.4.12 is not in OID_ATTR, so parseName
// falls back to the raw OID string → subject = '2.5.4.12=CEO'
export const TITLE_ATTR_CERT_B64 =
    'MIIBnzCCAXgCAQEwDQYJKoZIhvcNAQELBQAwDjEMMAoGA1UEDAwDQ0VPMB4XDTI2MDUxMTAwMDAwMFoXDTM2MDUwNzAwMDAwMFowDjEMMAoGA1UEDAwDQ0VPMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAIDAQABMA0GCSqGSIb3DQEBCwUAAxIAAAAAAAAAAAAAAAAAAAAAAAA=';

// Self-signed EC P-256 certificate (valid 2026-05-10 → 2036-05-07, CN=ec test, O=EC Org, C=US)
export const EC_CERT_B64 =
    'MIIBtTCCAVugAwIBAgIUHW0UGEKzy86qLYBTF1Gxey5bUQMwCgYIKoZIzj0EAwIwMDEQ' +
    'MA4GA1UEAwwHZWMgdGVzdDEPMA0GA1UECgwGRUMgT3JnMQswCQYDVQQGEwJVUzAeFw0y' +
    'NjA1MTAyMjQ1MjhaFw0zNjA1MDcyMjQ1MjhaMDAxEDAOBgNVBAMMB2VjIHRlc3QxDzAN' +
    'BgNVBAoMBkVDIE9yZzELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC' +
    'AARCUUnlWU0Jkyi6OrO5QKr3roVihOPvHQ80djhaZe7Nl+8YHcJrmA6r1kKOYhWpFpA+' +
    'WOlwVdRTVSxhw+4gZgIfo1MwUTAdBgNVHQ4EFgQU7a+5sts1mjhXHTJaqf73E5OlctMw' +
    'HwYDVR0jBBgwFoAU7a+5sts1mjhXHTJaqf73E5OlctMwDwYDVR0TAQH/BAUwAwEB/zAK' +
    'BggqhkjOPQQDAgNIADBFAiEAw4jycUqf0heA5MUsCkMxyqIVt8O7ytub8m7Xhtap5dUC' +
    'IEKKY25DsuaMMMvFJ9xx2fgOriEcAtyebuT6YsNXm1a0';

// ED25519 certificate (valid 2026-05-10 → 2026-05-11, CN=ed test) — algorithm OID not in OID_SPKI
export const ED25519_CERT_B64 =
    'MIIBODCB66ADAgECAhRE0BonwLpqwS4Z6nLODviS7auyWjAFBgMrZXAwEjEQMA4GA1UE' +
    'AwwHZWQgdGVzdDAeFw0yNjA1MTAyMzIzMzNaFw0yNjA1MTEyMzIzMzNaMBIxEDAOBgNV' +
    'BAMMB2VkIHRlc3QwKjAFBgMrZXADIQBfqM4RwuipytPCy6Mueh5wFcl6h8Ju3AH/S3Ni' +
    'kX1fx6NTMFEwHQYDVR0OBBYEFPn3Hcb6pNgnrgLlus4jIk5vg8DrMB8GA1UdIwQYMBaA' +
    'FPn3Hcb6pNgnrgLlus4jIk5vg8DrMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA2fvo' +
    'taIQyWwjAStyYYBlKdJSDVuNzM4YPtbPXC3iVADLSpU5VkaeRHLC2JwONeFbKu/mcNx0' +
    '1GDYBNWqi+nCDQ==';

// RSA-2048 certificate with GeneralizedTime dates (2050-01-01 → 2060-01-01, CN=gen test)
export const GENTIME_CERT_B64 =
    'MIICozCCAYugAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhnZW4g' +
    'dGVzdDAiGA8yMDUwMDEwMTAwMDAwMFoYDzIwNjAwMTAxMDAwMDAwWjATMREwDwYD' +
    'VQQDDAhnZW4gdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKZZ' +
    '9zeLI/p6hfKH7rWRBJslziFhjXRGumJREpNgdO/hjw9Ck9I/da3DhEZPgadBAMcc' +
    'xmch1ZnevUIDS8CRliif5oZzpyNJO5O5y0qFs6ZoEn5bU+Lf+/7JIY1gyhK6J1g9' +
    'o9OZu8VNCvx96jdO+oEdLwJDK93pgjbJYIdWbVl/i5wQCBml4SEw/UHuYcq1I6e7' +
    '7MCC13u0DP/kBKjGUwhlapYJA+Tqe0j5Qcm3hP9SAgQ7uUQSZLdbA6ed3gD4OhU8' +
    'BQOdeEvAQFGfaRqznQwUOuZ9dZf6DFPmfm4EmlLHJezSUvVQh0ZDIhkckLpgkndm' +
    'CT3LRgxLMsdHukaEdGsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAIxmpcEE9din4Xb' +
    'dqE+7aWUVYX6QgBRHyr0TM56rjg5uMLkhaj3NDism+dLzMblQprdqGnhABRWonn65' +
    'alEU5eO8BwsX6uUvprZmn7GqJCQVavL4Pttttq/heNIegbiIJ2atGcgaS/PrXQmE' +
    'Xz9UG2SrxeHWisvB8T16ak49WBa4TTYhg1/vNYFlv4yX8GFGB+u7f1p2+BZ9C0HG' +
    'wNY6npToudrbx6AWfOwHzr5Bp7/NvGyOyDE8UB7JWg8cxoCCE3pk1nfM8F5n6xlM3' +
    '3nevGcOU4wupIGXhzjnN9KsKLHptfS+xtyf9UC+58SS+JsI5+166gYoyAacAfhVzN' +
    'LJCKQ==';

// RSA-2048 cert with serial 0xC8 (200) — DER-encoded with leading 0x00, covers strip-leading-zero branch
export const BIGSERIAL_CERT_B64 =
    'MIIC+TCCAeGgAwIBAgICAMgwDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAwwKYmlnIHNl' +
    'cmlhbDAeFw0yNjA1MTAyMzQwNDFaFw0yNjA1MTEyMzQwNDFaMBUxEzARBgNVBAMMCmJp' +
    'ZyBzZXJpYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDzdRQkUxprXRm7' +
    'G3NTTrIijdPM9c7IbBq7BCZ09Q4eGCWM//Up7hVDVybfmHI4n9aWNKlrHNfOG/jyT6VF' +
    'B/tzsJPZFyJKExHlKbv2PABcPENAXqz8hdJIz5WwiwmyTClx7J1kaGNLFEwdAauxR38u' +
    'l5Knxb0ZwcdPB/rHmCxrTcmBNrVDioFMh9jY3D9NXU1AchKmPPzNonHE2r1ZEVuah0XG' +
    'SqXnQLt0ZsJlqt/4Tf57zY2cuawwvSRi/Efu/AsTpBe/07DjKOQOFKDGZrR9aouARu/j' +
    'W0KmF8DU/i4Q9IWHIpU+S6I41XTvYNf5ClELiapD0YLGHCYpjsncMbvRAgMBAAGjUzBR' +
    'MB0GA1UdDgQWBBS8KfVQUX8+znYGC5mpVhCmnwzh8DAfBgNVHSMEGDAWgBS8KfVQUX8+' +
    'znYGC5mpVhCmnwzh8DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAr' +
    'FyxM+Rln/RxDIbOAbAHmtodXifJo7eo2GI793U/Vmqzck8ItogxG1Khw5rLrNRz0F8WJ' +
    'Zj8S2PM1iz6UzFizDBzq5FTifs35QXXus9pk92hGhxv/apamlL0RlEOUxqqItX9llRvw' +
    'gseHn9rJeOhofHhYDLb4JvBZkwzKUCqmPwsuzu0NRoSQy+HsZE+dkyyUsYXRHAOLEVwo' +
    'ITVzS6N13qSVtEGqqGSqeSG92JgLguOBHaM3uXcknOV6tws3J7qtH8xH9tLhDiBwoB7b' +
    'VB7YTm3/3yTsQrE8nRPuJqpm4XNQxOuRJxyWSsUosIS0KHrqtNpvI8+nU6snwRX1YINJ';

// RSA cert with empty inner SEQUENCE in BIT STRING — triggers the RSA key-size parse fallback
// (mod is undefined because SEQUENCE has no children, so parseKeyAlg returns 'RSA')
export const RSA_FALLBACK_CERT_B64 =
    'MIGjMH+gAwIBAgIBKjANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxyc2EgZmFsbGJhY2swHhcN' +
    'MjYwNTExMDAwMDAwWhcNMzYwNTA3MDAwMDAwWjAXMRUwEwYDVQQDDAxyc2EgZmFsbGJhY2swFDAN' +
    'BgkqhkiG9w0BAQEFAAMDADAAMA0GCSqGSIb3DQEBCwUAAxEAAAAAAAAAAAAAAAAAAAAAAA==';

// Self-signed RSA-2048 test certificate (valid 2026-05-10 → 2036-05-07)
// CN=samlguy test, O=Test Org, C=US  (self-signed)
export const TEST_CERT_B64 =
    'MIIDTzCCAjegAwIBAgIUPPkpKrOIL3XCGLiWcFQCLHfL4dAwDQYJKoZIhvcNAQEL' +
    'BQAwNzEVMBMGA1UEAwwMc2FtbGd1eSB0ZXN0MREwDwYDVQQKDAhUZXN0IE9yZzEL' +
    'MAkGA1UEBhMCVVMwHhcNMjYwNTEwMjIwNDA1WhcNMzYwNTA3MjIwNDA1WjA3MRUw' +
    'EwYDVQQDDAxzYW1sZ3V5IHRlc3QxETAPBgNVBAoMCFRlc3QgT3JnMQswCQYDVQQG' +
    'EwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZyBV4ddo7boAzy' +
    'X0M1sachAfh4REG2TMazFKj3acJkpGwCoFvL5/7j+32mZFP3wKLWDgOcZBN9SdBg' +
    'SllAnaDEEqls7i/K5Nw7UZHAJu+s5vfWCFajvMXm6W7fyJtLjGLMVw7YvIbzfEYK' +
    'FcHi3DVyd3uvQIVAGXM6n3CRsZD9u+ZC8UIxeFRnuKbPr/nvqBCz7ocwFirPYPii' +
    'IuCXQrmexcNJdAB8S+UvURcaU0JXgibwiQj05vGtYLOQGgLheA/Acur/ZFG23Y64' +
    'xdDp5BbEdLChzZFwC5Fx6afsbH1Rh2dv8c936/BVnE3785JY2tx5eVN8u4bApt2z' +
    'PVrzMA8CAwEAAaNTMFEwHQYDVR0OBBYEFNxjDEuglN6s7m+MMi7CeKiTl+SmMB8G' +
    'A1UdIwQYMBaAFNxjDEuglN6s7m+MMi7CeKiTl+SmMA8GA1UdEwEB/wQFMAMBAf8w' +
    'DQYJKoZIhvcNAQELBQADggEBACGfBPqLw3G/lqGgaoXVBw2m6ZqUgfDfP9nmGONG' +
    'SxiUGioBRhTJccPDyvhvBl27FFZLDyn0Ipak5XwyfdWGExo/HcodeO0G073/CTkz' +
    'iz3u/R4Df0Da5qTJ2uRpcOpFsLjqbr5HhTkThO864XEWgjvnQnFSFgMbNfYmJ4OW' +
    'jsy9btCxocJyegs5I/IxZ8YpM6nqPpf7zEZ5mOqbY7Uk5FZkyJ5NKo5y6GK60bv' +
    'Klg4PuMk8Fd3kqs0y9NGFG7reSCJCkDrS+n1iRxuzVmi+7Vrpie7KFMD378Wfin' +
    'evrq2Kj7RVY22oQ1JodHU4pqT2mtQmQkW67xilQZnRA58v8N4=';
