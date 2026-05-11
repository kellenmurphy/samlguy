import { describe, it, expect } from 'vitest';
import { FIELD_EXPLANATIONS, SAML_TS_KEY } from './explanations';

const EXPECTED_KEYS = [
    'saml.binding',
    'saml.messageType',
    'saml.status',
    'saml.issuer',
    'saml.destination',
    'saml.acsUrl',
    'saml.nameId',
    'saml.inResponseTo',
    'saml.relayState',
    'saml.encrypted',
    'saml.signingCert',
    'saml.attributes',
    'saml.ts.authnInstant',
    'saml.ts.sessionNotOnOrAfter',
    'saml.ts.notBefore',
    'saml.ts.notOnOrAfter',
    'saml.ts.subjectConfirmationNotOnOrAfter',
    'jwt.algorithm',
    'jwt.tokenType',
    'jwt.keyId',
    'jwt.issuer',
    'jwt.subject',
    'jwt.audience',
    'jwt.jwtId',
    'jwt.scopes',
    'jwt.ts.issuedAt',
    'jwt.ts.notBefore',
    'jwt.ts.expires',
];

describe('FIELD_EXPLANATIONS', () => {
    it.each(EXPECTED_KEYS)('has a non-empty string for "%s"', (key) => {
        expect(typeof FIELD_EXPLANATIONS[key]).toBe('string');
        expect(FIELD_EXPLANATIONS[key].length).toBeGreaterThan(0);
    });
});

describe('SAML_TS_KEY', () => {
    it('maps all SAML timestamp labels to known FIELD_EXPLANATIONS keys', () => {
        for (const [label, key] of Object.entries(SAML_TS_KEY)) {
            expect(FIELD_EXPLANATIONS[key], `SAML_TS_KEY["${label}"] points to missing key "${key}"`).toBeDefined();
        }
    });
});
