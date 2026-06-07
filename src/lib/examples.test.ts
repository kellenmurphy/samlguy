import { describe, it, expect } from 'vitest';
import { EXAMPLES, EXAMPLE_CATEGORIES, type ExampleCategory } from './examples';
import { decodeSaml } from './saml';
import { decodeJwt } from './jwt';
import { isMetadata, parseMetadata } from './metadata';

describe('EXAMPLES', () => {
    it('has at least one entry for every declared category', () => {
        const cats = new Set(EXAMPLES.map((e) => e.category));
        for (const cat of EXAMPLE_CATEGORIES) {
            expect(cats.has(cat), `missing category: ${cat}`).toBe(true);
        }
    });

    it('every example generates a non-empty string', () => {
        for (const ex of EXAMPLES) {
            expect(ex.payload().length).toBeGreaterThan(0);
        }
    });

    it('SAMLResponse examples decode without error via decodeSaml', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'SAMLResponse')) {
            expect(() => decodeSaml(ex.payload())).not.toThrow();
        }
    });

    it('SAMLResponse examples have Success status', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'SAMLResponse')) {
            const result = decodeSaml(ex.payload());
            expect(result.summary.status?.code).toContain('Success');
        }
    });

    it('SAMLRequest examples decode without error via decodeSaml', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'SAMLRequest')) {
            expect(() => decodeSaml(ex.payload())).not.toThrow();
        }
    });

    it('SAMLRequest examples are identified as SAMLRequest message type', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'SAMLRequest')) {
            const result = decodeSaml(ex.payload());
            expect(result.summary.messageType).toBe('SAMLRequest');
        }
    });

    it('Query string examples decode without error via decodeSaml', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'Query string')) {
            expect(() => decodeSaml(ex.payload())).not.toThrow();
        }
    });

    it('Full URL examples decode without error via decodeSaml', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'Full URL')) {
            expect(() => decodeSaml(ex.payload())).not.toThrow();
        }
    });

    it('JWT examples decode without error via decodeJwt', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'JWT')) {
            expect(() => decodeJwt(ex.payload())).not.toThrow();
        }
    });

    it('JWT examples have three dot-separated parts', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'JWT')) {
            expect(ex.payload().split('.').length).toBe(3);
        }
    });

    it('Authorization header examples decode without error via decodeJwt', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'Authorization header')) {
            expect(() => decodeJwt(ex.payload())).not.toThrow();
        }
    });

    it('Authorization header examples start with Authorization: Bearer', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'Authorization header')) {
            expect(ex.payload()).toMatch(/^Authorization:\s+Bearer\s+/i);
        }
    });

    it('Query string examples contain SAMLRequest or SAMLResponse parameter', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'Query string')) {
            expect(ex.payload()).toMatch(/SAMLRequest=|SAMLResponse=/);
        }
    });

    it('Full URL examples are valid HTTPS URLs', () => {
        for (const ex of EXAMPLES.filter((e) => e.category === 'Full URL')) {
            const payload = ex.payload();
            expect(() => new URL(payload)).not.toThrow();
            expect(new URL(payload).protocol).toBe('https:');
        }
    });

    it('redirect-encoded examples use redirect binding', () => {
        const qs = EXAMPLES.find(
            (e) => e.category === 'Query string' && e.label.includes('Redirect')
        );
        const url = EXAMPLES.find((e) => e.category === 'Full URL');
        expect(qs).toBeDefined();
        expect(url).toBeDefined();
        expect(decodeSaml(qs!.payload()).summary.binding).toBe('redirect');
        expect(decodeSaml(url!.payload()).summary.binding).toBe('redirect');
    });

    it('MFA SAMLResponse has REFEDS MFA authn context', () => {
        const mfa = EXAMPLES.find(
            (e) => e.category === 'SAMLResponse' && e.label.includes('MFA')
        );
        expect(mfa).toBeDefined();
        expect(decodeSaml(mfa!.payload()).summary.authnContext?.classRef).toBe(
            'https://refeds.org/profile/mfa'
        );
    });

    it('MFA SAMLRequest has REFEDS MFA requested authn context', () => {
        const mfa = EXAMPLES.find(
            (e) => e.category === 'SAMLRequest' && e.label.includes('MFA')
        );
        expect(mfa).toBeDefined();
        const result = decodeSaml(mfa!.payload());
        expect(result.summary.requestedAuthnContext?.classRefs).toContain(
            'https://refeds.org/profile/mfa'
        );
    });

    it('Metadata examples are detected and parse via parseMetadata', () => {
        const metaExamples = EXAMPLES.filter((e) => e.category === 'Metadata');
        expect(metaExamples.length).toBeGreaterThan(0);
        for (const ex of metaExamples) {
            const payload = ex.payload();
            expect(isMetadata(payload)).toBe(true);
            expect(() => parseMetadata(payload)).not.toThrow();
            expect(parseMetadata(payload).entity.entityId).toMatch(/^https:\/\//);
        }
    });

    it('OIDC ID token example has typ JWT in header', () => {
        const idToken = EXAMPLES.find((e) => e.label === 'OIDC ID token');
        expect(idToken).toBeDefined();
        const result = decodeJwt(idToken!.payload());
        expect(result.header.typ).toBe('JWT');
    });

    it('access token example has typ at+JWT in header', () => {
        const at = EXAMPLES.find((e) => e.label === 'OAuth 2.0 access token');
        expect(at).toBeDefined();
        const result = decodeJwt(at!.payload());
        expect(result.header.typ).toBe('at+JWT');
    });
});

describe('EXAMPLE_CATEGORIES', () => {
    it('is an array of unique category strings', () => {
        expect(new Set(EXAMPLE_CATEGORIES).size).toBe(EXAMPLE_CATEGORIES.length);
    });

    it('covers all categories used in EXAMPLES', () => {
        const inExamples = new Set<ExampleCategory>(EXAMPLES.map((e) => e.category));
        for (const cat of inExamples) {
            expect(EXAMPLE_CATEGORIES).toContain(cat);
        }
    });
});
