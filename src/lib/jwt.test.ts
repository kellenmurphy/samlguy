import { describe, it, expect } from 'vitest';
import { decodeJwt } from './jwt';

// Pre-computed test JWTs (signature is always the literal string "sig" — not cryptographically valid,
// but sufficient since decodeJwt does not verify signatures)

const RS256_FULL =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InVzZXIxMjMiLCJhdWQiOiJjbGllbnRfaWQiLCJpYXQiOjk5OTk5NjQwMCwiZXhwIjoxMDAwMDAwMDAwLCJuYmYiOjk5OTk5NjQwMCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCJ9' +
    '.sig';

const ALG_NONE =
    'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0' +
    '.eyJzdWIiOiJhdHRhY2tlciJ9' +
    '.sig';

const HS256 =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiJhdHRhY2tlciJ9' +
    '.sig';

const SCOPE_ARRAY =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiJ1c2VyIiwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSJdfQ' +
    '.sig';

const SCP_STRING =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiJ1c2VyIiwic2NwIjoicmVhZCB3cml0ZSJ9' +
    '.sig';

const SCP_ARRAY =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiJ1c2VyIiwic2NwIjpbInJlYWQiLCJ3cml0ZSJdfQ' +
    '.sig';

const NO_SCOPE =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiJ1c2VyIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9' +
    '.sig';

const NO_TIMESTAMPS =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiJ1c2VyIn0' +
    '.sig';

describe('decodeJwt — RS256 with full claims', () => {
    const result = decodeJwt(RS256_FULL);

    it('populates header', () => {
        expect(result.header).toMatchObject({ alg: 'RS256', typ: 'JWT' });
    });

    it('populates payload', () => {
        expect(result.payload).toMatchObject({
            iss: 'https://issuer.example.com',
            sub: 'user123',
        });
    });

    it('captures raw JWT string', () => {
        expect(result.raw).toBe(RS256_FULL);
    });

    it('captures signature', () => {
        expect(result.signature).toBe('sig');
    });

    it('isAlgNone is false', () => {
        expect(result.isAlgNone).toBe(false);
    });

    it('isWeakAlg is false for RS256', () => {
        expect(result.isWeakAlg).toBe(false);
    });

    it('parses iat timestamp', () => {
        expect(result.timestamps.iat?.raw).toBe(999996400);
        expect(result.timestamps.iat?.expired).toBe(true);
        expect(result.timestamps.iat?.date.toISOString()).toBe('2001-09-09T00:46:40.000Z');
    });

    it('parses exp timestamp', () => {
        expect(result.timestamps.exp?.raw).toBe(1000000000);
        expect(result.timestamps.exp?.expired).toBe(true);
    });

    it('parses nbf timestamp', () => {
        expect(result.timestamps.nbf?.raw).toBe(999996400);
    });

    it('parses scope string into array', () => {
        expect(result.scopes).toEqual(['openid', 'profile', 'email']);
    });
});

describe('decodeJwt — Bearer prefix', () => {
    it('strips "Bearer " prefix (case-insensitive)', () => {
        const result = decodeJwt('Bearer ' + RS256_FULL);
        expect(result.raw).toBe(RS256_FULL);
        expect(result.header.alg).toBe('RS256');
    });

    it('strips lowercase "bearer "', () => {
        const result = decodeJwt('bearer ' + RS256_FULL);
        expect(result.raw).toBe(RS256_FULL);
    });
});

describe('decodeJwt — alg:none', () => {
    const result = decodeJwt(ALG_NONE);

    it('sets isAlgNone to true', () => {
        expect(result.isAlgNone).toBe(true);
    });

    it('isWeakAlg is false (none is dangerous, not "weak HMAC")', () => {
        expect(result.isWeakAlg).toBe(false);
    });
});

describe('decodeJwt — HS256 (symmetric/weak)', () => {
    const result = decodeJwt(HS256);

    it('sets isWeakAlg to true for HS256', () => {
        expect(result.isWeakAlg).toBe(true);
    });

    it('isAlgNone is false', () => {
        expect(result.isAlgNone).toBe(false);
    });
});

describe('decodeJwt — scope variations', () => {
    it('parses scope as array', () => {
        expect(decodeJwt(SCOPE_ARRAY).scopes).toEqual(['openid', 'profile']);
    });

    it('parses scp as string', () => {
        expect(decodeJwt(SCP_STRING).scopes).toEqual(['read', 'write']);
    });

    it('parses scp as array', () => {
        expect(decodeJwt(SCP_ARRAY).scopes).toEqual(['read', 'write']);
    });

    it('returns null when no scope or scp claim', () => {
        expect(decodeJwt(NO_SCOPE).scopes).toBeNull();
    });
});

describe('decodeJwt — missing timestamps', () => {
    const result = decodeJwt(NO_TIMESTAMPS);

    it('iat is undefined', () => {
        expect(result.timestamps.iat).toBeUndefined();
    });

    it('exp is undefined', () => {
        expect(result.timestamps.exp).toBeUndefined();
    });

    it('nbf is undefined', () => {
        expect(result.timestamps.nbf).toBeUndefined();
    });
});

// header: {"alg":42,"typ":"JWT"} — alg is a number, not a string
const ALG_NOT_STRING =
    'eyJhbGciOjQyLCJ0eXAiOiJKV1QifQ' +
    '.eyJzdWIiOiJ1c2VyIn0' +
    '.sig';

describe('decodeJwt — non-string alg', () => {
    const result = decodeJwt(ALG_NOT_STRING);

    it('treats non-string alg as empty string (isAlgNone false)', () => {
        expect(result.isAlgNone).toBe(false);
    });

    it('treats non-string alg as empty string (isWeakAlg false)', () => {
        expect(result.isWeakAlg).toBe(false);
    });
});

describe('decodeJwt — error cases', () => {
    it('throws on a string with fewer than 3 parts', () => {
        expect(() => decodeJwt('header.payload')).toThrow('Invalid JWT');
    });

    it('throws on a string with more than 3 parts', () => {
        expect(() => decodeJwt('a.b.c.d')).toThrow('Invalid JWT');
    });

    it('throws when header is not valid JSON after base64url decode', () => {
        // "bm90anNvbg" decodes to "notjson"
        expect(() => decodeJwt('bm90anNvbg.eyJzdWIiOiJ1In0.sig')).toThrow(
            'could not decode header'
        );
    });

    it('throws when payload is not valid JSON after base64url decode', () => {
        // header is valid, payload decodes to "notjson"
        expect(() =>
            decodeJwt('eyJhbGciOiJSUzI1NiJ9.bm90anNvbg.sig')
        ).toThrow('could not decode payload');
    });
});
