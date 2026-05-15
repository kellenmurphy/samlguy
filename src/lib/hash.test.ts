import { describe, it, expect } from 'vitest';
import { encodePayload, decodePayload } from './hash';

describe('encodePayload', () => {
    it('round-trips an ASCII string', () => {
        const s = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.sig';
        expect(decodePayload(encodePayload(s))).toBe(s);
    });

    it('round-trips a Unicode string', () => {
        expect(decodePayload(encodePayload('Hello 🌍 — IAM café'))).toBe('Hello 🌍 — IAM café');
    });

    it('round-trips an empty string', () => {
        expect(decodePayload(encodePayload(''))).toBe('');
    });

    it('produces no +, /, or = characters in output', () => {
        const result = encodePayload('SAMLRequest=abc+def/ghi=&RelayState=https%3A%2F%2Fexample.com');
        expect(result).not.toMatch(/[+/=]/);
    });

    it('replaces + with - (standard base64 → base64url)', () => {
        // '~þ' encodes via UTF-8 to bytes whose standard base64 is 'fsO+'
        expect(encodePayload('~þ')).toBe('fsO-');
    });

    it('replaces / with _ (standard base64 → base64url)', () => {
        // '~ÿ' encodes via UTF-8 to bytes whose standard base64 is 'fsO/'
        expect(encodePayload('~ÿ')).toBe('fsO_');
    });

    it('strips = padding (1-byte input produces ==)', () => {
        expect(encodePayload('A')).toBe('QQ');
    });

    it('strips = padding (2-byte input produces single =)', () => {
        expect(encodePayload('hi')).toBe('aGk');
    });
});

describe('decodePayload', () => {
    it('decodes a known base64url value', () => {
        expect(decodePayload('aGVsbG8')).toBe('hello');
    });

    it('restores - to + before decoding', () => {
        expect(decodePayload('fsO-')).toBe('~þ');
    });

    it('restores _ to / before decoding', () => {
        expect(decodePayload('fsO_')).toBe('~ÿ');
    });

    it('handles missing = padding (1-byte)', () => {
        expect(decodePayload('QQ')).toBe('A');
    });

    it('handles missing = padding (2-byte)', () => {
        expect(decodePayload('aGk')).toBe('hi');
    });
});
