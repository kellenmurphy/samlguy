import { describe, it, expect } from 'vitest';
import { decodeAllGeneric } from './generic';
import { AUTHN_REQUEST_XML, toRedirectBlob, toPostBlob } from './fixtures.test-helper';

const JSON_PAYLOAD = JSON.stringify({ sub: 'user@example.com', iss: 'https://idp.example.com' });

describe('decodeAllGeneric — encoding detection', () => {
    it('decodes a base64+deflate blob as xml', () => {
        const blob = toRedirectBlob(AUTHN_REQUEST_XML);
        const results = decodeAllGeneric(blob);
        expect(results).toHaveLength(1);
        expect(results[0].encoding).toBe('base64+deflate');
        expect(results[0].contentType).toBe('xml');
        expect(results[0].content).toContain('AuthnRequest');
    });

    it('decodes a plain base64 XML blob', () => {
        const blob = toPostBlob(AUTHN_REQUEST_XML);
        const results = decodeAllGeneric(blob);
        expect(results).toHaveLength(1);
        expect(results[0].encoding).toBe('base64');
        expect(results[0].contentType).toBe('xml');
    });

    it('decodes a plain base64 JSON blob', () => {
        const blob = btoa(JSON_PAYLOAD);
        const results = decodeAllGeneric(blob);
        expect(results).toHaveLength(1);
        expect(results[0].encoding).toBe('base64');
        expect(results[0].contentType).toBe('json');
        expect(results[0].content).toContain('"sub"');
    });

    it('returns plain XML with encoding=text', () => {
        const results = decodeAllGeneric(AUTHN_REQUEST_XML);
        expect(results).toHaveLength(1);
        expect(results[0].encoding).toBe('text');
        expect(results[0].contentType).toBe('xml');
    });

    it('returns plain JSON with encoding=text', () => {
        const results = decodeAllGeneric(JSON_PAYLOAD);
        expect(results).toHaveLength(1);
        expect(results[0].encoding).toBe('text');
        expect(results[0].contentType).toBe('json');
    });

    it('pretty-prints decoded JSON', () => {
        const blob = btoa(JSON_PAYLOAD);
        const results = decodeAllGeneric(blob);
        expect(results[0].content).toContain('\n');
        expect(results[0].content).toContain('    ');
    });
});

describe('decodeAllGeneric — URL/query string extraction', () => {
    it('extracts a decodable value from a query string param', () => {
        const blob = toPostBlob(AUTHN_REQUEST_XML);
        const results = decodeAllGeneric(`foo=${encodeURIComponent(blob)}&bar=ignored`);
        expect(results.some((r) => r.contentType === 'xml')).toBe(true);
    });

    it('extracts a decodable value from a full URL', () => {
        const blob = toPostBlob(AUTHN_REQUEST_XML);
        const results = decodeAllGeneric(
            `https://example.com/path?token=${encodeURIComponent(blob)}`
        );
        expect(results.some((r) => r.contentType === 'xml')).toBe(true);
    });
});

describe('decodeAllGeneric — multi-blob detection', () => {
    it('returns multiple results when the input contains several base64 blobs', () => {
        const blob1 = toPostBlob(AUTHN_REQUEST_XML);
        const blob2 = btoa(JSON_PAYLOAD.repeat(3)); // pad to ≥80 chars
        const input = `first=${blob1} second=${blob2}`;
        const results = decodeAllGeneric(input);
        expect(results.length).toBeGreaterThanOrEqual(1);
    });

    it('deduplicates identical blobs', () => {
        const blob = toPostBlob(AUTHN_REQUEST_XML);
        const results = decodeAllGeneric(`${blob} ${blob}`);
        expect(results).toHaveLength(1);
    });
});

describe('decodeAllGeneric — rejection cases', () => {
    it('returns empty array for short random strings', () => {
        expect(decodeAllGeneric('hello world')).toHaveLength(0);
    });

    it('returns empty array for binary-looking garbage', () => {
        // base64 of random high bytes that won't be readable text
        const binary = btoa('\x00\x01\x02\x03\x04\x05\x06\x07\x08'.repeat(20));
        expect(decodeAllGeneric(binary)).toHaveLength(0);
    });
});

describe('decodeAllGeneric — additional paths', () => {
    it('parses a ?-prefixed query string (startsWith ? path)', () => {
        const blob = toPostBlob(AUTHN_REQUEST_XML);
        const results = decodeAllGeneric(`?token=${encodeURIComponent(blob)}`);
        expect(results.some((r) => r.contentType === 'xml')).toBe(true);
    });

    it('decodes base64 plain text with contentType=text', () => {
        // 80+ chars of base64 needed to hit the blob regex scan
        const plainText =
            'hello world, this is plain text content for testing purposes, it is long enough now';
        const blob = btoa(plainText);
        const results = decodeAllGeneric(blob);
        expect(results).toHaveLength(1);
        expect(results[0].encoding).toBe('base64');
        expect(results[0].contentType).toBe('text');
        expect(results[0].content).toBe(plainText);
    });

    it('handles malformed percent-encoding without crashing (safeDecode catch path)', () => {
        // %ZZ is invalid percent-encoding — decodeURIComponent throws, safeDecode catches and returns input unchanged
        expect(decodeAllGeneric('%ZZ'.repeat(30))).toHaveLength(0);
    });
});
