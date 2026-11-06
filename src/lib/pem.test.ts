import { describe, it, expect } from 'vitest';
import { createPublicKey, generateKeyPairSync, X509Certificate, type KeyObject } from 'node:crypto';
import { base64ToBytes, encodeTlv, jwkToPem, jwkToSpki, toPem } from './pem';
import { certPublicKeySpki } from './cert';
import { TEST_CERT_B64, EC_CERT_B64, ED25519_CERT_B64 } from './fixtures.test-helper';

/** Node's own SPKI DER for a key, as the independent oracle. */
function nodeSpki(key: KeyObject): Uint8Array {
    return new Uint8Array(key.export({ type: 'spki', format: 'der' }));
}

function publicJwk(key: KeyObject): Record<string, unknown> {
    return key.export({ format: 'jwk' }) as Record<string, unknown>;
}

const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

describe('base64ToBytes', () => {
    it('decodes standard base64 with whitespace', () => {
        expect(Array.from(base64ToBytes('AQID\nBA=='))).toEqual([1, 2, 3, 4]);
    });

    it('decodes base64url without padding', () => {
        expect(Array.from(base64ToBytes('-_8'))).toEqual([0xfb, 0xff]);
    });
});

describe('encodeTlv', () => {
    it('uses a short-form length under 128 bytes', () => {
        expect(Array.from(encodeTlv(0x04, Uint8Array.of(1, 2)))).toEqual([0x04, 0x02, 1, 2]);
    });

    it('uses a one-byte long-form length from 128 to 255 bytes', () => {
        const out = encodeTlv(0x04, new Uint8Array(200));
        expect(Array.from(out.slice(0, 3))).toEqual([0x04, 0x81, 200]);
        expect(out.length).toBe(203);
    });

    it('uses a two-byte long-form length from 256 bytes', () => {
        const out = encodeTlv(0x04, new Uint8Array(300));
        expect(Array.from(out.slice(0, 4))).toEqual([0x04, 0x82, 0x01, 0x2c]);
        expect(out.length).toBe(304);
    });
});

describe('toPem', () => {
    const pem = toPem(TEST_CERT_B64, 'CERTIFICATE');
    const lines = pem.trimEnd().split('\n');

    it('wraps the body in BEGIN and END armor', () => {
        expect(lines[0]).toBe('-----BEGIN CERTIFICATE-----');
        expect(lines.at(-1)).toBe('-----END CERTIFICATE-----');
        expect(pem.endsWith('\n')).toBe(true);
    });

    it('wraps the body at 64 columns', () => {
        const body = lines.slice(1, -1);
        expect(body.slice(0, -1).every((l) => l.length === 64)).toBe(true);
        expect(body.at(-1)!.length).toBeLessThanOrEqual(64);
    });

    it('produces a certificate that Node parses back', () => {
        const cert = new X509Certificate(pem);
        expect(cert.subject).toContain('CN=samlguy test');
    });

    it('accepts DER bytes as well as base64', () => {
        expect(toPem(base64ToBytes(TEST_CERT_B64), 'CERTIFICATE')).toBe(pem);
    });

    it('emits armor only for empty input', () => {
        expect(toPem(new Uint8Array(0), 'PUBLIC KEY')).toBe(
            '-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n'
        );
    });
});

describe('certPublicKeySpki', () => {
    it.each([
        ['RSA', TEST_CERT_B64],
        ['EC', EC_CERT_B64],
        ['Ed25519', ED25519_CERT_B64]
    ])('matches the %s public key Node extracts from the certificate', (_, b64) => {
        const expected = nodeSpki(new X509Certificate(Buffer.from(b64, 'base64')).publicKey);
        expect(Array.from(certPublicKeySpki(b64))).toEqual(Array.from(expected));
    });

    it('produces a PUBLIC KEY PEM that Node parses back', () => {
        const pem = toPem(certPublicKeySpki(TEST_CERT_B64), 'PUBLIC KEY');
        expect(createPublicKey(pem).asymmetricKeyType).toBe('rsa');
    });

    it('rejects a structure with no SubjectPublicKeyInfo', () => {
        const truncated = encodeTlv(0x30, encodeTlv(0x30, encodeTlv(0x02, Uint8Array.of(1))));
        expect(() => certPublicKeySpki(Buffer.from(truncated).toString('base64'))).toThrow(
            'no SubjectPublicKeyInfo'
        );
    });
});

describe('jwkToSpki', () => {
    const cases: [string, KeyObject][] = [
        ['RSA-2048', generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey],
        ['RSA-4096', generateKeyPairSync('rsa', { modulusLength: 4096 }).publicKey],
        ['EC P-256', generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey],
        ['EC P-384', generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey],
        ['EC P-521', generateKeyPairSync('ec', { namedCurve: 'P-521' }).publicKey],
        ['Ed25519', generateKeyPairSync('ed25519').publicKey],
        ['Ed448', generateKeyPairSync('ed448').publicKey],
        ['X25519', generateKeyPairSync('x25519').publicKey],
        ['X448', generateKeyPairSync('x448').publicKey]
    ];

    it.each(cases)('matches Node for %s', (_, key) => {
        expect(Array.from(jwkToSpki(publicJwk(key)))).toEqual(Array.from(nodeSpki(key)));
    });

    it('strips leading zero bytes from the RSA modulus', () => {
        const key = cases[0][1];
        const jwk = publicJwk(key);
        const padded = { ...jwk, n: b64u(Uint8Array.of(0, 0, ...base64ToBytes(jwk.n as string))) };
        expect(Array.from(jwkToSpki(padded))).toEqual(Array.from(nodeSpki(key)));
    });

    it('ignores private and metadata members', () => {
        const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const jwk = {
            ...(privateKey.export({ format: 'jwk' }) as Record<string, unknown>),
            kid: 'k1',
            use: 'sig',
            alg: 'ES256'
        };
        expect(Array.from(jwkToSpki(jwk))).toEqual(Array.from(nodeSpki(publicKey)));
    });

    it('rejects a missing RSA member', () => {
        expect(() => jwkToSpki({ kty: 'RSA', n: 'AQAB' })).toThrow('JWK is missing "e"');
    });

    it('rejects an empty member', () => {
        expect(() => jwkToSpki({ kty: 'RSA', n: '', e: 'AQAB' })).toThrow('JWK is missing "n"');
    });

    it('rejects an unsupported EC curve', () => {
        expect(() => jwkToSpki({ kty: 'EC', crv: 'secp256k1', x: 'AA', y: 'AA' })).toThrow(
            'Unsupported curve: secp256k1'
        );
    });

    it('rejects a missing curve', () => {
        expect(() => jwkToSpki({ kty: 'OKP', x: 'AA' })).toThrow('Unsupported curve: none');
    });

    it('rejects EC coordinates of the wrong length', () => {
        const jwk = publicJwk(cases[2][1]);
        expect(() => jwkToSpki({ ...jwk, x: b64u(new Uint8Array(31)) })).toThrow(
            'EC P-256 coordinates must be 32 bytes'
        );
        expect(() => jwkToSpki({ ...jwk, y: b64u(new Uint8Array(33)) })).toThrow(
            'EC P-256 coordinates must be 32 bytes'
        );
    });

    it('rejects an OKP key of the wrong length', () => {
        expect(() =>
            jwkToSpki({ kty: 'OKP', crv: 'Ed25519', x: b64u(new Uint8Array(31)) })
        ).toThrow('Ed25519 public key must be 32 bytes');
    });

    it('rejects symmetric keys', () => {
        expect(() => jwkToSpki({ kty: 'oct', k: 'c2VjcmV0' })).toThrow('no public key');
    });

    it('rejects unknown and missing key types', () => {
        expect(() => jwkToSpki({ kty: 'DSA' })).toThrow('Unsupported key type: DSA');
        expect(() => jwkToSpki({})).toThrow('Unsupported key type: none');
    });
});

describe('jwkToPem', () => {
    it('produces a PUBLIC KEY PEM that Node parses back', () => {
        const key = generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey;
        const pem = jwkToPem(publicJwk(key));
        expect(pem.startsWith('-----BEGIN PUBLIC KEY-----\n')).toBe(true);
        expect(Array.from(nodeSpki(createPublicKey(pem)))).toEqual(Array.from(nodeSpki(key)));
    });
});
