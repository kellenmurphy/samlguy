import { describe, it, expect } from 'vitest';
import { decodeCert } from './cert';
import {
    TEST_CERT_B64,
    EC_CERT_B64,
    GENTIME_CERT_B64,
    ED25519_CERT_B64,
    BIGSERIAL_CERT_B64,
    RSA_FALLBACK_CERT_B64,
    UTCTIME_OLD_CERT_B64,
    EC_NO_CURVE_CERT_B64,
    RSA_NO_ZERO_CERT_B64,
    TITLE_ATTR_CERT_B64
} from './fixtures.test-helper';

describe('decodeCert', () => {
    const cert = decodeCert(TEST_CERT_B64);

    it('parses the subject', () => {
        expect(cert.subject).toBe('CN=samlguy test, O=Test Org, C=US');
    });

    it('parses the issuer (self-signed, same as subject)', () => {
        expect(cert.issuer).toBe('CN=samlguy test, O=Test Org, C=US');
    });

    it('detects RSA-2048 key algorithm', () => {
        expect(cert.keyAlgorithm).toBe('RSA-2048');
    });

    it('parses the serial number', () => {
        // openssl output: 3CF9292AB3882F75C218B8967054022C77CBE1D0
        expect(cert.serialNumber).toBe(
            '3c:f9:29:2a:b3:88:2f:75:c2:18:b8:96:70:54:02:2c:77:cb:e1:d0'
        );
    });

    it('parses notBefore', () => {
        expect(cert.validFrom.toISOString()).toBe('2026-05-10T22:04:05.000Z');
    });

    it('parses notAfter', () => {
        expect(cert.validTo.toISOString()).toBe('2036-05-07T22:04:05.000Z');
    });

    it('reports the cert as currently valid', () => {
        // cert is valid 2026-05-10 → 2036-05-07
        expect(cert.isValid).toBe(true);
    });

    it('throws on invalid base64', () => {
        expect(() => decodeCert('not-valid-base64!!!')).toThrow();
    });
});

describe('decodeCert — EC P-256', () => {
    const cert = decodeCert(EC_CERT_B64);

    it('detects EC P-256 key algorithm', () => {
        expect(cert.keyAlgorithm).toBe('EC P-256');
    });

    it('parses subject', () => {
        expect(cert.subject).toBe('CN=ec test, O=EC Org, C=US');
    });

    it('reports the cert as currently valid', () => {
        expect(cert.isValid).toBe(true);
    });
});

describe('decodeCert — ED25519 (unknown algorithm OID)', () => {
    const cert = decodeCert(ED25519_CERT_B64);

    it('returns the raw OID string for an unknown algorithm', () => {
        // ED25519 OID 1.3.101.112 is not in OID_SPKI — covers the !name fallback path
        expect(cert.keyAlgorithm).toBe('1.3.101.112');
    });

    it('still parses subject correctly', () => {
        expect(cert.subject).toBe('CN=ed test');
    });
});

describe('decodeCert — high serial number (0xC8, requires leading-zero strip)', () => {
    const cert = decodeCert(BIGSERIAL_CERT_B64);

    it('strips the DER leading 0x00 from the serial number', () => {
        // Serial 200 (0xC8) is DER-encoded as 00 c8; the parser strips the leading zero
        expect(cert.serialNumber).toBe('c8');
    });

    it('parses subject correctly', () => {
        expect(cert.subject).toBe('CN=big serial');
    });
});

describe('decodeCert — RSA key size parse fallback', () => {
    const cert = decodeCert(RSA_FALLBACK_CERT_B64);

    it('returns "RSA" when BIT STRING inner SEQUENCE has no children', () => {
        expect(cert.keyAlgorithm).toBe('RSA');
    });

    it('parses subject correctly', () => {
        expect(cert.subject).toBe('CN=rsa fallback');
    });
});

describe('decodeCert — GeneralizedTime (post-2049 dates)', () => {
    const cert = decodeCert(GENTIME_CERT_B64);

    it('parses notBefore from GeneralizedTime encoding', () => {
        expect(cert.validFrom.toISOString()).toBe('2050-01-01T00:00:00.000Z');
    });

    it('parses notAfter from GeneralizedTime encoding', () => {
        expect(cert.validTo.toISOString()).toBe('2060-01-01T00:00:00.000Z');
    });

    it('reports the cert as not yet valid', () => {
        expect(cert.isValid).toBe(false);
    });
});

describe('decodeCert — UTCTime year >= 50 (1900+y branch)', () => {
    const cert = decodeCert(UTCTIME_OLD_CERT_B64);

    it('parses 1986 from two-digit year 86', () => {
        expect(cert.validFrom.toISOString()).toBe('1986-01-01T00:00:00.000Z');
    });

    it('parses 1996 from two-digit year 96', () => {
        expect(cert.validTo.toISOString()).toBe('1996-01-01T00:00:00.000Z');
    });

    it('reports the cert as not valid (dates in the past)', () => {
        expect(cert.isValid).toBe(false);
    });

    it('parses subject correctly', () => {
        expect(cert.subject).toBe('CN=utctime old');
    });
});

describe('decodeCert — EC with no curve OID in AlgorithmIdentifier', () => {
    const cert = decodeCert(EC_NO_CURVE_CERT_B64);

    it('returns "EC " when algId has no curve parameter', () => {
        expect(cert.keyAlgorithm).toBe('EC ');
    });

    it('parses subject correctly', () => {
        expect(cert.subject).toBe('CN=ec no curve');
    });
});

describe('decodeCert — RSA modulus with no leading zero byte', () => {
    const cert = decodeCert(RSA_NO_ZERO_CERT_B64);

    it('computes key size without subtracting the leading-zero byte', () => {
        expect(cert.keyAlgorithm).toBe('RSA-8');
    });

    it('parses subject correctly', () => {
        expect(cert.subject).toBe('CN=rsa no zero');
    });
});

describe('decodeCert — DN attribute with unknown OID', () => {
    const cert = decodeCert(TITLE_ATTR_CERT_B64);

    it('falls back to raw OID string for unrecognized attribute type', () => {
        expect(cert.subject).toBe('2.5.4.12=CEO');
    });
});
