/**
 * PEM encoding for certificates and public keys (RFC 7468), plus conversion of
 * public JWKs (RFC 7517 / RFC 7518 / RFC 8037) to SubjectPublicKeyInfo
 * (RFC 5280). No external library, same as the DER parser in cert.ts.
 */

export type PemLabel = 'CERTIFICATE' | 'PUBLIC KEY';

/** Decode standard or base64url, ignoring whitespace and missing padding. */
export function base64ToBytes(b64: string): Uint8Array {
    let s = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (s.length % 4) s += '='.repeat(4 - (s.length % 4));
    const binary = atob(s);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
}

/** Wrap DER bytes (or a base64 DER string) in PEM armor, 64 columns per line. */
export function toPem(der: Uint8Array | string, label: PemLabel): string {
    const bytes = typeof der === 'string' ? base64ToBytes(der) : der;
    const body = bytesToBase64(bytes).match(/.{1,64}/g) ?? [];
    return [`-----BEGIN ${label}-----`, ...body, `-----END ${label}-----`, ''].join('\n');
}

/** Encode one DER tag-length-value with a minimal definite length. */
export function encodeTlv(tag: number, value: Uint8Array): Uint8Array {
    const len = value.length;
    let header: number[];
    if (len < 0x80) {
        header = [tag, len];
    } else {
        const lenBytes: number[] = [];
        for (let n = len; n > 0; n >>= 8) lenBytes.unshift(n & 0xff);
        header = [tag, 0x80 | lenBytes.length, ...lenBytes];
    }
    const out = new Uint8Array(header.length + len);
    out.set(header, 0);
    out.set(value, header.length);
    return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }
    return out;
}

const seq = (...items: Uint8Array[]) => encodeTlv(0x30, concat(...items));
const bitString = (bytes: Uint8Array) => encodeTlv(0x03, concat(Uint8Array.of(0), bytes));

/** Unsigned big-endian integer as a DER INTEGER: strip leading zeros, keep it positive. */
function derUint(bytes: Uint8Array): Uint8Array {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    const trimmed = bytes.slice(i);
    return encodeTlv(0x02, trimmed[0] & 0x80 ? concat(Uint8Array.of(0), trimmed) : trimmed);
}

/** Pre-encoded OBJECT IDENTIFIER TLVs. */
const OID = {
    rsaEncryption: Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01),
    ecPublicKey: Uint8Array.of(0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01),
    'P-256': Uint8Array.of(0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07),
    'P-384': Uint8Array.of(0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22),
    'P-521': Uint8Array.of(0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23),
    X25519: Uint8Array.of(0x06, 0x03, 0x2b, 0x65, 0x6e),
    X448: Uint8Array.of(0x06, 0x03, 0x2b, 0x65, 0x6f),
    Ed25519: Uint8Array.of(0x06, 0x03, 0x2b, 0x65, 0x70),
    Ed448: Uint8Array.of(0x06, 0x03, 0x2b, 0x65, 0x71)
} as const;

/** Coordinate length in bytes for each EC curve. */
const EC_COORD_LEN: Record<string, number> = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };

/** Public key length in bytes for each OKP curve. */
const OKP_KEY_LEN: Record<string, number> = { X25519: 32, X448: 56, Ed25519: 32, Ed448: 57 };

function member(jwk: Record<string, unknown>, name: string): Uint8Array {
    const v = jwk[name];
    if (typeof v !== 'string' || v === '') throw new Error(`JWK is missing "${name}"`);
    return base64ToBytes(v);
}

function curveOf(jwk: Record<string, unknown>, lengths: Record<string, number>): string {
    const crv = jwk.crv;
    if (typeof crv !== 'string' || !(crv in lengths)) {
        throw new Error(`Unsupported curve: ${typeof crv === 'string' ? crv : 'none'}`);
    }
    return crv;
}

/**
 * Convert a public JWK to DER SubjectPublicKeyInfo. Supports RSA, EC (P-256,
 * P-384, P-521) and OKP (Ed25519, Ed448, X25519, X448). Symmetric (`oct`) keys
 * have no public form and are rejected.
 */
export function jwkToSpki(jwk: Record<string, unknown>): Uint8Array {
    switch (jwk.kty) {
        case 'RSA': {
            const rsaKey = seq(derUint(member(jwk, 'n')), derUint(member(jwk, 'e')));
            return seq(seq(OID.rsaEncryption, Uint8Array.of(0x05, 0x00)), bitString(rsaKey));
        }
        case 'EC': {
            const crv = curveOf(jwk, EC_COORD_LEN);
            const x = member(jwk, 'x');
            const y = member(jwk, 'y');
            const len = EC_COORD_LEN[crv];
            if (x.length !== len || y.length !== len) {
                throw new Error(`EC ${crv} coordinates must be ${len} bytes`);
            }
            const point = concat(Uint8Array.of(0x04), x, y);
            return seq(seq(OID.ecPublicKey, OID[crv as keyof typeof OID]), bitString(point));
        }
        case 'OKP': {
            const crv = curveOf(jwk, OKP_KEY_LEN);
            const x = member(jwk, 'x');
            if (x.length !== OKP_KEY_LEN[crv]) {
                throw new Error(`${crv} public key must be ${OKP_KEY_LEN[crv]} bytes`);
            }
            return seq(seq(OID[crv as keyof typeof OID]), bitString(x));
        }
        case 'oct':
            throw new Error('Symmetric (oct) keys have no public key to export');
        default:
            throw new Error(
                `Unsupported key type: ${typeof jwk.kty === 'string' ? jwk.kty : 'none'}`
            );
    }
}

/** A public JWK as an SPKI `-----BEGIN PUBLIC KEY-----` PEM. */
export function jwkToPem(jwk: Record<string, unknown>): string {
    return toPem(jwkToSpki(jwk), 'PUBLIC KEY');
}
