import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import {
    algParams,
    keysFromJwks,
    keysFromX5c,
    parseKeyInput,
    selectKeys,
    verifyJwt,
    type CandidateKey
} from './jws';
import { toPem } from './pem';
import { TEST_CERT_B64 } from './fixtures.test-helper';

const b64u = (b: Uint8Array | string) => Buffer.from(b).toString('base64url');

type Pair = { publicKey: KeyObject; privateKey: KeyObject };

const rsa: Pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const p256: Pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const p384: Pair = generateKeyPairSync('ec', { namedCurve: 'P-384' });
const p521: Pair = generateKeyPairSync('ec', { namedCurve: 'P-521' });
const ed: Pair = generateKeyPairSync('ed25519');

const HASH: Record<string, string> = { '256': 'sha256', '384': 'sha384', '512': 'sha512' };

/** Sign a compact JWS the way an issuer would. */
function makeToken(
    alg: string,
    key: KeyObject,
    header: Record<string, unknown> = {},
    payload: Record<string, unknown> = { sub: 'u1' }
): string {
    const input = `${b64u(JSON.stringify({ alg, typ: 'JWT', ...header }))}.${b64u(JSON.stringify(payload))}`;
    const bits = alg.slice(2);
    let sig: Buffer;
    if (alg.startsWith('RS')) sig = sign(HASH[bits], Buffer.from(input), key);
    else if (alg.startsWith('PS'))
        sig = sign(HASH[bits], Buffer.from(input), {
            key,
            padding: 6, // RSA_PKCS1_PSS_PADDING
            saltLength: Number(bits) / 8
        });
    else if (alg.startsWith('ES'))
        sig = sign(HASH[bits], Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' });
    else sig = sign(null, Buffer.from(input), key);
    return `${input}.${b64u(sig)}`;
}

const jwkOf = (k: KeyObject, extra: Record<string, unknown> = {}) => ({
    ...(k.export({ format: 'jwk' }) as Record<string, unknown>),
    ...extra
});

const jwks = (...keys: Record<string, unknown>[]) => keysFromJwks(keys, 'jwks');

describe('algParams', () => {
    it('maps every supported alg', () => {
        for (const alg of [
            'RS256',
            'RS384',
            'RS512',
            'PS256',
            'PS384',
            'PS512',
            'ES256',
            'ES384',
            'ES512',
            'EdDSA',
            'Ed25519'
        ]) {
            expect(algParams(alg)).not.toBeNull();
        }
    });

    it('uses the hash length as the PSS salt length', () => {
        expect(algParams('PS384')?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 48 });
    });

    it('pins ES512 to P-521 and a 132-byte signature', () => {
        const p = algParams('ES512');
        expect(p?.importParams).toEqual({ name: 'ECDSA', namedCurve: 'P-521' });
        expect(p?.sigLen).toBe(132);
    });

    it('has nothing for HMAC, none or unknown algs', () => {
        expect(algParams('HS256')).toBeNull();
        expect(algParams('none')).toBeNull();
        expect(algParams('ES256K')).toBeNull();
    });
});

describe('verifyJwt', () => {
    const cases: [string, Pair][] = [
        ['RS256', rsa],
        ['RS384', rsa],
        ['RS512', rsa],
        ['PS256', rsa],
        ['PS384', rsa],
        ['PS512', rsa],
        ['ES256', p256],
        ['ES384', p384],
        ['ES512', p521],
        ['EdDSA', ed]
    ];

    it.each(cases)('verifies %s', async (alg, pair) => {
        const r = await verifyJwt(makeToken(alg, pair.privateKey), jwks(jwkOf(pair.publicKey)));
        expect(r.status).toBe('valid');
        expect(r.key?.index).toBe(0);
    });

    it('rejects a tampered payload', async () => {
        const [h, , s] = makeToken('RS256', rsa.privateKey).split('.');
        const forged = `${h}.${b64u(JSON.stringify({ sub: 'admin' }))}.${s}`;
        const r = await verifyJwt(forged, jwks(jwkOf(rsa.publicKey)));
        expect(r).toEqual({ status: 'invalid', detail: 'Signature does not match the key' });
    });

    it('rejects a signature from a different key and counts the keys tried', async () => {
        const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const token = makeToken('RS256', other.privateKey);
        const r = await verifyJwt(token, jwks(jwkOf(rsa.publicKey), jwkOf(rsa.publicKey)));
        expect(r.detail).toBe('Signature does not match any of 2 candidate keys');
    });

    it('selects the key by kid', async () => {
        const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const token = makeToken('ES256', p256.privateKey, { kid: 'b' });
        const r = await verifyJwt(
            token,
            jwks(jwkOf(other.publicKey, { kid: 'a' }), jwkOf(p256.publicKey, { kid: 'b' }))
        );
        expect(r.status).toBe('valid');
        expect(r.key?.kid).toBe('b');
        expect(r.key?.index).toBe(1);
    });

    it('reports a kid with no matching key', async () => {
        const token = makeToken('ES256', p256.privateKey, { kid: 'missing' });
        const r = await verifyJwt(token, jwks(jwkOf(p256.publicKey, { kid: 'a' })));
        expect(r).toEqual({ status: 'no-key', detail: 'No signing key with kid "missing"' });
    });

    it('tries every key when the JWKS carries no kids', async () => {
        const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const token = makeToken('ES256', p256.privateKey, { kid: 'x' });
        const r = await verifyJwt(token, jwks(jwkOf(other.publicKey), jwkOf(p256.publicKey)));
        expect(r.status).toBe('valid');
        expect(r.key?.index).toBe(1);
    });

    it('reports no key when nothing is left to try', async () => {
        const r = await verifyJwt(makeToken('RS256', rsa.privateKey), []);
        expect(r).toEqual({ status: 'no-key', detail: 'No signing key for RS256' });
    });

    it('reports no key when no candidate fits the alg', async () => {
        const r = await verifyJwt(makeToken('ES256', p256.privateKey), jwks(jwkOf(rsa.publicKey)));
        expect(r).toEqual({
            status: 'no-key',
            detail: 'None of the candidate keys can verify ES256'
        });
    });

    it('rejects an ECDSA signature of the wrong length', async () => {
        const token = makeToken('ES256', p256.privateKey).replace(
            /\.[^.]+$/,
            `.${b64u(new Uint8Array(70))}`
        );
        const r = await verifyJwt(token, jwks(jwkOf(p256.publicKey)));
        expect(r).toEqual({
            status: 'invalid',
            detail: 'ES256 signatures are 64 bytes; this one is 70'
        });
    });

    it('rejects a signature that is not base64url', async () => {
        const token = makeToken('RS256', rsa.privateKey).replace(/\.[^.]+$/, '.***');
        const r = await verifyJwt(token, jwks(jwkOf(rsa.publicKey)));
        expect(r).toEqual({ status: 'invalid', detail: 'Signature is not valid base64url' });
    });

    it('says HMAC tokens need the shared secret', async () => {
        const token = `${b64u(JSON.stringify({ alg: 'HS256' }))}.${b64u('{}')}.c2ln`;
        const r = await verifyJwt(token, jwks(jwkOf(rsa.publicKey)));
        expect(r).toEqual({
            status: 'unsupported',
            detail: 'HS256 is verified with a shared secret, not a public key'
        });
    });

    it('reports alg none as unsigned', async () => {
        const token = `${b64u(JSON.stringify({ alg: 'none' }))}.${b64u('{}')}.`;
        expect((await verifyJwt(token, [])).status).toBe('unsigned');
    });

    it('reports unknown and missing algs as unsupported', async () => {
        const unknown = `${b64u(JSON.stringify({ alg: 'ES256K' }))}.${b64u('{}')}.c2ln`;
        expect((await verifyJwt(unknown, [])).detail).toBe('Unsupported algorithm: ES256K');
        const missing = `${b64u(JSON.stringify({ typ: 'JWT' }))}.${b64u('{}')}.c2ln`;
        expect((await verifyJwt(missing, [])).detail).toBe('Unsupported algorithm: none given');
    });

    it('rejects input that is not a compact JWS', async () => {
        expect(await verifyJwt('a.b', [])).toEqual({
            status: 'invalid',
            detail: 'Not a compact JWS'
        });
    });

    it('rejects a header that is not JSON', async () => {
        expect(await verifyJwt(`${b64u('not json')}.e30.c2ln`, [])).toEqual({
            status: 'invalid',
            detail: 'Header is not valid JSON'
        });
    });
});

describe('selectKeys', () => {
    const base = (extra: Partial<CandidateKey>): CandidateKey => ({
        spki: new Uint8Array(),
        source: 'jwks',
        index: 0,
        ...extra
    });

    it('never tries encryption keys', () => {
        expect(
            selectKeys({ alg: 'RS256' }, [base({ use: 'enc' }), base({ use: 'sig', index: 1 })])
        ).toEqual([base({ use: 'sig', index: 1 })]);
    });

    it('skips keys pinned to another alg', () => {
        expect(
            selectKeys({ alg: 'RS256' }, [base({ alg: 'PS256' }), base({ alg: 'RS256', index: 1 })])
        ).toEqual([base({ alg: 'RS256', index: 1 })]);
    });

    it('keeps every usable key when the header has no kid', () => {
        expect(
            selectKeys({ alg: 'RS256' }, [base({ kid: 'a' }), base({ kid: 'b', index: 1 })])
        ).toHaveLength(2);
    });
});

describe('keysFromJwks', () => {
    it('skips entries with no public form and records positions', () => {
        const keys = keysFromJwks(
            [
                null,
                'x',
                { kty: 'oct', k: 'c2VjcmV0' },
                jwkOf(p256.publicKey, { kid: 'k', use: 'sig', alg: 'ES256' })
            ],
            'jwks'
        );
        expect(keys).toHaveLength(1);
        expect(keys[0]).toMatchObject({
            index: 3,
            kid: 'k',
            use: 'sig',
            alg: 'ES256',
            source: 'jwks'
        });
        expect(keys[0].jwk?.kid).toBe('k');
    });

    it('ignores non-string metadata', () => {
        const [key] = keysFromJwks([jwkOf(p256.publicKey, { kid: 7 })], 'jwks');
        expect(key.kid).toBeUndefined();
    });
});

describe('keysFromX5c', () => {
    it('takes the leaf certificate key', () => {
        const [key] = keysFromX5c({ x5c: [TEST_CERT_B64, 'ignored'] });
        expect(key).toMatchObject({ source: 'x5c', index: 0 });
        expect(key.spki.length).toBeGreaterThan(200);
    });

    it('returns nothing without a usable x5c', () => {
        expect(keysFromX5c({})).toEqual([]);
        expect(keysFromX5c({ x5c: [42] })).toEqual([]);
        expect(keysFromX5c({ x5c: ['AAAA'] })).toEqual([]);
    });

    it('verifies a token against its own x5c certificate', async () => {
        // the fixture certificate has no private key here, so a foreign signature must fail
        const token = makeToken('RS256', rsa.privateKey, { x5c: [TEST_CERT_B64] });
        const r = await verifyJwt(token, keysFromX5c({ x5c: [TEST_CERT_B64] }));
        expect(r.status).toBe('invalid');
    });
});

describe('parseKeyInput', () => {
    it('reads a JWKS', () => {
        const text = JSON.stringify({
            keys: [jwkOf(rsa.publicKey, { kid: 'a' }), jwkOf(p256.publicKey)]
        });
        const keys = parseKeyInput(text);
        expect(keys.map((k) => [k.source, k.index, k.kid])).toEqual([
            ['pasted', 0, 'a'],
            ['pasted', 1, undefined]
        ]);
    });

    it('reads a single JWK', async () => {
        const keys = parseKeyInput(JSON.stringify(jwkOf(ed.publicKey)));
        expect((await verifyJwt(makeToken('EdDSA', ed.privateKey), keys)).status).toBe('valid');
    });

    it('reads a PUBLIC KEY PEM', async () => {
        const pem = rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string;
        const keys = parseKeyInput(`  ${pem}  `);
        expect((await verifyJwt(makeToken('PS256', rsa.privateKey), keys)).status).toBe('valid');
    });

    it('reads a CERTIFICATE PEM', () => {
        const [key] = parseKeyInput(toPem(TEST_CERT_B64, 'CERTIFICATE'));
        expect(key.source).toBe('pasted');
        expect(key.spki.length).toBeGreaterThan(200);
    });

    it('explains what it accepts', () => {
        expect(() => parseKeyInput('hello')).toThrow(
            'Paste a JWK, a JWKS, or a PUBLIC KEY or CERTIFICATE PEM'
        );
    });

    it('rejects broken JSON', () => {
        expect(() => parseKeyInput('{ nope')).toThrow('Not valid JSON');
    });

    it('rejects JSON with no public key', () => {
        expect(() => parseKeyInput(JSON.stringify({ kty: 'oct', k: 'c2VjcmV0' }))).toThrow(
            'No usable public key'
        );
    });

    it('rejects an unreadable certificate or key', () => {
        expect(() =>
            parseKeyInput('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----')
        ).toThrow('Could not read the certificate');
        expect(() =>
            parseKeyInput('-----BEGIN PUBLIC KEY-----\n***\n-----END PUBLIC KEY-----')
        ).toThrow('Could not read the public key');
    });
});
