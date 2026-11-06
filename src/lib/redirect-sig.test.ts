import { describe, it, expect, vi } from 'vitest';
import {
    constants,
    createHash,
    generateKeyPairSync,
    privateEncrypt,
    sign,
    verify as verifySig,
    type KeyObject
} from 'node:crypto';
import { deflateRaw } from 'pako';
import {
    ecCurve,
    ecdsaRaw,
    parseRedirectKeys,
    parseSignedRedirect,
    SIGALG_RSA_SHA1,
    verifyRedirect,
    type RedirectKey
} from './redirect-sig';
import { encodeTlv, toPem } from './pem';
import { decodeSaml } from './saml';
import { TEST_CERT_B64 } from './fixtures.test-helper';

const MORE = 'http://www.w3.org/2001/04/xmldsig-more#';
const REQ = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2026-11-06T20:00:00Z"><saml:Issuer>https://sp.example.org/shibboleth</saml:Issuer></samlp:AuthnRequest>`;
const VALUE = Buffer.from(deflateRaw(new TextEncoder().encode(REQ))).toString('base64');

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const p256 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });
const p521 = generateKeyPairSync('ec', { namedCurve: 'P-521' });
const ed = generateKeyPairSync('ed25519');

const spkiOf = (k: KeyObject) => new Uint8Array(k.export({ type: 'spki', format: 'der' }));
const keyOf = (k: KeyObject, label = 'k'): RedirectKey => ({ spki: spkiOf(k), label });

/** A certificate-shaped DER around a public key; the outer signature is never checked. */
function fakeCertB64(pub: KeyObject): string {
    const seq = (...p: Uint8Array[]) => encodeTlv(0x30, Buffer.concat(p));
    const time = encodeTlv(0x17, new TextEncoder().encode('260101000000Z'));
    const tbs = seq(
        encodeTlv(0xa0, encodeTlv(0x02, Uint8Array.of(2))),
        encodeTlv(0x02, Uint8Array.of(1)),
        seq(encodeTlv(0x06, Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b))),
        seq(),
        seq(time, time),
        seq(),
        spkiOf(pub)
    );
    return Buffer.from(seq(tbs, seq(), encodeTlv(0x03, Uint8Array.of(0)))).toString('base64');
}

/**
 * Sign a redirect query the way an SP does. `enc` URL-encodes each value; the
 * signature covers exactly that encoding.
 */
function signedQuery(
    sigAlg: string,
    key: KeyObject,
    opts: {
        relayState?: string;
        hash?: string | null;
        der?: boolean;
        enc?: (s: string) => string;
        param?: string;
    } = {}
): string {
    const enc = opts.enc ?? encodeURIComponent;
    const parts = [`${opts.param ?? 'SAMLRequest'}=${enc(VALUE)}`];
    if (opts.relayState !== undefined) parts.push(`RelayState=${enc(opts.relayState)}`);
    parts.push(`SigAlg=${enc(sigAlg)}`);
    const octets = Buffer.from(parts.join('&'));
    const hash = opts.hash === undefined ? 'sha256' : opts.hash;
    const sig =
        key.asymmetricKeyType === 'ec'
            ? sign(hash, octets, { key, dsaEncoding: opts.der ? 'der' : 'ieee-p1363' })
            : sign(hash, octets, key);
    return `${parts.join('&')}&Signature=${enc(sig.toString('base64'))}`;
}

const verify = async (query: string, keys: RedirectKey[]) =>
    verifyRedirect(parseSignedRedirect(query)!, keys);

describe('parseSignedRedirect', () => {
    it('returns null for an unsigned query', () => {
        expect(parseSignedRedirect(`SAMLRequest=${encodeURIComponent(VALUE)}`)).toBeNull();
    });

    it('builds the signed octets from the raw parameters, ignoring others and order', () => {
        const q = `foo=1&SigAlg=a%3Ab&RelayState=r%2Fs&SAMLRequest=v%2B1&Signature=AAEC&SigAlg=ignored`;
        const s = parseSignedRedirect(`?${q}`)!;
        expect(new TextDecoder().decode(s.signedOctets)).toBe(
            'SAMLRequest=v%2B1&RelayState=r%2Fs&SigAlg=a%3Ab'
        );
        expect(s.sigAlg).toBe('a:b');
        expect(Array.from(s.signature)).toEqual([0, 1, 2]);
    });

    it('omits RelayState when absent and handles SAMLResponse and valueless params', () => {
        const s = parseSignedRedirect('SAMLResponse=v&SigAlg=x&Signature=AA%3D%3D&flag')!;
        expect(new TextDecoder().decode(s.signedOctets)).toBe('SAMLResponse=v&SigAlg=x');
    });

    it('keeps a literal + in the Signature as base64, not a space', () => {
        const s = parseSignedRedirect('SAMLRequest=v&SigAlg=x&Signature=AA+B')!;
        expect(Array.from(s.signature)).toEqual([0x00, 0x0f, 0x81]);
    });

    it('refuses a Signature that is not base64', () => {
        expect(() => parseSignedRedirect('SAMLRequest=v&SigAlg=x&Signature=%2A%2A%2A')).toThrow(
            'not valid base64'
        );
    });

    it('refuses a signature without SigAlg or without a message', () => {
        expect(() => parseSignedRedirect('SAMLRequest=v&Signature=AA')).toThrow(
            'SigAlg is missing'
        );
        expect(() => parseSignedRedirect('SigAlg=x&Signature=AA')).toThrow(
            'No SAMLRequest or SAMLResponse'
        );
    });
});

describe('verifyRedirect', () => {
    it.each(['256', '384', '512'])('verifies RSA-SHA%s', async (bits) => {
        const q = signedQuery(`${MORE}rsa-sha${bits}`, rsa.privateKey, {
            relayState: 'ss:mem:1',
            hash: `sha${bits}`
        });
        expect(await verify(q, [keyOf(rsa.publicKey)])).toMatchObject({
            status: 'valid',
            detail: 'Signature verified',
            algorithm: `RSA-SHA${bits}`
        });
    });

    it.each([
        ['256', p256],
        ['384', p384],
        ['512', p521]
    ] as const)('verifies ECDSA-SHA%s with r||s and with DER', async (bits, pair) => {
        for (const der of [false, true]) {
            const q = signedQuery(`${MORE}ecdsa-sha${bits}`, pair.privateKey, {
                hash: `sha${bits}`,
                der
            });
            expect((await verify(q, [keyOf(pair.publicKey)])).status).toBe('valid');
        }
    });

    it('flags RSA-SHA1 as deprecated, verifying it where the platform allows SHA-1', async () => {
        // Some platforms (Fedora's default crypto policy) refuse SHA-1 signatures, so build the
        // PKCS#1 v1.5 signature by hand: raw RSA over the SHA-1 DigestInfo.
        const parts = [
            `SAMLRequest=${encodeURIComponent(VALUE)}`,
            `SigAlg=${encodeURIComponent(SIGALG_RSA_SHA1)}`
        ];
        const digestInfo = Buffer.concat([
            Buffer.from('3021300906052b0e03021a05000414', 'hex'),
            createHash('sha1').update(parts.join('&')).digest()
        ]);
        const sig = privateEncrypt(
            { key: rsa.privateKey, padding: constants.RSA_PKCS1_PADDING },
            digestInfo
        );
        const q = `${parts.join('&')}&Signature=${encodeURIComponent(sig.toString('base64'))}`;
        let sha1Ok = true;
        try {
            verifySig('sha1', Buffer.from(parts.join('&')), rsa.publicKey, sig);
        } catch {
            sha1Ok = false;
        }
        const r = await verify(q, [keyOf(rsa.publicKey)]);
        expect(r.status).toBe(sha1Ok ? 'valid' : 'invalid');
        expect(r.detail).toContain('SHA-1 is deprecated');
    });

    it('treats a verify the platform refuses as no match', async () => {
        const spy = vi.spyOn(crypto.subtle, 'verify').mockRejectedValueOnce(new Error('refused'));
        const q = signedQuery(`${MORE}rsa-sha256`, rsa.privateKey);
        expect((await verify(q, [keyOf(rsa.publicKey)])).status).toBe('invalid');
        spy.mockRestore();
    });

    it('uses the encoding as received, not a normalised one', async () => {
        // lowercase percent-escapes are equally valid URL-encoding; the signer signed these bytes
        const lower = (s: string) =>
            encodeURIComponent(s).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());
        const q = signedQuery(`${MORE}rsa-sha256`, rsa.privateKey, {
            relayState: 'a/b',
            enc: lower
        });
        expect((await verify(q, [keyOf(rsa.publicKey)])).status).toBe('valid');
        // the same parameters re-encoded in uppercase no longer match
        const upper = q.replace(/%[0-9a-f]{2}/g, (m) => m.toUpperCase());
        expect((await verify(upper, [keyOf(rsa.publicKey)])).status).toBe('invalid');
    });

    it('rejects a tampered RelayState', async () => {
        const q = signedQuery(`${MORE}rsa-sha256`, rsa.privateKey, { relayState: 'good' });
        expect(
            await verify(q.replace('RelayState=good', 'RelayState=evil'), [keyOf(rsa.publicKey)])
        ).toEqual({
            status: 'invalid',
            detail: 'Signature does not match the key',
            algorithm: 'RSA-SHA256'
        });
    });

    it('tries every key and reports the one that verified', async () => {
        const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const q = signedQuery(`${MORE}rsa-sha256`, rsa.privateKey);
        const r = await verify(q, [keyOf(other.publicKey, 'old'), keyOf(rsa.publicKey, 'new')]);
        expect(r.key?.label).toBe('new');
        const miss = await verify(q, [keyOf(other.publicKey), keyOf(other.publicKey)]);
        expect(miss.detail).toBe('Signature does not match any of 2 keys');
    });

    it('reports no usable key for the algorithm', async () => {
        const q = signedQuery(`${MORE}ecdsa-sha256`, p256.privateKey);
        expect((await verify(q, [keyOf(rsa.publicKey), keyOf(ed.publicKey)])).status).toBe(
            'no-key'
        );
        const r = signedQuery(`${MORE}rsa-sha256`, rsa.privateKey);
        expect(await verify(r, [keyOf(p256.publicKey)])).toEqual({
            status: 'no-key',
            detail: 'None of the keys can verify RSA-SHA256',
            algorithm: 'RSA-SHA256'
        });
    });

    it('reports an unsupported SigAlg', async () => {
        const q = `SAMLRequest=v&SigAlg=${encodeURIComponent('http://www.w3.org/2000/09/xmldsig#dsa-sha1')}&Signature=AA%3D%3D`;
        expect((await verify(q, [])).status).toBe('unsupported');
    });
});

describe('ecCurve', () => {
    it('names each supported curve and nothing else', () => {
        expect(ecCurve(spkiOf(p256.publicKey))).toBe('P-256');
        expect(ecCurve(spkiOf(p384.publicKey))).toBe('P-384');
        expect(ecCurve(spkiOf(p521.publicKey))).toBe('P-521');
        expect(ecCurve(spkiOf(rsa.publicKey))).toBeNull();
        expect(ecCurve(spkiOf(ed.publicKey))).toBeNull();
        expect(
            ecCurve(spkiOf(generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).publicKey))
        ).toBeNull();
    });

    it('returns null for truncated or odd input', () => {
        expect(ecCurve(new Uint8Array())).toBeNull();
        // ecPublicKey with no curve OID following
        expect(
            ecCurve(
                Uint8Array.of(
                    0x30,
                    0x0b,
                    0x30,
                    0x09,
                    0x06,
                    0x07,
                    0x2a,
                    0x86,
                    0x48,
                    0xce,
                    0x3d,
                    0x02,
                    0x01
                )
            )
        ).toBeNull();
        // AlgorithmIdentifier starting with something other than an OID
        expect(ecCurve(Uint8Array.of(0x30, 0x04, 0x30, 0x02, 0x05, 0x00))).toBeNull();
        // a long-form length
        const long = Uint8Array.of(
            0x30,
            0x81,
            0x0b,
            0x30,
            0x09,
            0x06,
            0x07,
            0x2a,
            0x86,
            0x48,
            0xce,
            0x3d,
            0x02,
            0x01
        );
        expect(ecCurve(long)).toBeNull();
    });
});

describe('ecdsaRaw', () => {
    it('leaves r||s and malformed DER alone', () => {
        const raw = new Uint8Array(64).fill(1);
        expect(ecdsaRaw(raw, 'P-256')).toBe(raw);
        const bad = Uint8Array.of(0x30, 0x04, 0x05, 0x00, 0x05, 0x00);
        expect(ecdsaRaw(bad, 'P-256')).toBe(bad);
        const tooLong = Uint8Array.of(0x30, 0x25, 0x02, 0x21, ...new Uint8Array(33).fill(1));
        expect(ecdsaRaw(tooLong, 'P-256')).toBe(tooLong);
    });

    it('reads a DER signature with a long-form length', () => {
        const r = new Uint8Array(66).fill(2);
        const s = new Uint8Array(66).fill(3);
        const der = encodeTlv(0x30, Buffer.concat([encodeTlv(0x02, r), encodeTlv(0x02, s)]));
        expect(der[1]).toBe(0x81);
        const out = ecdsaRaw(der, 'P-521');
        expect(out.slice(0, 66)).toEqual(r);
        expect(out.slice(66)).toEqual(s);
    });
});

describe('parseRedirectKeys', () => {
    const spMeta = (keys: string) =>
        `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sp.example.org/shibboleth"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keys}<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs" index="1"/></md:SPSSODescriptor></md:EntityDescriptor>`;
    const kd = (b64: string, use?: string) =>
        `<md:KeyDescriptor${use ? ` use="${use}"` : ''}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;

    it('takes signing and unlabelled keys from SP metadata, skipping encryption keys', async () => {
        const enc = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const keys = parseRedirectKeys(
            spMeta(
                kd(fakeCertB64(enc.publicKey), 'encryption') +
                    kd(fakeCertB64(rsa.publicKey), 'signing') +
                    kd(fakeCertB64(p256.publicKey))
            )
        );
        expect(keys.map((k) => k.label)).toEqual([
            'SP metadata certificate 2',
            'SP metadata certificate 3'
        ]);
        const q = signedQuery(`${MORE}rsa-sha256`, rsa.privateKey);
        expect((await verify(q, keys)).key?.label).toBe('SP metadata certificate 2');
    });

    it('skips unreadable certificates and says when nothing is left', () => {
        expect(() => parseRedirectKeys(spMeta(kd('AAAA', 'signing')))).toThrow(
            'no usable signing certificate'
        );
    });

    it('asks for SP metadata when given IdP metadata', () => {
        const idp = spMeta('').replace(/SPSSODescriptor/g, 'IDPSSODescriptor');
        expect(() => parseRedirectKeys(idp)).toThrow('no SPSSODescriptor');
    });

    it('reads certificate and public key PEMs and a bare base64 certificate', async () => {
        const q = signedQuery(`${MORE}rsa-sha256`, rsa.privateKey);
        const b64 = fakeCertB64(rsa.publicKey);
        for (const text of [
            toPem(b64, 'CERTIFICATE'),
            rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string,
            b64
        ]) {
            expect((await verify(q, parseRedirectKeys(text))).status).toBe('valid');
        }
        expect(parseRedirectKeys(` ${TEST_CERT_B64} `)[0].label).toBe('pasted certificate');
    });

    it('explains what it accepts', () => {
        expect(() => parseRedirectKeys('hello')).toThrow('Paste the SP metadata');
        expect(() => parseRedirectKeys('A'.repeat(120))).toThrow(
            'Could not read the base64 certificate'
        );
    });
});

describe('decodeSaml keeps the raw query', () => {
    it('keeps the encoding exactly as received', () => {
        const q = signedQuery(`${MORE}rsa-sha256`, rsa.privateKey, { relayState: 'x/y' });
        const r = decodeSaml(`https://idp.example.org/sso?${q}`);
        expect(r.source.query).toBe(q);
        expect(r.source.redirectSigned).toBe(true);
    });
});
