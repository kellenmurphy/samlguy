/**
 * HTTP-Redirect binding signature verification (SAML 2.0 Bindings §3.4.4.1).
 *
 * The signature covers the octets "SAMLRequest=value&RelayState=value&SigAlg=value"
 * (or SAMLResponse), built from the parameters exactly as URL-encoded in the
 * received query string. Decoding and re-encoding them would change the bytes,
 * so the raw query is split on "&" and never normalised.
 */
import { base64ToBytes } from './pem.js';
import { certPublicKeySpki } from './cert.js';
import { isMetadata, parseMetadata } from './metadata.js';
import { parseKeyInput } from './jws.js';

export const SIGALG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

interface SigAlgParams {
    label: string;
    importParams: RsaHashedImportParams | EcKeyImportParams;
    verifyParams: Algorithm | EcdsaParams;
    deprecated?: boolean;
}

const MORE = 'http://www.w3.org/2001/04/xmldsig-more#';

/** SigAlg URIs (RFC 6931 / XML Signature 1.1) that WebCrypto can verify. */
export const SIG_ALGS: Record<string, SigAlgParams> = {
    [SIGALG_RSA_SHA1]: {
        label: 'RSA-SHA1',
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
        deprecated: true
    },
    ...Object.fromEntries(
        (['256', '384', '512'] as const).flatMap((bits) => [
            [
                `${MORE}rsa-sha${bits}`,
                {
                    label: `RSA-SHA${bits}`,
                    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` },
                    verifyParams: { name: 'RSASSA-PKCS1-v1_5' }
                }
            ],
            [
                `${MORE}ecdsa-sha${bits}`,
                {
                    label: `ECDSA-SHA${bits}`,
                    // the curve comes from the key; set per key at import time
                    importParams: { name: 'ECDSA', namedCurve: '' },
                    verifyParams: { name: 'ECDSA', hash: `SHA-${bits}` }
                }
            ]
        ])
    )
};

export interface SignedRedirect {
    /** The exact octets the signature covers. */
    signedOctets: Uint8Array;
    /** The SigAlg URI, URL-decoded. */
    sigAlg: string;
    /** The signature bytes. */
    signature: Uint8Array;
}

/** Split a raw query into name and still-encoded value, first occurrence wins. */
function rawParams(query: string): Map<string, string> {
    const params = new Map<string, string>();
    for (const part of query.replace(/^\?/, '').split('&')) {
        const eq = part.indexOf('=');
        const name = eq === -1 ? part : part.slice(0, eq);
        if (!params.has(name)) params.set(name, eq === -1 ? '' : part.slice(eq + 1));
    }
    return params;
}

/**
 * Percent-decode a parameter. A literal "+" is kept rather than read as a
 * space: neither base64 nor a SigAlg URI contains spaces, and a sender that
 * failed to encode a base64 "+" still meant a "+".
 */
function pctDecode(v: string): string {
    return decodeURIComponent(v);
}

/**
 * Extract what an HTTP-Redirect signature covers from a raw query string, or
 * null when the query carries no Signature. Throws on a signature that is
 * present but unusable.
 */
export function parseSignedRedirect(query: string): SignedRedirect | null {
    const p = rawParams(query);
    const sig = p.get('Signature');
    if (sig === undefined) return null;
    const sigAlg = p.get('SigAlg');
    if (sigAlg === undefined) throw new Error('Signature is present but SigAlg is missing');

    const msgName = p.has('SAMLRequest')
        ? 'SAMLRequest'
        : p.has('SAMLResponse')
          ? 'SAMLResponse'
          : null;
    if (!msgName) throw new Error('No SAMLRequest or SAMLResponse in the query');

    // Bindings §3.4.4.1: message, then RelayState if present, then SigAlg
    const parts = [`${msgName}=${p.get(msgName)}`];
    if (p.has('RelayState')) parts.push(`RelayState=${p.get('RelayState')}`);
    parts.push(`SigAlg=${sigAlg}`);

    let signature: Uint8Array;
    try {
        signature = base64ToBytes(pctDecode(sig));
    } catch {
        throw new Error('Signature is not valid base64');
    }
    return {
        signedOctets: new TextEncoder().encode(parts.join('&')),
        sigAlg: pctDecode(sigAlg),
        signature
    };
}

/** A verification key, with where it came from for the UI. */
export interface RedirectKey {
    spki: Uint8Array;
    label: string;
}

/**
 * Read verification keys from pasted text: SP metadata (its signing
 * KeyDescriptors, or ones with no use), a CERTIFICATE or PUBLIC KEY PEM, or a
 * bare base64 certificate as found inside ds:X509Certificate.
 */
export function parseRedirectKeys(text: string): RedirectKey[] {
    const trimmed = text.trim();
    if (isMetadata(trimmed)) {
        const { entity } = parseMetadata(trimmed);
        const sp = entity.roles.filter((r) => r.kind === 'sp');
        if (sp.length === 0)
            throw new Error('The metadata has no SPSSODescriptor; paste the SP metadata');
        const keys: RedirectKey[] = [];
        for (const role of sp) {
            role.keys.forEach((k, i) => {
                if (k.use === 'encryption') return;
                try {
                    keys.push({
                        spki: certPublicKeySpki(k.certificate),
                        label: `SP metadata certificate ${i + 1}`
                    });
                } catch {
                    // an unreadable certificate cannot verify anything
                }
            });
        }
        if (keys.length === 0) throw new Error('The SP metadata has no usable signing certificate');
        return keys;
    }
    if (/^[A-Za-z0-9+/=\s]+$/.test(trimmed) && trimmed.length > 100) {
        try {
            return [{ spki: certPublicKeySpki(trimmed), label: 'pasted certificate' }];
        } catch {
            throw new Error('Could not read the base64 certificate');
        }
    }
    let parsed;
    try {
        parsed = parseKeyInput(trimmed);
    } catch {
        throw new Error(
            'Paste the SP metadata, a CERTIFICATE or PUBLIC KEY PEM, or a base64 certificate'
        );
    }
    return parsed.map((k) => ({ spki: k.spki, label: 'pasted key' }));
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** OBJECT IDENTIFIER value bytes (hex) to curve name. */
const CURVE_OIDS: Record<string, string> = {
    '2a8648ce3d030107': 'P-256',
    '2b81040022': 'P-384',
    '2b81040023': 'P-521'
};
const EC_PUBLIC_KEY_OID = '2a8648ce3d0201';

/** Skip a DER tag and length; returns the offset of the value and its length. */
function header(b: Uint8Array, o: number): { value: number; len: number } {
    const first = b[o + 1];
    if (!(first & 0x80)) return { value: o + 2, len: first };
    const n = first & 0x7f;
    let len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[o + 2 + i];
    return { value: o + 2 + n, len };
}

/**
 * The named curve of an EC SubjectPublicKeyInfo, or null for any other key:
 * SEQUENCE { SEQUENCE { OID ecPublicKey, OID curve }, BIT STRING }.
 */
export function ecCurve(spki: Uint8Array): string | null {
    // reads past the end yield undefined rather than throwing, and fail the tag checks
    const outer = header(spki, 0);
    const algId = header(spki, outer.value);
    if (spki[algId.value] !== 0x06) return null;
    const alg = header(spki, algId.value);
    if (hex(spki.slice(alg.value, alg.value + alg.len)) !== EC_PUBLIC_KEY_OID) return null;
    const curveAt = alg.value + alg.len;
    if (spki[curveAt] !== 0x06) return null;
    const curve = header(spki, curveAt);
    return CURVE_OIDS[hex(spki.slice(curve.value, curve.value + curve.len))] ?? null;
}

const CURVE_LEN: Record<string, number> = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };

/**
 * XML Signature specifies ECDSA values as r || s, but some implementations
 * send the DER SEQUENCE { r, s } instead; accept either.
 */
export function ecdsaRaw(sig: Uint8Array, curve: string): Uint8Array {
    const n = CURVE_LEN[curve];
    if (sig.length === 2 * n || sig[0] !== 0x30) return sig;
    try {
        let o = 2;
        if (sig[1] & 0x80) o += sig[1] & 0x7f;
        const read = () => {
            if (sig[o] !== 0x02) throw new Error('not an INTEGER');
            const len = sig[o + 1];
            const v = sig.slice(o + 2, o + 2 + len);
            o += 2 + len;
            const trimmed = v[0] === 0 ? v.slice(1) : v;
            if (trimmed.length > n) throw new Error('integer too long');
            const out = new Uint8Array(n);
            out.set(trimmed, n - trimmed.length);
            return out;
        };
        const r = read();
        const s = read();
        const raw = new Uint8Array(2 * n);
        raw.set(r, 0);
        raw.set(s, n);
        return raw;
    } catch {
        return sig;
    }
}

export type RedirectVerifyStatus = 'valid' | 'invalid' | 'no-key' | 'unsupported';

export interface RedirectVerifyResult {
    status: RedirectVerifyStatus;
    detail: string;
    algorithm?: string;
    key?: RedirectKey;
}

/** Verify an HTTP-Redirect signature against the given keys. Never throws. */
export async function verifyRedirect(
    signed: SignedRedirect,
    keys: RedirectKey[]
): Promise<RedirectVerifyResult> {
    const alg = SIG_ALGS[signed.sigAlg];
    if (!alg) return { status: 'unsupported', detail: `Unsupported SigAlg: ${signed.sigAlg}` };
    const note = alg.deprecated ? ' (SHA-1 is deprecated; the SP should move to RSA-SHA256)' : '';

    let tried = 0;
    for (const key of keys) {
        let importParams = alg.importParams;
        let sig = signed.signature;
        if (importParams.name === 'ECDSA') {
            const curve = ecCurve(key.spki);
            if (!curve) continue;
            importParams = { name: 'ECDSA', namedCurve: curve };
            sig = ecdsaRaw(sig, curve);
        }
        let cryptoKey: CryptoKey;
        try {
            cryptoKey = await crypto.subtle.importKey(
                'spki',
                key.spki as Uint8Array<ArrayBuffer>,
                importParams,
                false,
                ['verify']
            );
        } catch {
            continue;
        }
        tried++;
        let ok: boolean;
        try {
            ok = await crypto.subtle.verify(
                alg.verifyParams,
                cryptoKey,
                sig as Uint8Array<ArrayBuffer>,
                signed.signedOctets as Uint8Array<ArrayBuffer>
            );
        } catch {
            // some platforms refuse SHA-1 signatures outright; that is not a match
            ok = false;
        }
        if (ok) {
            return {
                status: 'valid',
                detail: `Signature verified${note}`,
                algorithm: alg.label,
                key
            };
        }
    }

    if (tried === 0) {
        return {
            status: 'no-key',
            detail: `None of the keys can verify ${alg.label}`,
            algorithm: alg.label
        };
    }
    return {
        status: 'invalid',
        detail:
            (tried === 1
                ? 'Signature does not match the key'
                : `Signature does not match any of ${tried} keys`) + note,
        algorithm: alg.label
    };
}
