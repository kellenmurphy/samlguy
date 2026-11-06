/**
 * JWS signature verification (RFC 7515 / RFC 7518) in the browser with
 * WebCrypto. Keys come from a JWKS, a pasted JWK / JWKS / PEM, or the token's
 * own x5c header; every key is normalised to SubjectPublicKeyInfo first, so a
 * JWK, a PEM public key and a certificate are all imported the same way.
 */
import { base64ToBytes, jwkToSpki } from './pem.js';
import { certPublicKeySpki } from './cert.js';

export type KeySource = 'jwks' | 'pasted' | 'x5c';

/** A public key ready to try against a token, with the JWK metadata that narrows the choice. */
export interface CandidateKey {
    spki: Uint8Array;
    source: KeySource;
    /** Position in the JWKS or chain, for pointing at the key in the UI. */
    index: number;
    kid?: string;
    alg?: string;
    use?: string;
    /** The JWK this key came from, when it came from one. */
    jwk?: Record<string, unknown>;
}

export type VerifyStatus = 'valid' | 'invalid' | 'no-key' | 'unsupported' | 'unsigned';

export interface VerifyResult {
    status: VerifyStatus;
    detail: string;
    /** The key that verified the signature, when one did. */
    key?: CandidateKey;
}

interface AlgParams {
    importParams: RsaHashedImportParams | EcKeyImportParams | Algorithm;
    verifyParams: Algorithm | RsaPssParams | EcdsaParams;
    /** Fixed signature length in bytes, for algorithms that have one. */
    sigLen?: number;
}

const SHA = { '256': 'SHA-256', '384': 'SHA-384', '512': 'SHA-512' } as const;
type Bits = keyof typeof SHA;

/** WebCrypto parameters for a JWS alg, or null when it cannot be verified with a public key. */
export function algParams(alg: string): AlgParams | null {
    const m = /^(RS|PS|ES)(256|384|512)$/.exec(alg);
    if (m) {
        const bits = m[2] as Bits;
        const hash = SHA[bits];
        if (m[1] === 'RS') {
            return {
                importParams: { name: 'RSASSA-PKCS1-v1_5', hash },
                verifyParams: { name: 'RSASSA-PKCS1-v1_5' }
            };
        }
        if (m[1] === 'PS') {
            return {
                importParams: { name: 'RSA-PSS', hash },
                verifyParams: { name: 'RSA-PSS', saltLength: Number(bits) / 8 }
            };
        }
        const curve = { '256': 'P-256', '384': 'P-384', '512': 'P-521' }[bits];
        return {
            importParams: { name: 'ECDSA', namedCurve: curve },
            verifyParams: { name: 'ECDSA', hash },
            // JWS carries r || s, each the curve's field size (RFC 7518 §3.4)
            sigLen: { '256': 64, '384': 96, '512': 132 }[bits]
        };
    }
    if (alg === 'EdDSA' || alg === 'Ed25519') {
        return { importParams: { name: 'Ed25519' }, verifyParams: { name: 'Ed25519' }, sigLen: 64 };
    }
    return null;
}

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

/** Turn a JWKS's keys into candidates, skipping entries that have no public form. */
export function keysFromJwks(keys: unknown[], source: KeySource): CandidateKey[] {
    const out: CandidateKey[] = [];
    keys.forEach((k, index) => {
        if (typeof k !== 'object' || k === null) return;
        const jwk = k as Record<string, unknown>;
        let spki: Uint8Array;
        try {
            spki = jwkToSpki(jwk);
        } catch {
            return;
        }
        out.push({
            spki,
            source,
            index,
            kid: str(jwk.kid),
            alg: str(jwk.alg),
            use: str(jwk.use),
            jwk
        });
    });
    return out;
}

/** Candidates from the token's x5c header: the leaf certificate's key comes first. */
export function keysFromX5c(header: Record<string, unknown>): CandidateKey[] {
    if (!Array.isArray(header.x5c)) return [];
    const leaf: unknown = header.x5c[0];
    if (typeof leaf !== 'string') return [];
    try {
        return [{ spki: certPublicKeySpki(leaf), source: 'x5c', index: 0 }];
    } catch {
        return [];
    }
}

/**
 * Parse a pasted key: a JWKS, a single JWK, a `PUBLIC KEY` PEM or a
 * `CERTIFICATE` PEM. Throws with a readable message when it is none of those.
 */
export function parseKeyInput(text: string): CandidateKey[] {
    const trimmed = text.trim();
    if (trimmed.startsWith('{')) {
        let data: unknown;
        try {
            data = JSON.parse(trimmed);
        } catch {
            throw new Error('Not valid JSON');
        }
        const obj = data as Record<string, unknown>;
        const list = Array.isArray(obj.keys) ? obj.keys : [obj];
        const keys = keysFromJwks(list, 'pasted');
        if (keys.length === 0) throw new Error('No usable public key in the JWK or JWKS');
        return keys;
    }
    const pem = /-----BEGIN (PUBLIC KEY|CERTIFICATE)-----([\s\S]*?)-----END \1-----/.exec(trimmed);
    if (!pem) throw new Error('Paste a JWK, a JWKS, or a PUBLIC KEY or CERTIFICATE PEM');
    const body = pem[2].replace(/\s+/g, '');
    try {
        const spki = pem[1] === 'CERTIFICATE' ? certPublicKeySpki(body) : base64ToBytes(body);
        return [{ spki, source: 'pasted', index: 0 }];
    } catch {
        throw new Error(
            `Could not read the ${pem[1] === 'CERTIFICATE' ? 'certificate' : 'public key'}`
        );
    }
}

/**
 * The keys worth trying for this header, in order. A kid narrows the set to
 * matching keys when any key carries a kid; encryption keys and keys pinned
 * to a different alg are never tried.
 */
export function selectKeys(header: Record<string, unknown>, keys: CandidateKey[]): CandidateKey[] {
    const alg = str(header.alg);
    const usable = keys.filter((k) => k.use !== 'enc' && (k.alg === undefined || k.alg === alg));
    const kid = str(header.kid);
    if (kid !== undefined && usable.some((k) => k.kid !== undefined)) {
        return usable.filter((k) => k.kid === kid);
    }
    return usable;
}

async function importSpki(spki: Uint8Array, params: AlgParams): Promise<CryptoKey | null> {
    try {
        return await crypto.subtle.importKey(
            'spki',
            spki as Uint8Array<ArrayBuffer>,
            params.importParams,
            false,
            ['verify']
        );
    } catch {
        // wrong key type or curve for this alg
        return null;
    }
}

/** Verify a compact JWS against the given keys. Never throws. */
export async function verifyJwt(token: string, keys: CandidateKey[]): Promise<VerifyResult> {
    const parts = token.split('.');
    if (parts.length !== 3) return { status: 'invalid', detail: 'Not a compact JWS' };
    const [h, p, s] = parts;

    let header: Record<string, unknown>;
    try {
        header = JSON.parse(new TextDecoder().decode(base64ToBytes(h))) as Record<string, unknown>;
    } catch {
        return { status: 'invalid', detail: 'Header is not valid JSON' };
    }
    const alg = str(header.alg) ?? '';

    if (alg.toLowerCase() === 'none') {
        return { status: 'unsigned', detail: 'alg "none" carries no signature to verify' };
    }
    if (/^HS(256|384|512)$/.test(alg)) {
        return {
            status: 'unsupported',
            detail: `${alg} is verified with a shared secret, not a public key`
        };
    }
    const params = algParams(alg);
    if (!params)
        return { status: 'unsupported', detail: `Unsupported algorithm: ${alg || 'none given'}` };

    const candidates = selectKeys(header, keys);
    if (candidates.length === 0) {
        const kid = str(header.kid);
        return {
            status: 'no-key',
            detail: kid ? `No signing key with kid "${kid}"` : `No signing key for ${alg}`
        };
    }

    let sig: Uint8Array;
    try {
        sig = base64ToBytes(s);
    } catch {
        return { status: 'invalid', detail: 'Signature is not valid base64url' };
    }
    if (params.sigLen !== undefined && sig.length !== params.sigLen) {
        return {
            status: 'invalid',
            detail: `${alg} signatures are ${params.sigLen} bytes; this one is ${sig.length}`
        };
    }

    const data = new TextEncoder().encode(`${h}.${p}`);
    let imported = 0;
    for (const key of candidates) {
        const cryptoKey = await importSpki(key.spki, params);
        if (!cryptoKey) continue;
        imported++;
        const ok = await crypto.subtle.verify(
            params.verifyParams,
            cryptoKey,
            sig as Uint8Array<ArrayBuffer>,
            data
        );
        if (ok) return { status: 'valid', detail: 'Signature verified', key };
    }

    if (imported === 0) {
        return { status: 'no-key', detail: `None of the candidate keys can verify ${alg}` };
    }
    return {
        status: 'invalid',
        detail:
            imported === 1
                ? 'Signature does not match the key'
                : `Signature does not match any of ${imported} candidate keys`
    };
}
