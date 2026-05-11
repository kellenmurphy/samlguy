import { relativeLabel, isExpired } from './time.js';

export interface JwtTimestamp {
    raw: number;
    date: Date;
    label: string;
    expired: boolean;
}

export interface JwtDecodeResult {
    raw: string;
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string;
    isAlgNone: boolean;
    isWeakAlg: boolean;
    timestamps: {
        iat?: JwtTimestamp;
        exp?: JwtTimestamp;
        nbf?: JwtTimestamp;
    };
    scopes: string[] | null;
}

function base64urlDecode(s: string): string {
    const padded = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = padded.length % 4;
    return atob(pad === 0 ? padded : padded + '='.repeat(4 - pad));
}

function parseTimestamp(val: unknown): JwtTimestamp | undefined {
    if (typeof val !== 'number') return undefined;
    const date = new Date(val * 1000);
    return { raw: val, date, label: relativeLabel(date), expired: isExpired(date) };
}

function parseScopes(payload: Record<string, unknown>): string[] | null {
    const scope = payload.scope;
    const scp = payload.scp;

    if (typeof scope === 'string' && scope.trim())
        return scope.trim().split(/\s+/);
    if (Array.isArray(scope))
        return scope.filter((s): s is string => typeof s === 'string');
    if (typeof scp === 'string' && scp.trim())
        return scp.trim().split(/\s+/);
    if (Array.isArray(scp))
        return scp.filter((s): s is string => typeof s === 'string');
    return null;
}

export function decodeJwt(input: string): JwtDecodeResult {
    const trimmed = input.trim().replace(/^Bearer\s+/i, '');
    const parts = trimmed.split('.');
    if (parts.length !== 3)
        throw new Error('Invalid JWT: expected 3 dot-separated parts');

    const [headerB64, payloadB64, signature] = parts;

    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;

    try {
        header = JSON.parse(base64urlDecode(headerB64)) as Record<string, unknown>;
    } catch {
        throw new Error('Invalid JWT: could not decode header');
    }

    try {
        payload = JSON.parse(base64urlDecode(payloadB64)) as Record<string, unknown>;
    } catch {
        throw new Error('Invalid JWT: could not decode payload');
    }

    const alg = typeof header.alg === 'string' ? header.alg : '';
    const isAlgNone = alg.toLowerCase() === 'none';
    const isWeakAlg = /^HS/i.test(alg);

    return {
        raw: trimmed,
        header,
        payload,
        signature,
        isAlgNone,
        isWeakAlg,
        timestamps: {
            iat: parseTimestamp(payload.iat),
            exp: parseTimestamp(payload.exp),
            nbf: parseTimestamp(payload.nbf),
        },
        scopes: parseScopes(payload),
    };
}
