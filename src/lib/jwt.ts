export interface JwtDecodeResult {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string;
}

export function decodeJwt(_input: string): JwtDecodeResult {
    throw new Error('Not implemented');
}
