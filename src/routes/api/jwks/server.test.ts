import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GET } from './+server';

function makeEvent(params: Record<string, string>) {
    const url = new URL('https://samlguy.com/api/jwks');
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    return { url } as Parameters<typeof GET>[0];
}

const jsonResponse = (body: unknown) =>
    new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
    });

const ISSUER = 'https://idp.example.com';
const DISCOVERY = { issuer: ISSUER, jwks_uri: 'https://keys.example.com/jwks.json' };
const RSA_JWK = { kty: 'RSA', kid: 'k1', use: 'sig', alg: 'RS256', n: 'AQAB', e: 'AQAB' };

/** Answer the discovery request, then the JWKS request. */
function serve(discovery: unknown, jwks?: unknown) {
    const responses = [jsonResponse(discovery)];
    if (jwks !== undefined) responses.push(jsonResponse(jwks));
    vi.mocked(fetch).mockImplementation(async () => responses.shift()!);
}

describe('GET /api/jwks', () => {
    beforeEach(() => {
        vi.stubGlobal('fetch', vi.fn());
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('returns 400 when issuer param is missing', async () => {
        await expect(GET(makeEvent({}))).rejects.toMatchObject({ status: 400 });
    });

    it('vets the issuer the same way discovery does', async () => {
        await expect(GET(makeEvent({ issuer: 'http://idp.example.com' }))).rejects.toMatchObject({
            status: 400,
            body: { message: 'issuer must use HTTPS' }
        });
    });

    it('fetches the JWKS named by the discovery document', async () => {
        serve(DISCOVERY, { keys: [RSA_JWK] });
        const res = await GET(makeEvent({ issuer: ISSUER }));
        expect(res.status).toBe(200);
        expect(res.headers.get('Access-Control-Allow-Origin')).toBe('https://samlguy.com');
        expect(await res.json()).toEqual({ jwks_uri: DISCOVERY.jwks_uri, keys: [RSA_JWK] });
        expect(vi.mocked(fetch).mock.calls.map((c) => c[0])).toEqual([
            'https://idp.example.com/.well-known/openid-configuration',
            'https://keys.example.com/jwks.json'
        ]);
    });

    it('strips private and symmetric key members', async () => {
        serve(DISCOVERY, {
            keys: [
                { ...RSA_JWK, d: 'x', p: 'x', q: 'x', dp: 'x', dq: 'x', qi: 'x', oth: [] },
                { kty: 'oct', kid: 'h', k: 'c2VjcmV0' }
            ]
        });
        const body = await (await GET(makeEvent({ issuer: ISSUER }))).json();
        expect(body.keys).toEqual([RSA_JWK, { kty: 'oct', kid: 'h' }]);
    });

    it('drops entries that are not objects', async () => {
        serve(DISCOVERY, { keys: [RSA_JWK, null, 'x', [1], 3] });
        const body = await (await GET(makeEvent({ issuer: ISSUER }))).json();
        expect(body.keys).toEqual([RSA_JWK]);
    });

    it.each([
        ['missing', { issuer: ISSUER }],
        ['not a string', { issuer: ISSUER, jwks_uri: 42 }],
        ['a non-object document', 'nope'],
        ['a null document', null]
    ])('returns 502 when jwks_uri is %s', async (_, discovery) => {
        serve(discovery);
        await expect(GET(makeEvent({ issuer: ISSUER }))).rejects.toMatchObject({
            status: 502,
            body: { message: 'discovery document has no jwks_uri' }
        });
    });

    it('refuses a plaintext jwks_uri', async () => {
        serve({ ...DISCOVERY, jwks_uri: 'http://keys.example.com/jwks.json' });
        await expect(GET(makeEvent({ issuer: ISSUER }))).rejects.toMatchObject({
            status: 400,
            body: { message: 'jwks_uri must use HTTPS' }
        });
        expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('refuses a jwks_uri on an IP literal', async () => {
        serve({ ...DISCOVERY, jwks_uri: 'https://169.254.169.254/keys' });
        await expect(GET(makeEvent({ issuer: ISSUER }))).rejects.toMatchObject({
            status: 400,
            body: { message: 'jwks_uri must use a domain name, not an IP address' }
        });
    });

    it('refuses a jwks_uri that is not a URL', async () => {
        serve({ ...DISCOVERY, jwks_uri: 'not a url' });
        await expect(GET(makeEvent({ issuer: ISSUER }))).rejects.toMatchObject({
            status: 400,
            body: { message: 'invalid jwks_uri URL' }
        });
    });

    it.each([
        ['has no keys array', { nope: true }],
        ['is not an object', 7],
        ['is null', null]
    ])('returns 502 when the JWKS %s', async (_, jwks) => {
        serve(DISCOVERY, jwks);
        await expect(GET(makeEvent({ issuer: ISSUER }))).rejects.toMatchObject({
            status: 502,
            body: { message: 'response is not a JWK Set' }
        });
    });

    it('returns 502 for an oversized key set', async () => {
        serve(DISCOVERY, { keys: Array.from({ length: 51 }, () => RSA_JWK) });
        await expect(GET(makeEvent({ issuer: ISSUER }))).rejects.toMatchObject({
            status: 502,
            body: { message: 'JWK Set has more than 50 keys' }
        });
    });

    it('names the JWKS endpoint when it fails', async () => {
        vi.mocked(fetch)
            .mockResolvedValueOnce(jsonResponse(DISCOVERY))
            .mockResolvedValueOnce(new Response(null, { status: 404 }));
        await expect(GET(makeEvent({ issuer: ISSUER }))).rejects.toMatchObject({
            status: 404,
            body: { message: 'JWKS endpoint returned 404' }
        });
    });
});
