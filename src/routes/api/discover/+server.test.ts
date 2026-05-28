import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GET } from './+server';

function makeEvent(params: Record<string, string>) {
    const url = new URL('https://samlguy.com/api/discover');
    for (const [k, v] of Object.entries(params)) {
        url.searchParams.set(k, v);
    }
    return { url } as Parameters<typeof GET>[0];
}

function makeJsonResponse(body: unknown, init: ResponseInit = {}) {
    return new Response(JSON.stringify(body), {
        status: 200,
        ...init,
        headers: { 'Content-Type': 'application/json', ...init.headers }
    });
}

describe('GET /api/discover', () => {
    beforeEach(() => {
        vi.stubGlobal('fetch', vi.fn());
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.useRealTimers();
    });

    // --- Input validation ---

    it('returns 400 when issuer param is missing', async () => {
        await expect(GET(makeEvent({}))).rejects.toMatchObject({ status: 400 });
    });

    it('returns 400 for an invalid issuer URL', async () => {
        await expect(GET(makeEvent({ issuer: 'not a url' }))).rejects.toMatchObject({ status: 400 });
    });

    it('returns 400 when issuer is not HTTPS', async () => {
        await expect(
            GET(makeEvent({ issuer: 'http://idp.example.com' }))
        ).rejects.toMatchObject({ status: 400 });
    });

    // --- Fetch failures ---

    it('returns 504 when the discovery fetch times out (AbortError thrown directly)', async () => {
        const abortErr = Object.assign(new Error('aborted'), { name: 'AbortError' });
        vi.mocked(fetch).mockRejectedValue(abortErr);
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 504 });
    });

    it('aborts the fetch and returns 504 when the 5-second timer fires', async () => {
        vi.useFakeTimers();
        vi.mocked(fetch).mockImplementation((_url, options) => {
            return new Promise((_resolve, reject) => {
                (options as RequestInit).signal?.addEventListener('abort', () => {
                    reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
                });
            });
        });
        const request = GET(makeEvent({ issuer: 'https://idp.example.com' }));
        // Attach the rejection handler before advancing timers so the rejection
        // is never unhandled when the abort fires mid-await.
        const assertion = expect(request).rejects.toMatchObject({ status: 504 });
        await vi.advanceTimersByTimeAsync(5001);
        await assertion;
    });

    it('returns 502 when the fetch fails for a non-timeout reason (e.g. redirect blocked)', async () => {
        vi.mocked(fetch).mockRejectedValue(new TypeError('redirect mode is set to error'));
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 502 });
    });

    it('passes through non-ok HTTP status from the discovery endpoint', async () => {
        vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 404 }));
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 404 });
    });

    // --- Response size limits ---

    it('returns 502 when Content-Length header exceeds the size cap', async () => {
        vi.mocked(fetch).mockResolvedValue(
            new Response('{}', {
                status: 200,
                headers: { 'content-length': '200000' }
            })
        );
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 502 });
    });

    it('returns 502 when the response body exceeds the size cap even without Content-Length', async () => {
        const bigBody = 'x'.repeat(100_001);
        vi.mocked(fetch).mockResolvedValue(new Response(bigBody, { status: 200 }));
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 502 });
    });

    // --- Response body validation ---

    it('returns 502 when the response body is not valid JSON', async () => {
        vi.mocked(fetch).mockResolvedValue(new Response('<html>nope</html>', { status: 200 }));
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 502 });
    });

    it('returns 502 when the JSON body is not an object (e.g. a number)', async () => {
        vi.mocked(fetch).mockResolvedValue(new Response('42', { status: 200 }));
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 502 });
    });

    it('returns 502 when the JSON body is null', async () => {
        vi.mocked(fetch).mockResolvedValue(new Response('null', { status: 200 }));
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 502 });
    });

    it('returns 502 when the JSON object has no issuer field', async () => {
        vi.mocked(fetch).mockResolvedValue(makeJsonResponse({ token_endpoint: 'https://idp.example.com/token' }));
        await expect(
            GET(makeEvent({ issuer: 'https://idp.example.com' }))
        ).rejects.toMatchObject({ status: 502 });
    });

    // --- Happy path ---

    it('returns the discovery document with CORS header on success', async () => {
        const doc = {
            issuer: 'https://idp.example.com',
            authorization_endpoint: 'https://idp.example.com/auth',
            token_endpoint: 'https://idp.example.com/token',
            jwks_uri: 'https://idp.example.com/keys'
        };
        vi.mocked(fetch).mockResolvedValue(makeJsonResponse(doc));

        const response = await GET(makeEvent({ issuer: 'https://idp.example.com' }));

        expect(response.status).toBe(200);
        expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://samlguy.com');
        expect(await response.json()).toEqual(doc);
    });

    it('strips a trailing slash from the issuer before appending the discovery path', async () => {
        const doc = { issuer: 'https://idp.example.com/' };
        vi.mocked(fetch).mockResolvedValue(makeJsonResponse(doc));

        await GET(makeEvent({ issuer: 'https://idp.example.com/' }));

        expect(vi.mocked(fetch)).toHaveBeenCalledWith(
            'https://idp.example.com/.well-known/openid-configuration',
            expect.objectContaining({ redirect: 'error' })
        );
    });
});
