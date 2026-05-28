import { error, json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

const MAX_BODY_BYTES = 100_000;
const TIMEOUT_MS = 5_000;
const CORS_ORIGIN = 'https://samlguy.com';

export const GET: RequestHandler = async ({ url }) => {
    const issuer = url.searchParams.get('issuer');

    if (!issuer) {
        error(400, 'issuer parameter required');
    }

    let issuerUrl: URL;
    try {
        issuerUrl = new URL(issuer);
    } catch {
        error(400, 'invalid issuer URL');
    }

    if (issuerUrl.protocol !== 'https:') {
        error(400, 'issuer must use HTTPS');
    }

    const discoveryUrl = `${issuerUrl.href.replace(/\/$/, '')}/.well-known/openid-configuration`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    let response!: Response;
    try {
        response = await fetch(discoveryUrl, {
            headers: { Accept: 'application/json' },
            redirect: 'error',
            signal: controller.signal
        });
    } catch (e) {
        if (e instanceof Error && e.name === 'AbortError') {
            error(504, 'discovery endpoint timed out');
        }
        error(502, 'failed to reach discovery endpoint');
    } finally {
        clearTimeout(timeout);
    }

    if (!response.ok) {
        error(response.status, `discovery endpoint returned ${response.status}`);
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength !== null && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
        error(502, 'discovery document exceeds size limit');
    }

    const text = await response.text();
    if (text.length > MAX_BODY_BYTES) {
        error(502, 'discovery document exceeds size limit');
    }

    let data: unknown;
    try {
        data = JSON.parse(text);
    } catch {
        error(502, 'discovery endpoint returned invalid JSON');
    }

    if (typeof data !== 'object' || data === null || !('issuer' in data)) {
        error(502, 'response is not a valid OIDC discovery document');
    }

    return json(data, {
        headers: { 'Access-Control-Allow-Origin': CORS_ORIGIN }
    });
};
