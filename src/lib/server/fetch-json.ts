import { error } from '@sveltejs/kit';

const MAX_BODY_BYTES = 100_000;
const TIMEOUT_MS = 5_000;

export const CORS_ORIGIN = 'https://samlguy.com';

/**
 * Parse and vet a URL the proxy is about to fetch: HTTPS only, and a domain
 * name rather than an IP literal. Legitimate OIDC issuers and JWKS endpoints
 * always have domain names. Cloudflare Workers lack RFC 1918 reachability, but
 * closing the class is better than relying on infrastructure assumptions.
 */
export function vetRemoteUrl(raw: string, name: string): URL {
    let url: URL;
    try {
        url = new URL(raw);
    } catch {
        error(400, `invalid ${name} URL`);
    }
    if (url.protocol !== 'https:') {
        error(400, `${name} must use HTTPS`);
    }
    if (url.hostname.startsWith('[') || /^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
        error(400, `${name} must use a domain name, not an IP address`);
    }
    return url;
}

/** The discovery document location for an issuer, per OpenID Connect Discovery 1.0 §4. */
export function discoveryUrl(issuer: URL): string {
    return `${issuer.href.replace(/\/$/, '')}/.well-known/openid-configuration`;
}

/**
 * Fetch a small JSON document with a timeout, no redirects and a size cap.
 * `noun` names the endpoint in error messages ("discovery", "JWKS").
 */
export async function fetchJson(url: string, noun: string): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    let response!: Response;
    try {
        response = await fetch(url, {
            headers: { Accept: 'application/json' },
            // Workers do not implement redirect: 'error' (it throws a TypeError on
            // every request), so take the redirect response and refuse it below
            redirect: 'manual',
            signal: controller.signal
        });
    } catch (e) {
        if (e instanceof Error && e.name === 'AbortError') {
            error(504, `${noun} endpoint timed out`);
        }
        error(502, `failed to reach ${noun} endpoint`);
    } finally {
        clearTimeout(timeout);
    }

    if (response.status >= 300 && response.status < 400) {
        error(502, `${noun} endpoint redirected; redirects are not followed`);
    }

    if (!response.ok) {
        error(response.status, `${noun} endpoint returned ${response.status}`);
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength !== null && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
        error(502, `${noun} document exceeds size limit`);
    }

    const text = await response.text();
    if (text.length > MAX_BODY_BYTES) {
        error(502, `${noun} document exceeds size limit`);
    }

    try {
        return JSON.parse(text) as unknown;
    } catch {
        error(502, `${noun} endpoint returned invalid JSON`);
    }
}
