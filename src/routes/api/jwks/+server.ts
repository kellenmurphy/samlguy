import { error, json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { CORS_ORIGIN, discoveryUrl, fetchJson, vetRemoteUrl } from '#lib/server/fetch-json.ts';

const MAX_KEYS = 50;

/** JWK members that carry private or symmetric key material (RFC 7518 §6). */
const SECRET_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/**
 * Fetch an issuer's JWKS. Accepts only the issuer and takes `jwks_uri` from
 * the issuer's own discovery document, so the proxy never fetches a URL the
 * caller chose. Returns `{ jwks_uri, keys }` with secret members stripped.
 */
export const GET: RequestHandler = async ({ url }) => {
    const issuer = url.searchParams.get('issuer');

    if (!issuer) {
        error(400, 'issuer parameter required');
    }

    const discovery = await fetchJson(discoveryUrl(vetRemoteUrl(issuer, 'issuer')), 'discovery');
    const jwksUri =
        typeof discovery === 'object' && discovery !== null && 'jwks_uri' in discovery
            ? discovery.jwks_uri
            : undefined;
    if (typeof jwksUri !== 'string') {
        error(502, 'discovery document has no jwks_uri');
    }

    const jwks = await fetchJson(vetRemoteUrl(jwksUri, 'jwks_uri').href, 'JWKS');
    const keys =
        typeof jwks === 'object' && jwks !== null && 'keys' in jwks ? jwks.keys : undefined;
    if (!Array.isArray(keys)) {
        error(502, 'response is not a JWK Set');
    }
    if (keys.length > MAX_KEYS) {
        error(502, `JWK Set has more than ${MAX_KEYS} keys`);
    }

    const publicKeys = keys
        .filter(
            (k): k is Record<string, unknown> =>
                typeof k === 'object' && k !== null && !Array.isArray(k)
        )
        .map((k) =>
            Object.fromEntries(Object.entries(k).filter(([name]) => !SECRET_MEMBERS.includes(name)))
        );

    return json(
        { jwks_uri: jwksUri, keys: publicKeys },
        { headers: { 'Access-Control-Allow-Origin': CORS_ORIGIN } }
    );
};
