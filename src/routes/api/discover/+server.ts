import { error, json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { CORS_ORIGIN, discoveryUrl, fetchJson, vetRemoteUrl } from '#lib/server/fetch-json.ts';

export const GET: RequestHandler = async ({ url }) => {
    const issuer = url.searchParams.get('issuer');

    if (!issuer) {
        error(400, 'issuer parameter required');
    }

    const data = await fetchJson(discoveryUrl(vetRemoteUrl(issuer, 'issuer')), 'discovery');

    if (typeof data !== 'object' || data === null || !('issuer' in data)) {
        error(502, 'response is not a valid OIDC discovery document');
    }

    return json(data, {
        headers: { 'Access-Control-Allow-Origin': CORS_ORIGIN }
    });
};
