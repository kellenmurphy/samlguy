import { error, json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

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

    const response = await fetch(discoveryUrl, {
        headers: { Accept: 'application/json' }
    });

    if (!response.ok) {
        error(response.status, `discovery endpoint returned ${response.status}`);
    }

    const data: unknown = await response.json();
    return json(data);
};
