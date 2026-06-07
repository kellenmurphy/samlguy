import type { MetadataResult } from './metadata';

// Static health checks that can be derived from a single pasted metadata document.
// Intentionally limited to what's verifiable from the XML itself — checks that need
// the partner's side (entityID mismatch, ACS-vs-AuthnRequest, attribute release) or a
// network round-trip (reachable logos, refresh Content-Type, the "cert cliff") can't be
// surfaced from one document and are deliberately out of scope.
//
// Note: signature *presence* is reported independently in the UI, not here — and we do not
// cryptographically verify signatures (that needs exclusive XML canonicalization plus a trust
// anchor). The only signature concern raised as a check is a deprecated signing algorithm.

const DEPRECATED_SIG_ALGS = new Set([
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
    'http://www.w3.org/2000/09/xmldsig#hmac-sha1'
]);

const LEGACY_PROTOCOLS = new Set([
    'urn:mace:shibboleth:1.0',
    'urn:oasis:names:tc:SAML:1.1:protocol',
    'urn:oasis:names:tc:SAML:1.0:protocol'
]);

// Known-bad entity-category URIs seen in production metadata, mapped to the value that
// was almost certainly intended. Extend as more typos surface.
const MISSPELLED_CATEGORIES: Record<string, string> = {
    'https://refeds.org/sirtf': 'https://refeds.org/sirtfi',
    'http://refeds.org/sirtf': 'https://refeds.org/sirtfi',
    'https://refeds.org/sirtfi1': 'https://refeds.org/sirtfi',
    'http://id.incommon.org/category/research-and-scholaship':
        'http://id.incommon.org/category/research-and-scholarship'
};

const EXPIRY_WARN_DAYS = 14;
const MS_PER_DAY = 86_400_000;

export type CheckSeverity = 'error' | 'warning' | 'info';

export interface MetadataCheck {
    severity: CheckSeverity;
    title: string;
    detail: string;
}

export function checkMetadata(result: MetadataResult): MetadataCheck[] {
    const checks: MetadataCheck[] = [];
    const e = result.entity;

    // ── Expiry ──────────────────────────────────────────────────────────────────
    if (!e.validUntil) {
        checks.push({
            severity: 'info',
            title: 'No validUntil',
            detail: 'This metadata declares no validUntil expiry. Some partners require one; per-entity exports often omit it while federation aggregates always set it.'
        });
    } else {
        const vu = new Date(e.validUntil);
        if (isNaN(vu.getTime())) {
            checks.push({
                severity: 'warning',
                title: 'Unparseable validUntil',
                detail: `validUntil "${e.validUntil}" is not a valid timestamp and may be rejected.`
            });
        } else {
            const days = (vu.getTime() - Date.now()) / MS_PER_DAY;
            if (days < 0) {
                checks.push({
                    severity: 'error',
                    title: 'Metadata expired',
                    detail: 'The validUntil date has passed. Partners that honor it will reject this metadata wholesale until it is re-published.'
                });
            } else if (days <= EXPIRY_WARN_DAYS) {
                checks.push({
                    severity: 'warning',
                    title: 'Metadata expiring soon',
                    detail: `validUntil is about ${Math.ceil(days)} day(s) away. Re-sign and publish before it lapses to avoid a federation-wide outage.`
                });
            }
        }
    }

    // ── Weak signature algorithm (presence/verification handled in the UI) ────────
    if (result.signature && DEPRECATED_SIG_ALGS.has(result.signature.algorithm ?? '')) {
        checks.push({
            severity: 'warning',
            title: 'Weak metadata signature algorithm',
            detail: 'The metadata signature uses SHA-1, which many partners have deprecated and will reject. Re-sign with SHA-256 or stronger.'
        });
    }

    // ── entityID hygiene ──────────────────────────────────────────────────────────
    if (e.entityId !== e.entityId.trim()) {
        checks.push({
            severity: 'warning',
            title: 'entityID has surrounding whitespace',
            detail: 'Leading or trailing whitespace makes the entityID a different string to partners and silently breaks trust matching.'
        });
    } else if (/^https?:\/\//i.test(e.entityId) && e.entityId.endsWith('/')) {
        checks.push({
            severity: 'info',
            title: 'entityID ends with a trailing slash',
            detail: 'A trailing slash is significant: "https://sp/" and "https://sp" are distinct entityIDs. Confirm both sides register it identically.'
        });
    }

    // ── Entity-category typos ─────────────────────────────────────────────────────
    for (const cat of e.entityCategories) {
        const suggestion = MISSPELLED_CATEGORIES[cat];
        if (suggestion) {
            checks.push({
                severity: 'warning',
                title: 'Misspelled entity category',
                detail: `"${cat}" looks like a typo of "${suggestion}". Partners keying on the correct URI will silently ignore this value, so the category effectively does nothing.`
            });
        }
    }

    // ── Per-role checks ───────────────────────────────────────────────────────────
    for (const role of e.roles) {
        const label = role.kind === 'idp' ? 'IdP' : 'SP';

        if (role.keys.length === 0) {
            checks.push({
                severity: 'warning',
                title: `${label} publishes no certificate`,
                detail: 'This role has no KeyDescriptor, so partners cannot verify its signatures or encrypt to it.'
            });
        } else if (!role.keys.some((k) => k.use === 'signing' || k.use === undefined)) {
            checks.push({
                severity: 'warning',
                title: `${label} has no signing certificate`,
                detail: 'No KeyDescriptor with use="signing" (or unspecified use). Partners may be unable to verify this role’s signed messages.'
            });
        }

        if (role.keys.some((k) => k.certificate.includes('-----'))) {
            checks.push({
                severity: 'error',
                title: 'Certificate contains PEM headers',
                detail: 'A <ds:X509Certificate> includes PEM armor (-----BEGIN CERTIFICATE-----). Only the raw base64 DER belongs inside the element; the headers break certificate parsing.'
            });
        }

        const endpoints = [
            ...(role.singleSignOnServices ?? []),
            ...(role.assertionConsumerServices ?? []),
            ...role.singleLogoutServices
        ];
        if (endpoints.some((ep) => /^http:\/\//i.test(ep.location))) {
            checks.push({
                severity: 'warning',
                title: `${label} has a plaintext (HTTP) endpoint`,
                detail: 'One or more SSO/SLO/ACS endpoints use http://. SAML endpoints should always be served over HTTPS.'
            });
        }

        if (role.protocolSupport.some((p) => LEGACY_PROTOCOLS.has(p))) {
            checks.push({
                severity: 'info',
                title: `${label} advertises legacy SAML 1.x`,
                detail: 'This role still advertises SAML 1.1 / Shibboleth 1.0 support, long deprecated in favour of SAML 2.0. Usually harmless but worth retiring.'
            });
        }
    }

    return checks;
}
