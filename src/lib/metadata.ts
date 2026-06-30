const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_MDUI = 'urn:oasis:names:tc:SAML:metadata:ui';
const NS_MDATTR = 'urn:oasis:names:tc:SAML:metadata:attribute';
const NS_MDRPI = 'urn:oasis:names:tc:SAML:metadata:rpi';
const NS_SHIBMD = 'urn:mace:shibboleth:metadata:1.0';
const NS_XML = 'http://www.w3.org/XML/1998/namespace';

export type KeyUse = 'signing' | 'encryption';

export interface MetadataEndpoint {
    binding: string;
    location: string;
    responseLocation?: string;
    index?: number;
    isDefault?: boolean;
}

export interface MetadataKey {
    use?: KeyUse;
    certificate: string; // cleaned base64 DER
}

export interface RequestedAttribute {
    name: string;
    friendlyName?: string;
    isRequired?: boolean;
    nameFormat?: string;
}

export interface LangString {
    lang: string;
    value: string;
}

export interface MetadataLogo {
    url: string;
    width?: string;
    height?: string;
}

export interface MduiInfo {
    displayNames: LangString[];
    descriptions: LangString[];
    logos: MetadataLogo[];
    informationURLs: LangString[];
    privacyURLs: LangString[];
}

export interface ContactPerson {
    type: string;
    company?: string;
    givenName?: string;
    surName?: string;
    emails: string[];
}

export interface RoleDescriptor {
    kind: 'idp' | 'sp';
    protocolSupport: string[];
    keys: MetadataKey[];
    nameIdFormats: string[];
    singleLogoutServices: MetadataEndpoint[];
    mdui?: MduiInfo;
    // IdP only
    singleSignOnServices?: MetadataEndpoint[];
    wantAuthnRequestsSigned?: boolean;
    scopes?: string[];
    // SP only
    assertionConsumerServices?: MetadataEndpoint[];
    authnRequestsSigned?: boolean;
    wantAssertionsSigned?: boolean;
    requestedAttributes?: RequestedAttribute[];
    serviceNames?: LangString[];
}

export interface OrganizationInfo {
    names: LangString[];
    displayNames: LangString[];
    urls: LangString[];
}

export interface EntityMetadata {
    entityId: string;
    validUntil?: string;
    cacheDuration?: string;
    registrationAuthority?: string;
    entityCategories: string[];
    organization?: OrganizationInfo;
    contacts: ContactPerson[];
    roles: RoleDescriptor[];
}

export interface MetadataResult {
    entity: EntityMetadata;
    // set when the entity was extracted from an EntitiesDescriptor aggregate
    aggregateCount?: number;
    // Presence of a document-level <ds:Signature>. This records only that a signature
    // exists and which algorithm it claims — it is NOT cryptographically verified.
    signature?: { algorithm?: string };
}

// ── DOM helpers (mirrors the namespace-aware pattern in saml.ts) ────────────────

function getEl(parent: Document | Element, ns: string, localName: string): Element | null {
    return parent.getElementsByTagNameNS(ns, localName).item(0);
}

function getEls(parent: Document | Element, ns: string, localName: string): Element[] {
    return Array.from(parent.getElementsByTagNameNS(ns, localName));
}

function attr(el: Element | null, name: string): string | undefined {
    return el?.getAttribute(name) ?? undefined;
}

function txt(el: Element | null): string | undefined {
    const t = el?.textContent?.trim();
    return t || undefined;
}

function boolAttr(el: Element | null, name: string): boolean | undefined {
    const v = el?.getAttribute(name);
    if (v == null) return undefined;
    return v === 'true' || v === '1';
}

function langStr(el: Element): LangString {
    return { lang: el.getAttributeNS(NS_XML, 'lang') ?? '', value: txt(el) ?? '' };
}

function langList(parent: Element, ns: string, localName: string): LangString[] {
    return getEls(parent, ns, localName).map(langStr);
}

// ── Detection ───────────────────────────────────────────────────────────────────

// The first element (with any namespace prefix) must be EntityDescriptor / EntitiesDescriptor.
const METADATA_ROOT_EL = /^<(?:[\w.-]+:)?(?:EntityDescriptor|EntitiesDescriptor)[\s/>]/;

// Skip an optional BOM, XML prolog, and any leading comments with a linear scan, then check
// the first element. Done by index rather than one big regex to avoid catastrophic
// backtracking (ReDoS) on inputs like "<!--" followed by many "--><!--" repetitions.
export function isMetadata(raw: string): boolean {
    let i = raw.charCodeAt(0) === 0xfeff ? 1 : 0;
    const skipWs = () => {
        while (i < raw.length && /\s/.test(raw[i])) i++;
    };
    skipWs();

    if (raw.startsWith('<?', i)) {
        const end = raw.indexOf('?>', i + 2);
        if (end === -1) return false;
        i = end + 2;
        skipWs();
    }

    while (raw.startsWith('<!--', i)) {
        const end = raw.indexOf('-->', i + 4);
        if (end === -1) return false;
        i = end + 3;
        skipWs();
    }

    return METADATA_ROOT_EL.test(raw.slice(i));
}

// ── Parsing ───────────────────────────────────────────────────────────────────

const CATEGORY_ATTR_NAMES = new Set([
    'http://macedir.org/entity-category',
    'http://macedir.org/entity-category-support',
    'urn:oasis:names:tc:SAML:attribute:assurance-certification'
]);

export function parseMetadata(raw: string): MetadataResult {
    const doc = new DOMParser().parseFromString(raw.trim(), 'application/xml');
    if (doc.querySelector('parsererror')) {
        throw new Error('Metadata is not valid XML');
    }

    const entityEls = getEls(doc, NS_MD, 'EntityDescriptor');
    if (entityEls.length === 0) {
        throw new Error('No EntityDescriptor found in metadata');
    }

    const isAggregate = doc.documentElement.localName === 'EntitiesDescriptor';
    const sigEl = getEl(doc, NS_DS, 'Signature');
    const signature = sigEl
        ? { algorithm: attr(getEl(sigEl, NS_DS, 'SignatureMethod'), 'Algorithm') }
        : undefined;
    return {
        entity: parseEntity(entityEls[0]),
        aggregateCount: isAggregate ? entityEls.length : undefined,
        signature
    };
}

function parseEntity(el: Element): EntityMetadata {
    const idp = getEls(el, NS_MD, 'IDPSSODescriptor').map((r) => parseRole(r, 'idp'));
    const sp = getEls(el, NS_MD, 'SPSSODescriptor').map((r) => parseRole(r, 'sp'));

    const orgEl = getEl(el, NS_MD, 'Organization');
    const organization: OrganizationInfo | undefined = orgEl
        ? {
              names: langList(orgEl, NS_MD, 'OrganizationName'),
              displayNames: langList(orgEl, NS_MD, 'OrganizationDisplayName'),
              urls: langList(orgEl, NS_MD, 'OrganizationURL')
          }
        : undefined;

    return {
        entityId: attr(el, 'entityID') ?? '',
        validUntil: attr(el, 'validUntil'),
        cacheDuration: attr(el, 'cacheDuration'),
        registrationAuthority: attr(
            getEl(el, NS_MDRPI, 'RegistrationInfo'),
            'registrationAuthority'
        ),
        entityCategories: parseEntityCategories(el),
        organization,
        contacts: getEls(el, NS_MD, 'ContactPerson').map(parseContact),
        roles: [...idp, ...sp]
    };
}

function parseEntityCategories(el: Element): string[] {
    const ea = getEl(el, NS_MDATTR, 'EntityAttributes');
    if (!ea) return [];
    const values: string[] = [];
    for (const a of getEls(ea, NS_SAML, 'Attribute')) {
        if (!CATEGORY_ATTR_NAMES.has(attr(a, 'Name') ?? '')) continue;
        for (const v of getEls(a, NS_SAML, 'AttributeValue')) {
            const t = txt(v);
            if (t) values.push(t);
        }
    }
    return values;
}

function parseContact(el: Element): ContactPerson {
    return {
        type: attr(el, 'contactType') ?? '',
        company: txt(getEl(el, NS_MD, 'Company')),
        givenName: txt(getEl(el, NS_MD, 'GivenName')),
        surName: txt(getEl(el, NS_MD, 'SurName')),
        emails: getEls(el, NS_MD, 'EmailAddress')
            .map((e) => txt(e)?.replace(/^mailto:/i, ''))
            .filter((e): e is string => !!e)
    };
}

function parseRole(el: Element, kind: 'idp' | 'sp'): RoleDescriptor {
    const role: RoleDescriptor = {
        kind,
        protocolSupport: (attr(el, 'protocolSupportEnumeration') ?? '')
            .split(/\s+/)
            .filter(Boolean),
        keys: parseKeys(el),
        nameIdFormats: getEls(el, NS_MD, 'NameIDFormat')
            .map((f) => txt(f))
            .filter((f): f is string => !!f),
        singleLogoutServices: parseEndpoints(el, 'SingleLogoutService'),
        mdui: parseMdui(el)
    };

    if (kind === 'idp') {
        role.singleSignOnServices = parseEndpoints(el, 'SingleSignOnService');
        role.wantAuthnRequestsSigned = boolAttr(el, 'WantAuthnRequestsSigned');
        role.scopes = getEls(el, NS_SHIBMD, 'Scope')
            .map((s) => txt(s))
            .filter((s): s is string => !!s);
    } else {
        role.assertionConsumerServices = parseEndpoints(el, 'AssertionConsumerService');
        role.authnRequestsSigned = boolAttr(el, 'AuthnRequestsSigned');
        role.wantAssertionsSigned = boolAttr(el, 'WantAssertionsSigned');
        const acs = getEl(el, NS_MD, 'AttributeConsumingService');
        if (acs) {
            role.serviceNames = langList(acs, NS_MD, 'ServiceName');
            role.requestedAttributes = getEls(acs, NS_MD, 'RequestedAttribute').map((ra) => ({
                name: attr(ra, 'Name') ?? '',
                friendlyName: attr(ra, 'FriendlyName'),
                isRequired: boolAttr(ra, 'isRequired'),
                nameFormat: attr(ra, 'NameFormat')
            }));
        }
    }

    return role;
}

function parseKeys(roleEl: Element): MetadataKey[] {
    const keys: MetadataKey[] = [];
    for (const kd of getEls(roleEl, NS_MD, 'KeyDescriptor')) {
        const cert = txt(getEl(kd, NS_DS, 'X509Certificate'))?.replace(/\s+/g, '');
        if (!cert) continue;
        const use = attr(kd, 'use');
        keys.push({
            use: use === 'signing' || use === 'encryption' ? use : undefined,
            certificate: cert
        });
    }
    return keys;
}

function parseEndpoints(roleEl: Element, localName: string): MetadataEndpoint[] {
    return getEls(roleEl, NS_MD, localName).map((e) => {
        const index = attr(e, 'index');
        return {
            binding: attr(e, 'Binding') ?? '',
            location: attr(e, 'Location') ?? '',
            responseLocation: attr(e, 'ResponseLocation'),
            index: index != null ? Number(index) : undefined,
            isDefault: boolAttr(e, 'isDefault')
        };
    });
}

function parseMdui(roleEl: Element): MduiInfo | undefined {
    const ui = getEl(roleEl, NS_MDUI, 'UIInfo');
    if (!ui) return undefined;
    return {
        displayNames: langList(ui, NS_MDUI, 'DisplayName'),
        descriptions: langList(ui, NS_MDUI, 'Description'),
        informationURLs: langList(ui, NS_MDUI, 'InformationURL'),
        privacyURLs: langList(ui, NS_MDUI, 'PrivacyStatementURL'),
        logos: getEls(ui, NS_MDUI, 'Logo').map((l) => ({
            url: txt(l) ?? '',
            width: attr(l, 'width'),
            height: attr(l, 'height')
        }))
    };
}

// ── Display label maps (same shape as AUTHN_CONTEXT_LABELS in saml.ts) ──────────

export const BINDING_LABELS: Record<string, string> = {
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST': 'HTTP-POST',
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign': 'HTTP-POST-SimpleSign',
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect': 'HTTP-Redirect',
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact': 'HTTP-Artifact',
    'urn:oasis:names:tc:SAML:2.0:bindings:SOAP': 'SOAP',
    'urn:oasis:names:tc:SAML:2.0:bindings:PAOS': 'PAOS (ECP)',
    'urn:oasis:names:tc:SAML:2.0:bindings:URI': 'URI',
    // Legacy SAML 1.x / Shibboleth bindings still seen on long-lived IdPs
    'urn:mace:shibboleth:1.0:profiles:AuthnRequest': 'Shibboleth 1.0 AuthnRequest',
    'urn:oasis:names:tc:SAML:1.0:profiles:browser-post': 'SAML 1.0 Browser/POST'
};

export const ENTITY_CATEGORY_LABELS: Record<string, string> = {
    // ── Research & Scholarship ──────────────────────────────────────────────────
    'http://refeds.org/category/research-and-scholarship': 'R&S (REFEDS)',
    'https://refeds.org/category/research-and-scholarship': 'R&S (REFEDS)',
    'http://id.incommon.org/category/research-and-scholarship': 'R&S (InCommon)',
    'http://www.swamid.se/category/research-and-education': 'R&E (SWAMID)',
    // ── Code of Conduct ─────────────────────────────────────────────────────────
    'http://www.geant.net/uri/dataprotection-code-of-conduct/v1': 'GÉANT CoCo v1',
    'https://www.geant.net/uri/dataprotection-code-of-conduct/v1': 'GÉANT CoCo v1',
    'http://www.geant.net/uri/dataprotection-code-of-conduct/v2': 'GÉANT CoCo v2',
    'https://geant.org/category/code-of-conduct/v2': 'GÉANT CoCo v2',
    'https://refeds.org/category/code-of-conduct/v1': 'REFEDS CoCo v1',
    'https://refeds.org/category/code-of-conduct/v2': 'REFEDS CoCo v2',
    // ── SIRTFI & assurance frameworks ───────────────────────────────────────────
    'https://refeds.org/sirtfi': 'SIRTFI',
    'http://refeds.org/sirtfi': 'SIRTFI',
    'https://refeds.org/sirtfi/v2': 'SIRTFI v2',
    'https://refeds.org/sirtfi2': 'SIRTFI v2',
    'http://www.swamid.se/policy/assurance/al1': 'SWAMID AL1',
    'http://www.swamid.se/policy/assurance/al2': 'SWAMID AL2',
    'http://www.swamid.se/policy/assurance/al3': 'SWAMID AL3',
    'https://idem.garr.it/af/IDEM-P0': 'IDEM P0',
    'https://idem.garr.it/af/IDEM-P1': 'IDEM P1',
    'https://idem.garr.it/af/IDEM-P2': 'IDEM P2',
    'http://id.elegnamnden.se/ec/1.0/loa3-pnr': 'Swedish eID LoA3 (PNR)',
    // ── Attribute-release / access profiles ─────────────────────────────────────
    'https://refeds.org/category/personalized': 'Personalized Access',
    'http://refeds.org/category/personalized': 'Personalized Access',
    'https://refeds.org/category/pseudonymous': 'Pseudonymous Access',
    'https://refeds.org/category/anonymous': 'Anonymous Access',
    'http://refeds.org/category/anonymous': 'Anonymous Access',
    'http://refeds.org/category/hide-from-discovery': 'Hide From Discovery',
    'https://refeds.org/profile/mfa': 'REFEDS MFA',
    // ── Other well-known categories ─────────────────────────────────────────────
    'http://clarin.eu/category/clarin-member': 'CLARIN Member',
    'https://myacademicid.org/entity-categories/esi': 'MyAcademicID ESI',
    'http://id.elegnamnden.se/ec/1.0/eidas-naturalperson': 'eIDAS Natural Person',
    'http://www.swamid.se/category/hei-service': 'SWAMID HEI Service',
    // ── Federation registration markers ─────────────────────────────────────────
    'http://id.incommon.org/category/registered-by-incommon': 'Registered by InCommon',
    'http://eduid.hu/category/registered-by-eduidhu': 'Registered by eduID.hu'
};

const REFEDS_CoC_HOME = 'https://wiki.refeds.org/display/CODE/Data+Protection+Code+of+Conduct+Home';

export const ENTITY_CATEGORY_SPEC_URLS: Record<string, string> = {
    // R&S
    'http://refeds.org/category/research-and-scholarship':
        'https://refeds.org/category/research-and-scholarship',
    'https://refeds.org/category/research-and-scholarship':
        'https://refeds.org/category/research-and-scholarship',
    'http://id.incommon.org/category/research-and-scholarship':
        'https://incommon.org/federation/research-scholarship-adopters/',
    // Code of Conduct
    'http://www.geant.net/uri/dataprotection-code-of-conduct/v1': REFEDS_CoC_HOME,
    'https://www.geant.net/uri/dataprotection-code-of-conduct/v1': REFEDS_CoC_HOME,
    'http://www.geant.net/uri/dataprotection-code-of-conduct/v2': REFEDS_CoC_HOME,
    'https://geant.org/category/code-of-conduct/v2':
        'https://refeds.org/category/code-of-conduct/v2',
    'https://refeds.org/category/code-of-conduct/v1':
        'https://refeds.org/category/code-of-conduct/v1',
    'https://refeds.org/category/code-of-conduct/v2':
        'https://refeds.org/category/code-of-conduct/v2',
    // SIRTFI & assurance
    'https://refeds.org/sirtfi': 'https://refeds.org/sirtfi',
    'http://refeds.org/sirtfi': 'https://refeds.org/sirtfi',
    'https://refeds.org/sirtfi/v2': 'https://refeds.org/sirtfi/v2',
    'https://refeds.org/sirtfi2': 'https://refeds.org/sirtfi/v2',
    // Access profiles
    'https://refeds.org/category/personalized': 'https://refeds.org/category/personalized',
    'http://refeds.org/category/personalized': 'https://refeds.org/category/personalized',
    'https://refeds.org/category/pseudonymous': 'https://refeds.org/category/pseudonymous',
    'https://refeds.org/category/anonymous': 'https://refeds.org/category/anonymous',
    'http://refeds.org/category/anonymous': 'https://refeds.org/category/anonymous',
    'http://refeds.org/category/hide-from-discovery':
        'https://wiki.refeds.org/display/ENT/Hide+from+Discovery',
    'https://refeds.org/profile/mfa': 'https://refeds.org/profile/mfa',
    // Assurance frameworks
    'http://www.swamid.se/policy/assurance/al1': 'https://wiki.sunet.se/display/SWAMID',
    'http://www.swamid.se/policy/assurance/al2': 'https://wiki.sunet.se/display/SWAMID',
    'http://www.swamid.se/policy/assurance/al3': 'https://wiki.sunet.se/display/SWAMID',
    'https://idem.garr.it/af/IDEM-P0': 'https://idem.garr.it',
    'https://idem.garr.it/af/IDEM-P1': 'https://idem.garr.it',
    'https://idem.garr.it/af/IDEM-P2': 'https://idem.garr.it',
    'http://id.elegnamnden.se/ec/1.0/loa3-pnr': 'https://www.swedenconnect.se',
    'http://id.elegnamnden.se/ec/1.0/eidas-naturalperson': 'https://www.swedenconnect.se',
    // Other well-known
    'http://www.swamid.se/category/research-and-education': 'https://wiki.sunet.se/display/SWAMID',
    'http://www.swamid.se/category/hei-service': 'https://wiki.sunet.se/display/SWAMID',
    'http://clarin.eu/category/clarin-member':
        'https://www.clarin.eu/content/service-provider-federation',
    'https://myacademicid.org/entity-categories/esi':
        'https://myacademicid.org/entity-categories/esi',
    // Registration markers
    'http://id.incommon.org/category/registered-by-incommon':
        'https://incommon.org/federation/entity-categories/',
    'http://eduid.hu/category/registered-by-eduidhu': 'https://eduid.hu'
};

// Coarse classification used to colour entity-category badges in the UI. Pattern-based
// so that federation-specific values we don't label still land in a sensible bucket.
export type EntityCategoryKind = 'rs' | 'coco' | 'assurance' | 'access' | 'registration' | 'other';

export function entityCategoryKind(uri: string): EntityCategoryKind {
    const u = uri.toLowerCase();
    if (u.includes('research-and-scholarship') || u.includes('research-and-education')) return 'rs';
    if (u.includes('code-of-conduct')) return 'coco';
    if (
        u.includes('sirtfi') ||
        u.includes('/policy/assurance/') ||
        u.includes('/af/idem-') ||
        /\/(loa|al)[0-9]/.test(u)
    )
        return 'assurance';
    if (/\/(personalized|pseudonymous|anonymous)$/.test(u)) return 'access';
    if (u.includes('registered-by') || u.includes('/category/registered')) return 'registration';
    return 'other';
}
