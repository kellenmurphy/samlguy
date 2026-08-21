export type AttributeCategory = 'rs';

export interface AttributeInfo {
    friendlyName: string;
    categories: AttributeCategory[];
}

export const EPPN_OID = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.6';

export const ATTRIBUTE_REGISTRY: Record<string, AttributeInfo> = {
    // ── eduPerson ─────────────────────────────────────────────────────────────────
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': { friendlyName: 'eduPersonAffiliation', categories: [] },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.2': { friendlyName: 'eduPersonNickname', categories: [] },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.5': {
        friendlyName: 'eduPersonPrimaryAffiliation',
        categories: []
    },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': {
        friendlyName: 'eduPersonPrincipalName',
        categories: ['rs']
    },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.7': { friendlyName: 'eduPersonEntitlement', categories: [] },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.9': {
        friendlyName: 'eduPersonScopedAffiliation',
        categories: ['rs']
    },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.10': {
        friendlyName: 'eduPersonTargetedID',
        categories: ['rs']
    },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.11': { friendlyName: 'eduPersonAssurance', categories: [] },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.12': { friendlyName: 'eduPersonUniqueId', categories: ['rs'] },
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.13': { friendlyName: 'eduPersonOrcid', categories: [] },
    // ── inetOrgPerson / person ────────────────────────────────────────────────────
    'urn:oid:0.9.2342.19200300.100.1.1': { friendlyName: 'uid', categories: [] },
    'urn:oid:0.9.2342.19200300.100.1.3': { friendlyName: 'mail', categories: ['rs'] },
    'urn:oid:0.9.2342.19200300.100.1.37': { friendlyName: 'labeledUri', categories: [] },
    'urn:oid:0.9.2342.19200300.100.1.41': { friendlyName: 'mobile', categories: [] },
    'urn:oid:2.5.4.3': { friendlyName: 'cn', categories: [] },
    'urn:oid:2.5.4.4': { friendlyName: 'sn', categories: ['rs'] },
    'urn:oid:2.5.4.6': { friendlyName: 'c', categories: [] },
    'urn:oid:2.5.4.7': { friendlyName: 'l', categories: [] },
    'urn:oid:2.5.4.8': { friendlyName: 'st', categories: [] },
    'urn:oid:2.5.4.9': { friendlyName: 'street', categories: [] },
    'urn:oid:2.5.4.10': { friendlyName: 'o', categories: [] },
    'urn:oid:2.5.4.11': { friendlyName: 'ou', categories: [] },
    'urn:oid:2.5.4.12': { friendlyName: 'title', categories: [] },
    'urn:oid:2.5.4.17': { friendlyName: 'postalCode', categories: [] },
    'urn:oid:2.5.4.20': { friendlyName: 'telephoneNumber', categories: [] },
    'urn:oid:2.5.4.42': { friendlyName: 'givenName', categories: ['rs'] },
    'urn:oid:2.16.840.1.113730.3.1.2': { friendlyName: 'employeeType', categories: [] },
    'urn:oid:2.16.840.1.113730.3.1.3': { friendlyName: 'employeeNumber', categories: [] },
    'urn:oid:2.16.840.1.113730.3.1.4': { friendlyName: 'departmentNumber', categories: [] },
    'urn:oid:2.16.840.1.113730.3.1.39': { friendlyName: 'preferredLanguage', categories: [] },
    'urn:oid:2.16.840.1.113730.3.1.241': { friendlyName: 'displayName', categories: ['rs'] },
    // ── SCHAC ─────────────────────────────────────────────────────────────────────
    'urn:oid:1.3.6.1.4.1.25178.1.2.9': { friendlyName: 'schacHomeOrganization', categories: [] },
    'urn:oid:1.3.6.1.4.1.25178.1.2.10': {
        friendlyName: 'schacHomeOrganizationType',
        categories: []
    },
    'urn:oid:1.3.6.1.4.1.25178.1.2.14': { friendlyName: 'schacPersonalUniqueCode', categories: [] },
    'urn:oid:1.3.6.1.4.1.25178.1.2.15': { friendlyName: 'schacPersonalUniqueID', categories: [] },
    // ── Grouper / isMemberOf ──────────────────────────────────────────────────────
    'urn:oid:1.3.6.1.4.1.5923.1.5.1.1': { friendlyName: 'isMemberOf', categories: [] }
};

export function getAttributeInfo(name: string): AttributeInfo | undefined {
    return ATTRIBUTE_REGISTRY[name];
}

// Returns 'scoped' if the ePPN value contains @scope, 'unscoped' if not, null if not an ePPN attribute.
export function eppnScopedStatus(name: string, values: string[]): 'scoped' | 'unscoped' | null {
    if (name !== EPPN_OID) return null;
    if (values.length === 0) return null;
    return values[0].includes('@') ? 'scoped' : 'unscoped';
}
