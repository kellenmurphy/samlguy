import { describe, it, expect } from 'vitest';
import {
    getAttributeInfo,
    eppnScopedStatus,
    EPPN_OID,
    ATTRIBUTE_REGISTRY,
} from './attributes';

describe('ATTRIBUTE_REGISTRY', () => {
    it('EPPN_OID constant matches the registry entry', () => {
        expect(ATTRIBUTE_REGISTRY[EPPN_OID]?.friendlyName).toBe('eduPersonPrincipalName');
    });

    it('contains entries for core eduPerson OIDs', () => {
        expect(ATTRIBUTE_REGISTRY['urn:oid:1.3.6.1.4.1.5923.1.1.1.9']?.friendlyName).toBe(
            'eduPersonScopedAffiliation'
        );
        expect(ATTRIBUTE_REGISTRY['urn:oid:1.3.6.1.4.1.5923.1.1.1.10']?.friendlyName).toBe(
            'eduPersonTargetedID'
        );
        expect(ATTRIBUTE_REGISTRY['urn:oid:1.3.6.1.4.1.5923.1.1.1.12']?.friendlyName).toBe(
            'eduPersonUniqueId'
        );
    });

    it('contains entries for standard LDAP attributes', () => {
        expect(ATTRIBUTE_REGISTRY['urn:oid:0.9.2342.19200300.100.1.3']?.friendlyName).toBe('mail');
        expect(ATTRIBUTE_REGISTRY['urn:oid:2.5.4.42']?.friendlyName).toBe('givenName');
        expect(ATTRIBUTE_REGISTRY['urn:oid:2.5.4.4']?.friendlyName).toBe('sn');
        expect(ATTRIBUTE_REGISTRY['urn:oid:2.16.840.1.113730.3.1.241']?.friendlyName).toBe(
            'displayName'
        );
    });

    it('contains entries for SCHAC and isMemberOf', () => {
        expect(ATTRIBUTE_REGISTRY['urn:oid:1.3.6.1.4.1.25178.1.2.9']?.friendlyName).toBe(
            'schacHomeOrganization'
        );
        expect(ATTRIBUTE_REGISTRY['urn:oid:1.3.6.1.4.1.5923.1.5.1.1']?.friendlyName).toBe(
            'isMemberOf'
        );
    });
});

describe('getAttributeInfo', () => {
    it('returns rs category for eduPersonPrincipalName', () => {
        const info = getAttributeInfo('urn:oid:1.3.6.1.4.1.5923.1.1.1.6');
        expect(info?.categories).toContain('rs');
    });

    it('returns rs category for eduPersonScopedAffiliation', () => {
        const info = getAttributeInfo('urn:oid:1.3.6.1.4.1.5923.1.1.1.9');
        expect(info?.categories).toContain('rs');
    });

    it('returns rs for eduPersonTargetedID', () => {
        const info = getAttributeInfo('urn:oid:1.3.6.1.4.1.5923.1.1.1.10');
        expect(info?.categories).toContain('rs');
    });

    it('returns rs for eduPersonUniqueId', () => {
        const info = getAttributeInfo('urn:oid:1.3.6.1.4.1.5923.1.1.1.12');
        expect(info?.categories).toContain('rs');
    });

    it('returns empty categories for eduPersonEntitlement (not in R&S bundle)', () => {
        const info = getAttributeInfo('urn:oid:1.3.6.1.4.1.5923.1.1.1.7');
        expect(info?.categories).toHaveLength(0);
    });

    it('returns empty categories for attributes outside the R&S bundle', () => {
        const info = getAttributeInfo('urn:oid:2.5.4.3');
        expect(info?.friendlyName).toBe('cn');
        expect(info?.categories).toHaveLength(0);
    });

    it('returns undefined for unknown OIDs', () => {
        expect(getAttributeInfo('urn:oid:9.9.9.9.9')).toBeUndefined();
        expect(getAttributeInfo('unknown:attribute')).toBeUndefined();
    });
});

describe('eppnScopedStatus', () => {
    it('returns scoped when ePPN value contains @', () => {
        expect(eppnScopedStatus(EPPN_OID, ['user@example.edu'])).toBe('scoped');
    });

    it('returns unscoped when ePPN value has no @', () => {
        expect(eppnScopedStatus(EPPN_OID, ['username'])).toBe('unscoped');
    });

    it('returns null when ePPN has no values', () => {
        expect(eppnScopedStatus(EPPN_OID, [])).toBeNull();
    });

    it('returns null for non-ePPN attributes even with a scoped-looking value', () => {
        expect(
            eppnScopedStatus('urn:oid:0.9.2342.19200300.100.1.3', ['user@example.edu'])
        ).toBeNull();
    });

    it('returns null for completely unrecognized attribute names', () => {
        expect(eppnScopedStatus('unknown:attr', ['value'])).toBeNull();
    });
});
