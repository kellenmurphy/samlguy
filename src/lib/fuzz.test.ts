import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { decodeSaml, decodeAllSaml } from '$lib/saml';
import { decodeJwt } from '$lib/jwt';
import { decodeCert } from '$lib/cert';
import { decodeAllGeneric } from '$lib/generic';

// Invariant: any thrown value must be an Error instance.
// A non-Error throw (string, plain object, undefined, etc.) is a parser bug.
function neverThrowsNonError(fn: () => unknown): boolean {
    try {
        fn();
        return true;
    } catch (e) {
        return e instanceof Error;
    }
}

function bytesToBase64(bytes: Uint8Array): string {
    return btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(''));
}

describe('fuzz: decodeSaml', () => {
    it('never throws a non-Error for arbitrary string input', () => {
        fc.assert(fc.property(fc.string(), (s) => neverThrowsNonError(() => decodeSaml(s))));
    });
});

describe('fuzz: decodeAllSaml', () => {
    it('never throws a non-Error for arbitrary string input', () => {
        fc.assert(fc.property(fc.string(), (s) => neverThrowsNonError(() => decodeAllSaml(s))));
    });
});

describe('fuzz: decodeJwt', () => {
    it('never throws a non-Error for arbitrary string input', () => {
        fc.assert(fc.property(fc.string(), (s) => neverThrowsNonError(() => decodeJwt(s))));
    });
});

describe('fuzz: decodeCert — arbitrary base64 strings', () => {
    it('never throws a non-Error', () => {
        fc.assert(
            fc.property(fc.base64String(), (s) => neverThrowsNonError(() => decodeCert(s)))
        );
    });
});

describe('fuzz: decodeCert — valid base64 of arbitrary byte sequences', () => {
    it('never throws a non-Error', () => {
        fc.assert(
            fc.property(fc.uint8Array({ maxLength: 4096 }), (bytes) =>
                neverThrowsNonError(() => decodeCert(bytesToBase64(bytes)))
            )
        );
    });
});

describe('fuzz: decodeAllGeneric', () => {
    it('never throws a non-Error for arbitrary string input', () => {
        fc.assert(fc.property(fc.string(), (s) => neverThrowsNonError(() => decodeAllGeneric(s))));
    });
});
