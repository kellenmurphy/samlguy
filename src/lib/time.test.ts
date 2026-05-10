import { describe, it, expect } from 'vitest';
import { isExpired, relativeLabel } from './time';

function ago(ms: number): Date {
    return new Date(Date.now() - ms);
}

function fromNow(ms: number): Date {
    return new Date(Date.now() + ms);
}

const s = 1000;
const m = 60 * s;
const h = 60 * m;
const d = 24 * h;

describe('isExpired', () => {
    it('returns true for a past date', () => {
        expect(isExpired(ago(h))).toBe(true);
    });

    it('returns false for a future date', () => {
        expect(isExpired(fromNow(h))).toBe(false);
    });
});

describe('relativeLabel', () => {
    it('labels a date 30 seconds in the past as "just expired"', () => {
        expect(relativeLabel(ago(30 * s))).toBe('just expired');
    });

    it('labels a date 30 seconds in the future as "in a few seconds"', () => {
        expect(relativeLabel(fromNow(30 * s))).toBe('in a few seconds');
    });

    it('labels a date 5 minutes in the past', () => {
        expect(relativeLabel(ago(5 * m))).toBe('expired 5 minutes ago');
    });

    it('labels a date 1 minute in the future', () => {
        expect(relativeLabel(fromNow(m + 5 * s))).toBe('valid for 1 minute');
    });

    it('labels a date 2 hours in the past', () => {
        expect(relativeLabel(ago(2 * h))).toBe('expired 2 hours ago');
    });

    it('labels a date 1 hour in the future', () => {
        expect(relativeLabel(fromNow(h + m))).toBe('valid for 1 hour');
    });

    it('labels a date 3 days in the past', () => {
        expect(relativeLabel(ago(3 * d))).toBe('expired 3 days ago');
    });

    it('labels a date 1 day in the future', () => {
        expect(relativeLabel(fromNow(d + h))).toBe('valid for 1 day');
    });
});
