import { describe, it, expect } from 'vitest';
import { isExpired, relativeLabel, timeStatus } from './time';

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

describe('timeStatus', () => {
    it('defaults to expiry wording', () => {
        expect(timeStatus(ago(2 * h))).toEqual({ label: 'expired 2 hours ago', tone: 'bad' });
        expect(timeStatus(fromNow(2 * h))).toEqual({ label: 'valid for 2 hours', tone: 'good' });
    });

    it('matches relativeLabel for expiries', () => {
        for (const date of [ago(30 * s), fromNow(30 * s), ago(3 * d), fromNow(5 * m + 5 * s)]) {
            expect(timeStatus(date, 'expiry').label).toBe(relativeLabel(date));
        }
    });

    describe('notBefore', () => {
        it('is good once the window has opened', () => {
            expect(timeStatus(ago(3 * h), 'notBefore')).toEqual({
                label: 'valid since 3 hours ago',
                tone: 'good'
            });
        });

        it('is good the moment it opens', () => {
            expect(timeStatus(ago(10 * s), 'notBefore')).toEqual({
                label: 'just became valid',
                tone: 'good'
            });
        });

        it('is bad before the window opens', () => {
            expect(timeStatus(fromNow(2 * d + h), 'notBefore')).toEqual({
                label: 'not valid yet, starts in 2 days',
                tone: 'bad'
            });
        });

        it('is bad seconds before it opens', () => {
            expect(timeStatus(fromNow(30 * s), 'notBefore')).toEqual({
                label: 'valid in a few seconds',
                tone: 'bad'
            });
        });
    });

    describe('instant', () => {
        it('is neutral in the past', () => {
            expect(timeStatus(ago(m + 5 * s), 'instant')).toEqual({
                label: '1 minute ago',
                tone: 'neutral'
            });
        });

        it('is neutral seconds ago', () => {
            expect(timeStatus(ago(5 * s), 'instant')).toEqual({
                label: 'a few seconds ago',
                tone: 'neutral'
            });
        });

        it('treats a few seconds ahead as clock skew', () => {
            expect(timeStatus(fromNow(20 * s), 'instant')).toEqual({
                label: 'a few seconds in the future',
                tone: 'neutral'
            });
        });

        it('is bad well in the future', () => {
            expect(timeStatus(fromNow(d + h), 'instant')).toEqual({
                label: '1 day in the future',
                tone: 'bad'
            });
        });
    });
});
