/**
 * What a timestamp means, which decides how its distance from now reads:
 * - `expiry`: the end of a validity window (exp, NotOnOrAfter, validUntil).
 * - `notBefore`: the start of a validity window (nbf, NotBefore).
 * - `instant`: when something happened (iat, AuthnInstant).
 */
export type TimeKind = 'expiry' | 'notBefore' | 'instant';

/** good = green, bad = red, neutral = no judgement. */
export type TimeTone = 'good' | 'bad' | 'neutral';

export interface TimeStatus {
    label: string;
    tone: TimeTone;
}

export function isExpired(date: Date): boolean {
    return date.getTime() < Date.now();
}

/** Whole seconds from now: positive in the future, negative in the past. */
function secondsFromNow(date: Date): number {
    return Math.round((date.getTime() - Date.now()) / 1000);
}

/** "N minutes", "N hours" or "N days" for a distance of at least a minute. */
function span(abs: number): string {
    const [n, unit] =
        abs < 3600
            ? [Math.round(abs / 60), 'minute']
            : abs < 86400
              ? [Math.round(abs / 3600), 'hour']
              : [Math.round(abs / 86400), 'day'];
    return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

export function timeStatus(date: Date, kind: TimeKind = 'expiry'): TimeStatus {
    const diff = secondsFromNow(date);
    const abs = Math.abs(diff);
    const future = diff >= 0;
    const soon = abs < 60;

    switch (kind) {
        case 'expiry':
            if (future)
                return {
                    label: soon ? 'in a few seconds' : `valid for ${span(abs)}`,
                    tone: 'good'
                };
            return { label: soon ? 'just expired' : `expired ${span(abs)} ago`, tone: 'bad' };
        case 'notBefore':
            if (future) {
                return {
                    label: soon
                        ? 'valid in a few seconds'
                        : `not valid yet, starts in ${span(abs)}`,
                    tone: 'bad'
                };
            }
            return {
                label: soon ? 'just became valid' : `valid since ${span(abs)} ago`,
                tone: 'good'
            };
        case 'instant':
            // a few seconds ahead is ordinary clock skew, not worth flagging
            if (future && soon) return { label: 'a few seconds in the future', tone: 'neutral' };
            if (future) return { label: `${span(abs)} in the future`, tone: 'bad' };
            return { label: soon ? 'a few seconds ago' : `${span(abs)} ago`, tone: 'neutral' };
    }
}

/** The expiry wording of `timeStatus`, for certificate and metadata validity. */
export function relativeLabel(date: Date): string {
    return timeStatus(date, 'expiry').label;
}
